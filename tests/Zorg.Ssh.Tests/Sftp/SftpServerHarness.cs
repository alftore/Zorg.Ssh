using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Sftp;
using Zorg.Ssh.Tests.Transport;

namespace Zorg.Ssh.Tests.Sftp;

/// <summary>A reply, as a hostile client's test sees it.</summary>
internal sealed record SftpServerReply(byte Type, uint Id, byte[] Body)
{
    public uint Status
    {
        get
        {
            Assert.Equal(SftpMessage.Status, Type);
            return BinaryPrimitives.ReadUInt32BigEndian(Body);
        }
    }

    public byte[] Handle
    {
        get
        {
            Assert.Equal(SftpMessage.Handle, Type);
            SshReader reader = new(Body);
            return reader.ReadBinary().ToArray();
        }
    }

    public byte[] Data
    {
        get
        {
            Assert.Equal(SftpMessage.Data, Type);
            SshReader reader = new(Body);
            return reader.ReadBinary().ToArray();
        }
    }

    public string FirstName
    {
        get
        {
            Assert.Equal(SftpMessage.Name, Type);
            SshReader reader = new(Body);
            Assert.True(reader.ReadUInt32() >= 1);
            return Encoding.UTF8.GetString(reader.ReadBinary());
        }
    }

    public List<string> Names
    {
        get
        {
            Assert.Equal(SftpMessage.Name, Type);
            SshReader reader = new(Body);
            uint count = reader.ReadUInt32();
            List<string> names = [];
            for (uint i = 0; i < count; i++)
            {
                names.Add(Encoding.UTF8.GetString(reader.ReadBinary()));
                reader.ReadBinary();
                SftpAttributes.Read(ref reader);
            }

            return names;
        }
    }

    public SftpAttributes Attributes
    {
        get
        {
            Assert.Equal(SftpMessage.Attrs, Type);
            SshReader reader = new(Body);
            return SftpAttributes.Read(ref reader);
        }
    }
}

/// <summary>
/// A directory layout for attacks: a root, and beside it things a client must never reach.
/// <c>base/root</c> is served. <c>base/outside/secret.txt</c> holds <see cref="Secret"/>, and <c>base/secret.txt</c> is a second copy.
/// </summary>
internal sealed class SftpServerSandbox : IDisposable
{
    public const string Secret = "TOP-SECRET-CONTENT";

    public SftpServerSandbox()
    {
        Base = Directory.CreateTempSubdirectory("zorg-sftp-server").FullName;
        Root = Path.Combine(Base, "root");
        Outside = Path.Combine(Base, "outside");
        Directory.CreateDirectory(Root);
        Directory.CreateDirectory(Outside);
        File.WriteAllText(Path.Combine(Outside, "secret.txt"), Secret);
        File.WriteAllText(Path.Combine(Base, "secret.txt"), Secret);
    }

    public string Base { get; }

    public string Root { get; }

    public string Outside { get; }

    public string InRoot(string relative) => Path.Combine(Root, relative.Replace('/', Path.DirectorySeparatorChar));

    /// <summary>Everything outside the root, with contents. An attack mustn't change a byte of it.</summary>
    public Dictionary<string, string> SnapshotOutside()
    {
        // The root is left out rather than filtered: an attack can leave a link to itself there, and enumerating would follow it.
        Dictionary<string, string> snapshot = [];
        IEnumerable<string> top = Directory.EnumerateFileSystemEntries(Base).Where(e => e != Root);
        foreach (string file in top.Concat(Directory.EnumerateFileSystemEntries(Outside, "*", SearchOption.AllDirectories)))
        {
            snapshot[file] = File.Exists(file) ? File.ReadAllText(file) : "<directory>";
        }

        return snapshot;
    }

    /// <summary>Removes everything. Links go first, by hand: a recursive delete refuses a junction.</summary>
    public void Dispose()
    {
        RemoveLinks(Root);
        Directory.Delete(Base, recursive: true);
    }

    private static void RemoveLinks(string directory)
    {
        // A client can make a directory its owner can't read or enter, with MKDIR or SETSTAT. Root reads it anyway,
        // but a normal user (as in CI) can't list or empty it until the owner's bits are back. This is never a link.
        if (!OperatingSystem.IsWindows())
        {
            const UnixFileMode Owner = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
            File.SetUnixFileMode(directory, File.GetUnixFileMode(directory) | Owner);
        }

        foreach (string entry in Directory.GetFileSystemEntries(directory))
        {
            FileInfo info = new(entry);
            if (info.LinkTarget is null)
            {
                if (info.Attributes.HasFlag(FileAttributes.Directory))
                {
                    RemoveLinks(entry);
                }
            }
            else if (OperatingSystem.IsWindows() && info.Attributes.HasFlag(FileAttributes.Directory))
            {
                Directory.Delete(entry);
            }
            else
            {
                File.Delete(entry);
            }
        }
    }

    /// <summary>Makes a link to a directory. On Windows it's a junction, which needs no privilege and is just as dangerous.</summary>
    public static void LinkDirectory(string link, string target)
    {
        if (!OperatingSystem.IsWindows())
        {
            Directory.CreateSymbolicLink(link, target);
            return;
        }

        ProcessStartInfo start = new("cmd.exe") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        start.ArgumentList.Add("/c");
        start.ArgumentList.Add("mklink");
        start.ArgumentList.Add("/J");
        start.ArgumentList.Add(link);
        start.ArgumentList.Add(Path.GetFullPath(target, Path.GetDirectoryName(link)!));
        using Process process = Process.Start(start)!;
        process.WaitForExit();
        Assert.Equal(0, process.ExitCode);
    }

    /// <summary>Makes a real symbolic link, or skips: Windows needs a privilege for it.</summary>
    public static void Link(string link, string target, bool directory = false)
    {
        try
        {
            if (directory)
            {
                Directory.CreateSymbolicLink(link, target);
            }
            else
            {
                File.CreateSymbolicLink(link, target);
            }
        }
        catch (Exception ex) when (OperatingSystem.IsWindows() && ex is IOException or UnauthorizedAccessException)
        {
            if (Environment.GetEnvironmentVariable("CI") == "true")
            {
                throw;
            }

            Assert.Skip("Needs the privilege to create symbolic links.");
        }
    }
}

/// <summary>A raw SFTP client over an in-memory pipe to a real <see cref="SftpServer"/>. It can say anything, and keeps everything it was told.</summary>
internal sealed class SftpServerHarness : IAsyncDisposable
{
    public const uint Ok = 0;
    public const uint Eof = 1;
    public const uint NoSuchFile = 2;
    public const uint PermissionDenied = 3;
    public const uint Failure = 4;
    public const uint Unsupported = 8;

    public const uint OpenRead = 1;
    public const uint OpenWrite = 2;
    public const uint OpenAppend = 4;
    public const uint OpenCreate = 8;
    public const uint OpenTruncate = 0x10;
    public const uint OpenExclusive = 0x20;

    private readonly Stream _client;
    private readonly CancellationTokenSource _stop = new();
    private readonly List<byte[]> _replies = [];
    private uint _nextId = 100;

    private SftpServerHarness(Stream client, Task<int> serving)
    {
        _client = client;
        Serving = serving;
    }

    public Task<int> Serving { get; }

    public static SftpServerHarness StartRaw(SftpServerOptions options)
    {
        (Stream client, Stream server) = DuplexStream.CreatePair();
        return new SftpServerHarness(client, Task.Run(() => SftpServer.ServeStreamsAsync(server, server, options, CancellationToken.None)));
    }

    public static async Task<SftpServerHarness> StartAsync(SftpServerOptions options)
    {
        SftpServerHarness harness = StartRaw(options);
        await harness.SendAsync(new Packet().U8(SftpMessage.Init).U32(3).ToFrame());
        (byte type, byte[] body) = await harness.ReceiveAsync();
        Assert.Equal(SftpMessage.Version, type);
        Assert.Equal(3u, BinaryPrimitives.ReadUInt32BigEndian(body));
        return harness;
    }

    public static Packet Path(string path) => new Packet().Text(path);

    public static Packet Empty() => new();

    public async Task SendAsync(byte[] frame)
    {
        await _client.WriteAsync(frame, TestContext.Current.CancellationToken);
        await _client.FlushAsync(TestContext.Current.CancellationToken);
    }

    public async Task<SftpServerReply> RequestAsync(byte type, Packet body)
    {
        uint id = _nextId++;
        await SendAsync(new Packet().U8(type).U32(id).Raw(body.ToBytes()).ToFrame());
        (byte replyType, byte[] reply) = await ReceiveAsync();
        Assert.Equal(id, BinaryPrimitives.ReadUInt32BigEndian(reply));
        return new SftpServerReply(replyType, id, reply[4..]);
    }

    public Task<SftpServerReply> ExtendedAsync(string name, Packet arguments) =>
        RequestAsync(SftpMessage.Extended, new Packet().Text(name).Raw(arguments.ToBytes()));

    public Task<SftpServerReply> OpenAsync(string path, uint flags) =>
        RequestAsync(SftpMessage.Open, new Packet().Text(path).U32(flags).U32(0));

    public async Task<byte[]> OpenHandleAsync(string path, uint flags) => (await OpenAsync(path, flags)).Handle;

    public Task<SftpServerReply> ReadAsync(byte[] handle, ulong offset, uint length) =>
        RequestAsync(SftpMessage.Read, new Packet().Bytes(handle).U64(offset).U32(length));

    public Task<SftpServerReply> WriteAsync(byte[] handle, ulong offset, byte[] data) =>
        RequestAsync(SftpMessage.Write, new Packet().Bytes(handle).U64(offset).Bytes(data));

    public Task<SftpServerReply> CloseAsync(byte[] handle) => RequestAsync(SftpMessage.Close, new Packet().Bytes(handle));

    /// <summary>Reads a file through the protocol, if the server lets it.</summary>
    public async Task<string?> TryReadTextAsync(string path)
    {
        SftpServerReply open = await OpenAsync(path, OpenRead);
        if (open.Type != SftpMessage.Handle)
        {
            return null;
        }

        SftpServerReply read = await ReadAsync(open.Handle, 0, 4096);
        await CloseAsync(open.Handle);
        return read.Type == SftpMessage.Data ? Encoding.UTF8.GetString(read.Data) : string.Empty;
    }

    /// <summary>Fails if anything the server said held a real path. Status text is the likely place, and error paths the likely cause.</summary>
    public void AssertNothingLeaked(string serverPath)
    {
        string[] forms = [serverPath, serverPath.Replace('\\', '/'), System.IO.Path.GetFileName(serverPath)];
        foreach (byte[] reply in _replies)
        {
            string text = Encoding.UTF8.GetString(reply);
            foreach (string form in forms)
            {
                Assert.DoesNotContain(form, text, StringComparison.OrdinalIgnoreCase);
            }
        }
    }

    public async Task<int> CloseStreamAsync()
    {
        await _client.DisposeAsync();
        return await Serving.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        await _client.DisposeAsync();
        await _stop.CancelAsync();
        _stop.Dispose();
        try
        {
            await Serving.WaitAsync(TimeSpan.FromSeconds(10));
        }
        catch (Exception ex) when (ex is OperationCanceledException or TimeoutException)
        {
            // A test that wanted to know has already looked.
        }
    }

    private async Task<(byte Type, byte[] Body)> ReceiveAsync()
    {
        byte[] header = new byte[5];
        await _client.ReadExactlyAsync(header, TestContext.Current.CancellationToken);
        byte[] body = new byte[BinaryPrimitives.ReadUInt32BigEndian(header) - 1];
        await _client.ReadExactlyAsync(body, TestContext.Current.CancellationToken);
        _replies.Add(body);
        return (header[4], body);
    }
}

/// <summary>Keeps every log entry of a server session, with the exception attached, so a test can see what reached the log.</summary>
internal sealed class SftpRecordingLoggerFactory : Microsoft.Extensions.Logging.ILoggerFactory
{
    private readonly List<(Microsoft.Extensions.Logging.LogLevel Level, string Message, Exception? Exception)> _entries = [];

    public IReadOnlyList<(Microsoft.Extensions.Logging.LogLevel Level, string Message, Exception? Exception)> Entries
    {
        get
        {
            lock (_entries)
            {
                return [.. _entries];
            }
        }
    }

    public void AddProvider(Microsoft.Extensions.Logging.ILoggerProvider provider)
    {
    }

    public Microsoft.Extensions.Logging.ILogger CreateLogger(string categoryName) => new Recorder(this);

    public void Dispose()
    {
    }

    private sealed class Recorder(SftpRecordingLoggerFactory owner) : Microsoft.Extensions.Logging.ILogger
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => true;

        public void Log<TState>(Microsoft.Extensions.Logging.LogLevel logLevel, Microsoft.Extensions.Logging.EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (owner._entries)
            {
                owner._entries.Add((logLevel, formatter(state, exception), exception));
            }
        }
    }
}

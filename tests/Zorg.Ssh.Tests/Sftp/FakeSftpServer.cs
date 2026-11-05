using System;
using System.Buffers.Binary;
using System.Collections.Generic;
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

/// <summary>
/// Runs these tests after the parallel ones. They start hundreds of in-memory sessions, and that load
/// disturbed the allocation-counting tests in Crypto, which measure one thread during JIT tiering.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class SftpSerialTests
{
    public const string Name = "Sftp";
}

/// <summary>Builds SFTP packets by hand, so a test can say anything a hostile server could.</summary>
internal sealed class Packet
{
    private readonly List<byte> _bytes = [];

    public Packet U8(byte value)
    {
        _bytes.Add(value);
        return this;
    }

    public Packet U32(uint value)
    {
        byte[] bytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        _bytes.AddRange(bytes);
        return this;
    }

    public Packet U64(ulong value)
    {
        byte[] bytes = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        _bytes.AddRange(bytes);
        return this;
    }

    public Packet Raw(ReadOnlySpan<byte> value)
    {
        _bytes.AddRange(value);
        return this;
    }

    public Packet Bytes(ReadOnlySpan<byte> value)
    {
        U32((uint)value.Length);
        return Raw(value);
    }

    public Packet Text(string value) => Bytes(Encoding.UTF8.GetBytes(value));

    /// <summary>A name entry whose attributes are just permissions.</summary>
    public Packet Entry(string name, uint mode = 0x81A4) => Entry(Encoding.UTF8.GetBytes(name), mode);

    public Packet Entry(ReadOnlySpan<byte> name, uint mode = 0x81A4)
    {
        Bytes(name);
        Text("long name");
        U32(0x4);
        return U32(mode);
    }

    /// <summary>The finished packet, with its length field.</summary>
    public byte[] ToFrame()
    {
        byte[] frame = new byte[4 + _bytes.Count];
        BinaryPrimitives.WriteUInt32BigEndian(frame, (uint)_bytes.Count);
        _bytes.CopyTo(frame, 4);
        return frame;
    }

    public byte[] ToBytes() => [.. _bytes];
}

internal sealed record FakeRequest(byte Type, uint Id, byte[] Body)
{
    public string Path => FirstString();

    public string FirstString()
    {
        SshReader reader = new(Body);
        return Encoding.UTF8.GetString(reader.ReadBinary());
    }

    /// <summary>The strings at the start of the body, for checking argument order.</summary>
    public string[] Strings(int count)
    {
        SshReader reader = new(Body);
        string[] strings = new string[count];
        for (int i = 0; i < count; i++)
        {
            strings[i] = Encoding.UTF8.GetString(reader.ReadBinary());
        }

        return strings;
    }

    public (byte[] Handle, long Offset, uint Length) ReadArguments()
    {
        SshReader reader = new(Body);
        byte[] handle = reader.ReadBinary().ToArray();
        long offset = (long)reader.ReadUInt64();
        return (handle, offset, reader.ReadUInt32());
    }

    public (byte[] Handle, long Offset, byte[] Data) WriteArguments()
    {
        SshReader reader = new(Body);
        byte[] handle = reader.ReadBinary().ToArray();
        long offset = (long)reader.ReadUInt64();
        return (handle, offset, reader.ReadBinary().ToArray());
    }
}

internal delegate ValueTask FakeHandler(FakeSftpServer server, FakeRequest request);

/// <summary>An SFTP server in memory, over a duplex stream, driven by a handler. Every request is recorded.</summary>
internal sealed class FakeSftpServer : IAsyncDisposable
{
    public const uint StatusOk = 0;
    public const uint StatusEof = 1;
    public const uint StatusNoSuchFile = 2;
    public const uint StatusPermissionDenied = 3;
    public const uint StatusFailure = 4;

    private readonly Stream _stream;
    private readonly Lock _gate = new();
    private readonly List<FakeRequest> _requests = [];
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly CancellationTokenSource _stop = new();
    private readonly FakeHandler _handler;
    private TaskCompletionSource _requestSeen = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private Task? _loop;

    private FakeSftpServer(Stream stream, FakeHandler handler)
    {
        _stream = stream;
        _handler = handler;
    }

    public SftpClient Client { get; private set; } = null!;

    public IReadOnlyList<FakeRequest> Requests
    {
        get
        {
            lock (_gate)
            {
                return [.. _requests];
            }
        }
    }

    public static async Task<FakeSftpServer> StartAsync(
        FakeHandler handler,
        string[]? extensions = null,
        string? identification = null,
        SftpLimits? limits = null,
        long pauseThreshold = 1024 * 1024)
    {
        (Stream client, Stream server) = DuplexStream.CreatePair(pauseThreshold);
        FakeSftpServer fake = new(server, handler);
        Packet version = new Packet().U8(SftpMessage.Version).U32(3);
        foreach (string extension in extensions ?? [])
        {
            version.Text(extension).Text(extension == "statvfs@openssh.com" ? "2" : "1");
        }

        fake._loop = Task.Run(() => fake.RunAsync(version.ToFrame()));
        fake.Client = await SftpClient.StartAsync(client, client, client, identification, limits ?? SftpLimits.Default, CancellationToken.None);
        return fake;
    }

    /// <summary>Starts a server that sends these bytes as its whole handshake.</summary>
    public static async Task<(Task<SftpClient> Client, Stream Server)> StartRawAsync(byte[] handshake, SftpLimits? limits = null, bool close = false)
    {
        (Stream client, Stream server) = DuplexStream.CreatePair();
        byte[] init = new byte[9];
        await server.WriteAsync(handshake);
        if (close)
        {
            await server.DisposeAsync();
        }

        Task<SftpClient> started = SftpClient.StartAsync(client, client, client, null, limits ?? SftpLimits.Default, CancellationToken.None);
        if (!close)
        {
            await server.ReadExactlyAsync(init);
        }

        return (started, server);
    }

    public async ValueTask SendAsync(byte[] bytes)
    {
        await _writeLock.WaitAsync();
        try
        {
            await _stream.WriteAsync(bytes);
            await _stream.FlushAsync();
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public ValueTask SendStatusAsync(uint id, uint code = StatusOk, string message = "") =>
        SendAsync(new Packet().U8(SftpMessage.Status).U32(id).U32(code).Text(message).Text("en").ToFrame());

    public ValueTask SendHandleAsync(uint id, ReadOnlySpan<byte> handle) =>
        SendAsync(new Packet().U8(SftpMessage.Handle).U32(id).Bytes(handle).ToFrame());

    public ValueTask SendDataAsync(uint id, ReadOnlySpan<byte> data) =>
        SendAsync(new Packet().U8(SftpMessage.Data).U32(id).Bytes(data).ToFrame());

    public ValueTask SendNamesAsync(uint id, params string[] names)
    {
        Packet packet = new Packet().U8(SftpMessage.Name).U32(id).U32((uint)names.Length);
        foreach (string name in names)
        {
            packet.Entry(name);
        }

        return SendAsync(packet.ToFrame());
    }

    public ValueTask SendAttributesAsync(uint id, ulong size = 0) =>
        SendAsync(new Packet().U8(SftpMessage.Attrs).U32(id).U32(0x1).U64(size).ToFrame());

    /// <summary>Ends the connection, as a crash would.</summary>
    public async ValueTask CloseAsync()
    {
        await _stop.CancelAsync();
        await _stream.DisposeAsync();
    }

    /// <summary>Waits until the given number of requests has arrived, in total.</summary>
    public async Task WaitForRequestsAsync(int count, Func<FakeRequest, bool>? filter = null)
    {
        while (true)
        {
            Task seen;
            lock (_gate)
            {
                if (_requests.Count(filter ?? (_ => true)) >= count)
                {
                    return;
                }

                seen = _requestSeen.Task;
            }

            await seen.WaitAsync(TimeSpan.FromSeconds(20));
        }
    }

    public async ValueTask DisposeAsync()
    {
        await Client.DisposeAsync();
        await _stop.CancelAsync();
        await _stream.DisposeAsync();
        if (_loop is not null)
        {
            await _loop;
        }

        _stop.Dispose();
        _writeLock.Dispose();
    }

    private async Task RunAsync(byte[] version)
    {
        try
        {
            byte[] init = new byte[9];
            await _stream.ReadExactlyAsync(init, _stop.Token);
            await SendAsync(version);

            byte[] header = new byte[9];
            while (true)
            {
                await _stream.ReadExactlyAsync(header, _stop.Token);
                int bodyLength = (int)BinaryPrimitives.ReadUInt32BigEndian(header) - 5;
                byte[] body = new byte[bodyLength];
                await _stream.ReadExactlyAsync(body, _stop.Token);
                FakeRequest request = new(header[4], BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(5)), body);
                TaskCompletionSource seen;
                lock (_gate)
                {
                    _requests.Add(request);
                    seen = _requestSeen;
                    _requestSeen = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                }

                seen.TrySetResult();
                await _handler(this, request);
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or EndOfStreamException or IOException or ObjectDisposedException or InvalidOperationException)
        {
            // The client went away, or the test closed the connection.
        }
    }
}

/// <summary>A small working file system behind a <see cref="FakeSftpServer"/>, so hostile tests only override what they break.</summary>
internal sealed class FakeFiles
{
    private readonly Dictionary<uint, (string Path, int Position)> _handles = [];
    private uint _nextHandle;

    public Dictionary<string, byte[]> Files { get; } = [];

    /// <summary>Gets or sets the most bytes one READ returns.</summary>
    public Func<uint, uint> ReadLimit { get; set; } = wanted => wanted;

    /// <summary>Gets directory contents, by path, in batches. Each string is one name.</summary>
    public Dictionary<string, (string Name, uint Mode)[]> Directories { get; } = [];

    public int OpenHandles => _handles.Count;

    public async ValueTask HandleAsync(FakeSftpServer server, FakeRequest request)
    {
        switch (request.Type)
        {
            case SftpMessage.Open:
                await OpenAsync(server, request);
                break;
            case SftpMessage.OpenDir:
                if (!Directories.ContainsKey(request.Path))
                {
                    await server.SendStatusAsync(request.Id, FakeSftpServer.StatusNoSuchFile, "no such directory");
                    break;
                }

                await server.SendHandleAsync(request.Id, NewHandle(request.Path));
                break;
            case SftpMessage.ReadDir:
                await ReadDirectoryAsync(server, request);
                break;
            case SftpMessage.Close:
                _handles.Remove(HandleId(request.Body.AsSpan(4)));
                await server.SendStatusAsync(request.Id);
                break;
            case SftpMessage.Read:
                await ReadAsync(server, request);
                break;
            case SftpMessage.Write:
                (byte[] handle, long offset, byte[] data) = request.WriteArguments();
                Write(_handles[HandleId(handle)].Path, offset, data);
                await server.SendStatusAsync(request.Id);
                break;
            case SftpMessage.Fstat:
                await server.SendAttributesAsync(request.Id, (ulong)Files[_handles[HandleId(request.Body.AsSpan(4))].Path].Length);
                break;
            case SftpMessage.Stat or SftpMessage.Lstat:
                if (Files.TryGetValue(request.Path, out byte[]? file))
                {
                    await server.SendAttributesAsync(request.Id, (ulong)file.Length);
                }
                else
                {
                    await server.SendStatusAsync(request.Id, FakeSftpServer.StatusNoSuchFile);
                }

                break;
            default:
                await server.SendStatusAsync(request.Id);
                break;
        }
    }

    private static uint HandleId(ReadOnlySpan<byte> handle) => BinaryPrimitives.ReadUInt32BigEndian(handle);

    private byte[] NewHandle(string path)
    {
        uint id = _nextHandle++;
        _handles.Add(id, (path, 0));
        byte[] handle = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(handle, id);
        return handle;
    }

    private async ValueTask OpenAsync(FakeSftpServer server, FakeRequest request)
    {
        SshReader reader = new(request.Body);
        string path = Encoding.UTF8.GetString(reader.ReadBinary());
        uint flags = reader.ReadUInt32();
        if ((flags & 0x08) != 0)
        {
            if ((flags & 0x10) != 0 || !Files.ContainsKey(path))
            {
                Files[path] = [];
            }
        }
        else if (!Files.ContainsKey(path))
        {
            await server.SendStatusAsync(request.Id, FakeSftpServer.StatusNoSuchFile, "no such file");
            return;
        }

        await server.SendHandleAsync(request.Id, NewHandle(path));
    }

    private async ValueTask ReadAsync(FakeSftpServer server, FakeRequest request)
    {
        (byte[] handle, long offset, uint length) = request.ReadArguments();
        byte[] file = Files[_handles[HandleId(handle)].Path];
        if (offset >= file.Length)
        {
            await server.SendStatusAsync(request.Id, FakeSftpServer.StatusEof, "End of file");
            return;
        }

        int count = (int)Math.Min(Math.Min(length, ReadLimit(length)), file.Length - offset);
        await server.SendDataAsync(request.Id, file.AsSpan((int)offset, count));
    }

    private async ValueTask ReadDirectoryAsync(FakeSftpServer server, FakeRequest request)
    {
        uint id = HandleId(request.Body.AsSpan(4));
        (string path, int position) = _handles[id];
        (string Name, uint Mode)[] all = Directories[path];
        if (position >= all.Length)
        {
            await server.SendStatusAsync(request.Id, FakeSftpServer.StatusEof);
            return;
        }

        (string Name, uint Mode)[] batch = [.. all.Skip(position).Take(3)];
        _handles[id] = (path, position + batch.Length);
        Packet packet = new Packet().U8(SftpMessage.Name).U32(request.Id).U32((uint)batch.Length);
        foreach ((string name, uint mode) in batch)
        {
            packet.Entry(name, mode);
        }

        await server.SendAsync(packet.ToFrame());
    }

    private void Write(string path, long offset, byte[] data)
    {
        byte[] file = Files[path];
        long end = offset + data.Length;
        if (end > file.Length)
        {
            Array.Resize(ref file, (int)end);
            Files[path] = file;
        }

        data.CopyTo(file, offset);
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Sftp;
using Zorg.Ssh.Tests.Transport;
using static Zorg.Ssh.Tests.Sftp.SftpServerHarness;

namespace Zorg.Ssh.Tests.Sftp;

/// <summary>What the server does for an honest client, what ReadOnly refuses, and what a hostile one can't make it do.</summary>
[Collection(SftpSerialTests.Name)]
public sealed class SftpServerProtocolTests : IDisposable
{
    private readonly SftpServerSandbox _sandbox = new();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private SftpServerOptions Options => new() { RootDirectory = _sandbox.Root };

    private SftpServerOptions ReadOnlyOptions => new() { RootDirectory = _sandbox.Root, ReadOnly = true };

    public void Dispose() => _sandbox.Dispose();

    private async Task<(SftpClient Client, Task<int> Serving)> StartClientAsync(SftpServerOptions? options = null)
    {
        (Stream client, Stream server) = DuplexStream.CreatePair();
        SftpServerOptions used = options ?? Options;
        Task<int> serving = Task.Run(() => SftpServer.ServeStreamsAsync(server, server, used, CancellationToken.None), Ct);
        return (await SftpClient.StartAsync(client, client, client, null, SftpLimits.Default, Ct), serving);
    }

    private static bool IsOpenHere(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            try
            {
                using FileStream exclusive = new(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                return false;
            }
            catch (IOException)
            {
                return true;
            }
        }

        Assert.SkipUnless(OperatingSystem.IsLinux(), "Needs /proc.");
        return new DirectoryInfo("/proc/self/fd").EnumerateFileSystemInfos().Any(f => f.LinkTarget == path);
    }

    [Fact]
    public async Task A_recursive_create_makes_the_missing_parents_and_accepts_what_is_there()
    {
        (SftpClient sftp, Task<int> serving) = await StartClientAsync();
        await using (sftp)
        {
            await sftp.CreateDirectoryAsync("a/b/c", recursive: true, Ct);
            Assert.True(Directory.Exists(_sandbox.InRoot("a/b/c")));

            // Again, and with a deeper tail, a trailing slash, a "." and a rooted path.
            await sftp.CreateDirectoryAsync("a/b/c", recursive: true, Ct);
            await sftp.CreateDirectoryAsync("a/b/c/d/e/", recursive: true, Ct);
            await sftp.CreateDirectoryAsync("/a/./b/f", recursive: true, Ct);
            await sftp.CreateDirectoryAsync("/", recursive: true, Ct);
            Assert.True(Directory.Exists(_sandbox.InRoot("a/b/c/d/e")));
            Assert.True(Directory.Exists(_sandbox.InRoot("a/b/f")));

            // Without the flag it is the old call: the parent has to exist, and an existing directory is a failure.
            await Assert.ThrowsAsync<SftpFileNotFoundException>(() => sftp.CreateDirectoryAsync("x/y", recursive: false, Ct));
            await Assert.ThrowsAnyAsync<SftpException>(() => sftp.CreateDirectoryAsync("a", recursive: false, Ct));
            Assert.False(Directory.Exists(_sandbox.InRoot("x")));
        }

        await serving;
    }

    [Fact]
    public async Task A_recursive_create_refuses_a_path_that_runs_through_a_file()
    {
        (SftpClient sftp, Task<int> serving) = await StartClientAsync();
        await using (sftp)
        {
            await sftp.WriteAllBytesAsync("file", "x"u8.ToArray(), Ct);
            await sftp.CreateDirectoryAsync("dir", Ct);
            await sftp.WriteAllBytesAsync("dir/file", "x"u8.ToArray(), Ct);

            SftpException leaf = await Assert.ThrowsAsync<SftpException>(() => sftp.CreateDirectoryAsync("dir/file", recursive: true, Ct));
            Assert.Equal(SftpStatusCode.Failure, leaf.StatusCode);
            Assert.Contains("isn't a directory", leaf.Message);
            await Assert.ThrowsAsync<SftpException>(() => sftp.CreateDirectoryAsync("file/below/that", recursive: true, Ct));
            Assert.False(Directory.Exists(_sandbox.InRoot("dir/file")));
            Assert.Equal("x", await File.ReadAllTextAsync(_sandbox.InRoot("file"), Ct));
        }

        await serving;
    }

    [Fact]
    public async Task Clients_creating_the_same_directories_at_once_all_succeed()
    {
        const int Clients = 12;
        List<(SftpClient Client, Task<int> Serving)> started = [];
        for (int i = 0; i < Clients; i++)
        {
            started.Add(await StartClientAsync());
        }

        try
        {
            using ManualResetEventSlim go = new(false);
            Task[] creators = [.. started.Select((s, i) => Task.Run(
                async () =>
                {
                    go.Wait(Ct);
                    await s.Client.CreateDirectoryAsync($"shared/day-{i % 3}/deep/er", recursive: true, Ct);
                },
                Ct))];
            go.Set();
            await Task.WhenAll(creators);

            for (int day = 0; day < 3; day++)
            {
                Assert.True(Directory.Exists(_sandbox.InRoot($"shared/day-{day}/deep/er")));
            }
        }
        finally
        {
            foreach ((SftpClient client, Task<int> serving) in started)
            {
                await client.DisposeAsync();
                await serving;
            }
        }
    }

    [Fact]
    public async Task Our_client_gets_files_directories_and_attributes_through()
    {
        (SftpClient sftp, Task<int> serving) = await StartClientAsync();
        await using (sftp)
        {
            byte[] data = RandomNumberGenerator.GetBytes(1_000_003);
            await sftp.WriteAllBytesAsync("/data.bin", data, Ct);
            Assert.Equal(data, await sftp.ReadAllBytesAsync("/data.bin", Ct));
            Assert.Equal(data, await File.ReadAllBytesAsync(_sandbox.InRoot("data.bin"), Ct));

            await sftp.CreateDirectoryAsync("dir", Ct);
            await sftp.CreateDirectoryAsync("dir/sub", Ct);
            await sftp.WriteAllBytesAsync("dir/file.txt", "hello"u8.ToArray(), Ct);

            List<SftpEntry> entries = [];
            await foreach (SftpEntry entry in sftp.ListDirectoryAsync("dir", Ct))
            {
                entries.Add(entry);
            }

            Assert.Equal([".", "..", "file.txt", "sub"], entries.Select(e => e.Name).Order(StringComparer.Ordinal));
            SftpEntry file = entries.Single(e => e.Name == "file.txt");
            Assert.Equal(5, file.Attributes.Size);
            Assert.True(file.Attributes.IsRegularFile);
            Assert.True(entries.Single(e => e.Name == "sub").Attributes.IsDirectory);

            SftpAttributes attributes = await sftp.GetAttributesAsync("dir/file.txt", Ct);
            Assert.Equal(5, attributes.Size);
            Assert.True(attributes.IsRegularFile);
            Assert.True((await sftp.GetAttributesAsync("dir", Ct)).IsDirectory);
            Assert.True(await sftp.ExistsAsync("dir/file.txt", Ct));
            Assert.False(await sftp.ExistsAsync("dir/nothing", Ct));
            Assert.Equal("/dir/file.txt", await sftp.GetFullPathAsync("dir/./sub/../file.txt", Ct));

            await Assert.ThrowsAnyAsync<SftpException>(() => sftp.DeleteDirectoryAsync("dir", Ct));
            await sftp.RenameAsync("dir/file.txt", "dir/moved.txt", cancellationToken: Ct);
            Assert.False(await sftp.ExistsAsync("dir/file.txt", Ct));

            await sftp.WriteAllBytesAsync("dir/other.txt", "other"u8.ToArray(), Ct);
            await Assert.ThrowsAnyAsync<SftpException>(() => sftp.RenameAsync("dir/other.txt", "dir/moved.txt", cancellationToken: Ct));
            await sftp.RenameAsync("dir/other.txt", "dir/moved.txt", overwrite: true, Ct);
            Assert.Equal("other"u8.ToArray(), await sftp.ReadAllBytesAsync("dir/moved.txt", Ct));

            await sftp.DeleteFileAsync("dir/moved.txt", Ct);
            await sftp.DeleteDirectoryAsync("dir/sub", Ct);
            await sftp.DeleteDirectoryAsync("dir", Ct);
            Assert.False(Directory.Exists(_sandbox.InRoot("dir")));

            await Assert.ThrowsAsync<SftpFileNotFoundException>(() => sftp.ReadAllBytesAsync("missing", Ct));
            await Assert.ThrowsAsync<SftpFileNotFoundException>(() => sftp.DeleteFileAsync("missing", Ct));
            await Assert.ThrowsAsync<SftpFileNotFoundException>(() => sftp.CreateDirectoryAsync("no/such/parent", Ct));

            SftpFileSystemInfo info = await sftp.GetFileSystemInfoAsync("/", Ct);
            Assert.True(info.AvailableBytes > 0);
            Assert.False(info.IsReadOnly);

            await using (SftpFile opened = await sftp.OpenAsync("handle.txt", FileMode.Create, FileAccess.ReadWrite, Ct))
            {
                await opened.WriteAsync("0123456789"u8.ToArray(), Ct);
                await opened.SyncAsync(Ct);
                Assert.Equal(10, await opened.GetLengthAsync(Ct));
                await opened.SetLengthAsync(4, Ct);
                Assert.Equal(4, (await opened.GetAttributesAsync(Ct)).Size);
            }

            Assert.Equal("0123", await File.ReadAllTextAsync(_sandbox.InRoot("handle.txt"), Ct));
        }

        Assert.Equal(0, await serving.WaitAsync(TimeSpan.FromSeconds(10), Ct));
    }

    [Fact]
    public async Task Open_flags_behave_as_in_POSIX()
    {
        await File.WriteAllTextAsync(_sandbox.InRoot("f.txt"), "12345", Ct);
        await using SftpServerHarness client = await StartAsync(Options);

        Assert.Equal(NoSuchFile, (await client.OpenAsync("missing", OpenRead)).Status);
        Assert.Equal(NoSuchFile, (await client.OpenAsync("missing", OpenWrite)).Status);
        Assert.Equal(Failure, (await client.OpenAsync("f.txt", OpenWrite | OpenCreate | OpenExclusive)).Status);
        Assert.Equal(Failure, (await client.OpenAsync("/", OpenRead)).Status);

        byte[] append = await client.OpenHandleAsync("f.txt", OpenWrite | OpenAppend);
        Assert.Equal(Ok, (await client.WriteAsync(append, 0, "67"u8.ToArray())).Status);
        await client.CloseAsync(append);
        Assert.Equal("1234567", await File.ReadAllTextAsync(_sandbox.InRoot("f.txt"), Ct));

        byte[] readOnly = await client.OpenHandleAsync("f.txt", OpenRead);
        Assert.Equal(PermissionDenied, (await client.WriteAsync(readOnly, 0, "x"u8.ToArray())).Status);
        await client.CloseAsync(readOnly);

        byte[] writeOnly = await client.OpenHandleAsync("f.txt", OpenWrite);
        Assert.Equal(PermissionDenied, (await client.ReadAsync(writeOnly, 0, 10)).Status);
        await client.CloseAsync(writeOnly);

        await client.CloseAsync(await client.OpenHandleAsync("f.txt", OpenWrite | OpenTruncate));
        Assert.Empty(await File.ReadAllTextAsync(_sandbox.InRoot("f.txt"), Ct));
    }

    [Fact]
    public async Task A_read_past_the_end_is_EOF_and_a_directory_ends_with_EOF()
    {
        await File.WriteAllTextAsync(_sandbox.InRoot("f.txt"), "12345", Ct);
        await using SftpServerHarness client = await StartAsync(Options);

        byte[] file = await client.OpenHandleAsync("f.txt", OpenRead);
        Assert.Equal("345"u8.ToArray(), (await client.ReadAsync(file, 2, 100)).Data);
        Assert.Equal(Eof, (await client.ReadAsync(file, 5, 100)).Status);

        byte[] directory = (await client.RequestAsync(SftpMessage.OpenDir, Path("/"))).Handle;
        Assert.Equal(SftpMessage.Name, (await client.RequestAsync(SftpMessage.ReadDir, Empty().Bytes(directory))).Type);
        Assert.Equal(Eof, (await client.RequestAsync(SftpMessage.ReadDir, Empty().Bytes(directory))).Status);
    }

    [Fact]
    public async Task SETSTAT_changes_size_and_times_and_drops_special_mode_bits()
    {
        await File.WriteAllTextAsync(_sandbox.InRoot("f.txt"), "12345", Ct);
        Directory.CreateDirectory(_sandbox.InRoot("d"));
        await using SftpServerHarness client = await StartAsync(Options);

        Assert.Equal(Ok, (await client.RequestAsync(SftpMessage.SetStat, Path("f.txt").U32(1).U64(2))).Status);
        Assert.Equal(2, new FileInfo(_sandbox.InRoot("f.txt")).Length);

        const uint Time = 1_000_000_000;
        Assert.Equal(Ok, (await client.RequestAsync(SftpMessage.SetStat, Path("f.txt").U32(8).U32(Time).U32(Time))).Status);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(Time).UtcDateTime, File.GetLastWriteTimeUtc(_sandbox.InRoot("f.txt")));
        Assert.Equal(Ok, (await client.RequestAsync(SftpMessage.SetStat, Path("d").U32(8).U32(Time).U32(Time))).Status);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(Time).UtcDateTime, Directory.GetLastWriteTimeUtc(_sandbox.InRoot("d")));

        Assert.Equal(Unsupported, (await client.RequestAsync(SftpMessage.SetStat, Path("f.txt").U32(2).U32(0).U32(0))).Status);
        Assert.Equal(Failure, (await client.RequestAsync(SftpMessage.SetStat, Path("d").U32(1).U64(0))).Status);

        // 06777: setuid, setgid and rwx for all.
        Assert.Equal(Ok, (await client.RequestAsync(SftpMessage.SetStat, Path("f.txt").U32(4).U32(0xDFF))).Status);
        byte[] handle = await client.OpenHandleAsync("f.txt", OpenRead | OpenWrite);
        Assert.Equal(Ok, (await client.RequestAsync(SftpMessage.FSetStat, Empty().Bytes(handle).U32(4).U32(0xDFF))).Status);
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal((UnixFileMode)0x1FF, File.GetUnixFileMode(_sandbox.InRoot("f.txt")));
        }
    }

    [Fact]
    public async Task A_new_file_with_a_setuid_mode_loses_the_bit()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Unix modes.");
        await using SftpServerHarness client = await StartAsync(Options);
        SftpServerReply open = await client.RequestAsync(SftpMessage.Open, Path("new").U32(OpenWrite | OpenCreate).U32(4).U32(0x9ED));
        await client.CloseAsync(open.Handle);
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal((UnixFileMode)0, File.GetUnixFileMode(_sandbox.InRoot("new")) & (UnixFileMode.SetUser | UnixFileMode.SetGroup | UnixFileMode.StickyBit));
        }
    }

    [Fact]
    public async Task Unknown_requests_and_extensions_get_OP_UNSUPPORTED()
    {
        await using SftpServerHarness client = await StartAsync(Options);

        Assert.Equal(Unsupported, (await client.ExtendedAsync("hardlink@openssh.com", Path("a").Text("b"))).Status);
        Assert.Equal(Unsupported, (await client.ExtendedAsync("no-such@example.com", Empty())).Status);
        foreach (byte type in new byte[] { 0, 2, 21, 99, SftpMessage.Status, SftpMessage.Handle, SftpMessage.Data, SftpMessage.Name, SftpMessage.Attrs, SftpMessage.ExtendedReply, 255 })
        {
            Assert.Equal(Unsupported, (await client.RequestAsync(type, Empty())).Status);
        }

        // A second INIT isn't a handshake any more.
        Assert.Equal(Unsupported, (await client.RequestAsync(SftpMessage.Init, Empty())).Status);
    }

    [Fact]
    public async Task Limits_are_advertised_and_match_what_is_enforced()
    {
        await using SftpServerHarness client = await StartAsync(new SftpServerOptions { RootDirectory = _sandbox.Root, MaxOpenHandles = 7, MaxReadSize = 2048 });

        SftpServerReply limits = await client.ExtendedAsync("limits@openssh.com", Empty());
        Assert.Equal(SftpMessage.ExtendedReply, limits.Type);
        (ulong packet, ulong read, ulong write, ulong handles) = ReadLimits(limits.Body);
        Assert.Equal((ulong)SftpLimits.Default.MaxPacketLength, packet);
        Assert.Equal(2048ul, read);
        Assert.True(write < packet);
        Assert.Equal(7ul, handles);
    }

    private static (ulong Packet, ulong Read, ulong Write, ulong Handles) ReadLimits(byte[] body)
    {
        SshReader reader = new(body);
        return (reader.ReadUInt64(), reader.ReadUInt64(), reader.ReadUInt64(), reader.ReadUInt64());
    }

    [Fact]
    public async Task ReadOnly_refuses_every_mutating_operation()
    {
        await File.WriteAllTextAsync(_sandbox.InRoot("f.txt"), "12345", Ct);
        Directory.CreateDirectory(_sandbox.InRoot("d"));
        DateTime modified = File.GetLastWriteTimeUtc(_sandbox.InRoot("f.txt"));
        await using SftpServerHarness client = await StartAsync(ReadOnlyOptions);
        byte[] handle = await client.OpenHandleAsync("f.txt", OpenRead);

        foreach (uint flags in new[]
        {
            OpenWrite, OpenRead | OpenWrite, OpenAppend, OpenCreate, OpenTruncate, OpenExclusive, OpenRead | OpenCreate, OpenRead | OpenTruncate,
            OpenWrite | OpenCreate | OpenTruncate, OpenWrite | OpenCreate | OpenExclusive,
        })
        {
            Assert.Equal(PermissionDenied, (await client.OpenAsync("f.txt", flags)).Status);
            Assert.Equal(PermissionDenied, (await client.OpenAsync("new.txt", flags)).Status);
        }

        Assert.Equal(PermissionDenied, (await client.WriteAsync(handle, 0, "x"u8.ToArray())).Status);
        Assert.Equal(PermissionDenied, (await client.RequestAsync(SftpMessage.SetStat, Path("f.txt").U32(1).U64(0))).Status);
        Assert.Equal(PermissionDenied, (await client.RequestAsync(SftpMessage.FSetStat, Empty().Bytes(handle).U32(1).U64(0))).Status);
        Assert.Equal(PermissionDenied, (await client.RequestAsync(SftpMessage.Remove, Path("f.txt"))).Status);
        Assert.Equal(PermissionDenied, (await client.RequestAsync(SftpMessage.MkDir, Path("new").U32(0))).Status);
        Assert.Equal(PermissionDenied, (await client.RequestAsync(SftpMessage.RmDir, Path("d"))).Status);
        Assert.Equal(PermissionDenied, (await client.RequestAsync(SftpMessage.Rename, Path("f.txt").Text("g.txt"))).Status);
        Assert.Equal(PermissionDenied, (await client.RequestAsync(SftpMessage.SymLink, Path("f.txt").Text("l"))).Status);
        Assert.Equal(PermissionDenied, (await client.ExtendedAsync("posix-rename@openssh.com", Path("f.txt").Text("g.txt"))).Status);
        Assert.Equal(PermissionDenied, (await client.ExtendedAsync("fsync@openssh.com", Empty().Bytes(handle))).Status);

        Assert.Equal("12345", await File.ReadAllTextAsync(_sandbox.InRoot("f.txt"), Ct));
        Assert.Equal(modified, File.GetLastWriteTimeUtc(_sandbox.InRoot("f.txt")));
        Assert.Equal(["d", "f.txt"], Directory.GetFileSystemEntries(_sandbox.Root).Select(System.IO.Path.GetFileName).Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task ReadOnly_still_reads_and_lists()
    {
        await File.WriteAllTextAsync(_sandbox.InRoot("f.txt"), "12345", Ct);
        (SftpClient sftp, _) = await StartClientAsync(ReadOnlyOptions);
        await using (sftp)
        {
            Assert.Equal("12345"u8.ToArray(), await sftp.ReadAllBytesAsync("f.txt", Ct));
            Assert.True((await sftp.GetFileSystemInfoAsync("/", Ct)).IsReadOnly);
            await Assert.ThrowsAsync<SftpPermissionDeniedException>(() => sftp.WriteAllBytesAsync("f.txt", new byte[1], Ct));
        }
    }

    [Theory]
    [InlineData(0xFFFFFFFFu)]
    [InlineData(0x80000000u)]
    [InlineData(256u * 1024 + 65)]
    [InlineData(0u)]
    [InlineData(1u)]
    [InlineData(4u)]
    public async Task A_bad_packet_length_ends_the_session_without_waiting_for_the_body(uint length)
    {
        await using SftpServerHarness client = await StartAsync(Options);
        await client.SendAsync(new Packet().U32(length).ToBytes());
        Assert.Equal(1, await client.Serving.WaitAsync(TimeSpan.FromSeconds(10), Ct));
    }

    [Fact]
    public async Task A_stream_that_ends_inside_a_packet_ends_the_session()
    {
        await using SftpServerHarness client = await StartAsync(Options);
        await client.SendAsync(new Packet().U32(100).U8(SftpMessage.Stat).ToBytes());
        Assert.Equal(1, await client.CloseStreamAsync());
    }

    [Theory]
    [InlineData(SftpMessage.Open)]
    [InlineData(SftpMessage.Stat)]
    [InlineData(SftpMessage.Version)]
    public async Task Anything_but_INIT_first_ends_the_session(byte type)
    {
        await using SftpServerHarness client = StartRaw(Options);
        await client.SendAsync(new Packet().U8(type).U32(1).Text("x").ToFrame());
        Assert.Equal(1, await client.Serving.WaitAsync(TimeSpan.FromSeconds(10), Ct));
        Assert.Empty(Directory.GetFileSystemEntries(_sandbox.Root));
    }

    [Fact]
    public async Task The_handle_limit_holds_for_files_and_directories_and_closing_frees_one()
    {
        await File.WriteAllTextAsync(_sandbox.InRoot("f.txt"), "x", Ct);
        await using SftpServerHarness client = await StartAsync(new SftpServerOptions { RootDirectory = _sandbox.Root, MaxOpenHandles = 2 });

        byte[] first = await client.OpenHandleAsync("f.txt", OpenRead);
        byte[] second = (await client.RequestAsync(SftpMessage.OpenDir, Path("/"))).Handle;
        Assert.Equal(Failure, (await client.OpenAsync("f.txt", OpenRead)).Status);
        Assert.Equal(Failure, (await client.RequestAsync(SftpMessage.OpenDir, Path("/"))).Status);
        Assert.Equal(Failure, (await client.OpenAsync("new.txt", OpenWrite | OpenCreate)).Status);
        Assert.False(File.Exists(_sandbox.InRoot("new.txt")));

        Assert.Equal(Ok, (await client.CloseAsync(first)).Status);
        Assert.Equal(SftpMessage.Handle, (await client.OpenAsync("f.txt", OpenRead)).Type);
        Assert.Equal(Ok, (await client.CloseAsync(second)).Status);
    }

    [Fact]
    public async Task Handles_are_random_and_say_nothing_about_the_file()
    {
        await File.WriteAllTextAsync(_sandbox.InRoot("f.txt"), "x", Ct);
        await using SftpServerHarness client = await StartAsync(Options);
        await using SftpServerHarness other = await StartAsync(Options);

        byte[] one = await client.OpenHandleAsync("f.txt", OpenRead);
        byte[] two = await client.OpenHandleAsync("f.txt", OpenRead);
        Assert.Equal(16, one.Length);
        Assert.NotEqual(one, two);
        Assert.DoesNotContain("f.txt", Encoding.Latin1.GetString(one), StringComparison.Ordinal);

        // A handle means nothing outside its session, or after it's closed.
        Assert.Equal(Failure, (await other.ReadAsync(one, 0, 1)).Status);
        await client.CloseAsync(one);
        Assert.Equal(Failure, (await client.ReadAsync(one, 0, 1)).Status);
        Assert.Equal(Failure, (await client.CloseAsync(one)).Status);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(15)]
    [InlineData(17)]
    [InlineData(300)]
    public async Task A_handle_of_the_wrong_length_is_refused(int length)
    {
        await using SftpServerHarness client = await StartAsync(Options);
        byte[] handle = new byte[length];
        Assert.Equal(Failure, (await client.ReadAsync(handle, 0, 1)).Status);
        Assert.Equal(Failure, (await client.CloseAsync(handle)).Status);
        Assert.Equal(Failure, (await client.RequestAsync(SftpMessage.Fstat, Empty().Bytes(handle))).Status);
        Assert.Equal(Failure, (await client.RequestAsync(SftpMessage.ReadDir, Empty().Bytes(handle))).Status);
    }

    [Fact]
    public async Task A_handle_of_one_kind_cant_be_used_as_the_other()
    {
        await File.WriteAllTextAsync(_sandbox.InRoot("f.txt"), "x", Ct);
        await using SftpServerHarness client = await StartAsync(Options);
        byte[] file = await client.OpenHandleAsync("f.txt", OpenRead);
        byte[] directory = (await client.RequestAsync(SftpMessage.OpenDir, Path("/"))).Handle;

        Assert.Equal(Failure, (await client.RequestAsync(SftpMessage.ReadDir, Empty().Bytes(file))).Status);
        Assert.Equal(Failure, (await client.ReadAsync(directory, 0, 1)).Status);
        Assert.Equal(Failure, (await client.WriteAsync(directory, 0, [1])).Status);
    }

    [Fact]
    public async Task A_huge_READ_gets_the_cap()
    {
        await File.WriteAllBytesAsync(_sandbox.InRoot("big"), new byte[100_000], Ct);
        await using SftpServerHarness client = await StartAsync(new SftpServerOptions { RootDirectory = _sandbox.Root, MaxReadSize = 4096 });
        byte[] handle = await client.OpenHandleAsync("big", OpenRead);

        Assert.Equal(4096, (await client.ReadAsync(handle, 0, uint.MaxValue)).Data.Length);
        Assert.Equal(4096, (await client.ReadAsync(handle, 0, 0x80000000)).Data.Length);
        Assert.Equal(Eof, (await client.ReadAsync(handle, 0, 0)).Status);
    }

    [Theory]
    [InlineData(ulong.MaxValue)]
    [InlineData(0x8000000000000000ul)]
    public async Task Offsets_past_what_a_file_can_hold_are_refused(ulong offset)
    {
        await File.WriteAllBytesAsync(_sandbox.InRoot("f"), new byte[10], Ct);
        await using SftpServerHarness client = await StartAsync(Options);
        byte[] handle = await client.OpenHandleAsync("f", OpenRead | OpenWrite);

        Assert.Equal(Eof, (await client.ReadAsync(handle, offset, 10)).Status);
        Assert.Equal(Failure, (await client.WriteAsync(handle, offset, [1])).Status);
        Assert.Equal(Failure, (await client.WriteAsync(handle, long.MaxValue, [1])).Status);
        Assert.Equal(10, new FileInfo(_sandbox.InRoot("f")).Length);
    }

    [Fact]
    public async Task A_big_directory_comes_in_batches_and_all_of_it_arrives()
    {
        for (int i = 0; i < 1000; i++)
        {
            await File.WriteAllBytesAsync(_sandbox.InRoot($"file-{i:D4}"), [], Ct);
        }

        await using SftpServerHarness client = await StartAsync(new SftpServerOptions { RootDirectory = _sandbox.Root, MaxListingBatch = 50 });
        byte[] handle = (await client.RequestAsync(SftpMessage.OpenDir, Path("/"))).Handle;
        List<string> names = [];
        while (true)
        {
            SftpServerReply batch = await client.RequestAsync(SftpMessage.ReadDir, Empty().Bytes(handle));
            if (batch.Type == SftpMessage.Status)
            {
                Assert.Equal(Eof, batch.Status);
                break;
            }

            Assert.InRange(batch.Names.Count, 1, 50);
            names.AddRange(batch.Names);
        }

        Assert.Equal(1002, names.Count);
        Assert.Equal(1002, names.Distinct(StringComparer.Ordinal).Count());
    }

    [Theory]
    [InlineData(SftpMessage.Open)]
    [InlineData(SftpMessage.Close)]
    [InlineData(SftpMessage.Read)]
    [InlineData(SftpMessage.Write)]
    [InlineData(SftpMessage.Lstat)]
    [InlineData(SftpMessage.Fstat)]
    [InlineData(SftpMessage.SetStat)]
    [InlineData(SftpMessage.FSetStat)]
    [InlineData(SftpMessage.OpenDir)]
    [InlineData(SftpMessage.ReadDir)]
    [InlineData(SftpMessage.Remove)]
    [InlineData(SftpMessage.MkDir)]
    [InlineData(SftpMessage.RmDir)]
    [InlineData(SftpMessage.RealPath)]
    [InlineData(SftpMessage.Stat)]
    [InlineData(SftpMessage.Rename)]
    [InlineData(SftpMessage.ReadLink)]
    [InlineData(SftpMessage.SymLink)]
    [InlineData(SftpMessage.Extended)]
    public async Task A_malformed_body_gets_a_failure_and_the_session_goes_on(byte type)
    {
        await using SftpServerHarness client = await StartAsync(Options);

        Assert.Equal(Failure, (await client.RequestAsync(type, Empty())).Status);
        Assert.Equal(Failure, (await client.RequestAsync(type, Empty().U32(0xFFFFFFFF))).Status);
        Assert.Equal(Failure, (await client.RequestAsync(type, Empty().U32(1000).U8(1))).Status);
        Assert.Equal(Failure, (await client.RequestAsync(type, Empty().Bytes([0xC3, 0x28]))).Status);
        Assert.Equal("/", (await client.RequestAsync(SftpMessage.RealPath, Path("/"))).FirstName);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task Random_packets_cause_nothing_but_statuses(int seed)
    {
        Random random = new(seed);
        byte[] types = [.. Enumerable.Range(3, 18).Select(i => (byte)i), SftpMessage.Extended];
        string[] extensions = ["posix-rename@openssh.com", "fsync@openssh.com", "statvfs@openssh.com", "limits@openssh.com"];
        await File.WriteAllTextAsync(_sandbox.InRoot("f.txt"), "12345", Ct);
        await using SftpServerHarness client = await StartAsync(Options);
        byte[] handle = await client.OpenHandleAsync("f.txt", OpenRead | OpenWrite);

        for (int i = 0; i < 3000; i++)
        {
            byte type = types[random.Next(types.Length)];
            Packet body = new();
            if (type == SftpMessage.Extended)
            {
                body.Text(extensions[random.Next(extensions.Length)]);
            }

            switch (random.Next(3))
            {
                case 0:
                    body.Bytes(handle);
                    break;
                case 1:
                    body.Text(random.Next(2) == 0 ? "f.txt" : "../f.txt");
                    break;
            }

            byte[] noise = new byte[random.Next(40)];
            random.NextBytes(noise);
            SftpServerReply reply = await client.RequestAsync(type, body.Raw(noise));
            Assert.Contains(reply.Type, new[] { SftpMessage.Status, SftpMessage.Handle, SftpMessage.Data, SftpMessage.Name, SftpMessage.Attrs, SftpMessage.ExtendedReply });
            if (reply.Type == SftpMessage.Handle)
            {
                await client.CloseAsync(reply.Handle);
            }
        }

        Assert.False(client.Serving.IsCompleted);
        client.AssertNothingLeaked(_sandbox.Base);
    }

    [Fact]
    public async Task Error_text_is_fixed_and_never_has_a_path()
    {
        Directory.CreateDirectory(_sandbox.InRoot("d"));
        await File.WriteAllTextAsync(_sandbox.InRoot("d/f"), "x", Ct);
        await using SftpServerHarness client = await StartAsync(Options);

        await client.RequestAsync(SftpMessage.Stat, Path("missing/deep"));
        await client.RequestAsync(SftpMessage.RmDir, Path("d"));
        await client.RequestAsync(SftpMessage.Rename, Path("missing").Text("x"));
        await client.OpenAsync("d", OpenWrite);
        await client.RequestAsync(SftpMessage.MkDir, Path("d/f/sub").U32(0));
        await client.RequestAsync(SftpMessage.SymLink, Path("x").Text("no/parent/l"));
        await client.RequestAsync(SftpMessage.Stat, Path(new string('a', 3000)));
        client.AssertNothingLeaked(_sandbox.Base);
    }

    [Fact]
    public async Task Handles_close_when_the_client_goes_away()
    {
        await File.WriteAllTextAsync(_sandbox.InRoot("f.txt"), "x", Ct);
        await using SftpServerHarness client = await StartAsync(Options);
        await client.OpenHandleAsync("f.txt", OpenRead | OpenWrite);
        Assert.True(IsOpenHere(_sandbox.InRoot("f.txt")));

        Assert.Equal(0, await client.CloseStreamAsync());
        Assert.False(IsOpenHere(_sandbox.InRoot("f.txt")));
    }

    [Fact]
    public async Task Handles_close_when_the_session_is_cancelled_and_the_cancellation_is_reported()
    {
        await File.WriteAllTextAsync(_sandbox.InRoot("f.txt"), "x", Ct);
        (Stream client, Stream server) = DuplexStream.CreatePair();
        await using (client)
        await using (server)
        {
            using CancellationTokenSource stop = new();
            Task<int> serving = Task.Run(() => SftpServer.ServeStreamsAsync(server, server, Options, stop.Token), Ct);
            await client.WriteAsync(new Packet().U8(SftpMessage.Init).U32(3).ToFrame(), Ct);
            await client.WriteAsync(new Packet().U8(SftpMessage.Open).U32(1).Text("f.txt").U32(OpenRead).U32(0).ToFrame(), Ct);

            // The replies, not a poll: the probe opens the file exclusively, which could make the server's open fail.
            await ReadFrameAsync(client);
            Assert.Equal(SftpMessage.Handle, (await ReadFrameAsync(client))[0]);
            Assert.True(IsOpenHere(_sandbox.InRoot("f.txt")));
            await stop.CancelAsync();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => serving);
            Assert.False(IsOpenHere(_sandbox.InRoot("f.txt")));
        }
    }

    [Fact]
    public async Task A_client_that_stops_reading_holds_nothing_and_can_be_cancelled()
    {
        await File.WriteAllBytesAsync(_sandbox.InRoot("big"), new byte[60_000], Ct);
        (Stream client, Stream server) = DuplexStream.CreatePair(pauseThreshold: 1024);
        await using (client)
        await using (server)
        {
            using CancellationTokenSource stop = new();
            Task<int> serving = Task.Run(() => SftpServer.ServeStreamsAsync(server, server, Options, stop.Token), Ct);
            await client.WriteAsync(new Packet().U8(SftpMessage.Init).U32(3).ToFrame(), Ct);
            byte[] header = new byte[5];
            await client.ReadExactlyAsync(header, Ct);
            byte[] rest = new byte[System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(header) - 1];
            await client.ReadExactlyAsync(rest, Ct);

            await client.WriteAsync(new Packet().U8(SftpMessage.Open).U32(1).Text("big").U32(OpenRead).U32(0).ToFrame(), Ct);
            await client.ReadExactlyAsync(new byte[5 + 4 + 4 + 16], Ct);
            for (uint i = 0; i < 20; i++)
            {
                await client.WriteAsync(new Packet().U8(SftpMessage.Stat).U32(i).Text("big").ToFrame(), Ct);
            }

            await stop.CancelAsync();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => serving.WaitAsync(TimeSpan.FromSeconds(10), Ct));
        }
    }

    [Fact]
    public async Task A_FIFO_with_no_writer_ends_the_session_instead_of_hanging_it()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "FIFOs are a Unix thing.");
        using System.Diagnostics.Process mkfifo = System.Diagnostics.Process.Start("mkfifo", _sandbox.InRoot("fifo"));
        await mkfifo.WaitForExitAsync(Ct);

        // Without the type check, as on a Unix whose types can't be read, or with a FIFO swapped in after the look.
        await using SftpServerHarness client = await StartAsync(new SftpServerOptions { RootDirectory = _sandbox.Root, OpenTimeout = TimeSpan.FromMilliseconds(200), CheckTypeBeforeOpen = false });

        await client.SendAsync(new Packet().U8(SftpMessage.Open).U32(1).Text("fifo").U32(OpenRead).U32(0).ToFrame());
        Assert.Equal(1, await client.Serving.WaitAsync(TimeSpan.FromSeconds(10), Ct));

        // Unstick the thread still waiting in open.
        await using FileStream writer = new(_sandbox.InRoot("fifo"), FileMode.Open, FileAccess.Write);
    }

    [Fact]
    public async Task S1_a_FIFO_is_refused_before_it_is_opened_and_the_session_carries_on()
    {
        // Finding S1: an OPEN or SETSTAT of a FIFO blocked in open(2) for OpenTimeout. Where the type can be read it's
        // refused before the open, so nothing blocks and the session goes on.
        Assert.SkipUnless(OperatingSystem.IsLinux() || OperatingSystem.IsMacOS(), "Only Linux and macOS have a call here that tells a FIFO's type.");
        MakeFifo("fifo");
        File.CreateSymbolicLink(_sandbox.InRoot("to-fifo"), "fifo");
        await File.WriteAllTextAsync(_sandbox.InRoot("plain.txt"), "x", Ct);
        await using SftpServerHarness client = await StartAsync(new SftpServerOptions { RootDirectory = _sandbox.Root, OpenTimeout = TimeSpan.FromSeconds(20) });

        System.Diagnostics.Stopwatch elapsed = System.Diagnostics.Stopwatch.StartNew();
        Assert.Equal(Failure, (await client.OpenAsync("fifo", OpenRead)).Status);
        Assert.Equal(Failure, (await client.OpenAsync("to-fifo", OpenRead)).Status);
        Assert.Equal(Failure, (await client.OpenAsync("fifo", OpenWrite)).Status);
        Assert.Equal(Failure, (await client.RequestAsync(SftpMessage.SetStat, Path("fifo").U32(4).U32(0x1A4))).Status);
        Assert.True(elapsed.Elapsed < TimeSpan.FromSeconds(10), $"took {elapsed.Elapsed}");

        byte[] handle = await client.OpenHandleAsync("plain.txt", OpenRead);
        Assert.Equal("x"u8.ToArray(), (await client.ReadAsync(handle, 0, 10)).Data);
        Assert.False(client.Serving.IsCompleted);
    }

    [Fact]
    public async Task S1_an_open_that_blocks_lets_go_of_the_namespace_gate()
    {
        // Finding S1: the open blocked while holding the process-wide gate, so every other session's path requests
        // waited for OpenTimeout. The type check is off here, as for a FIFO swapped in after the look.
        Assert.SkipWhen(OperatingSystem.IsWindows(), "FIFOs are a Unix thing.");
        MakeFifo("fifo");
        await File.WriteAllTextAsync(_sandbox.InRoot("plain.txt"), "x", Ct);
        SftpServerOptions options = new() { RootDirectory = _sandbox.Root, OpenTimeout = TimeSpan.FromSeconds(5), CheckTypeBeforeOpen = false };
        await using SftpServerHarness attacker = await StartAsync(options);
        await using SftpServerHarness victim = await StartAsync(options);

        await attacker.SendAsync(new Packet().U8(SftpMessage.Open).U32(1).Text("fifo").U32(OpenRead).U32(0).ToFrame());
        await Task.Delay(500, Ct);
        System.Diagnostics.Stopwatch during = System.Diagnostics.Stopwatch.StartNew();
        Assert.Equal(SftpMessage.Attrs, (await victim.RequestAsync(SftpMessage.Stat, Path("plain.txt"))).Type);
        Assert.True(during.Elapsed < TimeSpan.FromSeconds(2), $"the victim's stat waited {during.Elapsed} for the attacker's open");
        Assert.False(attacker.Serving.IsCompleted);

        Assert.Equal(1, await attacker.Serving.WaitAsync(TimeSpan.FromSeconds(20), Ct));

        // The session that timed out had let go of the gate, so it didn't release it again (or leave it held).
        Assert.Equal(SftpMessage.Attrs, (await victim.RequestAsync(SftpMessage.Stat, Path("plain.txt"))).Type);

        // Unstick the thread still waiting in open.
        await using FileStream writer = new(_sandbox.InRoot("fifo"), FileMode.Open, FileAccess.Write);
    }

    [Fact]
    public async Task S1_an_open_that_blocks_then_finishes_takes_the_gate_back_and_is_still_verified()
    {
        // Finding S1: the open lets go of the gate while it's blocked, and must take it back before it's checked, once.
        Assert.SkipWhen(OperatingSystem.IsWindows(), "FIFOs are a Unix thing.");
        MakeFifo("fifo");
        await File.WriteAllTextAsync(_sandbox.InRoot("plain.txt"), "x", Ct);
        SftpServerOptions options = new() { RootDirectory = _sandbox.Root, OpenTimeout = TimeSpan.FromSeconds(20), CheckTypeBeforeOpen = false };
        await using SftpServerHarness client = await StartAsync(options);
        await using SftpServerHarness other = await StartAsync(options);

        Task<SftpServerReply> open = client.OpenAsync("fifo", OpenRead);
        await Task.Delay(500, Ct);
        Assert.False(open.IsCompleted);
        Assert.Equal(SftpMessage.Attrs, (await other.RequestAsync(SftpMessage.Stat, Path("plain.txt")).WaitAsync(TimeSpan.FromSeconds(2), Ct)).Type);

        // A writer lets the open finish. What it opened can't seek, so Verify, under the gate again, refuses it.
        await using FileStream writer = await Task.Run(() => new FileStream(_sandbox.InRoot("fifo"), FileMode.Open, FileAccess.Write), Ct);
        Assert.Equal(Failure, (await open.WaitAsync(TimeSpan.FromSeconds(10), Ct)).Status);

        // Released once: a second release would throw (the gate's most is 1), and none would leave both sessions stuck.
        Assert.Equal(SftpMessage.Attrs, (await client.RequestAsync(SftpMessage.Stat, Path("plain.txt")).WaitAsync(TimeSpan.FromSeconds(10), Ct)).Type);
        Assert.Equal(SftpMessage.Attrs, (await other.RequestAsync(SftpMessage.Stat, Path("plain.txt")).WaitAsync(TimeSpan.FromSeconds(10), Ct)).Type);
        Assert.False(client.Serving.IsCompleted);
    }

    [Fact]
    public async Task S4_an_open_is_refused_and_logged_when_the_descriptor_check_cant_read_proc()
    {
        // Finding S4: a null link target for /proc/self/fd/N skipped the identity check without a word. It now fails
        // closed: the open is refused, nothing is truncated or created, and a warning says why.
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Only Linux checks the descriptor through /proc.");
        await File.WriteAllTextAsync(_sandbox.InRoot("plain.txt"), "keep", Ct);
        SftpRecordingLoggerFactory log = new();
        await using SftpServerHarness client = await StartAsync(new SftpServerOptions
        {
            RootDirectory = _sandbox.Root,
            LoggerFactory = log,
            DescriptorLinks = "/proc-is-masked-here/self/fd",
        });

        Assert.Equal(Failure, (await client.OpenAsync("plain.txt", OpenRead)).Status);
        Assert.Equal(Failure, (await client.OpenAsync("plain.txt", OpenWrite | OpenTruncate)).Status);
        Assert.Equal(Failure, (await client.RequestAsync(SftpMessage.SetStat, Path("plain.txt").U32(4).U32(0x180))).Status);
        Assert.Equal("keep", await File.ReadAllTextAsync(_sandbox.InRoot("plain.txt"), Ct));
        Assert.Contains(log.Entries, e => e.Level == Microsoft.Extensions.Logging.LogLevel.Warning && e.Message.Contains("/proc/self/fd", StringComparison.Ordinal));
        Assert.DoesNotContain(log.Entries, e => e.Message.Contains("plain.txt", StringComparison.Ordinal));

        // With /proc readable, the same open goes through.
        await using SftpServerHarness normal = await StartAsync(new SftpServerOptions { RootDirectory = _sandbox.Root });
        Assert.Equal(SftpMessage.Handle, (await normal.OpenAsync("plain.txt", OpenRead)).Type);
    }

    private void MakeFifo(string name)
    {
        using System.Diagnostics.Process mkfifo = System.Diagnostics.Process.Start("mkfifo", _sandbox.InRoot(name));
        mkfifo.WaitForExit();
        Assert.Equal(0, mkfifo.ExitCode);
    }

    [Fact]
    public async Task A_FIFO_is_listed_and_stated_as_a_FIFO_not_as_a_regular_file()
    {
        // .NET calls a FIFO a file. A client that checks IsRegularFile before it opens, as docs/sftp.md says to, would
        // open it, and the open would block until OpenTimeout ended the session.
        // On macOS this is the only run of the lstat layout the server trusts, and it needs a Mac (the CI macOS job).
        Assert.SkipUnless(OperatingSystem.IsLinux() || OperatingSystem.IsMacOS(), "FIFOs are a Unix thing, and only Linux and macOS have a call here that tells their type.");
        using (System.Diagnostics.Process mkfifo = System.Diagnostics.Process.Start("mkfifo", _sandbox.InRoot("fifo")))
        {
            await mkfifo.WaitForExitAsync(Ct);
            Assert.Equal(0, mkfifo.ExitCode);
        }

        await File.WriteAllTextAsync(_sandbox.InRoot("file.txt"), "text", Ct);
        File.CreateSymbolicLink(_sandbox.InRoot("to-fifo"), "fifo");
        (SftpClient sftp, Task<int> serving) = await StartClientAsync();
        await using (sftp)
        {
            Dictionary<string, SftpAttributes> listed = [];
            await foreach (SftpEntry entry in sftp.ListDirectoryAsync("/", Ct))
            {
                listed[entry.Name] = entry.Attributes;
            }

            SftpAttributes fifo = listed["fifo"];
            Assert.False(fifo.IsRegularFile);
            Assert.False(fifo.IsDirectory);
            Assert.False(fifo.IsSymbolicLink);
            Assert.Equal(0, fifo.Size);
            Assert.True(listed["file.txt"].IsRegularFile);
            Assert.True(listed["to-fifo"].IsSymbolicLink);

            Assert.False((await sftp.GetAttributesAsync("fifo", Ct)).IsRegularFile);
            Assert.False((await sftp.GetLinkAttributesAsync("fifo", Ct)).IsRegularFile);
            Assert.False((await sftp.GetAttributesAsync("to-fifo", Ct)).IsRegularFile);
            Assert.True((await sftp.GetAttributesAsync("file.txt", Ct)).IsRegularFile);
        }

        Assert.Equal(0, await serving.WaitAsync(TimeSpan.FromSeconds(10), Ct));
    }

    [Fact]
    public async Task A_name_with_an_unpaired_surrogate_is_listed_as_a_name_that_cant_be_used()
    {
        // Only NTFS holds a name that isn't Unicode as UTF-16. Sent as U+FFFD it would look valid to a client and lead
        // nowhere, or to another file whose name really has U+FFFD in it.
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Only Windows names can hold an unpaired surrogate.");
        string bad = "bad\uD800.txt";
        await File.WriteAllTextAsync(_sandbox.InRoot(bad), "planted", Ct);
        await File.WriteAllTextAsync(_sandbox.InRoot("bad�.txt"), "the other file", Ct);
        Directory.CreateDirectory(_sandbox.InRoot("dir\uDC00"));

        (SftpClient sftp, Task<int> serving) = await StartClientAsync();
        await using (sftp)
        {
            List<SftpEntry> entries = [];
            await foreach (SftpEntry entry in sftp.ListDirectoryAsync("/", Ct))
            {
                entries.Add(entry);
            }

            SftpEntry[] invalid = [.. entries.Where(e => !e.HasValidName)];
            Assert.Equal(2, invalid.Length);
            Assert.All(invalid, e => Assert.False(e.IsSafeName));
            Assert.Contains(invalid, e => e.Attributes.IsRegularFile && e.Attributes.Size == 7);
            Assert.Contains(invalid, e => e.Attributes.IsDirectory);

            // The file that really has U+FFFD in its name is still listed, valid, and is the one its name reaches.
            SftpEntry genuine = Assert.Single(entries, e => e.HasValidName && e.Name == "bad�.txt");
            Assert.Equal(14, genuine.Attributes.Size);
            Assert.Equal("the other file"u8.ToArray(), await sftp.ReadAllBytesAsync("bad�.txt", Ct));
        }

        Assert.Equal(0, await serving.WaitAsync(TimeSpan.FromSeconds(10), Ct));

        // On the wire: the surrogate's three bytes, which no strict UTF-8 decoder accepts, in the name and the long name.
        await using SftpServerHarness client = await StartAsync(Options);
        byte[] handle = (await client.RequestAsync(SftpMessage.OpenDir, Path("/"))).Handle;
        byte[] body = (await client.RequestAsync(SftpMessage.ReadDir, Empty().Bytes(handle))).Body;
        byte[] wtf8 = [.. "bad"u8, 0xED, 0xA0, 0x80, .. ".txt"u8];
        Assert.Equal(2, CountOccurrences(body, wtf8));
        Assert.Equal(2, CountOccurrences(body, [.. "bad"u8, 0xEF, 0xBF, 0xBD, .. ".txt"u8]));
    }

    private static int CountOccurrences(byte[] haystack, byte[] needle)
    {
        int count = 0;
        for (int at = haystack.AsSpan().IndexOf(needle); at >= 0; at = haystack.AsSpan(at + 1).IndexOf(needle) is int next and >= 0 ? at + 1 + next : -1)
        {
            count++;
        }

        return count;
    }

    [Fact]
    public async Task A_missing_root_or_bad_limit_is_a_clear_error_for_the_host()
    {
        (Stream client, Stream server) = DuplexStream.CreatePair();
        await using (client)
        await using (server)
        {
            await Assert.ThrowsAsync<DirectoryNotFoundException>(() => SftpServer.ServeStreamsAsync(server, server, new SftpServerOptions { RootDirectory = _sandbox.InRoot("missing") }, Ct));
            await Assert.ThrowsAsync<ArgumentException>(() => SftpServer.ServeStreamsAsync(server, server, new SftpServerOptions { RootDirectory = string.Empty }, Ct));
            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => SftpServer.ServeStreamsAsync(server, server, new SftpServerOptions { RootDirectory = _sandbox.Root, MaxOpenHandles = 0 }, Ct));
            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => SftpServer.ServeStreamsAsync(server, server, new SftpServerOptions { RootDirectory = _sandbox.Root, MaxReadSize = 1024 * 1024 }, Ct));
            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => SftpServer.ServeStreamsAsync(server, server, new SftpServerOptions { RootDirectory = _sandbox.Root, MaxListingBatch = 0 }, Ct));
        }
    }

    private static async Task<byte[]> ReadFrameAsync(Stream stream)
    {
        byte[] length = new byte[4];
        await stream.ReadExactlyAsync(length, Ct);
        byte[] frame = new byte[System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(length)];
        await stream.ReadExactlyAsync(frame, Ct);
        return frame;
    }
}

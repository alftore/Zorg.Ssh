#pragma warning disable xUnit1069 // Tests reach the token through the Ct property, which the analyzer can't see.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Sftp;

namespace Zorg.Ssh.Tests.Sftp;

/// <summary>The client's behaviour against a well-behaved fake: pipelining, short reads, extensions and argument order.</summary>
[Collection(SftpSerialTests.Name)]
public class SftpClientTests
{
    private const int Limit = 30_000;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static byte[] Pattern(int length)
    {
        byte[] data = new byte[length];
        new Random(length).NextBytes(data);
        return data;
    }

    [Fact(Timeout = Limit)]
    public async Task Bytes_round_trip()
    {
        FakeFiles files = new();
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(files.HandleAsync);
        byte[] data = Pattern(1_000_000);

        await fake.Client.WriteAllBytesAsync("f", data, Ct);
        Assert.Equal(data, files.Files["f"]);
        Assert.Equal(data, await fake.Client.ReadAllBytesAsync("f", Ct));
        Assert.Equal(0, files.OpenHandles);
    }

    [Fact(Timeout = Limit)]
    public async Task Streams_round_trip()
    {
        FakeFiles files = new();
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(files.HandleAsync);
        byte[] data = Pattern(700_001);

        using (DribbleStream source = new(data))
        {
            await fake.Client.UploadFileAsync(source, "f", Ct);
        }

        Assert.Equal(data, files.Files["f"]);
        using MemoryStream received = new();
        await fake.Client.DownloadFileAsync("f", received, Ct);
        Assert.Equal(data, received.ToArray());
    }

    [Theory(Timeout = Limit)]
    [InlineData(1000u)]
    [InlineData(1u)]
    [InlineData(32767u)]
    public async Task Short_reads_never_end_a_download_early(uint limit)
    {
        byte[] data = Pattern(limit == 1 ? 3000 : 300_000);
        FakeFiles files = new() { Files = { ["f"] = data }, ReadLimit = _ => limit };
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(files.HandleAsync);

        Assert.Equal(data, await fake.Client.ReadAllBytesAsync("f", Ct));
    }

    [Fact(Timeout = Limit)]
    public async Task Random_short_reads_keep_the_bytes_in_order()
    {
        byte[] data = Pattern(1_000_000);
        Random random = new(99);
        FakeFiles files = new() { Files = { ["f"] = data }, ReadLimit = wanted => (uint)random.Next(1, (int)wanted + 1) };
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(files.HandleAsync);

        using MemoryStream received = new();
        await fake.Client.DownloadFileAsync("f", received, Ct);
        Assert.Equal(data, received.ToArray());
    }

    [Fact(Timeout = Limit)]
    public async Task A_short_read_through_a_file_stream_is_passed_on_and_only_eof_gives_zero()
    {
        byte[] data = Pattern(100);
        FakeFiles files = new() { Files = { ["f"] = data }, ReadLimit = _ => 7 };
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(files.HandleAsync);

        await using SftpFile file = await fake.Client.OpenAsync("f", cancellationToken: Ct);
        byte[] buffer = new byte[50];
        Assert.Equal(7, await file.ReadAsync(buffer, Ct));
        Assert.Equal(7, file.Position);

        using MemoryStream all = new();
        await all.WriteAsync(buffer.AsMemory(0, 7), Ct);
        while (true)
        {
            int read = await file.ReadAsync(buffer, Ct);
            if (read == 0)
            {
                break;
            }

            await all.WriteAsync(buffer.AsMemory(0, read), Ct);
        }

        Assert.Equal(data, all.ToArray());
    }

    [Fact(Timeout = Limit)]
    public async Task Reads_are_pipelined_before_any_answer_arrives()
    {
        byte[] data = Pattern(8 * 1024 * 1024);
        FakeFiles files = new() { Files = { ["f"] = data } };
        List<FakeRequest> held = [];
        int target = 2;
        int mostHeld = 0;
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(async (server, request) =>
        {
            if (request.Type != SftpMessage.Read)
            {
                await files.HandleAsync(server, request);
                return;
            }

            // Nothing is answered until a growing number of reads are on the wire at once. The end of the
            // file always answers, because the client stops asking for more once it's waiting on the end.
            held.Add(request);
            mostHeld = Math.Max(mostHeld, held.Count);
            (_, long offset, uint length) = request.ReadArguments();
            if (held.Count >= target || offset + length >= data.Length)
            {
                foreach (FakeRequest read in held)
                {
                    await files.HandleAsync(server, read);
                }

                held.Clear();
                target = Math.Min(target * 2, 40);
            }
        });

        Assert.Equal(data, await fake.Client.ReadAllBytesAsync("f", Ct));
        Assert.True(mostHeld >= 40, $"Only {mostHeld} reads were in flight.");
    }

    [Fact(Timeout = Limit)]
    public async Task Writes_are_pipelined_before_any_answer_arrives()
    {
        FakeFiles files = new();
        List<FakeRequest> held = [];
        bool released = false;
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(async (server, request) =>
        {
            if (request.Type != SftpMessage.Write || released)
            {
                await files.HandleAsync(server, request);
                return;
            }

            held.Add(request);
            if (held.Count == 40)
            {
                released = true;
                foreach (FakeRequest write in held)
                {
                    await files.HandleAsync(server, write);
                }
            }
        });

        byte[] data = Pattern(3_000_000);
        await fake.Client.WriteAllBytesAsync("f", data, Ct);
        Assert.True(released);
        Assert.Equal(data, files.Files["f"]);
    }

    [Fact(Timeout = Limit)]
    public async Task Responses_may_arrive_in_any_order()
    {
        byte[] data = Pattern(1_000_000);
        FakeFiles files = new() { Files = { ["f"] = data } };
        List<FakeRequest> held = [];
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(async (server, request) =>
        {
            if (request.Type != SftpMessage.Read)
            {
                await files.HandleAsync(server, request);
                return;
            }

            // Answer in pairs, newest first. The end of the file always answers, or the last read would wait forever.
            held.Add(request);
            (_, long offset, uint length) = request.ReadArguments();
            if (held.Count == 2 || offset + length >= data.Length)
            {
                for (int i = held.Count - 1; i >= 0; i--)
                {
                    await files.HandleAsync(server, held[i]);
                }

                held.Clear();
            }
        });

        Assert.Equal(data, await fake.Client.ReadAllBytesAsync("f", Ct));
    }

    [Fact(Timeout = Limit)]
    public async Task A_failed_write_stops_the_upload_and_says_why()
    {
        FakeFiles files = new();
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) => request.Type == SftpMessage.Write
            ? server.SendStatusAsync(request.Id, FakeSftpServer.StatusFailure, "disk full")
            : files.HandleAsync(server, request));

        using MemoryStream source = new(new byte[1_000_000]);
        SftpException ex = await Assert.ThrowsAsync<SftpException>(() => fake.Client.UploadFileAsync(source, "f", Ct));
        Assert.Contains("disk full", ex.Message);
        Assert.Equal("f", ex.Path);

        await fake.WaitForRequestsAsync(1, r => r.Type == SftpMessage.Close);
    }

    [Fact(Timeout = Limit)]
    public async Task A_failure_on_close_is_reported()
    {
        FakeFiles files = new();
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) => request.Type == SftpMessage.Close
            ? server.SendStatusAsync(request.Id, FakeSftpServer.StatusFailure, "quota exceeded")
            : files.HandleAsync(server, request));

        SftpException ex = await Assert.ThrowsAsync<SftpException>(() => fake.Client.WriteAllBytesAsync("f", new byte[10], Ct));
        Assert.Contains("quota", ex.Message);
    }

    [Fact(Timeout = Limit)]
    public async Task Status_codes_become_typed_exceptions()
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) => server.SendStatusAsync(request.Id, request.Path == "missing" ? FakeSftpServer.StatusNoSuchFile : FakeSftpServer.StatusPermissionDenied, "text"));

        SftpFileNotFoundException missing = await Assert.ThrowsAsync<SftpFileNotFoundException>(() => fake.Client.DeleteFileAsync("missing", Ct));
        Assert.Equal(SftpStatusCode.NoSuchFile, missing.StatusCode);
        Assert.Equal("missing", missing.Path);
        Assert.Contains("Check the path", missing.Message);

        SftpPermissionDeniedException denied = await Assert.ThrowsAsync<SftpPermissionDeniedException>(() => fake.Client.DeleteFileAsync("secret", Ct));
        Assert.Equal(SftpStatusCode.PermissionDenied, denied.StatusCode);
        Assert.Contains("rights", denied.Message);
    }

    [Fact(Timeout = Limit)]
    public async Task Exists_is_false_only_for_a_missing_path()
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) => request.Path switch
        {
            "missing" => server.SendStatusAsync(request.Id, FakeSftpServer.StatusNoSuchFile),
            "secret" => server.SendStatusAsync(request.Id, FakeSftpServer.StatusPermissionDenied),
            _ => server.SendAttributesAsync(request.Id),
        });

        Assert.True(await fake.Client.ExistsAsync("there", Ct));
        Assert.False(await fake.Client.ExistsAsync("missing", Ct));
        await Assert.ThrowsAsync<SftpPermissionDeniedException>(() => fake.Client.ExistsAsync("secret", Ct));
        Assert.All(fake.Requests, r => Assert.Equal(SftpMessage.Lstat, r.Type));
    }

    // OpenSSH sends target then link. The draft says link then target.
    [Theory(Timeout = Limit)]
    [InlineData(null, null, "link", "target")]
    [InlineData(null, "SSH-2.0-SomeServer", "link", "target")]
    [InlineData(null, "SSH-2.0-OpenSSH_9.9", "target", "link")]
    [InlineData("posix-rename@openssh.com", null, "target", "link")]
    [InlineData("posix-rename@openssh.com", "SSH-2.0-dropbear_2026.94", "target", "link")]
    public async Task Symlink_arguments_follow_the_server(string? extension, string? identification, string first, string second)
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(
            (server, request) => server.SendStatusAsync(request.Id),
            extensions: extension is null ? null : [extension],
            identification: identification);

        await fake.Client.CreateSymbolicLinkAsync("link", "target", Ct);
        FakeRequest request = Assert.Single(fake.Requests, r => r.Type == SftpMessage.SymLink);
        Assert.Equal([first, second], request.Strings(2));
    }

    [Fact(Timeout = Limit)]
    public async Task Overwriting_rename_uses_posix_rename_when_offered()
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) => server.SendStatusAsync(request.Id), extensions: ["posix-rename@openssh.com"]);

        await fake.Client.RenameAsync("a", "b", overwrite: true, Ct);
        FakeRequest extended = Assert.Single(fake.Requests);
        Assert.Equal(SftpMessage.Extended, extended.Type);
        Assert.Equal(["posix-rename@openssh.com", "a", "b"], extended.Strings(3));

        await fake.Client.RenameAsync("a", "b", cancellationToken: Ct);
        Assert.Equal(SftpMessage.Rename, fake.Requests[^1].Type);
    }

    [Fact(Timeout = Limit)]
    public async Task Overwriting_rename_without_the_extension_says_what_to_do()
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) => server.SendStatusAsync(request.Id, FakeSftpServer.StatusFailure));

        SftpException ex = await Assert.ThrowsAsync<SftpException>(() => fake.Client.RenameAsync("a", "b", overwrite: true, Ct));
        Assert.Contains("Delete the target first", ex.Message);
        Assert.Equal(SftpMessage.Rename, Assert.Single(fake.Requests).Type);
    }

    [Fact(Timeout = Limit)]
    public async Task Limits_are_honoured()
    {
        FakeFiles files = new() { Files = { ["f"] = Pattern(10_000) } };
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(
            (server, request) => request.Type == SftpMessage.Extended && request.FirstString() == "limits@openssh.com"
                ? server.SendAsync(new Packet().U8(SftpMessage.ExtendedReply).U32(request.Id).U64(0).U64(1000).U64(700).U64(0).ToFrame())
                : files.HandleAsync(server, request),
            extensions: ["limits@openssh.com"]);

        Assert.Equal(files.Files["f"], await fake.Client.ReadAllBytesAsync("f", Ct));
        await fake.Client.WriteAllBytesAsync("g", Pattern(5000), Ct);

        Assert.All(fake.Requests.Where(r => r.Type == SftpMessage.Read), r => Assert.True(r.ReadArguments().Length <= 1000));
        Assert.All(fake.Requests.Where(r => r.Type == SftpMessage.Write), r => Assert.True(r.WriteArguments().Data.Length <= 700));
        Assert.Contains(fake.Requests, r => r.Type == SftpMessage.Write);
    }

    [Fact(Timeout = Limit)]
    public async Task Max_packet_length_also_bounds_writes()
    {
        FakeFiles files = new();
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(
            (server, request) => request.Type == SftpMessage.Extended
                ? server.SendAsync(new Packet().U8(SftpMessage.ExtendedReply).U32(request.Id).U64(2048).U64(0).U64(0).U64(0).ToFrame())
                : files.HandleAsync(server, request),
            extensions: ["limits@openssh.com"]);

        await fake.Client.WriteAllBytesAsync("g", Pattern(5000), Ct);
        Assert.All(fake.Requests.Where(r => r.Type == SftpMessage.Write), r => Assert.True(r.Body.Length <= 2048));
    }

    [Fact(Timeout = Limit)]
    public async Task Missing_extensions_are_refused_without_a_round_trip()
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) => server.SendStatusAsync(request.Id));

        SftpException ex = Assert.Throws<SftpException>(() => { _ = fake.Client.GetFileSystemInfoAsync("/", Ct); });
        Assert.Equal(SftpStatusCode.OperationUnsupported, ex.StatusCode);
        Assert.Throws<SftpException>(() => { _ = fake.Client.CreateHardLinkAsync("a", "b", Ct); });
        await Assert.ThrowsAsync<SftpException>(() => fake.Client.CopyFileAsync("a", "b", cancellationToken: Ct));
        Assert.Empty(fake.Requests);
    }

    [Fact(Timeout = Limit)]
    public async Task Hardlink_sends_the_existing_file_first()
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) => server.SendStatusAsync(request.Id), extensions: ["hardlink@openssh.com"]);
        await fake.Client.CreateHardLinkAsync("new", "existing", Ct);
        Assert.Equal(["hardlink@openssh.com", "existing", "new"], Assert.Single(fake.Requests).Strings(3));
    }

    [Fact(Timeout = Limit)]
    public async Task Statvfs_is_parsed()
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(
            (server, request) => server.SendAsync(new Packet().U8(SftpMessage.ExtendedReply).U32(request.Id)
                .U64(4096).U64(512).U64(1000).U64(500).U64(400).U64(90).U64(80).U64(70).U64(12).U64(1).U64(255).ToFrame()),
            extensions: ["statvfs@openssh.com"]);

        SftpFileSystemInfo info = await fake.Client.GetFileSystemInfoAsync("/", Ct);
        Assert.Equal(new SftpFileSystemInfo { BlockSize = 4096, FragmentSize = 512, Blocks = 1000, FreeBlocks = 500, AvailableBlocks = 400, Files = 90, FreeFiles = 80, AvailableFiles = 70, FileSystemId = 12, IsReadOnly = true, MaxNameLength = 255 }, info);
        Assert.Equal(400UL * 512, info.AvailableBytes);
    }

    [Fact(Timeout = Limit)]
    public async Task S2_copy_without_overwrite_leaves_an_existing_file_alone_on_a_server_that_ignores_exclusive()
    {
        // Finding S2: FakeFiles ignores SSH_FXF_EXCL, as some servers do, so the open of an existing "b" succeeds.
        byte[] old = new byte[50];
        new Random(50).NextBytes(old);
        FakeFiles files = new() { Files = { ["a"] = new byte[10], ["b"] = old } };
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(files.HandleAsync, extensions: ["copy-data"]);

        SftpException ex = await Assert.ThrowsAsync<SftpException>(() => fake.Client.CopyFileAsync("a", "b", overwrite: false, Ct));
        Assert.Equal(SftpStatusCode.Failure, ex.StatusCode);
        Assert.Equal(old, files.Files["b"]);
        Assert.DoesNotContain(fake.Requests, r => r.Type == SftpMessage.Extended);
        Assert.Equal(0, files.OpenHandles);

        // A new destination is still copied.
        await fake.Client.CopyFileAsync("a", "c", overwrite: false, Ct);
        Assert.Single(fake.Requests, r => r.Type == SftpMessage.Extended);
    }

    [Fact(Timeout = Limit)]
    public async Task Copy_data_opens_both_files_and_copies_the_whole_source()
    {
        FakeFiles files = new() { Files = { ["a"] = new byte[10] } };
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(files.HandleAsync, extensions: ["copy-data"]);

        await fake.Client.CopyFileAsync("a", "b", overwrite: true, Ct);

        FakeRequest copy = Assert.Single(fake.Requests, r => r.Type == SftpMessage.Extended);
        SshReader reader = new(copy.Body);
        Assert.Equal("copy-data", reader.ReadUtf8String());
        Assert.Equal(4, reader.ReadBinary().Length);
        Assert.Equal(0UL, reader.ReadUInt64());
        Assert.Equal(0UL, reader.ReadUInt64());
        Assert.Equal(4, reader.ReadBinary().Length);
        Assert.Equal(0UL, reader.ReadUInt64());
        Assert.Equal(0, reader.Remaining);
        Assert.Equal(0, files.OpenHandles);
    }

    [Fact(Timeout = Limit)]
    public async Task Fsync_goes_by_handle()
    {
        FakeFiles files = new() { Files = { ["f"] = [] } };
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(files.HandleAsync, extensions: ["fsync@openssh.com"]);

        await using SftpFile file = await fake.Client.OpenAsync("f", FileMode.Open, FileAccess.Write, Ct);
        await file.SyncAsync(Ct);
        FakeRequest sync = Assert.Single(fake.Requests, r => r.Type == SftpMessage.Extended);
        Assert.Equal("fsync@openssh.com", sync.FirstString());
    }

    [Fact(Timeout = Limit)]
    public async Task Attributes_are_read_with_every_field()
    {
        DateTimeOffset access = DateTimeOffset.FromUnixTimeSeconds(1000);
        DateTimeOffset modified = DateTimeOffset.FromUnixTimeSeconds(2000);
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) =>
            server.SendAsync(new Packet().U8(SftpMessage.Attrs).U32(request.Id).U32(0x8000000F).U64(77).U32(5).U32(6).U32(0x41ED).U32(1000).U32(2000).U32(2)
                .Text("a").Text("b").Text("c").Text("d").ToFrame()));

        SftpAttributes attributes = await fake.Client.GetAttributesAsync("x", Ct);
        Assert.Equal(77, attributes.Size);
        Assert.Equal(5u, attributes.Uid);
        Assert.Equal(6u, attributes.Gid);
        Assert.Equal((UnixFileMode)0x1ED, attributes.Permissions);
        Assert.Equal(access, attributes.AccessTime);
        Assert.Equal(modified, attributes.ModifiedTime);
        Assert.True(attributes.IsDirectory);
        Assert.False(attributes.IsRegularFile);
        Assert.False(attributes.IsSymbolicLink);
    }

    [Fact(Timeout = Limit)]
    public async Task Only_set_attributes_are_sent()
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) => server.SendStatusAsync(request.Id));

        await fake.Client.SetAttributesAsync("x", new SftpAttributes { Permissions = UnixFileMode.UserRead }, Ct);
        SshReader reader = new(Assert.Single(fake.Requests).Body);
        Assert.Equal("x", reader.ReadUtf8String());
        Assert.Equal(0x4u, reader.ReadUInt32());
        Assert.Equal((uint)UnixFileMode.UserRead, reader.ReadUInt32());
        Assert.Equal(0, reader.Remaining);
    }

    [Fact(Timeout = Limit)]
    public async Task Attribute_pairs_must_be_set_together()
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) => server.SendStatusAsync(request.Id));

        Assert.Throws<ArgumentException>(() => { _ = fake.Client.SetAttributesAsync("x", new SftpAttributes { Uid = 1 }, Ct); });
        Assert.Throws<ArgumentException>(() => { _ = fake.Client.SetAttributesAsync("x", new SftpAttributes { ModifiedTime = DateTimeOffset.UtcNow }, Ct); });
        Assert.Throws<ArgumentException>(() => { _ = fake.Client.SetAttributesAsync("x", new SftpAttributes { Size = -1 }, Ct); });
        DateTimeOffset tooLate = new(2200, 1, 1, 0, 0, 0, TimeSpan.Zero);
        Assert.Throws<ArgumentException>(() => { _ = fake.Client.SetAttributesAsync("x", new SftpAttributes { ModifiedTime = tooLate, AccessTime = tooLate }, Ct); });
        Assert.Empty(fake.Requests);
    }

    [Fact(Timeout = Limit)]
    public async Task Paths_with_nul_are_refused_on_this_side()
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) => server.SendStatusAsync(request.Id));
        Assert.Throws<ArgumentException>(() => { _ = fake.Client.DeleteFileAsync("a\0b", Ct); });
        Assert.Throws<ArgumentException>(() => { _ = fake.Client.DeleteFileAsync(string.Empty, Ct); });
        Assert.Empty(fake.Requests);
    }

    [Fact(Timeout = Limit)]
    public async Task Open_modes_map_to_the_right_flags()
    {
        FakeFiles files = new() { Files = { ["f"] = [] } };
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(files.HandleAsync);

        (FileMode Mode, FileAccess Access, uint Flags)[] cases =
        [
            (FileMode.Open, FileAccess.Read, 0x01),
            (FileMode.Open, FileAccess.ReadWrite, 0x03),
            (FileMode.OpenOrCreate, FileAccess.Write, 0x0A),
            (FileMode.Create, FileAccess.Write, 0x1A),
            (FileMode.CreateNew, FileAccess.Write, 0x2A),
            (FileMode.Truncate, FileAccess.Write, 0x12),
            (FileMode.Append, FileAccess.Write, 0x0E),
        ];

        foreach ((FileMode mode, FileAccess access, uint flags) in cases)
        {
            await using SftpFile file = await fake.Client.OpenAsync("f", mode, access, Ct);
            SshReader reader = new(fake.Requests.Last(r => r.Type == SftpMessage.Open).Body);
            reader.ReadBinary();
            Assert.Equal(flags, reader.ReadUInt32());
        }

        await Assert.ThrowsAsync<ArgumentException>(() => fake.Client.OpenAsync("f", FileMode.Create, FileAccess.Read, Ct));
        await Assert.ThrowsAsync<ArgumentException>(() => fake.Client.OpenAsync("f", FileMode.Append, FileAccess.ReadWrite, Ct));
    }

    [Fact(Timeout = Limit)]
    public async Task A_file_stream_honours_its_access_and_seeks_without_the_network()
    {
        FakeFiles files = new() { Files = { ["f"] = Pattern(100) } };
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(files.HandleAsync);

        SftpFile file = await fake.Client.OpenAsync("f", cancellationToken: Ct);
        Assert.True(file.CanRead);
        Assert.False(file.CanWrite);
        Assert.True(file.CanSeek);
        await Assert.ThrowsAsync<NotSupportedException>(async () => await file.WriteAsync(new byte[1], Ct));

        int before = fake.Requests.Count;
        Assert.Equal(40, file.Seek(40, SeekOrigin.Begin));
        Assert.Equal(50, file.Seek(10, SeekOrigin.Current));
        Assert.Equal(before, fake.Requests.Count);
        Assert.Throws<ArgumentOutOfRangeException>(() => file.Seek(-1, SeekOrigin.Begin));
        Assert.Equal(99, file.Seek(-1, SeekOrigin.End));
        Assert.Equal(100, file.Length);

        await file.DisposeAsync();
        await fake.WaitForRequestsAsync(1, r => r.Type == SftpMessage.Close);
        await Assert.ThrowsAsync<ObjectDisposedException>(async () => await file.ReadExactlyAsync(new byte[1], Ct));
    }

    [Fact(Timeout = Limit)]
    public async Task Sync_stream_methods_work()
    {
        FakeFiles files = new() { Files = { ["f"] = Pattern(100) } };
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(files.HandleAsync);

#pragma warning disable CA1849, CA2022 // The sync methods are what this test is for.
        using SftpFile file = await fake.Client.OpenAsync("f", FileMode.Open, FileAccess.ReadWrite, Ct);
        byte[] buffer = new byte[10];
        Assert.Equal(10, file.Read(buffer, 0, 10));
        Assert.Equal(files.Files["f"][..10], buffer);
        file.Write([1, 2, 3], 0, 3);
        file.Flush();
        Assert.Equal(13, file.Position);
        Assert.Equal(1, files.Files["f"][10]);
#pragma warning restore CA1849, CA2022
    }

    [Fact(Timeout = Limit)]
    public async Task Dispose_closes_the_stream_and_ends_calls()
    {
        FakeFiles files = new();
        FakeSftpServer fake = await FakeSftpServer.StartAsync(files.HandleAsync);
        await using (fake)
        {
            await fake.Client.DisposeAsync();
            await fake.Client.DisposeAsync();
            await Assert.ThrowsAsync<SshConnectionException>(() => fake.Client.DeleteFileAsync("x", Ct));
        }
    }

    /// <summary>Gives its data a few bytes at a time, as a network source would.</summary>
    private sealed class DribbleStream(byte[] data) : MemoryStream(data)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            base.ReadAsync(buffer[..Math.Min(buffer.Length, 5000)], cancellationToken);
    }
}

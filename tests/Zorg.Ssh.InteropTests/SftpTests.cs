using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Sftp;

namespace Zorg.Ssh.InteropTests;

/// <summary>The SFTP client against the real sftp-server, in the oldest and newest OpenSSH we test.</summary>
public class SftpTests
{
    private const string User = "zorg";
    private const string Password = "zorg-test";
    private const string ThroughputLogVariable = "ZORG_SSH_SFTP_THROUGHPUT_LOG";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public static TheoryData<string> Peers() => new("openssh-10", "openssh-7.4");

    private static async Task<SshPeerContainer> StartAsync(string peer)
    {
        PeerTools.RequireContainers();
        string image = await SshPeerContainer.BuildImageAsync($"zorg-ssh-test/{peer}", Path.Combine(PeerTools.PeersPath, peer), Ct);
        return await SshPeerContainer.StartAsync(image, cancellationToken: Ct);
    }

    private static Task<SshClient> ConnectAsync(SshPeerContainer container) => SshClient.ConnectAsync(
        new SshClientOptions
        {
            Host = container.Host,
            Port = container.Port,
            UserName = User,
            Credentials = [SshCredential.FromPassword(Password)],
            HostKeyPolicy = HostKeyPolicy.AcceptAnyUnsafe(),
        },
        Ct);

    private static string Hash(ReadOnlySpan<byte> data) => Convert.ToHexString(SHA256.HashData(data));

    private static async Task<string> RemoteSha256Async(SshClient client, string path)
    {
        SshCommandResult result = await client.ExecuteAsync($"sha256sum '{path}'", Ct);
        Assert.Equal(0, result.ExitCode);
        return result.StandardOutput.Split(' ')[0].ToUpperInvariant();
    }

    [Theory]
    [MemberData(nameof(Peers))]
    public async Task A_large_file_survives_upload_and_download(string peer)
    {
        await using SshPeerContainer container = await StartAsync(peer);
        await using SshClient client = await ConnectAsync(container);
        await using SftpClient sftp = await client.OpenSftpAsync(Ct);

        byte[] data = RandomNumberGenerator.GetBytes(24 * 1024 * 1024 + 12345);
        using (MemoryStream source = new(data))
        {
            await sftp.UploadFileAsync(source, "big.bin", Ct);
        }

        Assert.Equal(Hash(data), await RemoteSha256Async(client, "big.bin"));

        using MemoryStream received = new();
        await sftp.DownloadFileAsync("big.bin", received, Ct);
        Assert.Equal(Hash(data), Hash(received.GetBuffer().AsSpan(0, (int)received.Length)));

        Assert.Equal(data.Length, (await sftp.GetAttributesAsync("big.bin", cancellationToken: Ct)).Size);
    }

    [Theory]
    [MemberData(nameof(Peers))]
    public async Task ReadAllBytes_and_WriteAllBytes_round_trip(string peer)
    {
        await using SshPeerContainer container = await StartAsync(peer);
        await using SshClient client = await ConnectAsync(container);
        await using SftpClient sftp = await client.OpenSftpAsync(Ct);

        byte[] data = RandomNumberGenerator.GetBytes(300_000);
        await sftp.WriteAllBytesAsync("round.bin", data, Ct);
        Assert.Equal(data, await sftp.ReadAllBytesAsync("round.bin", Ct));

        await sftp.WriteAllBytesAsync("round.bin", new byte[] { 1, 2, 3 }, Ct);
        Assert.Equal(new byte[] { 1, 2, 3 }, await sftp.ReadAllBytesAsync("round.bin", Ct));

        await sftp.WriteAllBytesAsync("empty.bin", ReadOnlyMemory<byte>.Empty, Ct);
        Assert.Empty(await sftp.ReadAllBytesAsync("empty.bin", Ct));
    }

    [Theory]
    [MemberData(nameof(Peers))]
    public async Task Directories_can_be_created_listed_and_removed(string peer)
    {
        await using SshPeerContainer container = await StartAsync(peer);
        await using SshClient client = await ConnectAsync(container);
        await using SftpClient sftp = await client.OpenSftpAsync(Ct);

        string home = await sftp.GetFullPathAsync(".", Ct);
        Assert.Equal("/home/zorg", home);

        await sftp.CreateDirectoryAsync("dir", Ct);
        await sftp.CreateDirectoryAsync("dir/sub", Ct);
        await sftp.WriteAllBytesAsync("dir/file.txt", "hello"u8.ToArray(), Ct);

        Assert.True(await sftp.ExistsAsync("dir/file.txt", Ct));
        Assert.False(await sftp.ExistsAsync("dir/nothing", Ct));

        List<SftpEntry> entries = [];
        await foreach (SftpEntry entry in sftp.ListDirectoryAsync("dir", Ct))
        {
            entries.Add(entry);
        }

        // Names come back as given, so these include the two the server always sends.
        Assert.Equal([".", "..", "file.txt", "sub"], entries.Select(e => e.Name).Order(StringComparer.Ordinal));
        SftpEntry file = entries.Single(e => e.Name == "file.txt");
        Assert.Equal(5, file.Attributes.Size);
        Assert.True(file.Attributes.IsRegularFile);
        Assert.True(file.IsSafeName);
        Assert.True(entries.Single(e => e.Name == "sub").Attributes.IsDirectory);
        Assert.False(entries.Single(e => e.Name == "..").IsSafeName);

        SftpException notEmpty = await Assert.ThrowsAnyAsync<SftpException>(() => sftp.DeleteDirectoryAsync("dir", Ct));
        Assert.Equal(SftpStatusCode.Failure, notEmpty.StatusCode);

        await sftp.DeleteFileAsync("dir/file.txt", Ct);
        await sftp.DeleteDirectoryAsync("dir/sub", Ct);
        await sftp.DeleteDirectoryAsync("dir", Ct);
        Assert.False(await sftp.ExistsAsync("dir", Ct));
    }

    [Theory]
    [MemberData(nameof(Peers))]
    public async Task Failures_are_typed(string peer)
    {
        await using SshPeerContainer container = await StartAsync(peer);
        await using SshClient client = await ConnectAsync(container);
        await using SftpClient sftp = await client.OpenSftpAsync(Ct);

        SftpFileNotFoundException missing = await Assert.ThrowsAsync<SftpFileNotFoundException>(() => sftp.ReadAllBytesAsync("missing.bin", Ct));
        Assert.Equal(SftpStatusCode.NoSuchFile, missing.StatusCode);
        Assert.Equal("missing.bin", missing.Path);

        SftpPermissionDeniedException denied = await Assert.ThrowsAsync<SftpPermissionDeniedException>(() => sftp.WriteAllBytesAsync("/etc/zorg-denied", new byte[1], Ct));
        Assert.Equal(SftpStatusCode.PermissionDenied, denied.StatusCode);

        await Assert.ThrowsAsync<SftpFileNotFoundException>(async () =>
        {
            await foreach (SftpEntry entry in sftp.ListDirectoryAsync("missing-directory", Ct))
            {
                Assert.Fail(entry.Name);
            }
        });

        // A refusal leaves the session working.
        Assert.Equal("/home/zorg", await sftp.GetFullPathAsync(".", Ct));
    }

    // OpenSSH's SSH_FXP_SYMLINK takes its arguments the other way round from the draft.
    [Theory]
    [MemberData(nameof(Peers))]
    public async Task Symbolic_links_point_the_right_way(string peer)
    {
        await using SshPeerContainer container = await StartAsync(peer);
        await using SshClient client = await ConnectAsync(container);
        await using SftpClient sftp = await client.OpenSftpAsync(Ct);

        await sftp.WriteAllBytesAsync("target.txt", "through the link"u8.ToArray(), Ct);
        await sftp.CreateSymbolicLinkAsync("link.txt", "target.txt", Ct);

        // Checked with the server's own tool, so a mistake can't cancel itself out.
        SshCommandResult readlink = await client.ExecuteAsync("readlink link.txt", Ct);
        Assert.Equal("target.txt\n", readlink.StandardOutput);

        Assert.Equal("target.txt", await sftp.ReadLinkAsync("link.txt", Ct));
        Assert.True((await sftp.GetAttributesAsync("link.txt", followSymbolicLinks: false, Ct)).IsSymbolicLink);
        Assert.True((await sftp.GetAttributesAsync("link.txt", cancellationToken: Ct)).IsRegularFile);
        Assert.Equal("through the link"u8.ToArray(), await sftp.ReadAllBytesAsync("link.txt", Ct));

        // A dangling link exists as far as ExistsAsync is concerned.
        await sftp.CreateSymbolicLinkAsync("dangling", "no-such-target", Ct);
        Assert.True(await sftp.ExistsAsync("dangling", Ct));
    }

    [Theory]
    [MemberData(nameof(Peers))]
    public async Task Rename_overwrites_only_when_asked(string peer)
    {
        await using SshPeerContainer container = await StartAsync(peer);
        await using SshClient client = await ConnectAsync(container);
        await using SftpClient sftp = await client.OpenSftpAsync(Ct);

        Assert.True(sftp.ServerExtensions.ContainsKey("posix-rename@openssh.com"));
        await sftp.WriteAllBytesAsync("a", "a"u8.ToArray(), Ct);
        await sftp.WriteAllBytesAsync("b", "b"u8.ToArray(), Ct);

        await Assert.ThrowsAnyAsync<SftpException>(() => sftp.RenameAsync("a", "b", cancellationToken: Ct));
        Assert.Equal("b"u8.ToArray(), await sftp.ReadAllBytesAsync("b", Ct));

        await sftp.RenameAsync("a", "b", overwrite: true, Ct);
        Assert.Equal("a"u8.ToArray(), await sftp.ReadAllBytesAsync("b", Ct));
        Assert.False(await sftp.ExistsAsync("a", Ct));

        await sftp.RenameAsync("b", "c", cancellationToken: Ct);
        Assert.True(await sftp.ExistsAsync("c", Ct));
    }

    [Theory]
    [MemberData(nameof(Peers))]
    public async Task A_big_listing_arrives_whole(string peer)
    {
        await using SshPeerContainer container = await StartAsync(peer);
        await using SshClient client = await ConnectAsync(container);
        await using SftpClient sftp = await client.OpenSftpAsync(Ct);

        const int Count = 5000;
        SshCommandResult made = await client.ExecuteAsync($"mkdir many && cd many && i=0; while [ $i -lt {Count} ]; do : > \"file-with-a-fairly-long-name-to-fill-packets-$i\"; i=$((i+1)); done", Ct);
        Assert.Equal(0, made.ExitCode);

        HashSet<string> names = new(StringComparer.Ordinal);
        await foreach (SftpEntry entry in sftp.ListDirectoryAsync("many", Ct))
        {
            Assert.True(names.Add(entry.Name));
        }

        Assert.Equal(Count + 2, names.Count);
    }

    [Theory]
    [MemberData(nameof(Peers))]
    public async Task Concurrent_transfers_share_a_session(string peer)
    {
        await using SshPeerContainer container = await StartAsync(peer);
        await using SshClient client = await ConnectAsync(container);
        await using SftpClient sftp = await client.OpenSftpAsync(Ct);

        byte[][] files = [.. Enumerable.Range(0, 6).Select(_ => RandomNumberGenerator.GetBytes(6 * 1024 * 1024))];
        await Task.WhenAll(files.Select((data, i) => Task.Run(
            async () =>
            {
                using MemoryStream source = new(data);
                await sftp.UploadFileAsync(source, $"c{i}.bin", Ct);
            },
            Ct)));

        // Reads, writes and metadata at the same time, in one session.
        Task<string>[] downloads = [.. files.Select((_, i) => Task.Run(
            async () =>
            {
                using MemoryStream received = new();
                await sftp.DownloadFileAsync($"c{i}.bin", received, Ct);
                return Hash(received.GetBuffer().AsSpan(0, (int)received.Length));
            },
            Ct))];
        Task[] stats = [.. Enumerable.Range(0, 500).Select(i => (Task)sftp.GetAttributesAsync($"c{i % files.Length}.bin", cancellationToken: Ct))];
        await Task.WhenAll(stats);

        Assert.Equal(files.Select(f => Hash(f)), await Task.WhenAll(downloads));
    }

    [Theory]
    [MemberData(nameof(Peers))]
    public async Task Several_sessions_share_a_connection(string peer)
    {
        await using SshPeerContainer container = await StartAsync(peer);
        await using SshClient client = await ConnectAsync(container);
        await using SftpClient first = await client.OpenSftpAsync(Ct);

        await using (SftpClient second = await client.OpenSftpAsync(Ct))
        {
            await second.WriteAllBytesAsync("shared.bin", new byte[] { 9 }, Ct);
        }

        // Closing one session leaves the other, and the connection, working.
        Assert.Equal(new byte[] { 9 }, await first.ReadAllBytesAsync("shared.bin", Ct));
        Assert.Equal(0, (await client.ExecuteAsync("true", Ct)).ExitCode);
    }

    [Theory]
    [MemberData(nameof(Peers))]
    public async Task A_rekey_in_the_middle_of_transfers_loses_nothing(string peer)
    {
        await using SshPeerContainer container = await StartAsync(peer);
        await using SshClient client = await ConnectAsync(container);
        await using SftpClient sftp = await client.OpenSftpAsync(Ct);

        byte[] data = RandomNumberGenerator.GetBytes(24 * 1024 * 1024);
        int before = client.CompletedKeyExchanges;
        await using (RekeyingStream source = new(new MemoryStream(data), client, 6_000_000))
        {
            await sftp.UploadFileAsync(source, "rekey.bin", Ct);
        }

        Assert.True(client.CompletedKeyExchanges > before, "No rekey finished during the upload.");
        Assert.Equal(Hash(data), await RemoteSha256Async(client, "rekey.bin"));

        before = client.CompletedKeyExchanges;
        using MemoryStream received = new();
        await using (RekeyingStream destination = new(received, client, 6_000_000, leaveOpen: true))
        {
            await sftp.DownloadFileAsync("rekey.bin", destination, Ct);
        }

        Assert.True(client.CompletedKeyExchanges > before, "No rekey finished during the download.");
        Assert.Equal(Hash(data), Hash(received.GetBuffer().AsSpan(0, (int)received.Length)));
    }

    [Theory]
    [MemberData(nameof(Peers))]
    public async Task Files_seek_read_and_write_like_streams(string peer)
    {
        await using SshPeerContainer container = await StartAsync(peer);
        await using SshClient client = await ConnectAsync(container);
        await using SftpClient sftp = await client.OpenSftpAsync(Ct);

        byte[] data = RandomNumberGenerator.GetBytes(200_000);
        await sftp.WriteAllBytesAsync("seek.bin", data, Ct);

        await using (SftpFile file = await sftp.OpenAsync("seek.bin", FileMode.Open, FileAccess.ReadWrite, Ct))
        {
            Assert.Equal(data.Length, await file.GetLengthAsync(Ct));
            Assert.Equal(data.Length - 100, file.Seek(-100, SeekOrigin.End));

            byte[] tail = new byte[1000];
            int read = await file.ReadAsync(tail, Ct);
            Assert.Equal(100, read);
            Assert.Equal(data[^100..], tail[..100]);
            Assert.Equal(0, await file.ReadAsync(tail, Ct));

            file.Position = 50;
            await file.WriteAsync(new byte[] { 1, 2, 3 }, Ct);
            Assert.Equal(53, file.Position);

            file.Position = 49;
            byte[] four = new byte[4];
            await file.ReadExactlyAsync(four, Ct);
            Assert.Equal(new byte[] { data[49], 1, 2, 3 }, four);

            await file.SetLengthAsync(1000, Ct);
            Assert.Equal(1000, await file.GetLengthAsync(Ct));

            file.Position = 500;
            using MemoryStream rest = new();
            await file.CopyToAsync(rest, Ct);
            Assert.Equal(500, rest.Length);
            Assert.Equal(1000, file.Position);
        }

        await using (SftpFile created = await sftp.OpenAsync("new.bin", FileMode.CreateNew, FileAccess.Write, Ct))
        {
            await created.WriteAsync(new byte[3], Ct);
            await created.CloseAsync(Ct);
        }

        await Assert.ThrowsAnyAsync<SftpException>(() => sftp.OpenAsync("new.bin", FileMode.CreateNew, FileAccess.Write, Ct));

        await using (SftpFile appended = await sftp.OpenAsync("new.bin", FileMode.Append, FileAccess.Write, Ct))
        {
            Assert.Equal(3, appended.Position);
            await appended.WriteAsync(new byte[] { 7 }, Ct);
        }

        Assert.Equal(new byte[] { 0, 0, 0, 7 }, await sftp.ReadAllBytesAsync("new.bin", Ct));
    }

    [Theory]
    [MemberData(nameof(Peers))]
    public async Task Attributes_can_be_set(string peer)
    {
        await using SshPeerContainer container = await StartAsync(peer);
        await using SshClient client = await ConnectAsync(container);
        await using SftpClient sftp = await client.OpenSftpAsync(Ct);

        await sftp.WriteAllBytesAsync("attr.bin", new byte[100], Ct);
        DateTimeOffset time = new(2020, 2, 3, 4, 5, 6, TimeSpan.Zero);
        await sftp.SetAttributesAsync(
            "attr.bin",
            new SftpAttributes
            {
                Permissions = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead,
                ModifiedTime = time,
                AccessTime = time,
                Size = 10,
            },
            Ct);

        SftpAttributes attributes = await sftp.GetAttributesAsync("attr.bin", cancellationToken: Ct);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead, attributes.Permissions);
        Assert.Equal(time, attributes.ModifiedTime);
        Assert.Equal(10, attributes.Size);
        Assert.Equal("640\n", (await client.ExecuteAsync("stat -c %a attr.bin", Ct)).StandardOutput);
    }

    [Theory]
    [MemberData(nameof(Peers))]
    public async Task OpenSsh_extensions_work(string peer)
    {
        await using SshPeerContainer container = await StartAsync(peer);
        await using SshClient client = await ConnectAsync(container);
        await using SftpClient sftp = await client.OpenSftpAsync(Ct);

        SftpFileSystemInfo info = await sftp.GetFileSystemInfoAsync("/", Ct);
        Assert.NotEqual(0UL, info.BlockSize);
        Assert.NotEqual(0UL, info.Blocks);

        await sftp.WriteAllBytesAsync("hard.bin", new byte[] { 5 }, Ct);
        await sftp.CreateHardLinkAsync("hard2.bin", "hard.bin", Ct);
        Assert.Equal("2\n", (await client.ExecuteAsync("stat -c %h hard.bin", Ct)).StandardOutput);
        Assert.Equal(new byte[] { 5 }, await sftp.ReadAllBytesAsync("hard2.bin", Ct));

        await using SftpFile file = await sftp.OpenAsync("hard.bin", FileMode.Open, FileAccess.Write, Ct);
        await file.WriteAsync(new byte[] { 6 }, Ct);
        await file.SyncAsync(Ct);
    }

    [Fact]
    public async Task The_newest_server_reports_limits_and_copies_on_the_server()
    {
        await using SshPeerContainer container = await StartAsync("openssh-10");
        await using SshClient client = await ConnectAsync(container);
        await using SftpClient sftp = await client.OpenSftpAsync(Ct);

        Assert.Equal("1", sftp.ServerExtensions["limits@openssh.com"]);
        byte[] data = RandomNumberGenerator.GetBytes(1_000_000);
        await sftp.WriteAllBytesAsync("copy-a.bin", data, Ct);

        await sftp.CopyFileAsync("copy-a.bin", "copy-b.bin", overwrite: false, Ct);
        Assert.Equal(data, await sftp.ReadAllBytesAsync("copy-b.bin", Ct));

        await Assert.ThrowsAnyAsync<SftpException>(() => sftp.CopyFileAsync("copy-a.bin", "copy-b.bin", overwrite: false, Ct));
        await sftp.CopyFileAsync("copy-a.bin", "copy-b.bin", overwrite: true, Ct);
    }

    [Fact]
    public async Task The_oldest_server_has_no_copy_data_and_says_so()
    {
        await using SshPeerContainer container = await StartAsync("openssh-7.4");
        await using SshClient client = await ConnectAsync(container);
        await using SftpClient sftp = await client.OpenSftpAsync(Ct);

        Assert.False(sftp.ServerExtensions.ContainsKey("limits@openssh.com"));
        SftpException ex = await Assert.ThrowsAsync<SftpException>(() => sftp.CopyFileAsync("a", "b", cancellationToken: Ct));
        Assert.Equal(SftpStatusCode.OperationUnsupported, ex.StatusCode);
    }

    [Theory]
    [MemberData(nameof(Peers))]
    public async Task A_tree_downloads_without_following_links(string peer)
    {
        await using SshPeerContainer container = await StartAsync(peer);
        await using SshClient client = await ConnectAsync(container);
        await using SftpClient sftp = await client.OpenSftpAsync(Ct);

        SshCommandResult made = await client.ExecuteAsync(
            "mkdir -p tree/a/b && echo one > tree/one.txt && echo two > tree/a/two.txt && echo three > tree/a/b/three.txt && ln -s /etc tree/outside && ln -s ../one.txt tree/a/link.txt",
            Ct);
        Assert.Equal(0, made.ExitCode);

        string local = Path.Combine(Path.GetTempPath(), "zorg-sftp-" + Guid.NewGuid().ToString("N"));
        try
        {
            await sftp.DownloadDirectoryAsync("tree", local, cancellationToken: Ct);

            Assert.Equal("one\n", await File.ReadAllTextAsync(Path.Combine(local, "one.txt"), Ct));
            Assert.Equal("two\n", await File.ReadAllTextAsync(Path.Combine(local, "a", "two.txt"), Ct));
            Assert.Equal("three\n", await File.ReadAllTextAsync(Path.Combine(local, "a", "b", "three.txt"), Ct));
            Assert.False(Path.Exists(Path.Combine(local, "outside")));
            Assert.False(Path.Exists(Path.Combine(local, "a", "link.txt")));
        }
        finally
        {
            Directory.Delete(local, recursive: true);
        }
    }

    [Theory]
    [MemberData(nameof(Peers))]
    public async Task A_killed_server_fails_calls_with_an_ssh_exception(string peer)
    {
        await using SshPeerContainer container = await StartAsync(peer);
        await using SshClient client = await ConnectAsync(container);
        await using SftpClient sftp = await client.OpenSftpAsync(Ct);

        await sftp.WriteAllBytesAsync("kill.bin", new byte[100], Ct);

        // Alpine's sshd runs internal-sftp and Debian's runs sftp-server. Spelling the names through a variable
        // keeps this script from matching itself.
        await client.ExecuteAsync(
            "a=sftp; for d in /proc/[0-9]*; do case \"$(tr '\\0' ' ' < $d/cmdline 2>/dev/null)\" in *$a-server*|*internal-$a*) kill -9 ${d#/proc/};; esac; done",
            Ct);

        await Assert.ThrowsAnyAsync<SshException>(async () =>
        {
            for (int i = 0; i < 1000; i++)
            {
                await sftp.GetAttributesAsync("kill.bin", cancellationToken: Ct);
            }
        });

        // The connection itself survives the session.
        Assert.Equal(0, (await client.ExecuteAsync("true", Ct)).ExitCode);
    }

    // Alpine's sshd serves SFTP from inside itself, so this is the openssh-10 run of the separate sftp-server program.
    // It also writes well past the 2 MiB window to stderr first, which nothing reads: that must not stall the session.
    [Fact]
    public async Task The_real_sftp_server_program_works_and_its_stderr_cant_stall_the_window()
    {
        PeerTools.RequireContainers();
        string image = await SshPeerContainer.BuildImageAsync("zorg-ssh-test/openssh-10", Path.Combine(PeerTools.PeersPath, "openssh-10"), Ct);
        await using SshPeerContainer container = await SshPeerContainer.StartAsync(
            image,
            ["/usr/sbin/sshd", "-D", "-e", "-o", "Subsystem=noisy /bin/sh -c 'head -c 8000000 /dev/zero >&2; exec /usr/lib/ssh/sftp-server'"],
            cancellationToken: Ct);
        await using SshClient client = await ConnectAsync(container);

        SftpClient sftp = await SftpClient.OpenOverChannelAsync(await client.OpenSubsystemAsync("noisy", Ct), client.ServerVersion, Ct);
        await using (sftp)
        {
            byte[] data = RandomNumberGenerator.GetBytes(4_000_000);
            await sftp.WriteAllBytesAsync("noisy.bin", data, Ct);
            Assert.Equal(data, await sftp.ReadAllBytesAsync("noisy.bin", Ct));

            await sftp.CreateSymbolicLinkAsync("noisy-link", "noisy.bin", Ct);
            Assert.Equal("noisy.bin\n", (await client.ExecuteAsync("readlink noisy-link", Ct)).StandardOutput);
        }
    }

    // Reports speed when a log file is named, so the numbers are real but never gate a run.
    [Theory]
    [MemberData(nameof(Peers))]
    public async Task Throughput_is_measured(string peer)
    {
        await using SshPeerContainer container = await StartAsync(peer);
        await using SshClient client = await ConnectAsync(container);
        await using SftpClient sftp = await client.OpenSftpAsync(Ct);

        byte[] data = RandomNumberGenerator.GetBytes(128 * 1024 * 1024);
        double bestUpload = 0;
        double bestDownload = 0;
        for (int round = 0; round < 3; round++)
        {
            using MemoryStream source = new(data);
            Stopwatch upload = Stopwatch.StartNew();
            await sftp.UploadFileAsync(source, "speed.bin", Ct);
            bestUpload = Math.Max(bestUpload, data.Length / 1e6 / upload.Elapsed.TotalSeconds);

            using MemoryStream destination = new(data.Length);
            Stopwatch download = Stopwatch.StartNew();
            await sftp.DownloadFileAsync("speed.bin", destination, Ct);
            bestDownload = Math.Max(bestDownload, data.Length / 1e6 / download.Elapsed.TotalSeconds);
            Assert.Equal(data.Length, destination.Length);
        }

        if (Environment.GetEnvironmentVariable(ThroughputLogVariable) is { Length: > 0 } log)
        {
            await File.AppendAllTextAsync(log, string.Create(CultureInfo.InvariantCulture, $"{peer}: upload {bestUpload:F0} MB/s, download {bestDownload:F0} MB/s\n"), Encoding.UTF8, CancellationToken.None);
        }
    }

    /// <summary>Asks for a rekey each time a set number of bytes has passed, from inside a transfer.</summary>
    private sealed class RekeyingStream(Stream inner, SshClient client, long interval, bool leaveOpen = false) : Stream
    {
        private long _total;

        public override bool CanRead => inner.CanRead;

        public override bool CanSeek => false;

        public override bool CanWrite => inner.CanWrite;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            int read = await inner.ReadAsync(buffer, cancellationToken);
            Passed(read);
            return read;
        }

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await inner.WriteAsync(buffer, cancellationToken);
            Passed(buffer.Length);
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing && !leaveOpen)
            {
                inner.Dispose();
            }

            base.Dispose(disposing);
        }

        private void Passed(int count)
        {
            long before = _total;
            _total += count;
            if (before / interval != _total / interval)
            {
                client.RequestRekey();
            }
        }
    }
}

#pragma warning disable xUnit1069 // Tests reach the token through the Ct property, which the analyzer can't see.

using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Sftp;

namespace Zorg.Ssh.Tests.Sftp;

/// <summary>Hostile file names, after the SSH.NET 2026 advisory: a listing must never write outside the destination.</summary>
[Collection(SftpSerialTests.Name)]
public sealed class SftpNamesTests : IDisposable
{
    private const int Limit = 30_000;
    private const uint Directory = 0x41ED;
    private const uint RegularFile = 0x81A4;
    private const uint SymbolicLink = 0xA1FF;

    private readonly string _sandbox = Path.Combine(Path.GetTempPath(), "zorg-sftp-" + Guid.NewGuid().ToString("N"));

    public SftpNamesTests()
    {
        System.IO.Directory.CreateDirectory(_sandbox);
        Destination = Path.Combine(_sandbox, "dest");
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private string Destination { get; }

    public void Dispose() => System.IO.Directory.Delete(_sandbox, recursive: true);

    public static TheoryData<string> HostileNames() => new(
        "../evil.txt",
        "..\\evil.txt",
        "../../../../etc/cron.d/evil",
        "/etc/passwd",
        "\\Windows\\evil.txt",
        "sub/../../evil.txt",
        "a/b",
        "a\\b",
        "evil\0.txt",
        "\0",
        "",
        new string('x', 300));

    private async Task<FakeSftpServer> ServerWithAsync(FakeFiles files) =>
        await FakeSftpServer.StartAsync(files.HandleAsync);

    private FileInfo[] WrittenOutsideDestination() =>
        [.. new DirectoryInfo(_sandbox).GetFiles("*", SearchOption.AllDirectories).Where(f => !f.FullName.StartsWith(Destination + Path.DirectorySeparatorChar, StringComparison.Ordinal))];

    [Theory(Timeout = Limit)]
    [MemberData(nameof(HostileNames))]
    public async Task SshNet_2026_a_hostile_file_name_is_rejected_and_nothing_is_written(string name)
    {
        FakeFiles files = new();
        files.Files["/d/" + name] = "evil"u8.ToArray();
        files.Files["/d/good.txt"] = "good"u8.ToArray();
        files.Directories["/d"] = [("good.txt", RegularFile), (name, RegularFile)];
        await using FakeSftpServer fake = await ServerWithAsync(files);

        SftpUnsafeNameException ex = await Assert.ThrowsAsync<SftpUnsafeNameException>(() => fake.Client.DownloadDirectoryAsync("/d", Destination, long.MaxValue, Ct));
        Assert.Equal(name, ex.EntryName);
        Assert.Equal("/d", ex.Path);

        // The whole directory is checked first, so not even the good file was written.
        Assert.Empty(new DirectoryInfo(_sandbox).GetFiles("*", SearchOption.AllDirectories));
    }

    [Theory(Timeout = Limit)]
    [MemberData(nameof(HostileNames))]
    public async Task SshNet_2026_a_hostile_directory_name_is_rejected(string name)
    {
        FakeFiles files = new();
        files.Directories["/d"] = [(name, Directory)];
        files.Directories["/d/" + name] = [("evil.txt", RegularFile)];
        files.Files["/d/" + name + "/evil.txt"] = "evil"u8.ToArray();
        await using FakeSftpServer fake = await ServerWithAsync(files);

        await Assert.ThrowsAsync<SftpUnsafeNameException>(() => fake.Client.DownloadDirectoryAsync("/d", Destination, long.MaxValue, Ct));
        Assert.Empty(new DirectoryInfo(_sandbox).GetFiles("*", SearchOption.AllDirectories));
        Assert.DoesNotContain(new DirectoryInfo(_sandbox).GetDirectories("*", SearchOption.AllDirectories), d => d.FullName != Destination);
    }

    [Fact(Timeout = Limit)]
    public async Task SshNet_2026_names_hostile_only_on_windows_are_rejected_there()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "These are ordinary names elsewhere.");
        foreach (string name in new[] { "C:evil.txt", "file.txt:stream", "CON", "nul.txt", "COM1.log", "evil.", "evil ", ".. ", "..." })
        {
            FakeFiles files = new();
            files.Files["/d/" + name] = "evil"u8.ToArray();
            files.Directories["/d"] = [(name, RegularFile)];
            await using FakeSftpServer fake = await ServerWithAsync(files);
            await Assert.ThrowsAsync<SftpUnsafeNameException>(() => fake.Client.DownloadDirectoryAsync("/d", Destination, long.MaxValue, Ct));
            Assert.Empty(WrittenOutsideDestination());
        }
    }

    [Fact(Timeout = Limit)]
    public async Task SshNet_2026_dot_and_dotdot_are_never_followed_whatever_they_claim_to_be()
    {
        FakeFiles files = new();
        files.Files["/d/ok.txt"] = "ok"u8.ToArray();
        files.Files["/d/."] = "evil"u8.ToArray();
        files.Files["/d/.."] = "evil"u8.ToArray();
        files.Directories["/d"] = [(".", RegularFile), ("..", Directory), ("ok.txt", RegularFile)];
        await using FakeSftpServer fake = await ServerWithAsync(files);

        await fake.Client.DownloadDirectoryAsync("/d", Destination, long.MaxValue, Ct);

        Assert.Equal(["ok.txt"], new DirectoryInfo(Destination).GetFileSystemInfos().Select(i => i.Name));
        Assert.DoesNotContain(fake.Requests, r => r.Type == SftpMessage.OpenDir && r.Path.EndsWith("..", StringComparison.Ordinal));
        Assert.Empty(WrittenOutsideDestination());
    }

    [Fact(Timeout = Limit)]
    public async Task SshNet_2026_a_listing_that_sends_a_name_twice_cant_overwrite_it()
    {
        FakeFiles files = new();
        files.Files["/d/same.txt"] = "server"u8.ToArray();
        files.Directories["/d"] = [("same.txt", RegularFile), ("same.txt", RegularFile)];
        await using FakeSftpServer fake = await ServerWithAsync(files);

        await Assert.ThrowsAsync<SftpUnsafeNameException>(() => fake.Client.DownloadDirectoryAsync("/d", Destination, long.MaxValue, Ct));
    }

    [Fact(Timeout = Limit)]
    public async Task SshNet_2026_an_existing_local_file_is_never_replaced()
    {
        System.IO.Directory.CreateDirectory(Destination);
        string existing = Path.Combine(Destination, "important.txt");
        await File.WriteAllTextAsync(existing, "mine", Ct);

        FakeFiles files = new();
        files.Files["/d/important.txt"] = "server"u8.ToArray();
        files.Directories["/d"] = [("important.txt", RegularFile)];
        await using FakeSftpServer fake = await ServerWithAsync(files);

        await Assert.ThrowsAsync<SftpUnsafeNameException>(() => fake.Client.DownloadDirectoryAsync("/d", Destination, long.MaxValue, Ct));
        Assert.Equal("mine", await File.ReadAllTextAsync(existing, Ct));
    }

    [Fact(Timeout = Limit)]
    public async Task SshNet_2026_a_file_where_a_directory_is_claimed_stops_the_download()
    {
        System.IO.Directory.CreateDirectory(Destination);
        await File.WriteAllTextAsync(Path.Combine(Destination, "sub"), "a file", Ct);

        FakeFiles files = new();
        files.Directories["/d"] = [("sub", Directory)];
        files.Directories["/d/sub"] = [];
        await using FakeSftpServer fake = await ServerWithAsync(files);

        await Assert.ThrowsAsync<SftpUnsafeNameException>(() => fake.Client.DownloadDirectoryAsync("/d", Destination, long.MaxValue, Ct));
    }

    [Fact(Timeout = Limit)]
    public async Task SshNet_2026_an_existing_local_link_is_never_followed()
    {
        string outside = Path.Combine(_sandbox, "outside");
        System.IO.Directory.CreateDirectory(outside);
        System.IO.Directory.CreateDirectory(Destination);
        string link = Path.Combine(Destination, "sub");
        try
        {
            System.IO.Directory.CreateSymbolicLink(link, outside);
        }
        catch (IOException)
        {
            Assert.Skip("This account can't create symbolic links.");
        }
        catch (UnauthorizedAccessException)
        {
            Assert.Skip("This account can't create symbolic links.");
        }

        FakeFiles files = new();
        files.Directories["/d"] = [("sub", Directory)];
        files.Directories["/d/sub"] = [("evil.txt", RegularFile)];
        files.Files["/d/sub/evil.txt"] = "evil"u8.ToArray();
        await using FakeSftpServer fake = await ServerWithAsync(files);

        await Assert.ThrowsAsync<SftpUnsafeNameException>(() => fake.Client.DownloadDirectoryAsync("/d", Destination, long.MaxValue, Ct));
        Assert.Empty(new DirectoryInfo(outside).GetFiles());
    }

    [Fact(Timeout = Limit)]
    public async Task A_tree_downloads_and_links_are_skipped()
    {
        FakeFiles files = new();
        files.Files["/d/a.txt"] = "a"u8.ToArray();
        files.Files["/d/sub/b.txt"] = "b"u8.ToArray();
        files.Directories["/d"] = [(".", Directory), ("..", Directory), ("a.txt", RegularFile), ("sub", Directory), ("link", SymbolicLink)];
        files.Directories["/d/sub"] = [("b.txt", RegularFile)];
        await using FakeSftpServer fake = await ServerWithAsync(files);

        // A trailing separator on the destination is as good as none.
        await fake.Client.DownloadDirectoryAsync("/d", Destination + Path.DirectorySeparatorChar, long.MaxValue, Ct);

        Assert.Equal("a", await File.ReadAllTextAsync(Path.Combine(Destination, "a.txt"), Ct));
        Assert.Equal("b", await File.ReadAllTextAsync(Path.Combine(Destination, "sub", "b.txt"), Ct));
        Assert.False(Path.Exists(Path.Combine(Destination, "link")));
        Assert.Equal(0, files.OpenHandles);
    }

    [Fact(Timeout = Limit)]
    public async Task A_server_can_fake_a_tree_only_so_deep()
    {
        FakeFiles files = new();
        files.Directories["/d"] = [("d", Directory)];
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) =>
        {
            // Every directory appears to contain another one.
            if (request.Type == SftpMessage.OpenDir)
            {
                files.Directories.TryAdd(request.Path, [("d", Directory)]);
            }

            return files.HandleAsync(server, request);
        });

        SftpException ex = await Assert.ThrowsAsync<SftpException>(() => fake.Client.DownloadDirectoryAsync("/d", Destination, long.MaxValue, Ct));
        Assert.Contains("levels deep", ex.Message);
    }

    [Fact(Timeout = Limit)]
    public async Task A_tree_stops_at_its_byte_limit()
    {
        FakeFiles files = new();
        files.Files["/d/a"] = new byte[600];
        files.Files["/d/b"] = new byte[600];
        files.Directories["/d"] = [("a", RegularFile), ("b", RegularFile)];
        await using FakeSftpServer fake = await ServerWithAsync(files);

        SftpException ex = await Assert.ThrowsAsync<SftpException>(() => fake.Client.DownloadDirectoryAsync("/d", Destination, maxTotalBytes: 1000, Ct));
        Assert.Contains("limit of", ex.Message);
    }

    [Fact(Timeout = Limit)]
    public async Task A_tree_stops_at_its_entry_limit()
    {
        FakeFiles files = new();
        files.Directories["/d"] = [("a", Directory), ("b", Directory), ("c", Directory)];
        files.Directories["/d/a"] = [];
        files.Directories["/d/b"] = [];
        files.Directories["/d/c"] = [];
        await using FakeSftpServer fake = await ServerWithAsync(files);

        fake.Client.Options = new SftpClientOptions { MaxDirectoryEntries = 2 };
        await Assert.ThrowsAsync<SftpException>(() => fake.Client.DownloadDirectoryAsync("/d", Destination, long.MaxValue, Ct));
    }

    [Fact(Timeout = Limit)]
    public async Task A_listing_returns_names_as_given_and_flags_the_unsafe_ones()
    {
        FakeFiles files = new();
        files.Directories["/d"] = [("../evil", RegularFile), ("good.txt", RegularFile), (".", Directory)];
        await using FakeSftpServer fake = await ServerWithAsync(files);

        SftpEntry[] entries = await fake.Client.ListDirectoryAsync("/d", Ct).ToArrayAsync(Ct);
        Assert.Equal(["../evil", "good.txt", "."], entries.Select(e => e.Name));
        Assert.Equal([false, true, false], entries.Select(e => e.IsSafeName));
    }

    [Fact(Timeout = Limit)]
    public async Task Names_that_arent_utf8_are_replaced_and_dont_end_the_session()
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) => request.Type switch
        {
            SftpMessage.OpenDir => server.SendHandleAsync(request.Id, [1]),
            SftpMessage.ReadDir when request.Id < 2 => server.SendAsync(new Packet().U8(SftpMessage.Name).U32(request.Id).U32(1).Entry([0x66, 0xE6, 0x6F]).ToFrame()),
            SftpMessage.ReadDir => server.SendStatusAsync(request.Id, FakeSftpServer.StatusEof),
            _ => server.SendStatusAsync(request.Id),
        });

        SftpEntry[] entries = await fake.Client.ListDirectoryAsync("/d", Ct).ToArrayAsync(Ct);
        Assert.Equal("f�o", Assert.Single(entries).Name);
    }

    [Theory]
    [InlineData("file.txt", true)]
    [InlineData(".hidden", true)]
    [InlineData("..hidden", true)]
    [InlineData("name with spaces.txt", true)]
    [InlineData("æøå.txt", true)]
    [InlineData(".", false)]
    [InlineData("..", false)]
    [InlineData("", false)]
    [InlineData("a/b", false)]
    [InlineData("a\\b", false)]
    [InlineData("a\0b", false)]
    public void IsSafeName_decides_on_the_name(string name, bool safe) =>
        Assert.Equal(safe, new SftpEntry { Name = name, Attributes = new SftpAttributes() }.IsSafeName);
}

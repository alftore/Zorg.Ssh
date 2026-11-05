using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Sftp;
using static Zorg.Ssh.Tests.Sftp.SftpServerHarness;

namespace Zorg.Ssh.Tests.Sftp;

/// <summary>Every way out of the root we know of, tried with every operation that takes a path.</summary>
[Collection(SftpSerialTests.Name)]
public sealed class SftpServerPathTests : IDisposable
{
    private readonly SftpServerSandbox _sandbox = new();

    private SftpServerOptions Options => new() { RootDirectory = _sandbox.Root };

    /// <summary>Paths that are portable attacks: the same on every OS.</summary>
    public static TheoryData<string> PortableEscapes() => new(
        "../secret.txt",
        "/../secret.txt",
        "../../secret.txt",
        "../../../../../../../../../../secret.txt",
        "../outside/secret.txt",
        "/../outside/secret.txt",
        "a/../../secret.txt",
        "a/b/c/../../../../secret.txt",
        "./../secret.txt",
        "/./.././secret.txt",
        "//../secret.txt",
        "..//..//secret.txt",
        "..",
        "../",
        "/..",
        "../..",
        "..%2fsecret.txt",
        "%2e%2e/secret.txt",
        "\uFF0E\uFF0E/secret.txt",
        "..\u2215secret.txt");

    /// <summary>Paths that mean something special only to Windows. They're refused there, and harmless names elsewhere.</summary>
    public static TheoryData<string> WindowsEscapes() => new(
        "..\\secret.txt",
        "..\\..\\secret.txt",
        "a\\..\\..\\secret.txt",
        "/..\\secret.txt",
        "\\..\\secret.txt",
        "..\\/secret.txt",
        "C:\\Windows\\win.ini",
        "C:/Windows/win.ini",
        "/C:/Windows/win.ini",
        "C:",
        "C:secret.txt",
        "\\Windows\\win.ini",
        "\\\\?\\C:\\Windows\\win.ini",
        "//?/C:/Windows/win.ini",
        "\\\\.\\PhysicalDrive0",
        "\\\\localhost\\c$\\Windows\\win.ini",
        "file.txt:stream",
        "file.txt::$DATA",
        "file.txt:stream:$DATA",
        "/dir:evil/x",
        "CON",
        "con",
        "PRN",
        "AUX",
        "NUL",
        "nul.txt",
        "NUL .txt",
        "COM1",
        "com9.log",
        "LPT1",
        "LPT9.tar.gz",
        "COM\u00B9",
        "LPT\u00B3",
        "CONIN$",
        "CONOUT$",
        "dir/NUL/x",
        "NUL/../file.txt",
        ".. /secret.txt",
        ".. ",
        "..  /secret.txt",
        ".. ./secret.txt",
        "... /secret.txt",
        ".../secret.txt",
        "....",
        "file.txt.",
        "file.txt ",
        "file.txt. . ",
        "dir./x",
        "dir /x",
        "a<b",
        "a>b",
        "a|b",
        "a\"b",
        "a?b",
        "a*b",
        "a\u0001b");

    public void Dispose() => _sandbox.Dispose();

    /// <summary>Tries a path with everything that takes one. The path decides what happens: this checks nothing got out.</summary>
    private async Task AttackAsync(SftpServerHarness client, string path)
    {
        Assert.NotEqual(SftpServerSandbox.Secret, await client.TryReadTextAsync(path));

        SftpServerReply stat = await client.RequestAsync(SftpMessage.Stat, Path(path));
        SftpServerReply lstat = await client.RequestAsync(SftpMessage.Lstat, Path(path));
        await client.RequestAsync(SftpMessage.OpenDir, Path(path));
        await client.RequestAsync(SftpMessage.ReadLink, Path(path));
        SftpServerReply realPath = await client.RequestAsync(SftpMessage.RealPath, Path(path));
        if (realPath.Type == SftpMessage.Name)
        {
            Assert.StartsWith("/", realPath.FirstName);
            Assert.DoesNotContain("..", realPath.FirstName.Split('/'));
        }

        await client.RequestAsync(SftpMessage.SetStat, Path(path).U32(1).U64(0));
        await client.RequestAsync(SftpMessage.Remove, Path(path));
        await client.RequestAsync(SftpMessage.RmDir, Path(path));
        await client.RequestAsync(SftpMessage.MkDir, Path(path + "-new").U32(0));
        await client.RequestAsync(SftpMessage.Rename, Path(path).Text("moved"));
        await client.RequestAsync(SftpMessage.Rename, Path("bait").Text(path + "-moved"));
        await client.ExtendedAsync("posix-rename@openssh.com", Path(path).Text("moved"));
        await client.RequestAsync(SftpMessage.SymLink, Path("bait").Text(path + "-link"));
        await client.RequestAsync(SftpMessage.SymLink, Path(path).Text("link-to-it"));
        SftpServerReply write = await client.OpenAsync(path + "-created", OpenWrite | OpenCreate);
        if (write.Type == SftpMessage.Handle)
        {
            await client.CloseAsync(write.Handle);
        }

        Assert.True(stat.Type != SftpMessage.Attrs || lstat.Type == SftpMessage.Attrs);
    }

    private async Task RunAttackAsync(string path)
    {
        Dictionary<string, string> before = _sandbox.SnapshotOutside();
        await File.WriteAllTextAsync(_sandbox.InRoot("bait"), "bait", TestContext.Current.CancellationToken);
        await using SftpServerHarness client = await StartAsync(Options);
        await AttackAsync(client, path);
        Assert.Equal(before, _sandbox.SnapshotOutside());
        client.AssertNothingLeaked(_sandbox.Base);
        Assert.False(client.Serving.IsCompleted);
    }

    [Theory]
    [MemberData(nameof(PortableEscapes))]
    public Task Portable_escape_reaches_nothing_outside(string path) => RunAttackAsync(path);

    [Theory]
    [MemberData(nameof(WindowsEscapes))]
    public Task Windows_escape_reaches_nothing_outside(string path) => RunAttackAsync(path);

    [Theory]
    [MemberData(nameof(WindowsEscapes))]
    public async Task Windows_special_names_are_refused_on_Windows(string path)
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows rules.");
        await File.WriteAllTextAsync(_sandbox.InRoot("file.txt"), "x", TestContext.Current.CancellationToken);
        Directory.CreateDirectory(_sandbox.InRoot("dir"));
        await using SftpServerHarness client = await StartAsync(Options);

        Assert.Equal(SftpMessage.Status, (await client.RequestAsync(SftpMessage.Stat, Path(path))).Type);
        Assert.Equal(SftpMessage.Status, (await client.OpenAsync(path, OpenWrite | OpenCreate)).Type);
        Assert.Equal(["dir", "file.txt"], Directory.GetFileSystemEntries(_sandbox.Root).Select(System.IO.Path.GetFileName).Order(StringComparer.Ordinal));
        Assert.Equal("x", await File.ReadAllTextAsync(_sandbox.InRoot("file.txt"), TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("file.txt:evil")]
    [InlineData("file.txt::$DATA")]
    public async Task Alternate_data_streams_can_be_neither_written_nor_read(string path)
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Alternate data streams are an NTFS feature.");
        await File.WriteAllTextAsync(_sandbox.InRoot("file.txt"), "x", TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(_sandbox.InRoot("file.txt") + ":hidden", "hidden", TestContext.Current.CancellationToken);
        await using SftpServerHarness client = await StartAsync(Options);

        Assert.Equal(Failure, (await client.OpenAsync(path, OpenWrite | OpenCreate)).Status);
        Assert.Equal(Failure, (await client.OpenAsync("file.txt:hidden", OpenRead)).Status);
    }

    [Fact]
    public async Task Dot_dot_stops_at_the_root_and_lands_inside_it()
    {
        await File.WriteAllTextAsync(_sandbox.InRoot("secret.txt"), "decoy", TestContext.Current.CancellationToken);
        await using SftpServerHarness client = await StartAsync(Options);

        Assert.Equal("decoy", await client.TryReadTextAsync("../../secret.txt"));
        Assert.Equal("decoy", await client.TryReadTextAsync("/../secret.txt"));
        Assert.Equal("/", (await client.RequestAsync(SftpMessage.RealPath, Path("../.."))).FirstName);
        Assert.Equal("/", (await client.RequestAsync(SftpMessage.RealPath, Path("."))).FirstName);
        Assert.Equal("/", (await client.RequestAsync(SftpMessage.RealPath, Path(string.Empty))).FirstName);
        Assert.Equal("/a/c", (await client.RequestAsync(SftpMessage.RealPath, Path("/a/./b/../c/"))).FirstName);
    }

    [Fact]
    public async Task An_absolute_path_is_relative_to_the_root()
    {
        string real = System.IO.Path.Combine(_sandbox.Outside, "secret.txt");
        await using SftpServerHarness client = await StartAsync(Options);

        Assert.Null(await client.TryReadTextAsync(real.Replace('\\', '/')));
        if (!OperatingSystem.IsWindows())
        {
            Assert.Null(await client.TryReadTextAsync(real));
            Assert.Null(await client.TryReadTextAsync("/etc/passwd"));
        }
    }

    [Theory]
    [InlineData("a\0")]
    [InlineData("\0")]
    [InlineData("a\0/../../secret.txt")]
    [InlineData("../secret.txt\0.jpg")]
    public async Task A_NUL_in_a_path_is_refused(string path)
    {
        await using SftpServerHarness client = await StartAsync(Options);
        Assert.Equal(Failure, (await client.RequestAsync(SftpMessage.Stat, Path(path))).Status);
        Assert.Equal(Failure, (await client.OpenAsync(path, OpenWrite | OpenCreate)).Status);
        Assert.Empty(Directory.GetFileSystemEntries(_sandbox.Root));
    }

    [Fact]
    public async Task A_path_past_the_length_limit_is_refused()
    {
        await using SftpServerHarness client = await StartAsync(Options);
        Assert.Equal(Failure, (await client.RequestAsync(SftpMessage.Stat, Path(new string('a', 5000)))).Status);
    }

    [Fact]
    public async Task The_root_itself_can_be_neither_removed_nor_renamed()
    {
        await using SftpServerHarness client = await StartAsync(Options);
        foreach (string root in new[] { "/", ".", "..", "../..", string.Empty })
        {
            Assert.Equal(PermissionDenied, (await client.RequestAsync(SftpMessage.RmDir, Path(root))).Status);
            Assert.Equal(Failure, (await client.RequestAsync(SftpMessage.Remove, Path(root))).Status);
            Assert.Equal(PermissionDenied, (await client.RequestAsync(SftpMessage.Rename, Path(root).Text("x"))).Status);
            Assert.Equal(Failure, (await client.RequestAsync(SftpMessage.SymLink, Path("x").Text(root))).Status);
        }

        Assert.True(Directory.Exists(_sandbox.Root));
    }

    /// <summary>A directory link leading out, at the top of the root or deep in it, on Windows as a junction.</summary>
    [Theory]
    [InlineData("out")]
    [InlineData("a/b/c/out")]
    public async Task A_directory_link_out_of_the_root_is_refused_for_every_operation(string linkPath)
    {
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(_sandbox.InRoot(linkPath))!);
        SftpServerSandbox.LinkDirectory(_sandbox.InRoot(linkPath), _sandbox.Outside);
        Dictionary<string, string> before = _sandbox.SnapshotOutside();
        await using SftpServerHarness client = await StartAsync(Options);

        string secret = $"{linkPath}/secret.txt";
        Assert.Equal(PermissionDenied, (await client.OpenAsync(secret, OpenRead)).Status);
        Assert.Equal(PermissionDenied, (await client.OpenAsync(secret, OpenWrite | OpenTruncate)).Status);
        Assert.Equal(PermissionDenied, (await client.OpenAsync($"{linkPath}/new.txt", OpenWrite | OpenCreate)).Status);
        Assert.Equal(PermissionDenied, (await client.OpenAsync($"{linkPath}/new.txt", OpenWrite | OpenCreate | OpenExclusive)).Status);
        Assert.Equal(PermissionDenied, (await client.RequestAsync(SftpMessage.Stat, Path(secret))).Status);
        Assert.Equal(PermissionDenied, (await client.RequestAsync(SftpMessage.Lstat, Path(secret))).Status);
        Assert.Equal(PermissionDenied, (await client.RequestAsync(SftpMessage.Stat, Path(linkPath))).Status);
        Assert.Equal(PermissionDenied, (await client.RequestAsync(SftpMessage.OpenDir, Path(linkPath))).Status);
        Assert.Equal(PermissionDenied, (await client.RequestAsync(SftpMessage.RealPath, Path(linkPath))).Status);
        Assert.Equal(PermissionDenied, (await client.RequestAsync(SftpMessage.RealPath, Path(secret))).Status);
        Assert.Equal(PermissionDenied, (await client.RequestAsync(SftpMessage.ReadLink, Path(linkPath))).Status);
        Assert.Equal(PermissionDenied, (await client.RequestAsync(SftpMessage.SetStat, Path(secret).U32(1).U64(0))).Status);
        Assert.Equal(PermissionDenied, (await client.RequestAsync(SftpMessage.SetStat, Path(linkPath).U32(4).U32(0x1FF))).Status);
        Assert.Equal(PermissionDenied, (await client.RequestAsync(SftpMessage.Remove, Path(secret))).Status);
        Assert.Equal(PermissionDenied, (await client.RequestAsync(SftpMessage.RmDir, Path($"{linkPath}/sub"))).Status);
        Assert.Equal(PermissionDenied, (await client.RequestAsync(SftpMessage.MkDir, Path($"{linkPath}/sub").U32(0))).Status);
        Assert.Equal(PermissionDenied, (await client.RequestAsync(SftpMessage.Rename, Path(secret).Text("stolen"))).Status);
        Assert.Equal(PermissionDenied, (await client.ExtendedAsync("posix-rename@openssh.com", Path(secret).Text("stolen"))).Status);
        Assert.Equal(PermissionDenied, (await client.RequestAsync(SftpMessage.SymLink, Path("x").Text($"{linkPath}/l"))).Status);
        Assert.Equal(PermissionDenied, (await client.ExtendedAsync("statvfs@openssh.com", Path(secret))).Status);

        Assert.Equal(before, _sandbox.SnapshotOutside());
        client.AssertNothingLeaked(_sandbox.Base);
    }

    [Fact]
    public async Task A_listing_shows_a_link_out_as_a_link_and_says_nothing_of_where_it_goes()
    {
        SftpServerSandbox.LinkDirectory(_sandbox.InRoot("out"), _sandbox.Outside);
        await using SftpServerHarness client = await StartAsync(Options);

        byte[] handle = (await client.RequestAsync(SftpMessage.OpenDir, Path("/"))).Handle;
        SftpServerReply batch = await client.RequestAsync(SftpMessage.ReadDir, Empty().Bytes(handle));
        Assert.Contains("out", batch.Names);
        SftpAttributes link = (await client.RequestAsync(SftpMessage.Lstat, Path("out"))).Attributes;
        Assert.True(link.IsSymbolicLink);
        client.AssertNothingLeaked(_sandbox.Base);
    }

    [Fact]
    public async Task A_link_out_can_be_removed_without_touching_its_target()
    {
        SftpServerSandbox.LinkDirectory(_sandbox.InRoot("out"), _sandbox.Outside);
        await using SftpServerHarness client = await StartAsync(Options);

        Assert.Equal(Ok, (await client.RequestAsync(SftpMessage.Remove, Path("out"))).Status);
        Assert.Equal(NoSuchFile, (await client.RequestAsync(SftpMessage.Lstat, Path("out"))).Status);
        Assert.True(File.Exists(System.IO.Path.Combine(_sandbox.Outside, "secret.txt")));
    }

    [Fact]
    public async Task RMDIR_doesnt_follow_a_link()
    {
        SftpServerSandbox.LinkDirectory(_sandbox.InRoot("out"), _sandbox.Outside);
        await using SftpServerHarness client = await StartAsync(Options);
        Assert.Equal(Failure, (await client.RequestAsync(SftpMessage.RmDir, Path("out"))).Status);
        Assert.True(Directory.Exists(_sandbox.Outside));
    }

    [Fact]
    public async Task A_link_that_stays_inside_works_and_realpath_resolves_it()
    {
        Directory.CreateDirectory(_sandbox.InRoot("real/deep"));
        await File.WriteAllTextAsync(_sandbox.InRoot("real/deep/f.txt"), "inside", TestContext.Current.CancellationToken);
        SftpServerSandbox.LinkDirectory(_sandbox.InRoot("alias"), _sandbox.InRoot("real"));
        await using SftpServerHarness client = await StartAsync(Options);

        Assert.Equal("inside", await client.TryReadTextAsync("alias/deep/f.txt"));
        Assert.Equal("/real/deep/f.txt", (await client.RequestAsync(SftpMessage.RealPath, Path("alias/deep/f.txt"))).FirstName);
        Assert.Equal("/real", (await client.RequestAsync(SftpMessage.ReadLink, Path("alias"))).FirstName);
    }

    [Fact]
    public async Task A_root_reached_through_a_link_still_works_and_still_confines()
    {
        string alias = System.IO.Path.Combine(_sandbox.Base, "alias");
        SftpServerSandbox.LinkDirectory(alias, _sandbox.Root);
        await File.WriteAllTextAsync(_sandbox.InRoot("f.txt"), "inside", TestContext.Current.CancellationToken);
        SftpServerSandbox.LinkDirectory(_sandbox.InRoot("out"), _sandbox.Outside);
        try
        {
            await using SftpServerHarness client = await StartAsync(new SftpServerOptions { RootDirectory = alias });
            Assert.Equal("inside", await client.TryReadTextAsync("f.txt"));
            Assert.Equal(PermissionDenied, (await client.OpenAsync("out/secret.txt", OpenRead)).Status);
        }
        finally
        {
            Directory.Delete(alias);
        }
    }

    [Fact]
    public async Task A_file_link_out_is_refused_but_lstat_sees_the_link()
    {
        SftpServerSandbox.Link(_sandbox.InRoot("link.txt"), System.IO.Path.Combine(_sandbox.Outside, "secret.txt"));
        await using SftpServerHarness client = await StartAsync(Options);

        Assert.Equal(PermissionDenied, (await client.OpenAsync("link.txt", OpenRead)).Status);
        Assert.Equal(PermissionDenied, (await client.OpenAsync("link.txt", OpenWrite | OpenTruncate)).Status);
        Assert.Equal(PermissionDenied, (await client.RequestAsync(SftpMessage.Stat, Path("link.txt"))).Status);
        Assert.Equal(PermissionDenied, (await client.RequestAsync(SftpMessage.SetStat, Path("link.txt").U32(1).U64(0))).Status);
        Assert.True((await client.RequestAsync(SftpMessage.Lstat, Path("link.txt"))).Attributes.IsSymbolicLink);
        Assert.Equal(SftpServerSandbox.Secret, await File.ReadAllTextAsync(System.IO.Path.Combine(_sandbox.Outside, "secret.txt"), TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("../outside/secret.txt")]
    [InlineData("../../../../../../../../../../../../../etc/passwd")]
    [InlineData("sub/../../outside/secret.txt")]
    public async Task A_relative_link_that_climbs_out_is_refused(string target)
    {
        Directory.CreateDirectory(_sandbox.InRoot("sub"));
        SftpServerSandbox.Link(_sandbox.InRoot("rel"), target.Replace('/', System.IO.Path.DirectorySeparatorChar));
        await using SftpServerHarness client = await StartAsync(Options);

        Assert.Equal(PermissionDenied, (await client.OpenAsync("rel", OpenRead)).Status);
        Assert.Equal(PermissionDenied, (await client.RequestAsync(SftpMessage.ReadLink, Path("rel"))).Status);
        client.AssertNothingLeaked(_sandbox.Base);
    }

    [Fact]
    public async Task A_relative_link_leaves_and_comes_back_is_still_refused()
    {
        string name = System.IO.Path.GetFileName(_sandbox.Root);
        await File.WriteAllTextAsync(_sandbox.InRoot("f.txt"), "x", TestContext.Current.CancellationToken);
        SftpServerSandbox.Link(_sandbox.InRoot("bounce"), $"..{System.IO.Path.DirectorySeparatorChar}{name}{System.IO.Path.DirectorySeparatorChar}f.txt");
        await using SftpServerHarness client = await StartAsync(Options);
        Assert.Equal(PermissionDenied, (await client.OpenAsync("bounce", OpenRead)).Status);
    }

    [Fact]
    public async Task A_chain_of_links_is_refused_where_it_leaves()
    {
        SftpServerSandbox.LinkDirectory(_sandbox.InRoot("last"), _sandbox.Outside);
        SftpServerSandbox.LinkDirectory(_sandbox.InRoot("middle"), _sandbox.InRoot("last"));
        SftpServerSandbox.LinkDirectory(_sandbox.InRoot("first"), _sandbox.InRoot("middle"));
        await using SftpServerHarness client = await StartAsync(Options);
        Assert.Equal(PermissionDenied, (await client.OpenAsync("first/secret.txt", OpenRead)).Status);
    }

    [Fact]
    public async Task A_link_loop_is_a_failure_not_a_hang()
    {
        SftpServerSandbox.Link(_sandbox.InRoot("a"), "b");
        SftpServerSandbox.Link(_sandbox.InRoot("b"), "a");
        await using SftpServerHarness client = await StartAsync(Options);
        Assert.Equal(Failure, (await client.RequestAsync(SftpMessage.Stat, Path("a"))).Status);
        Assert.Equal(Failure, (await client.OpenAsync("a/x", OpenRead)).Status);
    }

    [Fact]
    public async Task A_dangling_link_out_cant_be_used_to_create_a_file_outside()
    {
        string planted = System.IO.Path.Combine(_sandbox.Outside, "planted.txt");
        SftpServerSandbox.Link(_sandbox.InRoot("dangling"), planted);
        await using SftpServerHarness client = await StartAsync(Options);

        Assert.Equal(PermissionDenied, (await client.OpenAsync("dangling", OpenWrite | OpenCreate)).Status);
        Assert.Equal(Failure, (await client.OpenAsync("dangling", OpenWrite | OpenCreate | OpenExclusive)).Status);
        Assert.False(File.Exists(planted));
    }

    [Fact]
    public async Task A_dangling_link_inside_creates_its_target_inside()
    {
        SftpServerSandbox.Link(_sandbox.InRoot("dangling"), "target.txt");
        await using SftpServerHarness client = await StartAsync(Options);

        await client.CloseAsync(await client.OpenHandleAsync("dangling", OpenWrite | OpenCreate));
        Assert.True(File.Exists(_sandbox.InRoot("target.txt")));
    }

    [Theory]
    [InlineData("../outside/secret.txt", "l")]
    [InlineData("..", "l")]
    [InlineData("../..", "sub/l")]
    [InlineData("../../outside", "sub/l")]
    [InlineData("sub/../../outside", "l")]
    public async Task SYMLINK_refuses_a_target_that_climbs_out(string target, string link)
    {
        Directory.CreateDirectory(_sandbox.InRoot("sub"));
        await using SftpServerHarness client = await StartAsync(Options);

        Assert.Equal(PermissionDenied, (await client.RequestAsync(SftpMessage.SymLink, Path(target).Text(link))).Status);
        Assert.False(new FileInfo(_sandbox.InRoot(link)).Exists);
    }

    [Fact]
    public async Task SYMLINK_refuses_a_target_through_a_link_that_leads_out()
    {
        SftpServerSandbox.LinkDirectory(_sandbox.InRoot("out"), _sandbox.Outside);
        await using SftpServerHarness client = await StartAsync(Options);
        Assert.Equal(PermissionDenied, (await client.RequestAsync(SftpMessage.SymLink, Path("out/secret.txt").Text("l"))).Status);
    }

    [Theory]
    [InlineData("C:\\Windows")]
    [InlineData("\\\\server\\share")]
    [InlineData("..\\outside")]
    [InlineData("x:y")]
    public async Task SYMLINK_refuses_Windows_targets_on_Windows(string target)
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows rules.");
        await using SftpServerHarness client = await StartAsync(Options);
        Assert.Equal(Failure, (await client.RequestAsync(SftpMessage.SymLink, Path(target).Text("l"))).Status);
    }

    [Fact]
    public async Task SYMLINK_with_an_absolute_target_means_the_clients_root()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows() && !CanCreateLinks(), "Needs the privilege to create symbolic links.");
        Directory.CreateDirectory(_sandbox.InRoot("etc"));
        Directory.CreateDirectory(_sandbox.InRoot("sub"));
        await File.WriteAllTextAsync(_sandbox.InRoot("etc/passwd"), "decoy", TestContext.Current.CancellationToken);
        await using SftpServerHarness client = await StartAsync(Options);

        Assert.Equal(Ok, (await client.RequestAsync(SftpMessage.SymLink, Path("/etc/passwd").Text("sub/l"))).Status);
        Assert.Equal("decoy", await client.TryReadTextAsync("sub/l"));
        Assert.Equal("../etc/passwd", (await client.RequestAsync(SftpMessage.ReadLink, Path("sub/l"))).FirstName);
        Assert.Equal(
            string.Join(System.IO.Path.DirectorySeparatorChar, "..", "etc", "passwd"),
            new FileInfo(_sandbox.InRoot("sub/l")).LinkTarget);
    }

    [Fact]
    public async Task A_relative_link_moved_so_it_points_out_stops_working()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows() && !CanCreateLinks(), "Needs the privilege to create symbolic links.");
        Directory.CreateDirectory(_sandbox.InRoot("a/b"));
        await using SftpServerHarness client = await StartAsync(Options);

        Assert.Equal(Ok, (await client.RequestAsync(SftpMessage.SymLink, Path("../../x").Text("a/b/l"))).Status);
        Assert.Equal(Ok, (await client.RequestAsync(SftpMessage.Rename, Path("a/b/l").Text("moved"))).Status);
        Assert.Equal(PermissionDenied, (await client.OpenAsync("moved", OpenRead)).Status);
        Assert.Equal(PermissionDenied, (await client.RequestAsync(SftpMessage.ReadLink, Path("moved"))).Status);
    }

    /// <summary>
    /// What closes the race between sessions: nothing that goes from a path to an action may run while another
    /// does. This is the proof. The stress test below is too narrow a window to catch the gate being removed.
    /// </summary>
    [Theory]
    [InlineData(SftpMessage.Open)]
    [InlineData(SftpMessage.SetStat)]
    [InlineData(SftpMessage.Lstat)]
    [InlineData(SftpMessage.Stat)]
    [InlineData(SftpMessage.OpenDir)]
    [InlineData(SftpMessage.Remove)]
    [InlineData(SftpMessage.MkDir)]
    [InlineData(SftpMessage.RmDir)]
    [InlineData(SftpMessage.RealPath)]
    [InlineData(SftpMessage.Rename)]
    [InlineData(SftpMessage.ReadLink)]
    [InlineData(SftpMessage.SymLink)]
    public async Task Every_request_that_uses_a_path_waits_for_the_namespace_gate(byte type)
    {
        await using SftpServerHarness client = await StartAsync(Options);
        await AssertWaitsForGateAsync(() => client.RequestAsync(type, Path("x").Text("y").U32(0).U32(0)));
    }

    [Theory]
    [InlineData("posix-rename@openssh.com")]
    [InlineData("statvfs@openssh.com")]
    public async Task Extensions_that_use_a_path_wait_for_the_namespace_gate(string name)
    {
        await using SftpServerHarness client = await StartAsync(Options);
        await AssertWaitsForGateAsync(() => client.ExtendedAsync(name, Path("x").Text("y")));
    }

    [Fact]
    public async Task File_contents_dont_wait_for_the_namespace_gate()
    {
        await File.WriteAllTextAsync(_sandbox.InRoot("f.txt"), "12345", TestContext.Current.CancellationToken);
        await using SftpServerHarness client = await StartAsync(Options);
        byte[] handle = await client.OpenHandleAsync("f.txt", OpenRead);

        await SftpServerSession.NamespaceGate.WaitAsync(TestContext.Current.CancellationToken);
        try
        {
            SftpServerReply read = await client.ReadAsync(handle, 0, 5).WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
            Assert.Equal(5, read.Data.Length);
        }
        finally
        {
            SftpServerSession.NamespaceGate.Release();
        }
    }

    private static async Task AssertWaitsForGateAsync(Func<Task<SftpServerReply>> request)
    {
        await SftpServerSession.NamespaceGate.WaitAsync(TestContext.Current.CancellationToken);
        Task<SftpServerReply> reply;
        try
        {
            reply = request();
            await Task.Delay(100, TestContext.Current.CancellationToken);
            Assert.False(reply.IsCompleted);
        }
        finally
        {
            SftpServerSession.NamespaceGate.Release();
        }

        await reply.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// Two sessions of one client, one swapping a real directory for a link out while the other reads through it.
    /// A stress test of the whole path, with the gate and the check after opening both in place.
    /// </summary>
    [Fact]
    public async Task A_second_session_cant_swap_a_link_in_between_the_check_and_the_open()
    {
        Directory.CreateDirectory(_sandbox.InRoot("swap"));
        await File.WriteAllTextAsync(_sandbox.InRoot("swap/secret.txt"), "decoy", TestContext.Current.CancellationToken);
        SftpServerSandbox.LinkDirectory(_sandbox.InRoot("evil"), _sandbox.Outside);
        await using SftpServerHarness reader = await StartAsync(Options);
        await using SftpServerHarness swapper = await StartAsync(Options);

        using CancellationTokenSource done = new();
        Task swapping = Task.Run(
            async () =>
            {
                while (!done.IsCancellationRequested)
                {
                    await swapper.RequestAsync(SftpMessage.Rename, Path("swap").Text("parked"));
                    await swapper.RequestAsync(SftpMessage.Rename, Path("evil").Text("swap"));
                    await swapper.RequestAsync(SftpMessage.Rename, Path("swap").Text("evil"));
                    await swapper.RequestAsync(SftpMessage.Rename, Path("parked").Text("swap"));
                }
            },
            TestContext.Current.CancellationToken);

        for (int i = 0; i < 500; i++)
        {
            Assert.NotEqual(SftpServerSandbox.Secret, await reader.TryReadTextAsync("swap/secret.txt"));
        }

        await done.CancelAsync();
        await swapping;
    }

    private bool CanCreateLinks()
    {
        string probe = System.IO.Path.Combine(_sandbox.Base, "probe");
        try
        {
            File.CreateSymbolicLink(probe, "x");
            File.Delete(probe);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }
}

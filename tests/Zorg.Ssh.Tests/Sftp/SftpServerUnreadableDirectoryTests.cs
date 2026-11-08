using System;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Sftp;
using static Zorg.Ssh.Tests.Sftp.SftpServerHarness;

namespace Zorg.Ssh.Tests.Sftp;

/// <summary>A directory the server can't open is refused, as OpenSSH does. It is not an empty directory.</summary>
[Collection(SftpSerialTests.Name)]
public sealed class SftpServerUnreadableDirectoryTests : IDisposable
{
    private readonly SftpServerSandbox _sandbox = new();
    private Action? _restore;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose()
    {
        // The directory has to be readable again before the sandbox can delete it.
        _restore?.Invoke();
        _sandbox.Dispose();
    }

    [Fact]
    public async Task OPENDIR_on_a_directory_that_cannot_be_listed_is_permission_denied()
    {
        string locked = Lock();
        await using SftpServerHarness client = await StartAsync(new SftpServerOptions { RootDirectory = _sandbox.Root });

        Assert.Equal(PermissionDenied, (await client.RequestAsync(SftpMessage.OpenDir, Path("/locked"))).Status);
        // The readable ones around it still list.
        Assert.Equal(["locked", "readable"], await ListAsync(client, "/"));
        Assert.Equal(["a.txt"], await ListAsync(client, "/readable"));
        Assert.True(Directory.Exists(locked));
    }

    [Fact]
    public void The_dotnet_reader_throws_for_a_directory_it_cannot_open_and_still_lists_a_readable_one()
    {
        string locked = Lock();
        Assert.Throws<UnauthorizedAccessException>(() => SftpServerListing.OpenWithDotNet(locked));
        using SftpServerListing readable = SftpServerListing.OpenWithDotNet(_sandbox.InRoot("readable"));
        Assert.True(readable.TryNext(out SftpServerListedEntry entry));
        Assert.Equal("a.txt", entry.Name);
        Assert.False(readable.TryNext(out _));
    }

    [Fact]
    public void The_linux_raw_reader_throws_for_a_directory_it_cannot_open()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux() && SftpServerLinux.IsSupported, "The raw reader is used on Linux only.");
        string locked = Lock();
        Assert.Throws<UnauthorizedAccessException>(() => SftpServerListing.Open(locked));
    }

    [Fact]
    public void An_empty_readable_directory_still_lists_as_empty()
    {
        string empty = Path2("empty");
        Directory.CreateDirectory(empty);
        using SftpServerListing listing = SftpServerListing.Open(empty);
        Assert.False(listing.TryNext(out _));
    }

    private static async Task<string[]> ListAsync(SftpServerHarness client, string path)
    {
        byte[] handle = (await client.RequestAsync(SftpMessage.OpenDir, Path(path))).Handle;
        SftpServerReply batch = await client.RequestAsync(SftpMessage.ReadDir, Empty().Bytes(handle));
        return [.. batch.Names.Where(n => n is not "." and not "..").Order(StringComparer.Ordinal)];
    }

    private string Path2(string name) => _sandbox.InRoot(name);

    /// <summary>Makes <c>locked</c> (with a file inside) and a readable sibling. Skips when this account can't be denied.</summary>
    private string Lock()
    {
        string locked = _sandbox.InRoot("locked");
        Directory.CreateDirectory(locked);
        File.WriteAllText(System.IO.Path.Combine(locked, "secret.txt"), "x");
        Directory.CreateDirectory(_sandbox.InRoot("readable"));
        File.WriteAllText(_sandbox.InRoot("readable/a.txt"), "x");

        _restore = OperatingSystem.IsWindows() ? DenyOnWindows(locked) : DenyOnUnix(locked);

        try
        {
            _ = Directory.EnumerateFileSystemEntries(locked).FirstOrDefault();
        }
        catch (UnauthorizedAccessException)
        {
            return locked;
        }

        _restore();
        _restore = null;
        Assert.Skip("This account can still list the directory (running as root, or the ACL does not apply), so there is nothing to deny.");
        return locked;
    }

    [SupportedOSPlatform("windows")]
    private static Action DenyOnWindows(string path)
    {
        DirectoryInfo info = new(path);
        SecurityIdentifier me = WindowsIdentity.GetCurrent().User!;
        FileSystemAccessRule deny = new(me, FileSystemRights.ListDirectory, AccessControlType.Deny);
        DirectorySecurity security = info.GetAccessControl();
        security.AddAccessRule(deny);
        info.SetAccessControl(security);
        return () =>
        {
            DirectorySecurity back = info.GetAccessControl();
            back.RemoveAccessRule(deny);
            info.SetAccessControl(back);
        };
    }

    [UnsupportedOSPlatform("windows")]
    private static Action DenyOnUnix(string path)
    {
        File.SetUnixFileMode(path, UnixFileMode.None);
        return () => File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }
}

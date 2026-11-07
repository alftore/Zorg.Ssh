using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using Xunit;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Sftp;

namespace Zorg.Ssh.Tests.Sftp;

/// <summary>The server's own reading of a Linux directory gives exactly what .NET's gave, for every name .NET can decode.</summary>
public sealed class SftpServerLinuxListingTests : IDisposable
{
    private readonly SftpServerSandbox _sandbox = new();

    public void Dispose() => _sandbox.Dispose();

    [Fact]
    public void The_raw_reader_is_used_on_Linux_with_glibc_and_with_musl()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux only.");
        Assert.SkipUnless(
            RuntimeInformation.ProcessArchitecture is Architecture.X64 or Architecture.Arm64,
            "Only checked where the gate runs.");
        Assert.True(SftpServerLinux.IsSupported);
    }

    [Fact]
    public void Every_entry_has_the_attributes_dotnet_gave_it()
    {
        if (!OperatingSystem.IsLinux())
        {
            Assert.Skip("Linux only.");
            return;
        }

        Assert.SkipUnless(SftpServerLinux.IsSupported, "The raw reader isn't used here.");
        string root = _sandbox.Root;
        File.WriteAllText(Path.Combine(root, "file.txt"), "twelve bytes");
        File.WriteAllBytes(Path.Combine(root, "empty"), []);
        File.WriteAllText(Path.Combine(root, "setuid"), "x");
        File.SetUnixFileMode(Path.Combine(root, "setuid"), UnixFileMode.SetUser | UnixFileMode.UserRead | UnixFileMode.UserExecute | UnixFileMode.OtherRead);
        File.SetLastWriteTimeUtc(Path.Combine(root, "file.txt"), new DateTime(2001, 2, 3, 4, 5, 6, DateTimeKind.Utc));
        File.SetLastAccessTimeUtc(Path.Combine(root, "file.txt"), new DateTime(2002, 3, 4, 5, 6, 7, DateTimeKind.Utc));
        File.SetLastWriteTimeUtc(Path.Combine(root, "empty"), new DateTime(1965, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        Directory.CreateDirectory(Path.Combine(root, "dir"));
        File.SetUnixFileMode(Path.Combine(root, "dir"), (UnixFileMode)0x1C0 | UnixFileMode.StickyBit);
        File.CreateSymbolicLink(Path.Combine(root, "to-file"), "file.txt");
        File.CreateSymbolicLink(Path.Combine(root, "to-dir"), "dir");
        File.CreateSymbolicLink(Path.Combine(root, "dangling"), "nowhere");
        File.CreateSymbolicLink(Path.Combine(root, ".hidden-link"), "/etc");
        File.WriteAllText(Path.Combine(root, "naïve ✓ 😀"), "unicode");
        using (Process mkfifo = Process.Start("mkfifo", Path.Combine(root, "fifo")))
        {
            mkfifo.WaitForExit();
            Assert.Equal(0, mkfifo.ExitCode);
        }

        Dictionary<string, SftpAttributes> raw = Read(SftpServerListing.Open(root));
        Dictionary<string, SftpAttributes> dotnet = Read(SftpServerListing.OpenWithDotNet(root));
        Assert.Equal(10, dotnet.Count);
        Assert.Equal(dotnet.Keys, raw.Keys);
        // Links carry their own bits, 0777 on Linux, as OpenSSH sends: never their target's, which can be outside the
        // root, and never .NET's -1 for a dangling link. Both readers agree on that.
        Assert.All(new[] { "to-file", "to-dir", "dangling", ".hidden-link" }, name =>
        {
            Assert.True(raw[name].IsSymbolicLink, name);
            Assert.Equal((UnixFileMode)0x1FF, raw[name].Permissions);
            Assert.Equal((UnixFileMode)0x1FF, dotnet[name].Permissions);
        });

        foreach ((string name, SftpAttributes expected) in dotnet)
        {
            SftpAttributes actual = raw[name];
            Assert.True(expected.Size == actual.Size, $"{name}: size {expected.Size} from .NET, {actual.Size} raw");
            Assert.True(expected.Permissions == actual.Permissions, $"{name}: mode {expected.Permissions} from .NET, {actual.Permissions} raw");
            Assert.True(Wire(expected).AsSpan().SequenceEqual(Wire(actual)), $"{name}: {Convert.ToHexString(Wire(expected))} from .NET, {Convert.ToHexString(Wire(actual))} raw");
            Assert.True(expected.ModifiedTime == actual.ModifiedTime, $"{name}: mtime {expected.ModifiedTime} from .NET, {actual.ModifiedTime} raw");
            Assert.True(expected.AccessTime == actual.AccessTime, $"{name}: atime {expected.AccessTime} from .NET, {actual.AccessTime} raw");
            Assert.Equal(
                SftpServerAttributes.LongName(name, expected),
                SftpServerAttributes.LongName(name, actual));
        }

        Assert.Equal(12, raw["file.txt"].Size);
        Assert.True(raw["to-dir"].IsSymbolicLink);
        Assert.False(raw["fifo"].IsRegularFile);
    }

    /// <summary>The attributes as a client gets them, file type included.</summary>
    private static byte[] Wire(SftpAttributes attributes)
    {
        SshWriter writer = new(64);
        try
        {
            attributes.WriteWithFileType(ref writer);
            return writer.ToArray();
        }
        finally
        {
            writer.Dispose();
        }
    }

    private static Dictionary<string, SftpAttributes> Read(SftpServerListing listing)
    {
        using (listing)
        {
            Dictionary<string, SftpAttributes> entries = new(StringComparer.Ordinal);
            while (listing.TryNext(out SftpServerListedEntry entry))
            {
                Assert.Null(entry.RawName);
                entries.Add(entry.Name, entry.Attributes);
            }

            return entries;
        }
    }
}

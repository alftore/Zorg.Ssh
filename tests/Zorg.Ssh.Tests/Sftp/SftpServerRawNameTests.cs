using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Unicode;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Sftp;
using Zorg.Ssh.Tests.Transport;
using static Zorg.Ssh.Tests.Sftp.SftpServerHarness;

namespace Zorg.Ssh.Tests.Sftp;

/// <summary>
/// Names on Linux that aren't UTF-8. .NET would decode them with U+FFFD and look the entry up by that string, so the
/// server reads such directories itself: a listing gives the bytes and the entry's own attributes, and the check
/// before a directory moves up sees a link whatever its name.
/// </summary>
[Collection(SftpSerialTests.Name)]
public sealed class SftpServerRawNameTests : IDisposable
{
    private const string LinuxOnly = "Only Linux names are read as bytes by the server; Windows names are UTF-16.";

    private readonly SftpServerSandbox _sandbox = new();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private SftpServerOptions Options => new() { RootDirectory = _sandbox.Root };

    /// <summary>.NET can't delete what it can't name, so a shell empties the root first.</summary>
    public void Dispose()
    {
        if (OperatingSystem.IsLinux())
        {
            Sh("find . -mindepth 1 -delete");
        }

        _sandbox.Dispose();
    }

    /// <summary>Runs a shell script in the root. printf makes the bytes: <c>\346</c> is æ in Latin-1, and alone it isn't UTF-8.</summary>
    private void Sh(string script)
    {
        ProcessStartInfo start = new("sh") { WorkingDirectory = _sandbox.Root, UseShellExecute = false, RedirectStandardError = true };
        start.ArgumentList.Add("-c");
        start.ArgumentList.Add(script);
        using Process process = Process.Start(start)!;
        string error = process.StandardError.ReadToEnd();
        Assert.True(process.WaitForExit(30_000), "The shell didn't finish.");
        Assert.True(process.ExitCode == 0, $"sh -c '{script}' failed: {error}");
    }

    private async Task<(SftpClient Client, Task<int> Serving)> StartClientAsync()
    {
        (Stream client, Stream server) = DuplexStream.CreatePair();
        SftpServerOptions used = Options;
        Task<int> serving = Task.Run(() => SftpServer.ServeStreamsAsync(server, server, used, CancellationToken.None), Ct);
        return (await SftpClient.StartAsync(client, client, client, null, SftpLimits.Default, Ct), serving);
    }

    /// <summary>Lists a directory through the protocol, with each name and long name as the bytes that came.</summary>
    private static async Task<List<RawEntry>> ListRawAsync(SftpServerHarness client, string path)
    {
        byte[] handle = (await client.RequestAsync(SftpMessage.OpenDir, Path(path))).Handle;
        List<RawEntry> entries = [];
        while (true)
        {
            SftpServerReply batch = await client.RequestAsync(SftpMessage.ReadDir, Empty().Bytes(handle));
            if (batch.Type == SftpMessage.Status)
            {
                Assert.Equal(Eof, batch.Status);
                break;
            }

            entries.AddRange(Parse(batch.Body));
        }

        Assert.Equal(Ok, (await client.CloseAsync(handle)).Status);
        return entries;
    }

    private static List<RawEntry> Parse(byte[] body)
    {
        SshReader reader = new(body);
        uint count = reader.ReadUInt32();
        List<RawEntry> entries = [];
        for (uint i = 0; i < count; i++)
        {
            byte[] name = reader.ReadBinary().ToArray();
            byte[] longName = reader.ReadBinary().ToArray();
            entries.Add(new RawEntry(name, longName, SftpAttributes.Read(ref reader)));
        }

        return entries;
    }

    [Fact]
    public async Task A_Latin1_name_is_listed_as_its_bytes_with_its_own_size_and_a_real_FFFD_name_once()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), LinuxOnly);
        Sh(@"printf 'planted' > ""$(printf 'bad\346.txt')"" && mkdir ""$(printf 'dir\346')""");
        await File.WriteAllTextAsync(_sandbox.InRoot("bad�.txt"), "the other file", Ct);
        await File.WriteAllTextAsync(_sandbox.InRoot("plain.txt"), "plain", Ct);

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

            // The file whose name really has U+FFFD is listed once, valid, with its own size, and its name reaches it.
            SftpEntry genuine = Assert.Single(entries, e => e.Name == "bad�.txt" && e.HasValidName);
            Assert.Equal(14, genuine.Attributes.Size);
            Assert.Equal("the other file"u8.ToArray(), await sftp.ReadAllBytesAsync("bad�.txt", Ct));
            Assert.Equal(5, Assert.Single(entries, e => e.Name == "plain.txt").Attributes.Size);
            Assert.Equal(6, entries.Count);
        }

        Assert.Equal(0, await serving.WaitAsync(TimeSpan.FromSeconds(10), Ct));

        // On the wire: the bytes the file system holds, in the name and at the end of the long name.
        await using SftpServerHarness client = await StartAsync(Options);
        List<RawEntry> raw = await ListRawAsync(client, "/");
        RawEntry bad = Assert.Single(raw, e => Is(e.Name, [.. "bad"u8, 0xE6, .. ".txt"u8]));
        Assert.Equal(7, bad.Attributes.Size);
        Assert.True(bad.LongName.AsSpan().EndsWith((byte[])[.. " bad"u8, 0xE6, .. ".txt"u8]));
        Assert.StartsWith("-rw", Encoding.ASCII.GetString(bad.LongName, 0, 3), StringComparison.Ordinal);
        RawEntry directory = Assert.Single(raw, e => Is(e.Name, [.. "dir"u8, 0xE6]));
        Assert.True(directory.Attributes.IsDirectory);
        Assert.Equal((byte)'d', directory.LongName[0]);
        Assert.Single(raw, e => Is(e.Name, [.. "bad"u8, 0xEF, 0xBF, 0xBD, .. ".txt"u8]));
        Assert.Equal(raw.Count, raw.Select(e => Convert.ToHexString(e.Name)).Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public async Task A_FIFO_with_a_name_that_isnt_UTF8_is_listed_as_a_FIFO()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), LinuxOnly);
        Sh(@"mkfifo ""$(printf 'pipe\346')"" && ln -s ""$(printf 'pipe\346')"" ""$(printf 'to-pipe\346')""");

        await using SftpServerHarness client = await StartAsync(Options);
        List<RawEntry> raw = await ListRawAsync(client, "/");
        RawEntry fifo = Assert.Single(raw, e => Is(e.Name, [.. "pipe"u8, 0xE6]));
        Assert.False(fifo.Attributes.IsRegularFile);
        Assert.False(fifo.Attributes.IsDirectory);
        Assert.False(fifo.Attributes.IsSymbolicLink);
        Assert.Equal(0, fifo.Attributes.Size);
        Assert.True(Assert.Single(raw, e => Is(e.Name, [.. "to-pipe"u8, 0xE6])).Attributes.IsSymbolicLink);
    }

    [Fact]
    public async Task A_climbing_link_with_a_name_that_isnt_UTF8_stops_its_directory_moving_up()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), LinuxOnly);
        Directory.CreateDirectory(_sandbox.InRoot("a/b/c/d"));
        await File.WriteAllTextAsync(_sandbox.InRoot("x"), "x", Ct);

        // a/b/c/d/l climbs three levels, to the root. Moving a/b/c to the root leaves it one level too shallow.
        Sh(@"ln -s ../../../x ""a/b/c/d/$(printf 'l\346')""");
        await using SftpServerHarness client = await StartAsync(Options);
        Assert.Equal(PermissionDenied, (await client.RequestAsync(SftpMessage.Rename, Path("a/b/c").Text("c"))).Status);
        Assert.Equal(PermissionDenied, (await client.ExtendedAsync("posix-rename@openssh.com", Path("a/b/c").Text("c"))).Status);
        Assert.True(Directory.Exists(_sandbox.InRoot("a/b/c/d")));
        Assert.False(Directory.Exists(_sandbox.InRoot("c")));

        // Level is still fine.
        Assert.Equal(Ok, (await client.RequestAsync(SftpMessage.Rename, Path("a/b/c").Text("a/c"))).Status);
    }

    [Fact]
    public async Task A_climbing_link_below_a_directory_whose_name_isnt_UTF8_stops_the_move_too()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), LinuxOnly);
        Directory.CreateDirectory(_sandbox.InRoot("a/b/c"));
        await File.WriteAllTextAsync(_sandbox.InRoot("x"), "x", Ct);
        Sh(@"d=""a/b/c/$(printf 'd\346')"" && mkdir ""$d"" && ln -s ../../../x ""$d/l""");

        await using SftpServerHarness client = await StartAsync(Options);
        Assert.Equal(PermissionDenied, (await client.RequestAsync(SftpMessage.Rename, Path("a/b/c").Text("c"))).Status);
        Assert.Equal(PermissionDenied, (await client.ExtendedAsync("posix-rename@openssh.com", Path("a/b/c").Text("c"))).Status);
        Assert.True(Directory.Exists(_sandbox.InRoot("a/b/c")));
    }

    [Fact]
    public async Task A_link_target_that_isnt_UTF8_keeps_its_slashes_and_dots_in_the_check()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), LinuxOnly);
        Directory.CreateDirectory(_sandbox.InRoot("a/b/c/d"));
        Directory.CreateDirectory(_sandbox.InRoot("e/f/g/h"));

        // The first climbs three levels to a name with a bad byte. The second starts with "..\346", which is a plain
        // name to the kernel, so it doesn't climb at all, and the move is fine.
        Sh(@"ln -s ""$(printf '../../../x\346')"" a/b/c/d/l && ln -s ""$(printf '..\346/x')"" e/f/g/h/l");
        await using SftpServerHarness client = await StartAsync(Options);
        Assert.Equal(PermissionDenied, (await client.RequestAsync(SftpMessage.Rename, Path("a/b/c").Text("c"))).Status);
        Assert.Equal(Ok, (await client.RequestAsync(SftpMessage.Rename, Path("e/f/g").Text("g"))).Status);
        Assert.True(Directory.Exists(_sandbox.InRoot("g/h")));
    }

    [Fact]
    public async Task A_big_directory_with_names_that_arent_UTF8_comes_whole_across_batches()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), LinuxOnly);
        HashSet<string> expected = new(StringComparer.Ordinal);
        for (int i = 0; i < 400; i++)
        {
            await File.WriteAllBytesAsync(_sandbox.InRoot($"good-{i:D4}"), new byte[i % 7], Ct);
            expected.Add(Convert.ToHexString(Encoding.ASCII.GetBytes($"good-{i:D4}")));
        }

        Sh(@"i=0; while [ $i -lt 400 ]; do head -c $((i % 5)) /dev/zero > ""$(printf 'bad-%04d\346' $i)""; i=$((i + 1)); done");
        for (int i = 0; i < 400; i++)
        {
            expected.Add(Convert.ToHexString([.. Encoding.ASCII.GetBytes($"bad-{i:D4}"), 0xE6]));
        }

        await using SftpServerHarness client = await StartAsync(new SftpServerOptions { RootDirectory = _sandbox.Root, MaxListingBatch = 37 });
        List<RawEntry> raw = await ListRawAsync(client, "/");
        List<string> names = [.. raw.Select(e => Convert.ToHexString(e.Name)).Where(n => n is not ("2E" or "2E2E"))];
        Assert.Equal(800, names.Count);
        Assert.Equal(expected, names.ToHashSet(StringComparer.Ordinal));
        foreach (RawEntry entry in raw.Where(e => e.Name.Length > 4))
        {
            int i = int.Parse(Encoding.Latin1.GetString(entry.Name).AsSpan(entry.Name[0] == (byte)'g' ? 5 : 4, 4), System.Globalization.CultureInfo.InvariantCulture);
            Assert.Equal(entry.Name[0] == (byte)'g' ? i % 7 : i % 5, entry.Attributes.Size);
            Assert.Equal(entry.Name[0] == (byte)'g', Utf8.IsValid(entry.Name));
        }
    }

    [Fact]
    public async Task A_listing_handle_lets_go_of_its_directory_on_close_and_at_the_end_of_the_session()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Needs /proc.");
        Directory.CreateDirectory(_sandbox.InRoot("listed"));
        string real = _sandbox.InRoot("listed");
        int Open() => new DirectoryInfo("/proc/self/fd").EnumerateFileSystemInfos().Count(f => f.LinkTarget == real);

        SftpServerHarness client = await StartAsync(Options);
        byte[] closed = (await client.RequestAsync(SftpMessage.OpenDir, Path("listed"))).Handle;
        Assert.Equal(1, Open());
        Assert.Equal(Ok, (await client.CloseAsync(closed)).Status);
        Assert.Equal(0, Open());

        _ = (await client.RequestAsync(SftpMessage.OpenDir, Path("listed"))).Handle;
        _ = (await client.RequestAsync(SftpMessage.OpenDir, Path("listed"))).Handle;
        Assert.Equal(2, Open());
        Assert.Equal(0, await client.CloseStreamAsync());
        Assert.Equal(0, Open());
        await client.DisposeAsync();
    }

    private static bool Is(byte[] name, byte[] expected) => name.AsSpan().SequenceEqual(expected);

    private sealed record RawEntry(byte[] Name, byte[] LongName, SftpAttributes Attributes);
}

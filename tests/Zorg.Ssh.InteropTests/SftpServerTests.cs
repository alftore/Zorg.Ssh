using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Sftp;

namespace Zorg.Ssh.InteropTests;

/// <summary>Real clients against <see cref="SftpServer"/>: OpenSSH <c>sftp</c> in batch mode, our own client, and Paramiko.</summary>
public sealed class SftpServerTests : IDisposable
{
    private const string Secret = "TOP-SECRET-CONTENT";
    private const int RelayConnections = 3;

    private const string ParamikoScript = """
        import io, sys, paramiko

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(sys.argv[1], port=int(sys.argv[2]), username="alice", password="pw", look_for_keys=False, allow_agent=False)
        sftp = client.open_sftp()
        print("cwd", sftp.normalize("."))
        sftp.mkdir("made")
        data = bytes(range(256)) * 4096
        sftp.putfo(io.BytesIO(data), "made/data.bin")
        back = io.BytesIO()
        sftp.getfo("made/data.bin", back)
        print("same", back.getvalue() == data)
        print("size", sftp.stat("made/data.bin").st_size)
        sftp.rename("made/data.bin", "made/moved.bin")
        print("names", sorted(sftp.listdir("made")))
        try:
            sftp.stat("../secret.txt")
            print("escaped")
        except IOError as error:
            print("refused", type(error).__name__)
        try:
            sftp.open("out/secret.txt").read()
            print("escaped")
        except IOError as error:
            print("refused", type(error).__name__)
        sftp.remove("made/moved.bin")
        sftp.rmdir("made")
        sftp.close()
        client.close()
        print("done")
        """;

    private readonly string _base = Directory.CreateTempSubdirectory("zorg-sftp-server").FullName;
    private readonly SshHostKey _hostKey = SshHostKey.GenerateEd25519();

    public SftpServerTests()
    {
        Directory.CreateDirectory(Root);
        Directory.CreateDirectory(Outside);
        Directory.CreateDirectory(Local);
        File.WriteAllText(Path.Combine(Outside, "secret.txt"), Secret);
        File.WriteAllText(Path.Combine(_base, "secret.txt"), Secret);
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private string Root => Path.Combine(_base, "root");

    private string Outside => Path.Combine(_base, "outside");

    private string Local => Path.Combine(_base, "local");

    public void Dispose()
    {
        _hostKey.Dispose();

        // By hand, because a recursive delete refuses a junction.
        string link = Path.Combine(Root, "out");
        if (new FileInfo(link).LinkTarget is not null)
        {
            if (OperatingSystem.IsWindows())
            {
                Directory.Delete(link);
            }
            else
            {
                File.Delete(link);
            }
        }

        Directory.Delete(_base, recursive: true);
    }

    private static string RequireSftpClient()
    {
        string ssh = PeerTools.RequireSshClient();
        string sftp = Path.Combine(Path.GetDirectoryName(ssh)!, OperatingSystem.IsWindows() ? "sftp.exe" : "sftp");
        if (File.Exists(sftp))
        {
            return sftp;
        }

        if (PeerTools.PeersRequired)
        {
            throw new InvalidOperationException("CI and ZORG_REQUIRE_PEERS=1 need an OpenSSH sftp client.");
        }

        Assert.Skip("Needs an OpenSSH sftp client.");
        return string.Empty;
    }

    private static async Task<(int Code, string Output, string Error)> RunAsync(string program, IEnumerable<string> arguments, string? workingDirectory = null)
    {
        ProcessStartInfo start = new(program)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = workingDirectory ?? string.Empty,
        };
        foreach (string argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using Process process = Process.Start(start)!;
        Task<string> output = process.StandardOutput.ReadToEndAsync(Ct);
        Task<string> error = process.StandardError.ReadToEndAsync(Ct);
        process.StandardInput.Close();
        using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        limit.CancelAfter(TimeSpan.FromSeconds(120));
        await process.WaitForExitAsync(limit.Token);
        return (process.ExitCode, await output, await error);
    }

    private static void LinkOutside(string link, string target)
    {
        if (!OperatingSystem.IsWindows())
        {
            Directory.CreateSymbolicLink(link, target);
            return;
        }

        // A junction: it needs no privilege, and it's what a Windows attacker would hope to find.
        ProcessStartInfo start = new("cmd.exe") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (string argument in new[] { "/c", "mklink", "/J", link, target })
        {
            start.ArgumentList.Add(argument);
        }

        using Process process = Process.Start(start)!;
        process.WaitForExit();
        Assert.Equal(0, process.ExitCode);
    }

    private async Task<string> GenerateKeyAsync()
    {
        string ssh = PeerTools.RequireSshClient();
        string keygen = Path.Combine(Path.GetDirectoryName(ssh)!, OperatingSystem.IsWindows() ? "ssh-keygen.exe" : "ssh-keygen");
        string path = Path.Combine(_base, "user_key");
        (int code, _, _) = await RunAsync(keygen, ["-q", "-t", "ed25519", "-N", string.Empty, "-f", path]);
        Assert.Equal(0, code);
        return path;
    }

    private Task<SshServer> StartServerAsync(bool readOnly = false) => SshServer.StartAsync(
        new SshServerOptions
        {
            HostKeys = [_hostKey],
            MaxUnauthenticatedConnections = RelayConnections + 5,
            LoginGraceTime = TimeSpan.FromMinutes(2),
            PublicKeyHandler = (_, _) => ValueTask.FromResult(SshAuthDecision.Accept),
            PasswordHandler = (request, _) => ValueTask.FromResult(request.Password == "pw" ? SshAuthDecision.Accept : SshAuthDecision.Reject),
            SessionHandler = (session, ct) => session is { Kind: SshSessionKind.Subsystem, Command: "sftp" }
                ? SftpServer.ServeAsync(session, new SftpServerOptions { RootDirectory = Root, ReadOnly = readOnly }, ct)
                : Task.FromResult(1),
        },
        Ct);

    private async Task<(int Code, string Output, string Error)> BatchAsync(SshServer server, string keyPath, params string[] commands)
    {
        string sftp = RequireSftpClient();
        string batch = Path.Combine(_base, "batch.txt");
        await File.WriteAllTextAsync(batch, string.Join('\n', commands) + "\n", Ct);
        return await RunAsync(
            sftp,
            [
                "-F", "none", "-P", server.LocalEndPoint.Port.ToString(CultureInfo.InvariantCulture),
                "-i", keyPath, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                "-o", "LogLevel=ERROR", "-b", batch, "alice@127.0.0.1",
            ],
            Local);
    }

    private Task<SshClient> ConnectAsync(SshServer server) => SshClient.ConnectAsync(
        new SshClientOptions
        {
            Host = "127.0.0.1",
            Port = server.LocalEndPoint.Port,
            UserName = "alice",
            Credentials = [SshCredential.FromPassword("pw")],
            HostKeyPolicy = HostKeyPolicy.Fingerprint(_hostKey.Sha256Fingerprint),
        },
        Ct);

    private static string Hash(string path)
    {
        using FileStream stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private void AssertOutsideUntouched()
    {
        Assert.Equal(Secret, File.ReadAllText(Path.Combine(Outside, "secret.txt")));
        Assert.Equal(Secret, File.ReadAllText(Path.Combine(_base, "secret.txt")));
        Assert.Equal(["secret.txt"], Directory.GetFileSystemEntries(Outside).Select(Path.GetFileName));
    }

    [Fact]
    public async Task Sftp_moves_a_big_file_both_ways_intact()
    {
        string key = await GenerateKeyAsync();
        await using SshServer server = await StartServerAsync();
        string source = Path.Combine(Local, "big.bin");
        await File.WriteAllBytesAsync(source, RandomNumberGenerator.GetBytes(48 * 1024 * 1024 + 12345), Ct);

        (int code, string output, string error) = await BatchAsync(server, key, "put big.bin", "get big.bin back.bin");

        Assert.True(code == 0, output + error);
        Assert.Equal(Hash(source), Hash(Path.Combine(Root, "big.bin")));
        Assert.Equal(Hash(source), Hash(Path.Combine(Local, "back.bin")));
    }

    [Fact]
    public async Task Sftp_lists_renames_and_manages_directories()
    {
        string key = await GenerateKeyAsync();
        await using SshServer server = await StartServerAsync();
        await File.WriteAllTextAsync(Path.Combine(Local, "a.txt"), "hello", Ct);

        (int code, string output, string error) = await BatchAsync(
            server,
            key,
            "pwd",
            "mkdir dir",
            "cd dir",
            "pwd",
            "put a.txt",
            "ls -l",
            "rename a.txt b.txt",
            "ls",
            "df",
            "chmod 600 b.txt",
            "get -p b.txt copied.txt",
            "rm b.txt",
            "cd ..",
            "rmdir dir",
            "ls -la");

        Assert.True(code == 0, output + error);
        Assert.Contains("Remote working directory: /\n", output.ReplaceLineEndings("\n"));
        Assert.Contains("Remote working directory: /dir", output);
        Assert.Contains("a.txt", output);
        Assert.Contains("b.txt", output);
        Assert.Equal("hello", await File.ReadAllTextAsync(Path.Combine(Local, "copied.txt"), Ct));
        Assert.Empty(Directory.GetFileSystemEntries(Root));
    }

    [Fact]
    public async Task Sftp_escape_attempts_get_nothing_and_change_nothing()
    {
        string key = await GenerateKeyAsync();
        LinkOutside(Path.Combine(Root, "out"), Outside);
        await using SshServer server = await StartServerAsync();
        await File.WriteAllTextAsync(Path.Combine(Local, "evil.txt"), "evil", Ct);

        (int code, string output, string error) = await BatchAsync(
            server,
            key,
            "-get ../secret.txt stolen1",
            "-get ../../secret.txt stolen2",
            "-get /../outside/secret.txt stolen3",
            "-get out/secret.txt stolen4",
            "-cd ..",
            "pwd",
            "-cd out",
            "pwd",
            "-ls out",
            "-put evil.txt ../evil.txt",
            "-put evil.txt out/evil.txt",
            "-rm out/secret.txt",
            "-rename out/secret.txt taken",
            "-mkdir out/new",
            "-symlink ../secret.txt escape-link",
            "-symlink ../../outside/secret.txt escape-link2",
            "-get escape-link stolen6",
            "ls -la");

        Assert.True(code == 0, output + error);
        Assert.DoesNotContain("Remote working directory: /out", output);
        Assert.DoesNotContain(_base, output + error, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(_base.Replace('\\', '/'), output + error, StringComparison.OrdinalIgnoreCase);
        foreach (string file in Directory.GetFiles(Local))
        {
            Assert.DoesNotContain(Secret, await File.ReadAllTextAsync(file, Ct));
        }

        AssertOutsideUntouched();
        Assert.False(File.Exists(Path.Combine(_base, "evil.txt")));
        Assert.False(new FileInfo(Path.Combine(Root, "escape-link2")).Exists);
    }

    [Fact]
    public async Task Sftp_symlink_inside_the_root_works_where_links_can_be_made()
    {
        string key = await GenerateKeyAsync();
        await using SshServer server = await StartServerAsync();
        await File.WriteAllTextAsync(Path.Combine(Root, "real.txt"), "real", Ct);

        (int code, string output, string error) = await BatchAsync(server, key, "symlink real.txt link.txt", "get link.txt got.txt");
        if (code != 0 && OperatingSystem.IsWindows() && !File.Exists(Path.Combine(Root, "link.txt")))
        {
            Assert.SkipWhen(Environment.GetEnvironmentVariable("CI") != "true", "Needs the privilege to create symbolic links.");
        }

        Assert.True(code == 0, output + error);
        Assert.Equal("real", await File.ReadAllTextAsync(Path.Combine(Local, "got.txt"), Ct));
    }

    [Fact]
    public async Task Sftp_on_a_read_only_server_can_read_and_nothing_else()
    {
        string key = await GenerateKeyAsync();
        await File.WriteAllTextAsync(Path.Combine(Root, "keep.txt"), "keep", Ct);
        await File.WriteAllTextAsync(Path.Combine(Local, "new.txt"), "new", Ct);
        await using SshServer server = await StartServerAsync(readOnly: true);

        (int code, string output, string error) = await BatchAsync(
            server,
            key,
            "get keep.txt got.txt",
            "-put new.txt",
            "-rm keep.txt",
            "-mkdir d",
            "-rename keep.txt other.txt",
            "-symlink keep.txt l",
            "-chmod 600 keep.txt");

        Assert.True(code == 0, output + error);
        Assert.Equal("keep", await File.ReadAllTextAsync(Path.Combine(Local, "got.txt"), Ct));
        Assert.Equal(["keep.txt"], Directory.GetFileSystemEntries(Root).Select(Path.GetFileName));
    }

    [Fact]
    public async Task Our_client_works_over_a_real_connection()
    {
        LinkOutside(Path.Combine(Root, "out"), Outside);
        await using SshServer server = await StartServerAsync();
        await using SshClient client = await ConnectAsync(server);
        await using SftpClient sftp = await client.OpenSftpAsync(Ct);

        Assert.Equal("/", await sftp.GetFullPathAsync(".", Ct));
        Assert.True(sftp.ServerExtensions.ContainsKey("posix-rename@openssh.com"));

        byte[] data = RandomNumberGenerator.GetBytes(24 * 1024 * 1024 + 321);
        using (MemoryStream source = new(data))
        {
            await sftp.UploadFileAsync(source, "big.bin", Ct);
        }

        using MemoryStream received = new();
        await sftp.DownloadFileAsync("big.bin", received, Ct);
        Assert.Equal(SHA256.HashData(data), SHA256.HashData(received.ToArray()));
        Assert.Equal(SHA256.HashData(data), await File.ReadAllBytesAsync(Path.Combine(Root, "big.bin"), Ct).ContinueWith(t => SHA256.HashData(t.Result), Ct, TaskContinuationOptions.None, TaskScheduler.Default));

        await sftp.CreateDirectoryAsync("dir", Ct);
        await sftp.RenameAsync("big.bin", "dir/moved.bin", cancellationToken: Ct);
        List<string> names = [];
        await foreach (SftpEntry entry in sftp.ListDirectoryAsync("dir", Ct))
        {
            names.Add(entry.Name);
        }

        Assert.Equal([".", "..", "moved.bin"], names.Order(StringComparer.Ordinal));

        await Assert.ThrowsAsync<SftpFileNotFoundException>(() => sftp.ReadAllBytesAsync("../secret.txt", Ct));
        await Assert.ThrowsAsync<SftpPermissionDeniedException>(() => sftp.ReadAllBytesAsync("out/secret.txt", Ct));
        SftpPermissionDeniedException denied = await Assert.ThrowsAsync<SftpPermissionDeniedException>(() => sftp.WriteAllBytesAsync("out/evil", new byte[1], Ct));
        Assert.DoesNotContain(_base, denied.Message, StringComparison.OrdinalIgnoreCase);
        AssertOutsideUntouched();
    }

    [Fact]
    public async Task Sessions_of_one_connection_share_the_root_beside_other_kinds_of_session()
    {
        await using SshServer server = await StartServerAsync();
        await using SshClient client = await ConnectAsync(server);
        await using SftpClient first = await client.OpenSftpAsync(Ct);
        await using SftpClient second = await client.OpenSftpAsync(Ct);

        await first.WriteAllBytesAsync("a", new byte[] { 1 }, Ct);
        Assert.Equal(new byte[] { 1 }, await second.ReadAllBytesAsync("a", Ct));

        SshCommandResult notSftp = await client.ExecuteAsync("anything", Ct);
        Assert.Equal(1, notSftp.ExitCode);
    }

    [Fact]
    public async Task Paramiko_uses_the_server_and_cant_escape()
    {
        PeerTools.RequireContainers();
        LinkOutside(Path.Combine(Root, "out"), Outside);
        await using SshServer server = await StartServerAsync();
        string image = await SshPeerContainer.BuildImageAsync("zorg-ssh-test/python-ssh", Path.Combine(PeerTools.PeersPath, "python-ssh"), Ct);
        await using SshPeerContainer relay = await SshPeerContainer.StartAsync(image, ["python", "-u", "/app/relay.py"], cancellationToken: Ct);

        List<TcpClient> sockets = [];
        try
        {
            for (int i = 0; i < RelayConnections; i++)
            {
                TcpClient socket = new();
                await socket.ConnectAsync(relay.Host, relay.Port, Ct);
                sockets.Add(socket);
                _ = server.ServeStreamAsync(socket.GetStream(), Ct);
            }

            string output = await ContainerCli.RunAsync(TimeSpan.FromSeconds(60), Ct, "exec", relay.Id, "python", "-u", "-c", ParamikoScript, "127.0.0.1", "2222");
            Assert.Contains("cwd /", output);
            Assert.Contains("same True", output);
            Assert.Contains("size 1048576", output);
            Assert.Contains("names ['moved.bin']", output);
            Assert.DoesNotContain("escaped", output);
            Assert.Contains("refused FileNotFoundError", output);
            Assert.Contains("refused PermissionError", output);
            Assert.Contains("done", output);
            AssertOutsideUntouched();
        }
        finally
        {
            sockets.ForEach(static s => s.Dispose());
        }
    }
}

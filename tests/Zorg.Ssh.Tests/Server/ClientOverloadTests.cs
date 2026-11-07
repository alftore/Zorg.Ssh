using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Sftp;

namespace Zorg.Ssh.Tests.Server;

/// <summary>The options overloads of <see cref="SshClient.ExecuteAsync(string, SshProcessOptions, CancellationToken)"/> and <see cref="SshClient.OpenSftpAsync(SftpClientOptions, CancellationToken)"/>.</summary>
public sealed class ClientOverloadTests : IDisposable
{
    private readonly SshHostKey _hostKey = SshHostKey.GenerateEd25519();
    private readonly string _root = Directory.CreateTempSubdirectory("zorg-overloads-").FullName;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose()
    {
        _hostKey.Dispose();
        Directory.Delete(_root, recursive: true);
    }

    [Fact]
    public async Task ExecuteAsync_sends_the_environment_and_terminal_it_is_given()
    {
        await using SshServer server = await StartAsync(async (session, ct) =>
        {
            string text = $"{session.Environment.GetValueOrDefault("LANG")} {session.Pty?.Terminal} {session.Pty?.Columns}x{session.Pty?.Rows}";
            await session.Output.WriteAsync(Encoding.UTF8.GetBytes(text), ct);
            return 3;
        });
        await using SshClient client = await ConnectAsync(server);

        SshCommandResult plain = await client.ExecuteAsync("x", Ct);
        Assert.Equal("  x", plain.StandardOutput);

        SshProcessOptions options = new()
        {
            Environment = new Dictionary<string, string> { ["LANG"] = "C" },
            Pty = new SshPtyOptions { Terminal = "vt100", Columns = 100, Rows = 30 },
        };
        SshCommandResult result = await client.ExecuteAsync("x", options, Ct);
        Assert.Equal("C vt100 100x30", result.StandardOutput);
        Assert.Equal(3, result.ExitCode);

        Assert.Equal("  x", (await client.ExecuteAsync("x", null, Ct)).StandardOutput);
    }

    [Fact]
    public async Task OpenSftpAsync_applies_the_limits_it_is_given()
    {
        await File.WriteAllBytesAsync(Path.Combine(_root, "ten"), new byte[10], Ct);
        await using SshServer server = await StartAsync((session, ct) => SftpServer.ServeAsync(session, new SftpServerOptions { RootDirectory = _root }, ct));
        await using SshClient client = await ConnectAsync(server);

        await using (SftpClient defaults = await client.OpenSftpAsync(Ct))
        {
            Assert.Equal(10, (await defaults.ReadAllBytesAsync("ten", Ct)).Length);
        }

        await using SftpClient small = await client.OpenSftpAsync(new SftpClientOptions { MaxReadAllBytes = 4 }, Ct);
        SftpException ex = await Assert.ThrowsAsync<SftpException>(() => small.ReadAllBytesAsync("ten", Ct));
        Assert.Contains("SftpClientOptions.MaxReadAllBytes", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Sftp_limits_cant_be_negative()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new SftpClientOptions { MaxReadAllBytes = -1 });
        Assert.Throws<ArgumentOutOfRangeException>(() => new SftpClientOptions { MaxDirectoryEntries = -1 });
    }

    [Fact]
    public async Task Terminal_sizes_must_be_positive()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new SshPtyOptions { Columns = 0 });
        Assert.Throws<ArgumentOutOfRangeException>(() => new SshPtyOptions { Rows = -1 });

        await using SshServer server = await StartAsync(async (session, ct) =>
        {
            await session.Input.CopyToAsync(Stream.Null, ct);
            return 0;
        });
        await using SshClient client = await ConnectAsync(server);
        await using SshProcess shell = await client.StartShellAsync(null, Ct);

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => shell.ResizeAsync(0, 24, Ct));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => shell.ResizeAsync(80, -1, Ct));
        await shell.ResizeAsync(120, 40, Ct);
        await shell.StandardInput.DisposeAsync();
        await shell.WaitForExitAsync(Ct);
        Assert.Equal(0, shell.ExitCode);
    }

    [Fact]
    public void A_disconnect_reason_outside_the_list_keeps_its_number()
    {
        SshDisconnectedException known = new(SshDisconnectReason.TooManyConnections, "busy");
        Assert.Equal(12u, (uint)known.Reason);
        Assert.Contains("TooManyConnections", known.Message, StringComparison.Ordinal);

        SshDisconnectedException unknown = new((SshDisconnectReason)99, "odd");
        Assert.Equal(99u, (uint)unknown.Reason);
        Assert.Contains("reason 99", unknown.Message, StringComparison.Ordinal);
    }

    private Task<SshServer> StartAsync(Func<SshServerSession, CancellationToken, Task<int>> handler) => SshServer.StartAsync(
        new SshServerOptions
        {
            HostKeys = [_hostKey],
            PasswordHandler = (_, _) => ValueTask.FromResult(SshAuthDecision.Accept),
            SessionHandler = handler,
        },
        Ct);

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
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Zorg.Ssh.InteropTests;

/// <summary>
/// Independent SSH clients and audit tools against the public server (M4). They run in a container, and
/// reach the server through a relay there, which works even where containers can't connect out to the host.
/// </summary>
public sealed class ServerClientsTests : IDisposable
{
    private const int RelayConnections = 30;

    private readonly SshHostKey _hostKey = SshHostKey.GenerateEd25519();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => _hostKey.Dispose();

    private Task<SshServer> StartServerAsync() => SshServer.StartAsync(
        new SshServerOptions
        {
            HostKeys = [_hostKey],
            MaxUnauthenticatedConnections = RelayConnections + 5,
            LoginGraceTime = TimeSpan.FromMinutes(2),
            PasswordHandler = (request, _) => ValueTask.FromResult(
                request.UserName == "alice" && request.Password == "pw" ? SshAuthDecision.Accept : SshAuthDecision.Reject),
            SessionHandler = async (session, ct) =>
            {
                await session.Output.WriteAsync(Encoding.UTF8.GetBytes($"ran {session.Command}\n"), ct);
                return 3;
            },
        },
        Ct);

    private static async Task<SshPeerContainer> StartRelayAsync()
    {
        PeerTools.RequireContainers();
        string image = await SshPeerContainer.BuildImageAsync("zorg-ssh-test/python-ssh", Path.Combine(PeerTools.PeersPath, "python-ssh"), Ct);
        return await SshPeerContainer.StartAsync(image, ["python", "-u", "/app/relay.py"], cancellationToken: Ct);
    }

    /// <summary>Opens connections into the relay and serves each one, so that tools can connect to it.</summary>
    private static async Task<List<TcpClient>> FeedRelayAsync(SshServer server, SshPeerContainer relay)
    {
        List<TcpClient> sockets = [];
        for (int i = 0; i < RelayConnections; i++)
        {
            TcpClient socket = new();
            await socket.ConnectAsync(relay.Host, relay.Port, Ct);
            sockets.Add(socket);
            _ = server.ServeStreamAsync(socket.GetStream(), Ct);
        }

        return sockets;
    }

    [InteropTheory]
    [InlineData("client_paramiko.py")]
    [InlineData("client_asyncssh.py")]
    public async Task Python_clients_log_in_and_run_a_command(string script)
    {
        await using SshServer server = await StartServerAsync();
        await using SshPeerContainer relay = await StartRelayAsync();
        List<TcpClient> sockets = await FeedRelayAsync(server, relay);
        try
        {
            string output = await ContainerCli.RunAsync(TimeSpan.FromSeconds(60), Ct, "exec", relay.Id, "python", "-u", $"/app/{script}", "127.0.0.1", "2222");
            Assert.Contains("ran hello", output);
            Assert.Contains("exit 3", output);
        }
        finally
        {
            sockets.ForEach(static s => s.Dispose());
        }
    }

    [InteropFact]
    public async Task Ssh_audit_reports_no_failures_and_strict_KEX()
    {
        await using SshServer server = await StartServerAsync();
        await using SshPeerContainer relay = await StartRelayAsync();
        List<TcpClient> sockets = await FeedRelayAsync(server, relay);
        try
        {
            // ssh-audit exits non-zero when it has complaints, so the output is what counts.
            ContainerCli.CliResult result = await ContainerCli.TryRunAsync(
                TimeSpan.FromSeconds(120), Ct, "exec", relay.Id, "ssh-audit", "--no-colors", "-p", "2222", "127.0.0.1");
            await File.WriteAllTextAsync(Path.Combine(Path.GetTempPath(), "zorg-ssh-audit.txt"), result.Output + result.Error, Ct);
            Assert.Contains("kex-strict-s-v00@openssh.com", result.Output);
            Assert.DoesNotContain("(fail)", result.Output);
            Assert.DoesNotContain("vulnerable to the Terrapin", result.Output);
        }
        finally
        {
            sockets.ForEach(static s => s.Dispose());
        }
    }
}

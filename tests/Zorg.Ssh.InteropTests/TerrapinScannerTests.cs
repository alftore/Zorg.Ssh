using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Zorg.Ssh.InteropTests;

/// <summary>
/// Terrapin-Scanner (RUB-NDS, Apache-2.0) against the server. It is built from a pinned release inside the container
/// image (<c>Peers/terrapin-scanner</c>) and never touches the host. The scanner reaches the server through a relay in
/// its container, the way <see cref="ServerClientsTests"/> does for the other tools. It is one connection: the scanner
/// reads the algorithm lists and the strict key exchange markers and judges from those, so it needs no login.
/// </summary>
public sealed class TerrapinScannerTests : IDisposable
{
    private const int RelayConnections = 4;

    private readonly SshHostKey _hostKey = SshHostKey.GenerateEd25519();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => _hostKey.Dispose();

    [InteropFact]
    public async Task Terrapin_Scanner_reports_the_server_not_vulnerable_with_strict_key_exchange()
    {
        await using SshServer server = await SshServer.StartAsync(
            new SshServerOptions
            {
                HostKeys = [_hostKey],
                PasswordHandler = static (_, _) => ValueTask.FromResult(SshAuthDecision.Reject),
                SessionHandler = static (_, _) => Task.FromResult(0),
            },
            Ct);

        PeerTools.RequireContainers();
        string image = await SshPeerContainer.BuildImageAsync("zorg-ssh-test/terrapin-scanner", Path.Combine(PeerTools.PeersPath, "terrapin-scanner"), Ct);
        await using SshPeerContainer relay = await SshPeerContainer.StartAsync(image, cancellationToken: Ct);

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

            ContainerCli.CliResult result = await ContainerCli.TryRunAsync(
                TimeSpan.FromSeconds(60), Ct, "exec", relay.Id, "terrapin-scanner", "--connect", "127.0.0.1:2222", "--json", "--no-color");
            await File.WriteAllTextAsync(Path.Combine(Path.GetTempPath(), "zorg-terrapin-scanner.txt"), result.Output + result.Error, Ct);
            Assert.True(result.ExitCode == 0, $"terrapin-scanner exited {result.ExitCode}: {result.Output} {result.Error}");

            using JsonDocument report = JsonDocument.Parse(result.Output);
            JsonElement root = report.RootElement;
            Assert.True(root.GetProperty("IsServer").GetBoolean(), result.Output);
            Assert.StartsWith("SSH-2.0-", root.GetProperty("Banner").GetString(), StringComparison.Ordinal);

            // The vulnerability needs ChaCha20-Poly1305 or CBC with EtM and no strict key exchange on both sides.
            // This server offers the first, so strict key exchange is what makes it safe, and the scanner must see it.
            Assert.True(root.GetProperty("SupportsStrictKex").GetBoolean(), result.Output);
            Assert.False(root.GetProperty("SupportsCbcEtm").GetBoolean(), result.Output);
            Assert.False(root.GetProperty("Vulnerable").GetBoolean(), result.Output);
        }
        finally
        {
            sockets.ForEach(static s => s.Dispose());
        }
    }
}

using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Zorg.Ssh.Crypto;

namespace Zorg.Ssh.AotSmoke;

/// <summary>
/// <see cref="SshAlgorithms.LegacyUnsafe"/> under Native AOT: one in-memory login per finite-field group, each with an
/// <c>ssh-rsa</c> host key and a SHA-1 or encrypt-and-MAC MAC. Trimming keeps the legacy code only when something reaches
/// it, which this does, so this proves the published code runs: the modular exponentiation, RSA with SHA-1, and HMAC-SHA-1.
/// </summary>
internal static class LegacySmoke
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(60);

    public static async Task RunAsync(Action<string, bool> check)
    {
        (string Kex, string Mac)[] runs =
        [
            (LegacyAlgorithms.DhGroup14Sha256, LegacyAlgorithms.HmacSha1),
            (LegacyAlgorithms.DhGroup16Sha512, LegacyAlgorithms.HmacSha1Etm),
            (LegacyAlgorithms.DhGroup14Sha1, "hmac-sha2-256"),
        ];

        foreach ((string kex, string mac) in runs)
        {
            string name = $"legacy {kex}, ssh-rsa, aes128-ctr with {mac}";
            try
            {
                check(name, await LoginAsync(kex, mac));
            }
            catch (Exception ex) when (ex is SshException or IOException or OperationCanceledException or TimeoutException)
            {
                check($"{name} threw {ex.GetType().Name}: {ex.Message}", false);
            }
        }
    }

    private static async Task<bool> LoginAsync(string kex, string mac)
    {
        using CancellationTokenSource timeout = new(Limit);
        CancellationToken ct = timeout.Token;
        using SshHostKey hostKey = new(SshPrivateKey.GenerateRsa(2048));

        // The server offers Diffie-Hellman only when its list names it, so it names everything under test.
        await using SshServer server = await SshServer.StartAsync(
            new SshServerOptions
            {
                HostKeys = [hostKey],
                Algorithms = SshAlgorithms.LegacyUnsafe with { KeyExchange = [kex], HostKeys = [LegacyAlgorithms.RsaSha1], Ciphers = ["aes128-ctr"], Macs = [mac] },
                PasswordHandler = static (request, _) => ValueTask.FromResult(
                    request.Password == "smoke-password" ? SshAuthDecision.Accept : SshAuthDecision.Reject),
                SessionHandler = static async (session, token) =>
                {
                    await session.Output.WriteAsync(Encoding.ASCII.GetBytes($"ran: {session.Command}\n"), token);
                    return 3;
                },
            },
            ct);

        (Stream clientSide, Stream serverSide) = ConnectionSmoke.Duplex.CreatePair();
        Task serving = server.ServeStreamAsync(serverSide, ct);
        bool ok;
        await using (SshClient client = await SshClient.ConnectOverStreamAsync(
            clientSide,
            new SshClientOptions
            {
                Host = "smoke",
                UserName = "smoke",
                HostKeyPolicy = HostKeyPolicy.Fingerprint(hostKey.Sha256Fingerprint),
                Credentials = [SshCredential.FromPassword("smoke-password")],
                Algorithms = SshAlgorithms.LegacyUnsafe,
            },
            ct))
        {
            client.RequestRekey();
            SshCommandResult result = await client.ExecuteAsync("legacy", ct);
            ok = result.ExitCode == 3 && result.StandardOutput == "ran: legacy\n" && client.CompletedKeyExchanges >= 2;
        }

        await serving.WaitAsync(ct);
        return ok;
    }
}

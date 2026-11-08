using System;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.Keys;

namespace Zorg.Ssh.Tests.Server;

/// <summary>A4: a server's <c>Algorithms.HostKeys</c> also limits the signature algorithms it accepts from user keys, and what it advertises.</summary>
public sealed class UserKeyAlgorithmTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static async Task<(SshServer Server, SshHostKey HostKey)> StartAsync(SshAlgorithms algorithms, Action<string> seen)
    {
        SshHostKey hostKey = SshHostKey.GenerateEd25519();
        SshServer server = await SshServer.StartAsync(
            new SshServerOptions
            {
                HostKeys = [hostKey],
                Algorithms = algorithms,
                PublicKeyHandler = (request, _) =>
                {
                    seen(request.KeyType);
                    return ValueTask.FromResult(SshAuthDecision.Accept);
                },
                SessionHandler = static (_, _) => Task.FromResult(0),
            },
            Ct);
        return (server, hostKey);
    }

    private static SshClientOptions Options(SshServer server, SshHostKey hostKey, SshPrivateKey userKey) => new()
    {
        Host = "127.0.0.1",
        Port = server.LocalEndPoint.Port,
        UserName = "alice",
        Credentials = [new PrivateKeyCredential(() => userKey, ownsKey: false)],
        HostKeyPolicy = HostKeyPolicy.Fingerprint(hostKey.Sha256Fingerprint),
    };

    [Fact]
    public async Task A4_an_rsa_user_key_is_refused_when_HostKeys_names_no_rsa_algorithm()
    {
        SshPrivateKey rsa = SshPrivateKey.GenerateRsa(2048);
        int handlerCalls = 0;
        (SshServer server, SshHostKey hostKey) = await StartAsync(new SshAlgorithms { HostKeys = ["ssh-ed25519"] }, _ => handlerCalls++);
        await using (server)
        using (hostKey)
        {
            await Assert.ThrowsAsync<SshAuthenticationException>(() => SshClient.ConnectAsync(Options(server, hostKey, rsa), Ct));
            Assert.Equal(0, handlerCalls);
        }
    }

    [Fact]
    public async Task A4_an_ed25519_user_key_still_logs_in_when_HostKeys_is_narrowed()
    {
        SshPrivateKey ed = SshPrivateKey.GenerateEd25519();
        string? keyType = null;
        (SshServer server, SshHostKey hostKey) = await StartAsync(new SshAlgorithms { HostKeys = ["ssh-ed25519"] }, t => keyType = t);
        await using (server)
        using (hostKey)
        {
            await using SshClient client = await SshClient.ConnectAsync(Options(server, hostKey, ed), Ct);
            Assert.Equal("ssh-ed25519", keyType);
        }
    }

    [Fact]
    public async Task A4_an_rsa_user_key_logs_in_when_HostKeys_names_an_rsa_algorithm()
    {
        SshPrivateKey rsa = SshPrivateKey.GenerateRsa(2048);
        string? keyType = null;
        (SshServer server, SshHostKey hostKey) = await StartAsync(new SshAlgorithms { HostKeys = ["ssh-ed25519", "rsa-sha2-256"] }, t => keyType = t);
        await using (server)
        using (hostKey)
        {
            await using SshClient client = await SshClient.ConnectAsync(Options(server, hostKey, rsa), Ct);
            Assert.Equal("ssh-rsa", keyType);
        }
    }

    [Fact]
    public void A4_server_sig_algs_follows_HostKeys()
    {
        Assert.Equal(HostKeyAlgorithms.Default, SshAlgorithms.Default.ServerSignatureAlgorithms);
        Assert.Equal(["ssh-ed25519", "rsa-sha2-256"], new SshAlgorithms { HostKeys = ["rsa-sha2-256", "ssh-ed25519"] }.ServerSignatureAlgorithms);
        Assert.Equal(["ssh-ed25519"], new SshAlgorithms { HostKeys = ["ssh-ed25519"] }.ServerSignatureAlgorithms);
        Assert.Contains("ssh-rsa", SshAlgorithms.LegacyUnsafe.ServerSignatureAlgorithms);
    }
}

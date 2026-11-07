using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Zorg.Ssh.Tests.Server;

/// <summary><see cref="SshClient.HostKey"/>: the key the policy accepted, the same after a rekey, and each client's own.</summary>
public sealed class ClientHostKeyTests : IDisposable
{
    private readonly SshHostKey _hostKey = SshHostKey.GenerateEd25519();
    private readonly SshHostKey _innerKey = SshHostKey.GenerateEd25519();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose()
    {
        _hostKey.Dispose();
        _innerKey.Dispose();
    }

    private static Task<SshServer> StartAsync(SshHostKey key) => SshServer.StartAsync(
        new SshServerOptions
        {
            HostKeys = [key],
            PasswordHandler = static (_, _) => ValueTask.FromResult(SshAuthDecision.Accept),
            SessionHandler = static (_, _) => Task.FromResult(0),
            DirectTcpHandler = static (_, _) => ValueTask.FromResult(SshForwardDecision.Allow),
        },
        Ct);

    private static SshClientOptions Options(SshServer server, HostKeyPolicy policy) => new()
    {
        Host = "127.0.0.1",
        Port = server.LocalEndPoint.Port,
        UserName = "alice",
        Credentials = [SshCredential.FromPassword("pw")],
        HostKeyPolicy = policy,
    };

    private static string OpenSshForm(SshHostKey key) => $"{key.Key.PublicKey.KeyType} {Convert.ToBase64String(key.Key.PublicKey.Blob.Span)}";

    [Fact]
    public async Task HostKey_is_what_the_policy_was_shown_and_accepted()
    {
        await using SshServer server = await StartAsync(_hostKey);
        SshHostKeyInfo? seen = null;
        HostKeyPolicy policy = HostKeyPolicy.Custom((key, _) =>
        {
            seen = key;
            return ValueTask.FromResult(true);
        });

        await using SshClient client = await SshClient.ConnectAsync(Options(server, policy), Ct);

        Assert.NotNull(seen);
        Assert.Equal(seen, client.HostKey);
        Assert.Equal("127.0.0.1", client.HostKey.Host);
        Assert.Equal(server.LocalEndPoint.Port, client.HostKey.Port);
        Assert.Equal("ssh-ed25519", client.HostKey.KeyType);
        Assert.Equal(_hostKey.Sha256Fingerprint, client.HostKey.Sha256Fingerprint);
        Assert.Equal(OpenSshForm(_hostKey), client.HostKey.PublicKey);
    }

    [Fact]
    public async Task HostKey_is_set_whatever_the_policy()
    {
        await using SshServer server = await StartAsync(_hostKey);

        await using SshClient pinned = await SshClient.ConnectAsync(Options(server, HostKeyPolicy.Fingerprint(_hostKey.Sha256Fingerprint)), Ct);
        await using SshClient unverified = await SshClient.ConnectAsync(Options(server, HostKeyPolicy.AcceptAnyUnsafe()), Ct);

        Assert.Equal(_hostKey.Sha256Fingerprint, pinned.HostKey.Sha256Fingerprint);
        Assert.Equal(pinned.HostKey, unverified.HostKey);
    }

    [Fact]
    public async Task HostKey_stays_the_same_after_rekeys()
    {
        await using SshServer server = await StartAsync(_hostKey);
        await using SshClient client = await SshClient.ConnectAsync(Options(server, HostKeyPolicy.Fingerprint(_hostKey.Sha256Fingerprint)), Ct);
        SshHostKeyInfo before = client.HostKey;

        for (int i = 0; i < 3; i++)
        {
            int done = client.CompletedKeyExchanges;
            client.RequestRekey();
            Assert.Equal(0, (await client.ExecuteAsync("x", Ct)).ExitCode);
            using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(Ct);
            limit.CancelAfter(TimeSpan.FromSeconds(20));
            while (client.CompletedKeyExchanges <= done)
            {
                await Task.Delay(5, limit.Token);
            }
        }

        Assert.Equal(4, client.CompletedKeyExchanges);
        Assert.Same(before, client.HostKey);
        Assert.Equal(_hostKey.Sha256Fingerprint, client.HostKey.Sha256Fingerprint);
    }

    [Fact]
    public async Task Over_a_stream_HostKey_carries_the_host_and_port_from_the_options()
    {
        await using SshServer server = await StartAsync(_hostKey);
        using TcpClient tcp = new();
        await tcp.ConnectAsync(server.LocalEndPoint, Ct);
        SshClientOptions options = Options(server, HostKeyPolicy.Fingerprint(_hostKey.Sha256Fingerprint)) with { Host = "alias.example", Port = 2200 };

        await using SshClient client = await SshClient.ConnectOverStreamAsync(tcp.GetStream(), options, Ct);

        Assert.Equal("alias.example", client.HostKey.Host);
        Assert.Equal(2200, client.HostKey.Port);
        Assert.Equal(_hostKey.Sha256Fingerprint, client.HostKey.Sha256Fingerprint);
    }

    [Fact]
    public async Task Through_a_jump_host_each_client_has_its_own_servers_key()
    {
        await using SshServer bastionServer = await StartAsync(_hostKey);
        await using SshServer innerServer = await StartAsync(_innerKey);
        await using SshClient bastion = await SshClient.ConnectAsync(Options(bastionServer, HostKeyPolicy.Fingerprint(_hostKey.Sha256Fingerprint)), Ct);

        await using SshClient inner = await SshClient.ConnectAsync(
            Options(innerServer, HostKeyPolicy.Fingerprint(_innerKey.Sha256Fingerprint)) with { JumpHost = bastion },
            Ct);

        Assert.Equal(_hostKey.Sha256Fingerprint, bastion.HostKey.Sha256Fingerprint);
        Assert.Equal(bastionServer.LocalEndPoint.Port, bastion.HostKey.Port);
        Assert.Equal(_innerKey.Sha256Fingerprint, inner.HostKey.Sha256Fingerprint);
        Assert.Equal(OpenSshForm(_innerKey), inner.HostKey.PublicKey);
        Assert.Equal(innerServer.LocalEndPoint.Port, inner.HostKey.Port);
        Assert.Equal(0, (await inner.ExecuteAsync("x", Ct)).ExitCode);
    }
}

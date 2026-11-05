using System;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Zorg.Ssh.Tests.Server;

public sealed class AlgorithmOptionsTests : IDisposable
{
    private readonly SshHostKey _hostKey = SshHostKey.GenerateEd25519();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => _hostKey.Dispose();

    private SshServerOptions ServerOptions(SshAlgorithms? algorithms = null) => new()
    {
        HostKeys = [_hostKey],
        Algorithms = algorithms ?? SshAlgorithms.Default,
        PasswordHandler = (_, _) => ValueTask.FromResult(SshAuthDecision.Accept),
        SessionHandler = (_, _) => Task.FromResult(0),
    };

    private SshClientOptions ClientOptions(SshServer server, SshAlgorithms? algorithms = null) => new()
    {
        Host = "127.0.0.1",
        Port = server.LocalEndPoint.Port,
        UserName = "alice",
        Credentials = [SshCredential.FromPassword("pw")],
        HostKeyPolicy = HostKeyPolicy.Fingerprint(_hostKey.Sha256Fingerprint),
        Algorithms = algorithms ?? SshAlgorithms.Default,
    };

    [Fact]
    public async Task A_pinned_cipher_is_used_end_to_end()
    {
        SshAlgorithms pinned = new() { Ciphers = ["aes128-ctr"], Macs = ["hmac-sha2-256-etm@openssh.com"], KeyExchange = ["curve25519-sha256"] };
        await using SshServer server = await SshServer.StartAsync(ServerOptions(pinned), Ct);
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server, pinned), Ct);
        Assert.Equal(0, (await client.ExecuteAsync("x", Ct)).ExitCode);
    }

    [Fact]
    public async Task Disjoint_choices_fail_with_both_lists()
    {
        await using SshServer server = await SshServer.StartAsync(ServerOptions(new SshAlgorithms { Ciphers = ["aes128-ctr"] }), Ct);
        SshNegotiationException ex = await Assert.ThrowsAsync<SshNegotiationException>(
            () => SshClient.ConnectAsync(ClientOptions(server, new SshAlgorithms { Ciphers = ["aes256-gcm@openssh.com"] }), Ct));
        Assert.Contains("aes128-ctr", ex.Message);
    }

    [Theory]
    [InlineData("3des-cbc")]
    [InlineData("none")]
    [InlineData("aes256-gcm")]
    public async Task An_unsupported_name_fails_at_once_and_names_the_choices(string cipher)
    {
        await using SshServer server = await SshServer.StartAsync(ServerOptions(), Ct);
        ArgumentException ex = await Assert.ThrowsAsync<ArgumentException>(
            () => SshClient.ConnectAsync(ClientOptions(server, new SshAlgorithms { Ciphers = [cipher] }), Ct));
        Assert.Contains("aes256-gcm@openssh.com", ex.Message);
    }

    [Fact]
    public async Task An_empty_list_is_refused()
    {
        await Assert.ThrowsAsync<ArgumentException>(() => SshServer.StartAsync(ServerOptions(new SshAlgorithms { Macs = [] }), Ct));
    }
}

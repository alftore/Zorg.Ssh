using System;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Tests.Fuzzing;
using Zorg.Ssh.Tests.Transport;

namespace Zorg.Ssh.Tests.Server;

/// <summary>What a server's handlers learn about the client's address, and what a host key check learns about the key.</summary>
public sealed class RemoteEndPointTests : IDisposable
{
    private readonly SshHostKey _hostKey = SshHostKey.GenerateEd25519();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => _hostKey.Dispose();

    [Fact]
    public async Task Auth_handlers_and_the_session_see_the_clients_address_and_port()
    {
        IPEndPoint? password = null;
        IPEndPoint? publicKey = null;
        IPEndPoint? session = null;
        await using SshServer server = await SshServer.StartAsync(
            new SshServerOptions
            {
                HostKeys = [_hostKey],
                PublicKeyHandler = (request, _) =>
                {
                    publicKey = request.RemoteEndPoint;
                    return ValueTask.FromResult(SshAuthDecision.Reject);
                },
                PasswordHandler = (request, _) =>
                {
                    password = request.RemoteEndPoint;
                    return ValueTask.FromResult(SshAuthDecision.Accept);
                },
                SessionHandler = (s, _) =>
                {
                    session = s.RemoteEndPoint;
                    return Task.FromResult(0);
                },
            },
            Ct);

        await using SshClient client = await SshClient.ConnectAsync(
            new SshClientOptions
            {
                Host = "127.0.0.1",
                Port = server.LocalEndPoint.Port,
                UserName = "alice",
                Credentials = [SshCredential.FromPrivateKey(FuzzKeys.Ed25519OpenSsh), SshCredential.FromPassword("pw")],
                HostKeyPolicy = HostKeyPolicy.Fingerprint(_hostKey.Sha256Fingerprint),
            },
            Ct);
        Assert.Equal(0, (await client.ExecuteAsync("x", Ct)).ExitCode);

        Assert.NotNull(password);
        Assert.True(IPAddress.IsLoopback(password.Address));
        Assert.NotEqual(0, password.Port);
        Assert.NotEqual(server.LocalEndPoint.Port, password.Port);
        Assert.Equal(password, publicKey);
        Assert.Equal(password, session);
    }

    [Fact]
    public async Task A_stream_connection_has_no_address()
    {
        bool sawPassword = false;
        IPEndPoint? session = IPEndPoint.Parse("192.0.2.1:1");
        await using SshServer server = await SshServer.StartAsync(
            new SshServerOptions
            {
                HostKeys = [_hostKey],
                PasswordHandler = (request, _) =>
                {
                    sawPassword = request.RemoteEndPoint is null;
                    return ValueTask.FromResult(SshAuthDecision.Accept);
                },
                SessionHandler = (s, _) =>
                {
                    session = s.RemoteEndPoint;
                    return Task.FromResult(0);
                },
            },
            Ct);

        (Stream clientSide, Stream serverSide) = DuplexStream.CreatePair();
        Task served = server.ServeStreamAsync(serverSide, Ct);
        await using (SshClient client = await SshClient.ConnectOverStreamAsync(
            clientSide,
            new SshClientOptions
            {
                Host = "in-memory",
                UserName = "alice",
                Credentials = [SshCredential.FromPassword("pw")],
                HostKeyPolicy = HostKeyPolicy.Fingerprint(_hostKey.Sha256Fingerprint),
            },
            Ct))
        {
            Assert.Equal(0, (await client.ExecuteAsync("x", Ct)).ExitCode);
        }

        await served.WaitAsync(TimeSpan.FromSeconds(30), Ct);
        Assert.True(sawPassword);
        Assert.Null(session);
    }

    [Fact]
    public async Task A_custom_host_key_check_gets_the_key_in_OpenSSH_form()
    {
        SshHostKeyInfo? seen = null;
        await using SshServer server = await SshServer.StartAsync(
            new SshServerOptions
            {
                HostKeys = [_hostKey],
                PasswordHandler = (_, _) => ValueTask.FromResult(SshAuthDecision.Accept),
                SessionHandler = (_, _) => Task.FromResult(0),
            },
            Ct);

        await using SshClient client = await SshClient.ConnectAsync(
            new SshClientOptions
            {
                Host = "127.0.0.1",
                Port = server.LocalEndPoint.Port,
                UserName = "alice",
                Credentials = [SshCredential.FromPassword("pw")],
                HostKeyPolicy = HostKeyPolicy.Custom((key, _) =>
                {
                    seen = key;
                    return ValueTask.FromResult(true);
                }),
            },
            Ct);

        Assert.NotNull(seen);
        string expected = $"ssh-ed25519 {Convert.ToBase64String(_hostKey.Key.PublicKey.Blob.Span)}";
        Assert.Equal(expected, seen.PublicKey);
        Assert.Equal("ssh-ed25519", seen.KeyType);
        Assert.Equal(_hostKey.Sha256Fingerprint, seen.Sha256Fingerprint);

        // The text is what a known_hosts line holds after the host name, so it loads as one.
        string path = Path.Combine(Path.GetTempPath(), $"zorg-tofu-{Guid.NewGuid():N}");
        try
        {
            await File.WriteAllTextAsync(path, $"[{seen.Host}]:{seen.Port} {seen.PublicKey}\n", Ct);
            Assert.True(await HostKeyPolicy.KnownHostsFile(path).CheckAsync(seen.Host, seen.Port, _hostKey.Key.PublicKey, Ct));
        }
        finally
        {
            File.Delete(path);
        }
    }
}

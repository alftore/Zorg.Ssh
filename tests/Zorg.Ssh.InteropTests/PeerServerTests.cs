using System;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Transport;

namespace Zorg.Ssh.InteropTests;

/// <summary>Our client role against real servers in containers (tier T2).</summary>
public class PeerServerTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public static TheoryData<string> Peers() => new("openssh-10", "openssh-7.4", "dropbear");

    public static TheoryData<string> Kex() => new(KeyExchangeCatalog.Default);

    public static TheoryData<string, string> Ciphers() => new()
    {
        { "aes256-gcm@openssh.com", "hmac-sha2-256-etm@openssh.com" },
        { "aes128-gcm@openssh.com", "hmac-sha2-256-etm@openssh.com" },
        { "chacha20-poly1305@openssh.com", "hmac-sha2-256-etm@openssh.com" },
        { "aes256-ctr", "hmac-sha2-512-etm@openssh.com" },
        { "aes128-ctr", "hmac-sha2-256-etm@openssh.com" },
    };

    [InteropTheory]
    [MemberData(nameof(Peers))]
    public async Task Our_client_reaches_auth_on_each_server(string peer)
    {
        await using SshPeerContainer container = await StartAsync(peer);
        await AssertReachesAuthAsync(container, new TransportOptions
        {
            Role = SshRole.Client,
            HostKeyValidator = static (_, _) => ValueTask.FromResult(true),
        });
    }

    [InteropTheory]
    [MemberData(nameof(Kex))]
    public async Task Our_client_completes_each_key_exchange_with_OpenSSH(string kex)
    {
        await using SshPeerContainer container = await StartAsync("openssh-10");
        await AssertReachesAuthAsync(container, new TransportOptions
        {
            Role = SshRole.Client,
            KexAlgorithms = [kex],
            HostKeyValidator = static (_, _) => ValueTask.FromResult(true),
        });
    }

    [InteropTheory]
    [MemberData(nameof(Ciphers))]
    public async Task Our_client_talks_each_cipher_with_OpenSSH(string cipher, string mac)
    {
        await using SshPeerContainer container = await StartAsync("openssh-10");
        await AssertReachesAuthAsync(container, new TransportOptions
        {
            Role = SshRole.Client,
            Ciphers = [cipher],
            Macs = [mac],
            HostKeyValidator = static (_, _) => ValueTask.FromResult(true),
        });
    }

    private static async Task<SshPeerContainer> StartAsync(string peer)
    {
        PeerTools.RequireContainers();
        string image = await SshPeerContainer.BuildImageAsync(
            $"zorg-ssh-test/{peer}",
            Path.Combine(PeerTools.PeersPath, peer),
            Ct);
        return await SshPeerContainer.StartAsync(image, cancellationToken: Ct);
    }

    private static async Task AssertReachesAuthAsync(SshPeerContainer container, TransportOptions options)
    {
        using TcpClient socket = new();
        await socket.ConnectAsync(container.Host, container.Port, Ct);
        await using SshTransport transport = await SshTransport.StartAsync(socket.GetStream(), options, Ct);
        await RequestAuthServiceAsync(transport);
        await AssertServiceAcceptedAsync(transport);
    }

    private static async Task RequestAuthServiceAsync(SshTransport transport)
    {
        ValueTask send;
        SshWriter writer = new();
        try
        {
            writer.WriteByte(MessageNumber.ServiceRequest);
            writer.WriteUtf8String("ssh-userauth");
            send = transport.SendAsync(writer.Written, Ct);
        }
        finally
        {
            writer.Dispose();
        }

        await send;
    }

    private static async Task AssertServiceAcceptedAsync(SshTransport transport)
    {
        ReadOnlyMemory<byte> reply = await transport.ReceiveAsync(Ct);
        Assert.Equal(MessageNumber.ServiceAccept, reply.Span[0]);
    }
}

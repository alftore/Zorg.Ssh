using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Transport;
using static Zorg.Ssh.Tests.Transport.TransportHarness;

namespace Zorg.Ssh.Tests.Transport;

public class TransportTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public static TheoryData<string> AllKex() => new(KeyExchangeCatalog.Default);

    public static TheoryData<string, string?> AllCiphers() => new()
    {
        { "aes256-gcm@openssh.com", null },
        { "aes128-gcm@openssh.com", null },
        { "chacha20-poly1305@openssh.com", null },
        { "aes256-ctr", "hmac-sha2-512-etm@openssh.com" },
        { "aes128-ctr", "hmac-sha2-256-etm@openssh.com" },
        { "aes256-ctr", "hmac-sha2-512" },
        { "aes128-ctr", "hmac-sha2-256" },
    };

    private static async Task AssertRoundTrip(SshTransport from, SshTransport to, byte marker)
    {
        byte[] payload = new byte[5000];
        payload[0] = MessageNumber.ChannelData;
        payload[1] = marker;
        await from.SendAsync(payload, Ct);
        ReadOnlyMemory<byte> received = await to.ReceiveAsync(Ct);
        Assert.Equal(payload, received.ToArray());
    }

    [Theory]
    [MemberData(nameof(AllKex))]
    public async Task Each_key_exchange_completes_and_both_sides_agree(string kex)
    {
        (SshTransport client, SshTransport server) = await ConnectAsync(ClientOptions(kex: [kex]), ServerOptions(kex: [kex]), Ct);
        await using (client)
        await using (server)
        {
            Assert.True(client.SessionId.Span.SequenceEqual(server.SessionId.Span));
            Assert.False(client.SessionId.IsEmpty);
            MarkConnected(client, server);
            await AssertRoundTrip(client, server, 1);
            await AssertRoundTrip(server, client, 2);
        }
    }

    [Theory]
    [MemberData(nameof(AllCiphers))]
    public async Task Each_cipher_carries_traffic_both_ways(string cipher, string? mac)
    {
        IReadOnlyList<string> macs = mac is null ? PacketCipherCatalog.DefaultMacs : [mac];
        (SshTransport client, SshTransport server) = await ConnectAsync(
            ClientOptions(ciphers: [cipher], macs: macs),
            ServerOptions(ciphers: [cipher], macs: macs),
            Ct);
        await using (client)
        await using (server)
        {
            MarkConnected(client, server);
            for (int i = 0; i < 50; i++)
            {
                await AssertRoundTrip(client, server, (byte)i);
                await AssertRoundTrip(server, client, (byte)i);
            }
        }
    }

    [Fact]
    public async Task Every_host_key_type_proves_itself()
    {
        using SshPrivateKey ecdsa = SshPrivateKey.GenerateEcdsa("ecdsa-sha2-nistp256");
        using SshPrivateKey rsa = SshPrivateKey.GenerateRsa(2048);
        foreach (SshPrivateKey key in new[] { ecdsa, rsa })
        {
            (SshTransport client, SshTransport server) = await ConnectAsync(ClientOptions(), ServerOptions(hostKeys: [key]), Ct);
            await using (client)
            await using (server)
            {
                Assert.True(client.PeerHostKey!.Blob.Span.SequenceEqual(key.PublicKey.Blob.Span));
            }
        }
    }

    [Fact]
    public async Task A_rejected_host_key_stops_the_connection()
    {
        (Stream a, Stream b) = DuplexStream.CreatePair();
        Task<SshTransport> serverTask = SshTransport.StartAsync(b, ServerOptions(), Ct);
        await Assert.ThrowsAsync<SshHostKeyException>(() => SshTransport.StartAsync(a, ClientOptions(accept: false), Ct));
        await Assert.ThrowsAnyAsync<SshException>(() => serverTask);
    }

    [Fact]
    public async Task No_common_cipher_names_both_lists()
    {
        (Stream a, Stream b) = DuplexStream.CreatePair();
        Task<SshTransport> serverTask = SshTransport.StartAsync(b, ServerOptions(ciphers: ["aes128-ctr"]), Ct);
        SshNegotiationException ex = await Assert.ThrowsAsync<SshNegotiationException>(
            () => SshTransport.StartAsync(a, ClientOptions(ciphers: ["aes256-gcm@openssh.com"]), Ct));
        Assert.Contains("aes128-ctr", ex.PeerAlgorithms);
        Assert.Contains("aes256-gcm@openssh.com", ex.LocalAlgorithms);
        Assert.Contains("aes128-ctr", ex.Message);
        await Assert.ThrowsAnyAsync<SshException>(() => serverTask);
    }

    [Fact]
    public async Task The_server_lists_its_signature_algorithms_in_EXT_INFO()
    {
        (SshTransport client, SshTransport server) = await ConnectAsync(ClientOptions(), ServerOptions(), Ct);
        await using (client)
        await using (server)
        {
            client.SetPhase(TransportPhase.AwaitService);
            server.SetPhase(TransportPhase.AwaitService);
            await server.SendAsync(new byte[] { MessageNumber.ServiceAccept }, Ct);
            await client.ReceiveAsync(Ct);
            Assert.True(client.PeerExtensions.ContainsKey("server-sig-algs"));
        }
    }

    // Go CVE-2025-22869: a peer that stalls key exchange must not make us buffer without limit.
    [Fact]
    public async Task Writers_wait_while_a_rekey_is_stalled_and_nothing_grows()
    {
        (SshTransport client, SshTransport server) = await ConnectAsync(ClientOptions(), ServerOptions(), Ct);
        await using (client)
        await using (server)
        {
            MarkConnected(client, server);
            client.RequestRekey();

            // The server's receive path never runs, so the exchange can't finish.
            int sent = 0;
            byte[] payload = new byte[1000];
            payload[0] = MessageNumber.ChannelData;
            using CancellationTokenSource stop = new(TimeSpan.FromMilliseconds(500));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            {
                while (true)
                {
                    await client.SendAsync(payload, stop.Token);
                    sent++;
                }
            });
            Assert.True(sent <= 64, $"{sent} packets were accepted while parked; the queue holds 64.");
        }
    }

    [Fact]
    public async Task Data_sent_during_a_rekey_arrives_after_it_finishes()
    {
        (SshTransport client, SshTransport server) = await ConnectAsync(ClientOptions(), ServerOptions(), Ct);
        await using (client)
        await using (server)
        {
            MarkConnected(client, server);
            client.RequestRekey();
            await client.SendAsync(new byte[] { MessageNumber.ChannelData, 7 }, Ct);
            Task<ReadOnlyMemory<byte>> clientRead = client.ReceiveAsync(Ct).AsTask();
            ReadOnlyMemory<byte> received = await server.ReceiveAsync(Ct);
            Assert.Equal(7, received.Span[1]);
            await server.SendAsync(new byte[] { MessageNumber.ChannelData, 8 }, Ct);
            Assert.Equal(8, (await clientRead).Span[1]);
        }
    }

    [Fact]
    public async Task Disconnect_from_the_peer_surfaces_a_sanitised_exception()
    {
        (SshTransport client, SshTransport server) = await ConnectAsync(ClientOptions(), ServerOptions(), Ct);
        await using (client)
        await using (server)
        {
            MarkConnected(client, server);
            SshWriter writer = new();
            writer.WriteByte(MessageNumber.Disconnect);
            writer.WriteUInt32(11);
            writer.WriteUtf8String("bye\r\nFAKE LOG LINE\u001b[31m" + new string('x', 5000));
            writer.WriteUInt32(0);
            byte[] payload = writer.ToArray();
            writer.Dispose();
            await server.SendAsync(payload, Ct);

            SshDisconnectedException ex = await Assert.ThrowsAsync<SshDisconnectedException>(async () => await client.ReceiveAsync(Ct));
            Assert.Equal(11u, ex.ReasonCode);
            Assert.DoesNotContain('\n', ex.Description);
            Assert.DoesNotContain('\u001b', ex.Description);
            Assert.True(ex.Description.Length <= 256);
        }
    }

    [Fact]
    public async Task After_a_failure_every_call_fails_at_once()
    {
        (SshTransport client, SshTransport server) = await ConnectAsync(ClientOptions(), ServerOptions(), Ct);
        await using (client)
        {
            MarkConnected(client, server);
            await server.DisposeAsync();
            await Assert.ThrowsAnyAsync<SshConnectionException>(async () => await client.ReceiveAsync(Ct));
            await Assert.ThrowsAnyAsync<SshConnectionException>(async () => await client.ReceiveAsync(Ct));
            await Assert.ThrowsAnyAsync<SshConnectionException>(async () => await client.SendAsync(new byte[] { 94 }, Ct));
        }
    }

    [Fact]
    public async Task Unassigned_messages_get_unimplemented_and_the_connection_survives()
    {
        (SshTransport client, SshTransport server) = await ConnectAsync(ClientOptions(), ServerOptions(), Ct);
        await using (client)
        await using (server)
        {
            MarkConnected(client, server);
            await client.SendAsync(new byte[] { 200 }, Ct);
            await client.SendAsync(new byte[] { MessageNumber.ChannelData, 3 }, Ct);
            Assert.Equal(3, (await server.ReceiveAsync(Ct)).Span[1]);

            // The UNIMPLEMENTED reply is consumed by the client without reaching the caller.
            await server.SendAsync(new byte[] { MessageNumber.ChannelData, 4 }, Ct);
            Assert.Equal(4, (await client.ReceiveAsync(Ct)).Span[1]);
        }
    }

    [Fact]
    public async Task A_silent_peer_times_out_during_the_handshake()
    {
        (Stream a, Stream _) = DuplexStream.CreatePair();
        TransportOptions options = new()
        {
            Role = SshRole.Client,
            HostKeyValidator = (_, _) => ValueTask.FromResult(true),
            HandshakeTimeout = TimeSpan.FromMilliseconds(200),
        };
        await Assert.ThrowsAsync<SshConnectionException>(() => SshTransport.StartAsync(a, options, Ct));
    }

    [Fact]
    public Task Options_without_a_host_key_check_are_refused()
    {
        (Stream a, Stream _) = DuplexStream.CreatePair();
        return Assert.ThrowsAsync<ArgumentException>(() => SshTransport.StartAsync(a, new TransportOptions { Role = SshRole.Client }, Ct));
    }
}

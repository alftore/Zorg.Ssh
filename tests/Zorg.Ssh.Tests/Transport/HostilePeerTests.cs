using System;
using System.Buffers.Binary;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Transport;
using static Zorg.Ssh.Tests.Transport.TransportHarness;

namespace Zorg.Ssh.Tests.Transport;

/// <summary>A scripted peer breaks a rule, and the transport must end the connection with an SSH exception.</summary>
public class HostilePeerTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>Starts a real transport against a raw peer, runs the script, and returns the failure.</summary>
    private static async Task<SshException> RunAsync(SshRole role, Func<RawPeer, Task> script)
    {
        (Stream ours, Stream theirs) = DuplexStream.CreatePair();
        TransportOptions options = role == SshRole.Client ? ClientOptions() : ServerOptions();
        Task<SshTransport> start = SshTransport.StartAsync(ours, options, Ct);
        await using RawPeer peer = new(theirs);
        await peer.ExchangeIdentificationAsync(Ct);
        await script(peer);
        SshException failure = await Assert.ThrowsAnyAsync<SshException>(async () => await start.WaitAsync(TimeSpan.FromSeconds(10), Ct));
        return failure;
    }

    private static SshRole PeerRole(SshRole ours) => ours == SshRole.Client ? SshRole.Server : SshRole.Client;

    // Terrapin: a message injected before KEXINIT shifts the sequence numbers.
    [Theory]
    [InlineData((int)SshRole.Client)]
    [InlineData((int)SshRole.Server)]
    public async Task Strict_KEX_rejects_a_KEXINIT_that_is_not_the_first_packet(int roleValue)
    {
        SshRole role = (SshRole)roleValue;
        SshException failure = await RunAsync(role, async peer =>
        {
            await peer.SendAsync([MessageNumber.Ignore, 0, 0, 0, 0], Ct);
            await peer.SendAsync(RawPeer.KexInitPayload(PeerRole(role), strict: true), Ct);
        });
        Assert.IsAssignableFrom<SshProtocolException>(failure);
    }

    // Erlang CVE-2025-46712.
    [Theory]
    [InlineData(MessageNumber.Ignore)]
    [InlineData(MessageNumber.Debug)]
    [InlineData(MessageNumber.Unimplemented)]
    [InlineData(MessageNumber.ExtInfo)]
    [InlineData(200)]
    public async Task Strict_KEX_rejects_optional_messages_after_KEXINIT(byte message)
    {
        SshException failure = await RunAsync(SshRole.Server, async peer =>
        {
            await peer.SendAsync(RawPeer.KexInitPayload(SshRole.Client, strict: true), Ct);
            await peer.SendAsync([message, 0, 0, 0, 0], Ct);
        });
        Assert.IsAssignableFrom<SshProtocolException>(failure);
    }

    // Erlang CVE-2025-32433.
    [Theory]
    [InlineData(MessageNumber.ChannelOpen)]
    [InlineData(MessageNumber.ChannelRequest)]
    [InlineData(MessageNumber.GlobalRequest)]
    [InlineData(MessageNumber.UserAuthRequest)]
    [InlineData(MessageNumber.ServiceRequest)]
    public async Task Messages_from_later_layers_during_the_handshake_end_the_connection(byte message)
    {
        SshException failure = await RunAsync(SshRole.Server, peer => peer.SendAsync([message, 0, 0, 0, 0], Ct));
        Assert.IsAssignableFrom<SshProtocolException>(failure);
    }

    [Fact]
    public async Task A_second_KEXINIT_ends_the_connection()
    {
        SshException failure = await RunAsync(SshRole.Server, async peer =>
        {
            byte[] init = RawPeer.KexInitPayload(SshRole.Client);
            await peer.SendAsync(init, Ct);
            await peer.SendAsync(init, Ct);
        });
        Assert.IsAssignableFrom<SshProtocolException>(failure);
    }

    [Fact]
    public async Task NEWKEYS_before_the_exchange_ends_the_connection()
    {
        SshException failure = await RunAsync(SshRole.Server, async peer =>
        {
            await peer.SendAsync(RawPeer.KexInitPayload(SshRole.Client), Ct);
            await peer.SendAsync([MessageNumber.NewKeys], Ct);
        });
        Assert.IsAssignableFrom<SshProtocolException>(failure);
    }

    [Fact]
    public async Task NEWKEYS_before_any_KEXINIT_ends_the_connection()
    {
        SshException failure = await RunAsync(SshRole.Client, peer => peer.SendAsync([MessageNumber.NewKeys], Ct));
        Assert.IsAssignableFrom<SshProtocolException>(failure);
    }

    [Theory]
    [InlineData((int)SshRole.Client, MessageNumber.KexEcdhInit)]
    [InlineData((int)SshRole.Server, MessageNumber.KexEcdhReply)]
    [InlineData((int)SshRole.Server, 40)]
    public async Task KEX_messages_for_the_wrong_role_end_the_connection(int roleValue, byte message)
    {
        SshRole role = (SshRole)roleValue;
        SshException failure = await RunAsync(role, async peer =>
        {
            await peer.SendAsync(RawPeer.KexInitPayload(PeerRole(role)), Ct);
            await peer.SendAsync([message, 0, 0, 0, 0], Ct);
        });
        Assert.IsAssignableFrom<SshProtocolException>(failure);
    }

    [Theory]
    [InlineData(0u)]
    [InlineData(3u)]
    [InlineData(uint.MaxValue)]
    [InlineData(0x7FFFFFFFu)]
    public async Task Hostile_packet_lengths_during_the_handshake_end_the_connection(uint length)
    {
        byte[] header = new byte[8];
        BinaryPrimitives.WriteUInt32BigEndian(header, length);
        SshException failure = await RunAsync(SshRole.Server, peer => peer.SendRawAsync(header, Ct));
        Assert.IsAssignableFrom<SshProtocolException>(failure);
    }

    [Fact]
    public async Task A_truncated_KEXINIT_ends_the_connection()
    {
        SshException failure = await RunAsync(SshRole.Server, peer => peer.SendAsync([MessageNumber.KexInit, 1, 2, 3], Ct));
        Assert.IsAssignableFrom<SshProtocolException>(failure);
    }

    [Fact]
    public async Task A_KEX_reply_with_garbage_ends_the_connection()
    {
        SshException failure = await RunAsync(SshRole.Client, async peer =>
        {
            await peer.SendAsync(RawPeer.KexInitPayload(SshRole.Server), Ct);
            await peer.SendAsync([MessageNumber.KexEcdhReply, 0xFF, 0xFF, 0xFF, 0xFF], Ct);
        });
        Assert.IsAssignableFrom<SshProtocolException>(failure);
    }

    [Fact]
    public async Task A_KEX_reply_with_a_bad_signature_is_a_host_key_failure()
    {
        using Zorg.Ssh.Crypto.KeyExchangeMethod method = Zorg.Ssh.Crypto.KeyExchangeCatalog.Create("curve25519-sha256")!;
        SshException failure = await RunAsync(SshRole.Client, async peer =>
        {
            await peer.SendAsync(RawPeer.KexInitPayload(SshRole.Server), Ct);
            byte[] init = await peer.ReceiveAsync(MessageNumber.KexEcdhInit, 0, Ct);
            byte[] clientPublic = init.AsSpan(5).ToArray();
            byte[] serverPublic = method.ServerRespond(clientPublic, out byte[] _);

            SshWriter writer = new();
            writer.WriteByte(MessageNumber.KexEcdhReply);
            writer.WriteBinary(HostKey.PublicKey.Blob.Span);
            writer.WriteBinary(serverPublic);
            writer.WriteBinary(HostKey.Sign("ssh-ed25519", "not the exchange hash"u8));
            byte[] reply = writer.ToArray();
            writer.Dispose();
            await peer.SendAsync(reply, Ct);
        });
        Assert.IsType<SshHostKeyException>(failure);
    }

    // libssh CVE-2025-8277 shape: a wrong guess drops exactly one packet, and the exchange still completes.
    [Fact]
    public async Task A_wrong_guess_drops_one_packet_and_a_second_stray_packet_is_refused()
    {
        SshException failure = await RunAsync(SshRole.Server, async peer =>
        {
            await peer.SendAsync(RawPeer.KexInitPayload(SshRole.Client, extraNames: true, follows: true), Ct);
            await peer.SendAsync([40, 1, 2, 3], Ct);
            await peer.SendAsync([41, 1, 2, 3], Ct);
        });
        Assert.IsAssignableFrom<SshProtocolException>(failure);
    }

    [Fact]
    public async Task A_peer_that_closes_during_the_handshake_is_a_connection_failure()
    {
        (Stream ours, Stream theirs) = DuplexStream.CreatePair();
        Task<SshTransport> start = SshTransport.StartAsync(ours, ServerOptions(), Ct);
        await theirs.DisposeAsync();
        await Assert.ThrowsAnyAsync<SshConnectionException>(async () => await start.WaitAsync(TimeSpan.FromSeconds(10), Ct));
    }

    // RFC 4253 section 7.1, enforced by the permission table in a live session with real keys.
    [Fact]
    public async Task Non_KEX_messages_after_the_peers_rekey_KEXINIT_end_the_connection()
    {
        (SshTransport client, SshTransport server) = await ConnectAsync(ClientOptions(), ServerOptions(), Ct);
        await using (client)
        await using (server)
        {
            MarkConnected(client, server);
            client.RequestRekey();
            client.SendIgnoringKexForTests([MessageNumber.ChannelData, 1]);
            await Assert.ThrowsAnyAsync<SshProtocolException>(async () => await server.ReceiveAsync(Ct));
        }
    }

    [Fact]
    public async Task Connection_messages_before_auth_end_a_live_session()
    {
        (SshTransport client, SshTransport server) = await ConnectAsync(ClientOptions(), ServerOptions(), Ct);
        await using (client)
        await using (server)
        {
            await client.SendAsync(new byte[] { MessageNumber.ChannelOpen, 0, 0 }, Ct);
            await Assert.ThrowsAnyAsync<SshProtocolException>(async () => await server.ReceiveAsync(Ct));
        }
    }

    [Fact]
    public async Task A_late_EXT_INFO_ends_the_connection()
    {
        (SshTransport client, SshTransport server) = await ConnectAsync(ClientOptions(), ServerOptions(), Ct);
        await using (client)
        await using (server)
        {
            MarkConnected(client, server);
            await server.SendAsync(new byte[] { MessageNumber.ChannelData }, Ct);
            await client.ReceiveAsync(Ct);
            await server.SendAsync(new byte[] { MessageNumber.ExtInfo, 0, 0, 0, 0 }, Ct);
            await Assert.ThrowsAnyAsync<SshProtocolException>(async () => await client.ReceiveAsync(Ct));
        }
    }
}

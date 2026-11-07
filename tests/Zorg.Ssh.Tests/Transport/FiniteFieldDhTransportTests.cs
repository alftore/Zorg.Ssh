using System;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.KeyExchange;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Tests.Fuzzing.Stateful;
using Zorg.Ssh.Transport;
using static Zorg.Ssh.Tests.Transport.TransportHarness;

namespace Zorg.Ssh.Tests.Transport;

/// <summary>
/// Finite-field Diffie-Hellman in the transport. It uses KEX messages 30 and 31, like ECDH, so the message policy and strict
/// KEX must behave exactly as they do for ECDH: these tests check that, and that hostile public values are refused.
/// </summary>
public class FiniteFieldDhTransportTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public static TheoryData<string> Names => new(LegacyAlgorithms.KeyExchange);

    private static TransportOptions Client(string kex, CaptureLoggerFactory? logs = null, KeyExchangeExtension? extension = null) => new()
    {
        Role = SshRole.Client,
        KexAlgorithms = [kex],
        KeyExchangeExtension = extension ?? FiniteFieldDhExtension.Instance,
        HandshakeTimeout = TimeSpan.FromSeconds(20),
        HostKeyValidator = (_, _) => ValueTask.FromResult(true),
        Logger = logs?.CreateLogger("client") ?? Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance,
    };

    private static TransportOptions Server(string kex) => new()
    {
        Role = SshRole.Server,
        KexAlgorithms = [kex],
        KeyExchangeExtension = FiniteFieldDhExtension.Instance,
        HostKeys = [HostKey],
        HandshakeTimeout = TimeSpan.FromSeconds(20),
    };

    [Theory]
    [MemberData(nameof(Names))]
    public async Task Each_exchange_completes_with_strict_KEX_rekeys_and_logs_a_warning(string kex)
    {
        CaptureLoggerFactory logs = new();
        (SshTransport client, SshTransport server) = await ConnectAsync(Client(kex, logs), Server(kex), Ct);
        await using (client)
        await using (server)
        {
            Assert.True(client.SessionId.Span.SequenceEqual(server.SessionId.Span));
            MarkConnected(client, server);
            await RoundTripAsync(client, server, 1);

            // The transport is pulled by its reader (T1), so both sides read while the rekey runs.
            client.RequestRekey();
            await client.SendAsync(Payload(2), Ct);
            Task<byte[]> atServer = ReceiveCopyAsync(server);
            Task<byte[]> atClient = ReceiveCopyAsync(client);
            Assert.Equal(Payload(2), await atServer);
            await server.SendAsync(Payload(3), Ct);
            Assert.Equal(Payload(3), await atClient);
            Assert.True(client.CompletedKeyExchanges >= 2);
        }

        Assert.Contains(logs.Entries, line => line.Contains($"kex={kex}", StringComparison.Ordinal) && line.Contains("strict=True", StringComparison.Ordinal));
        Assert.Contains(logs.Entries, line => line.StartsWith("[Warning]", StringComparison.Ordinal) && line.Contains(kex, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Without_the_extension_a_finite_field_name_cannot_run()
    {
        (Stream a, Stream b) = DuplexStream.CreatePair();
        Task<SshTransport> server = SshTransport.StartAsync(b, Server(LegacyAlgorithms.DhGroup14Sha256), Ct);
        TransportOptions client = new()
        {
            Role = SshRole.Client,
            KexAlgorithms = [LegacyAlgorithms.DhGroup14Sha256],
            HostKeyValidator = (_, _) => ValueTask.FromResult(true),
        };

        SshNegotiationException failure = await Assert.ThrowsAsync<SshNegotiationException>(() => SshTransport.StartAsync(a, client, Ct));

        Assert.Contains("isn't available", failure.Message, StringComparison.Ordinal);
        await Assert.ThrowsAnyAsync<SshException>(() => server.WaitAsync(TimeSpan.FromSeconds(10), Ct));
    }

    // Guarantee 1: messages 30 and 31 keep the roles and order they have for ECDH.
    [Theory]
    [InlineData((int)SshRole.Client, MessageNumber.KexEcdhInit)]
    [InlineData((int)SshRole.Server, MessageNumber.KexEcdhReply)]
    [InlineData((int)SshRole.Server, 32)]
    [InlineData((int)SshRole.Server, 34)]
    public async Task KEXDH_messages_for_the_wrong_role_end_the_connection(int roleValue, byte message)
    {
        SshRole role = (SshRole)roleValue;
        SshException failure = await RunAsync(role, async peer =>
        {
            await peer.SendAsync(KexInit(role == SshRole.Client ? SshRole.Server : SshRole.Client), Ct);
            await peer.SendAsync(Mpint(message, BigInteger.One << 100), Ct);
        });
        Assert.IsAssignableFrom<SshProtocolException>(failure);
    }

    // Terrapin: strict KEX still demands KEXINIT first, whatever the method.
    [Theory]
    [InlineData((int)SshRole.Client)]
    [InlineData((int)SshRole.Server)]
    public async Task Strict_KEX_still_rejects_a_KEXINIT_that_is_not_the_first_packet(int roleValue)
    {
        SshRole role = (SshRole)roleValue;
        SshException failure = await RunAsync(role, async peer =>
        {
            await peer.SendAsync([MessageNumber.Ignore, 0, 0, 0, 0], Ct);
            await peer.SendAsync(KexInit(role == SshRole.Client ? SshRole.Server : SshRole.Client), Ct);
        });
        Assert.IsAssignableFrom<SshProtocolException>(failure);
    }

    public static TheoryData<string> HostileValues()
    {
        BigInteger p = new(DiffieHellmanGroup.Group14.Prime, isUnsigned: true, isBigEndian: true);
        return [string.Empty, "01", Hex(p - 1), Hex(p), Hex(p + 12345), "80", Hex((BigInteger.One << 4096) + 3)];
    }

    [Theory]
    [MemberData(nameof(HostileValues))]
    public async Task A_server_refuses_a_hostile_client_value(string hex)
    {
        SshException failure = await RunAsync(SshRole.Server, async peer =>
        {
            await peer.SendAsync(KexInit(SshRole.Client), Ct);
            await peer.SendAsync(String(MessageNumber.KexEcdhInit, Convert.FromHexString(hex)), Ct);
        });
        Assert.IsType<SshProtocolException>(failure);
        Assert.Contains("Diffie-Hellman", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_huge_client_value_is_refused_without_work()
    {
        // 200 KB fits a packet but not the group: refused on its length.
        SshException failure = await RunAsync(SshRole.Server, async peer =>
        {
            await peer.SendAsync(KexInit(SshRole.Client), Ct);
            byte[] huge = new byte[200_000];
            huge[0] = 1;
            await peer.SendAsync(String(MessageNumber.KexEcdhInit, huge), Ct);
        });
        Assert.IsType<SshProtocolException>(failure);
    }

    [Theory]
    [MemberData(nameof(HostileValues))]
    public async Task A_client_refuses_a_hostile_server_value(string hex)
    {
        SshException failure = await RunAsync(SshRole.Client, async peer =>
        {
            await peer.SendAsync(KexInit(SshRole.Server), Ct);
            await peer.ReceiveAsync(MessageNumber.KexEcdhInit, 0, Ct);
            SshWriter writer = new();
            writer.WriteByte(MessageNumber.KexEcdhReply);
            writer.WriteBinary(HostKey.PublicKey.Blob.Span);
            writer.WriteBinary(Convert.FromHexString(hex));
            writer.WriteBinary(HostKey.Sign("ssh-ed25519", "anything"u8));
            byte[] reply = writer.ToArray();
            writer.Dispose();
            await peer.SendAsync(reply, Ct);
        });
        Assert.IsType<SshProtocolException>(failure);
    }

    [Fact]
    public async Task A_valid_value_with_a_bad_signature_is_a_host_key_failure()
    {
        using KeyExchangeMethod method = FiniteFieldDhExtension.Instance.Create(LegacyAlgorithms.DhGroup14Sha256, 32)!;
        SshException failure = await RunAsync(SshRole.Client, async peer =>
        {
            await peer.SendAsync(KexInit(SshRole.Server), Ct);
            byte[] init = await peer.ReceiveAsync(MessageNumber.KexEcdhInit, 0, Ct);
            SshReader reader = new(init);
            reader.ReadByte();
            byte[] e = reader.ReadBinary().ToArray();
            byte[] f = method.ServerRespond(e, out _);
            SshWriter writer = new();
            writer.WriteByte(MessageNumber.KexEcdhReply);
            writer.WriteBinary(HostKey.PublicKey.Blob.Span);
            writer.WriteBinary(f);
            writer.WriteBinary(HostKey.Sign("ssh-ed25519", "not the exchange hash"u8));
            byte[] reply = writer.ToArray();
            writer.Dispose();
            await peer.SendAsync(reply, Ct);
        });
        Assert.IsType<SshHostKeyException>(failure);
    }

    private static async Task<SshException> RunAsync(SshRole role, Func<RawPeer, Task> script)
    {
        (Stream ours, Stream theirs) = DuplexStream.CreatePair();
        TransportOptions options = role == SshRole.Client ? Client(LegacyAlgorithms.DhGroup14Sha256) : Server(LegacyAlgorithms.DhGroup14Sha256);
        Task<SshTransport> start = SshTransport.StartAsync(ours, options, Ct);
        await using RawPeer peer = new(theirs);
        await peer.ExchangeIdentificationAsync(Ct);
        await script(peer);
        return await Assert.ThrowsAnyAsync<SshException>(async () => await start.WaitAsync(TimeSpan.FromSeconds(10), Ct));
    }

    private static byte[] KexInit(SshRole role) => new KexInitMessage
    {
        KexAlgorithms = [LegacyAlgorithms.DhGroup14Sha256, role == SshRole.Client ? KexMarkers.StrictClientV00 : KexMarkers.StrictServerV00],
        HostKeyAlgorithms = ["ssh-ed25519"],
        CiphersClientToServer = ["aes128-ctr"],
        CiphersServerToClient = ["aes128-ctr"],
        MacsClientToServer = ["hmac-sha2-256"],
        MacsServerToClient = ["hmac-sha2-256"],
        CompressionClientToServer = ["none"],
        CompressionServerToClient = ["none"],
    }.Encode();

    private static byte[] Mpint(byte message, BigInteger value) => String(message, value.ToByteArray(isUnsigned: false, isBigEndian: true));

    private static byte[] String(byte message, ReadOnlySpan<byte> body)
    {
        SshWriter writer = new(body.Length + 8);
        try
        {
            writer.WriteByte(message);
            writer.WriteBinary(body);
            return writer.ToArray();
        }
        finally
        {
            writer.Dispose();
        }
    }

    private static string Hex(BigInteger value) => Convert.ToHexString(value.ToByteArray(isUnsigned: false, isBigEndian: true));

    private static byte[] Payload(byte marker)
    {
        byte[] payload = new byte[3000];
        payload[0] = MessageNumber.ChannelData;
        payload[1] = marker;
        return payload;
    }

    private static async Task<byte[]> ReceiveCopyAsync(SshTransport transport) => (await transport.ReceiveAsync(Ct)).ToArray();

    private static async Task RoundTripAsync(SshTransport from, SshTransport to, byte marker)
    {
        byte[] payload = Payload(marker);
        await from.SendAsync(payload, Ct);
        ReadOnlyMemory<byte> received = await to.ReceiveAsync(Ct);
        Assert.Equal(payload, received.ToArray());
    }
}

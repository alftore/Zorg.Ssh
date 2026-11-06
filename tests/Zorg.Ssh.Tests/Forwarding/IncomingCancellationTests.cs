using System;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Connection;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Tests.Transport;
using Zorg.Ssh.Transport;
using static Zorg.Ssh.Tests.Forwarding.ScriptedServer;

namespace Zorg.Ssh.Tests.Forwarding;

/// <summary>
/// Accepting or refusing a channel the peer opened, with a token that has ended. A cancelled send was never queued,
/// so the peer's open must still be answered, and the channel slot must come back.
/// </summary>
public sealed class IncomingCancellationTests
{
    private const uint ConnectFailed = 2;
    private const uint ResourceShortage = 4;

    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(20);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static byte[] DirectTcpOpen(uint senderChannel) => Message(w =>
    {
        w.Byte(MessageNumber.ChannelOpen);
        w.String("direct-tcpip");
        w.UInt32(senderChannel);
        w.UInt32(1024);
        w.UInt32(1024);
        w.String("example.com");
        w.UInt32(80);
        w.String("127.0.0.1");
        w.UInt32(1);
    });

    private static async Task<(SshConnection Server, SshTransport Peer)> StartAsync(int maxChannels)
    {
        (SshTransport peer, SshTransport serverTransport) = await TransportHarness.ConnectAsync(
            TransportHarness.ClientOptions(),
            TransportHarness.ServerOptions(),
            Ct);
        TransportHarness.MarkConnected(peer, serverTransport);
        SshConnection server = new(serverTransport, maxChannels)
        {
            AcceptIncomingChannels = true,
            AcceptDirectTcp = true,
        };
        server.Start();
        return (server, peer);
    }

    private static async Task<IncomingChannelOpen> OpenAsync(SshConnection server, SshTransport peer, uint senderChannel)
    {
        await peer.SendAsync(DirectTcpOpen(senderChannel), Ct);
        return await server.IncomingChannels.ReadAsync(Ct).AsTask().WaitAsync(Limit, Ct);
    }

    /// <summary>Reads until the open's answer, and returns the message number with the reason if it was a refusal.</summary>
    private static async Task<(byte Number, uint Reason)> AnswerAsync(SshTransport peer, uint senderChannel)
    {
        while (true)
        {
            ReadOnlyMemory<byte> message = await peer.ReceiveAsync(Ct).AsTask().WaitAsync(Limit, Ct);
            SshReader reader = new(message.Span);
            byte number = reader.ReadByte();
            if (number is not (MessageNumber.ChannelOpenConfirmation or MessageNumber.ChannelOpenFailure))
            {
                continue;
            }

            Assert.Equal(senderChannel, reader.ReadUInt32());
            return (number, number == MessageNumber.ChannelOpenFailure ? reader.ReadUInt32() : 0);
        }
    }

    [Fact]
    public async Task A_cancelled_accept_refuses_the_open_instead_of_leaving_the_peer_waiting()
    {
        (SshConnection server, SshTransport peer) = await StartAsync(maxChannels: 8);
        await using (server)
        await using (peer)
        {
            IncomingChannelOpen open = await OpenAsync(server, peer, 5);
            using CancellationTokenSource ended = new();
            await ended.CancelAsync();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => server.AcceptIncomingAsync(open, ended.Token));

            (byte number, uint reason) = await AnswerAsync(peer, 5);
            Assert.Equal(MessageNumber.ChannelOpenFailure, number);
            Assert.Equal(ConnectFailed, reason);
        }
    }

    [Fact]
    public async Task A_cancelled_accept_gives_the_channel_slot_back()
    {
        (SshConnection server, SshTransport peer) = await StartAsync(maxChannels: 1);
        await using (server)
        await using (peer)
        {
            IncomingChannelOpen first = await OpenAsync(server, peer, 5);
            using CancellationTokenSource ended = new();
            await ended.CancelAsync();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => server.AcceptIncomingAsync(first, ended.Token));
            await AnswerAsync(peer, 5);

            // What the server does when a direct-tcpip ends, however it ends.
            server.ReleaseIncomingSession();

            // The only slot is free again: a second open is confirmed, not refused for too many channels.
            IncomingChannelOpen second = await OpenAsync(server, peer, 6);
            SshChannel channel = await server.AcceptIncomingAsync(second, Ct);
            await using (channel)
            {
                (byte number, _) = await AnswerAsync(peer, 6);
                Assert.Equal(MessageNumber.ChannelOpenConfirmation, number);
            }
        }
    }

    [Fact]
    public async Task A_cancelled_refusal_still_reaches_the_peer_and_does_not_throw()
    {
        (SshConnection server, SshTransport peer) = await StartAsync(maxChannels: 8);
        await using (server)
        await using (peer)
        {
            IncomingChannelOpen open = await OpenAsync(server, peer, 5);
            using CancellationTokenSource ended = new();
            await ended.CancelAsync();

            await server.RefuseIncomingAsync(open, SshConnection.OpenFailureResourceShortage, "full", ended.Token);

            (byte number, uint reason) = await AnswerAsync(peer, 5);
            Assert.Equal(MessageNumber.ChannelOpenFailure, number);
            Assert.Equal(ResourceShortage, reason);
        }
    }

    [Fact]
    public async Task A_live_token_still_confirms_and_refuses_as_before()
    {
        (SshConnection server, SshTransport peer) = await StartAsync(maxChannels: 8);
        await using (server)
        await using (peer)
        {
            IncomingChannelOpen first = await OpenAsync(server, peer, 5);
            await using (await server.AcceptIncomingAsync(first, Ct))
            {
                Assert.Equal(MessageNumber.ChannelOpenConfirmation, (await AnswerAsync(peer, 5)).Number);
            }

            IncomingChannelOpen second = await OpenAsync(server, peer, 6);
            await server.RefuseIncomingAsync(second, SshConnection.OpenFailureConnectFailed, "no", Ct);
            Assert.Equal(ConnectFailed, (await AnswerAsync(peer, 6)).Reason);
        }
    }
}

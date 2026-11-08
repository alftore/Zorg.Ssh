using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Auth;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Tests.Transport;
using Zorg.Ssh.Transport;
using static Zorg.Ssh.Tests.Forwarding.ScriptedServer;

namespace Zorg.Ssh.Tests.Forwarding;

/// <summary>What the review of the forwarding code found: five defects, and two gaps in the tests.</summary>
public sealed class ForwardingReviewRegressionTests
{
    private const uint ResourceShortage = 4;

    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(30);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static uint OpenSender(byte[] message)
    {
        SshReader reader = new(message);
        reader.ReadByte();
        reader.ReadUtf8String();
        return reader.ReadUInt32();
    }

    private static byte[] Confirmation(uint channel, uint sender, uint window, uint maxPacket) =>
        Message(w =>
        {
            w.Byte(MessageNumber.ChannelOpenConfirmation);
            w.UInt32(channel);
            w.UInt32(sender);
            w.UInt32(window);
            w.UInt32(maxPacket);
        });

    private static ValueTask<SshAuthDecision> Accept(SshPasswordRequest request, CancellationToken cancellationToken) =>
        ValueTask.FromResult(SshAuthDecision.Accept);

    // Guarantee 3: the connection has ended, so nothing may go on waiting for it.
    [Fact]
    public async Task A_confirmation_with_a_zero_packet_size_fails_the_open()
    {
        (ScriptedServer server, SshClient client) = await ConnectAsync(Ct);
        await using (server)
        await using (client)
        {
            Task<Stream> open = client.OpenTcpStreamAsync("example.com", 80, CancellationToken.None);
            uint id = OpenSender(await server.ExpectAsync(MessageNumber.ChannelOpen, Ct));
            await server.SendAsync(Confirmation(id, 7, 1024, 0), Ct);
            await Assert.ThrowsAnyAsync<SshException>(() => open.WaitAsync(Limit, Ct));
        }
    }

    // Guarantee 3: Dns refuses this length with an ArgumentOutOfRangeException, which must not escape.
    [Fact]
    public async Task A_host_name_dns_refuses_is_an_ordinary_refusal()
    {
        using SshHostKey key = SshHostKey.GenerateEd25519();
        await using SshServer server = SshServer.Create(
            new SshServerOptions
            {
                HostKeys = [key],
                PasswordHandler = Accept,
                SessionHandler = static (_, _) => Task.FromResult(0),
                DirectTcpHandler = static (_, _) => ValueTask.FromResult(SshForwardDecision.Allow),
            });
        (Stream clientSide, Stream serverSide) = DuplexStream.CreatePair();
        Task serving = server.ServeStreamAsync(serverSide, Ct);
        SshClient client = await SshClient.ConnectOverStreamAsync(
            clientSide,
            new SshClientOptions
            {
                Host = "x",
                UserName = "alice",
                Credentials = [SshCredential.FromPassword("pw")],
                HostKeyPolicy = HostKeyPolicy.AcceptAnyUnsafe(),
            },
            Ct);

        await Assert.ThrowsAnyAsync<SshException>(
            () => client.OpenTcpStreamAsync(new string('a', 255), 80, Ct).WaitAsync(Limit, Ct));
        await client.DisposeAsync();
        await serving.WaitAsync(Limit, Ct);
    }

    // A relay frees its slot before its channel goes. An open crossing that CLOSE is refused, and only that open.
    [Fact]
    public async Task A_session_open_crossing_a_relays_close_is_refused_without_ending_the_connection()
    {
        // The reset comes after a pause. On Linux, a reset that beats the server's connect to the finish makes the connect
        // fail, so the server sends CHANNEL_OPEN_FAILURE and there is no relay and no CLOSE to cross.
        await using TcpService target = new(static async (stream, ct) =>
        {
            await Task.Delay(200, ct);
            stream.Socket.Close(0);
        });
        using SshHostKey key = SshHostKey.GenerateEd25519();
        await using SshServer server = await SshServer.StartAsync(
            new SshServerOptions
            {
                HostKeys = [key],
                PasswordHandler = Accept,
                SessionHandler = static (_, _) => Task.FromResult(0),
                DirectTcpHandler = static (_, _) => ValueTask.FromResult(SshForwardDecision.Allow),
                MaxSessionsPerConnection = 1,
            },
            Ct);
        TcpClient socket = new();
        await socket.ConnectAsync(server.LocalEndPoint, Ct);
        await using SshTransport transport = await SshTransport.StartAsync(socket.GetStream(), TransportHarness.ClientOptions(), Ct);
        await new ClientAuthenticator(transport, "alice", null).AuthenticateAsync([SshCredential.FromPassword("pw")], Ct);

        await transport.SendAsync(
            Message(w =>
            {
                w.Byte(MessageNumber.ChannelOpen);
                w.String("direct-tcpip");
                w.UInt32(1);
                w.UInt32(1 << 20);
                w.UInt32(32768);
                w.String("127.0.0.1");
                w.UInt32((uint)target.Port);
                w.String("127.0.0.1");
                w.UInt32(1);
            }),
            Ct);
        List<byte> seen = [];
        try
        {
            byte received;
            do
            {
                received = (await transport.ReceiveAsync(Ct).AsTask().WaitAsync(Limit, Ct)).Span[0];
                seen.Add(received);
            }
            while (received != MessageNumber.ChannelClose);
        }
        catch (TimeoutException)
        {
            Assert.Fail($"No CHANNEL_CLOSE arrived. The server sent message numbers: {string.Join(", ", seen)}.");
        }

        // The slot is freed just after the CLOSE goes out, and this test holds its own CLOSE back.
        await Task.Delay(300, Ct);
        await transport.SendAsync(
            Message(static w =>
            {
                w.Byte(MessageNumber.ChannelOpen);
                w.String("session");
                w.UInt32(2);
                w.UInt32(1 << 20);
                w.UInt32(32768);
            }),
            Ct);

        byte[] reply = (await transport.ReceiveAsync(Ct).AsTask().WaitAsync(Limit, Ct)).ToArray();
        Assert.Equal(MessageNumber.ChannelOpenFailure, reply[0]);
        SshReader reader = new(reply);
        reader.ReadByte();
        Assert.Equal(2u, reader.ReadUInt32());
        Assert.Equal(ResourceShortage, reader.ReadUInt32());
    }

    // The peer holds a relay and a slot until it hears CLOSE, so running out of time to queue it can't lose it.
    [Fact]
    public async Task A_close_that_times_out_behind_a_full_queue_is_still_sent()
    {
        (Stream clientSide, Stream serverSide) = DuplexStream.CreatePair();
        Task<SshTransport> serving = Task.Run(
            async () =>
            {
                SshTransport started = await SshTransport.StartAsync(serverSide, TransportHarness.ServerOptions(), Ct);
                await new ServerAuthenticator(started, new ServerAuthOptions { Password = static (_, _, _) => ValueTask.FromResult(AuthDecision.Accept) }).AuthenticateAsync(Ct);
                return started;
            },
            Ct);
        await using SshClient client = await SshClient.ConnectOverStreamAsync(
            clientSide,
            new SshClientOptions
            {
                Host = "x",
                UserName = "alice",
                Credentials = [SshCredential.FromPassword("pw")],
                HostKeyPolicy = HostKeyPolicy.AcceptAnyUnsafe(),
            },
            Ct);
        await using SshTransport transport = await serving;

        async Task<Stream> OpenAsync(string host, uint sender)
        {
            Task<Stream> open = client.OpenTcpStreamAsync(host, 1, Ct);
            byte[] message;
            do
            {
                message = (await transport.ReceiveAsync(Ct).AsTask().WaitAsync(Limit, Ct)).ToArray();
            }
            while (message[0] != MessageNumber.ChannelOpen);

            await transport.SendAsync(Confirmation(OpenSender(message), sender, 0x7FFFFFFF, 32768), Ct);
            return await open;
        }

        Stream busy = await OpenAsync("a", 100);
        Stream closing = await OpenAsync("b", 200);

        // A key exchange parks the send queue, and this side doesn't read, so the writer fills it.
        client.RequestRekey();
        using CancellationTokenSource stop = new();
        Task writer = Task.Run(
            async () =>
            {
                byte[] chunk = new byte[32768];
                try
                {
                    while (true)
                    {
                        await busy.WriteAsync(chunk, stop.Token);
                    }
                }
                catch (OperationCanceledException)
                {
                    // That's how it ends.
                }
            },
            Ct);
        await Task.Delay(500, Ct);
        await closing.DisposeAsync();
        await stop.CancelAsync();
        await writer;

        List<uint> closed = [];
        while (!closed.Contains(200))
        {
            byte[] message = (await transport.ReceiveAsync(Ct).AsTask().WaitAsync(Limit, Ct)).ToArray();
            if (message[0] == MessageNumber.ChannelClose)
            {
                SshReader reader = new(message);
                reader.ReadByte();
                closed.Add(reader.ReadUInt32());
            }
        }

        Assert.Single(closed, 200u);
    }

    // Nothing goes out for a channel after its CLOSE, not even a refusal.
    [Fact]
    public async Task A_request_that_crosses_our_close_gets_no_reply()
    {
        (ScriptedServer server, SshClient client) = await ConnectAsync(Ct);
        await using (server)
        await using (client)
        {
            Task<Stream> open = client.OpenTcpStreamAsync("example.com", 80, Ct);
            uint id = OpenSender(await server.ExpectAsync(MessageNumber.ChannelOpen, Ct));
            await server.SendAsync(Confirmation(id, 7, 1 << 20, 32768), Ct);
            Stream stream = await open;
            await stream.DisposeAsync();
            await server.ExpectAsync(MessageNumber.ChannelClose, Ct);

            await server.SendAsync(
                Message(w =>
                {
                    w.Byte(MessageNumber.ChannelRequest);
                    w.UInt32(id);
                    w.String("keepalive@openssh.com");
                    w.Bool(true);
                }),
                Ct);
            await server.SendAsync(
                Message(static w =>
                {
                    w.Byte(MessageNumber.GlobalRequest);
                    w.String("ping@zorg");
                    w.Bool(true);
                }),
                Ct);

            // Replies keep their order, so everything the request caused comes before this answer.
            byte number;
            do
            {
                number = (await server.NextAsync(Ct).WaitAsync(Limit, Ct))[0];
                Assert.NotEqual(MessageNumber.ChannelFailure, number);
            }
            while (number != MessageNumber.RequestFailure);
        }
    }

    [Fact]
    public async Task Data_then_eof_then_close_all_reach_a_slow_local_reader()
    {
        // A whole window, so the relay's socket can't take it all while the local reader is stopped.
        const int Chunks = 64;
        const int ChunkSize = 32768;
        TaskCompletionSource<long> total = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await using TcpService target = new(
            async (stream, ct) =>
            {
                // Reads nothing until the test lets it, which is after the channel has closed. No timing involved.
                await release.Task.WaitAsync(ct);
                byte[] buffer = new byte[65536];
                long sum = 0;
                int read;
                while ((read = await stream.ReadAsync(buffer, ct)) != 0)
                {
                    sum += read;
                }

                total.TrySetResult(sum);
            },
            receiveBufferSize: 4096);
        (ScriptedServer server, SshClient client) = await ConnectAsync(Ct);
        await using (server)
        await using (client)
        {
            Task<SshRemoteForward> requested = client.ForwardRemotePortAsync("127.0.0.1", 8000, "127.0.0.1", target.Port, Ct);
            await server.ExpectAsync(MessageNumber.GlobalRequest, Ct);
            await server.SendAsync([MessageNumber.RequestSuccess], Ct);
            await using SshRemoteForward forward = await requested;

            await server.SendAsync(ForwardedOpen(1, "127.0.0.1", 8000), Ct);
            (uint? refusal, uint channel) = await server.OpenReplyAsync(Ct);
            Assert.Null(refusal);

            byte[] chunk = new byte[ChunkSize];
            for (int i = 0; i < Chunks; i++)
            {
                await server.SendAsync(
                    Message(w =>
                    {
                        w.Byte(MessageNumber.ChannelData);
                        w.UInt32(channel);
                        w.Bytes(chunk);
                    }),
                    Ct);
            }

            await server.SendAsync(
                Message(w =>
                {
                    w.Byte(MessageNumber.ChannelEof);
                    w.UInt32(channel);
                }),
                Ct);
            await server.SendAsync(
                Message(w =>
                {
                    w.Byte(MessageNumber.ChannelClose);
                    w.UInt32(channel);
                }),
                Ct);

            // The client answers a CLOSE with its own once its channel has closed. The local side hasn't closed its
            // socket, and won't until it is released below, so the relay's upward half is still running when the
            // channel closes. The relay can only finish by draining after the close, whatever the socket buffers hold.
            await server.ExpectAsync(MessageNumber.ChannelClose, Ct);

            release.SetResult();
            Assert.Equal((long)Chunks * ChunkSize, await total.Task.WaitAsync(Limit, Ct));
        }
    }

    [Fact]
    public async Task The_connection_ending_fails_several_waiting_requests()
    {
        (ScriptedServer server, SshClient client) = await ConnectAsync(Ct);
        await using (client)
        {
            Task<SshRemoteForward>[] waiting =
            [
                .. Enumerable.Range(0, 3).Select(i => client.ForwardRemotePortAsync("127.0.0.1", 8000 + i, "127.0.0.1", 9, Ct)),
            ];
            for (int i = 0; i < waiting.Length; i++)
            {
                await server.ExpectAsync(MessageNumber.GlobalRequest, Ct);
            }

            await server.DisposeAsync();
            foreach (Task<SshRemoteForward> request in waiting)
            {
                await Assert.ThrowsAnyAsync<SshConnectionException>(() => request.WaitAsync(Limit, Ct));
            }
        }
    }
}

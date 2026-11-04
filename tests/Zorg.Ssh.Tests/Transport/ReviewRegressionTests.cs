using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Connection;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Transport;
using static Zorg.Ssh.Tests.Transport.TransportHarness;

namespace Zorg.Ssh.Tests.Transport;

/// <summary>Each test is a finding from the independent M1 review. F and S numbers refer to that review.</summary>
public class ReviewRegressionTests
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(20);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static async Task DrainAsync(SshTransport transport, Action<byte>? onMessage, CancellationToken stop)
    {
        try
        {
            while (true)
            {
                ReadOnlyMemory<byte> message = await transport.ReceiveAsync(stop);
                onMessage?.Invoke(message.Span[0]);
            }
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested)
        {
        }
    }

    private static async Task WaitForAsync(Func<bool> condition)
    {
        using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        limit.CancelAfter(Limit);
        while (!condition())
        {
            await Task.Delay(5, limit.Token);
        }
    }

    // F1: a peer that demands UNIMPLEMENTED replies and never reads them must not hang our receive path.
    [Fact]
    public async Task F1_a_flood_of_unknown_messages_from_a_peer_that_stops_reading_ends_the_connection()
    {
        (SshTransport client, SshTransport server) = await ConnectAsync(ClientOptions(), ServerOptions(), Ct);
        await using (client)
        await using (server)
        {
            MarkConnected(client, server);
            Task flood = Task.Run(
                async () =>
                {
                    try
                    {
                        for (int i = 0; i < 40_000; i++)
                        {
                            await client.SendAsync(new byte[] { 200 }, Ct);
                        }
                    }
                    catch (SshException)
                    {
                        // The server hung up, which is the point.
                    }
                },
                Ct);

            await Assert.ThrowsAnyAsync<SshException>(async () => await DrainNoStop(server).WaitAsync(Limit, Ct));
            await flood.WaitAsync(Limit, Ct);
        }

        static async Task DrainNoStop(SshTransport transport)
        {
            while (true)
            {
                await transport.ReceiveAsync(Ct);
            }
        }
    }

    // F2: a keepalive during an upload used to block the receive loop on a parked, full send queue, so the
    // peer's KEXINIT was never read and an honest connection died at the rekey timeout.
    [Fact]
    public async Task F2_a_request_during_a_parked_upload_cannot_deadlock_a_rekey()
    {
        (SshTransport client, SshTransport server) = await ConnectAsync(ClientOptions(), ServerOptions(), Ct);
        SshConnection connection = new(client);
        await using (connection)
        await using (server)
        {
            MarkConnected(client, server);
            connection.Start();
            client.RequestRekey();

            const int Packets = 200;
            byte[] data = new byte[1000];
            data[0] = 120; // In the connection range, and meaningless to the test server.
            Task upload = Task.Run(
                async () =>
                {
                    for (int i = 0; i < Packets; i++)
                    {
                        await client.SendAsync(data, Ct);
                    }
                },
                Ct);

            // The queue is full and parked by now. This needs a reply, which used to block the loop.
            await Task.Delay(100, Ct);
            SshWriter writer = new();
            writer.WriteByte(MessageNumber.GlobalRequest);
            writer.WriteUtf8String("keepalive@openssh.com");
            writer.WriteBoolean(true);
            byte[] keepalive = writer.ToArray();
            writer.Dispose();
            await server.SendAsync(keepalive, Ct);

            int received = 0;
            using CancellationTokenSource stop = CancellationTokenSource.CreateLinkedTokenSource(Ct);
            Task drain = DrainAsync(server, m => received += m == 120 ? 1 : 0, stop.Token);

            await upload.WaitAsync(Limit, Ct);
            await WaitForAsync(() => received == Packets);
            Assert.True(client.CompletedKeyExchanges >= 2);
            await stop.CancelAsync();
            await drain;
        }
    }

    // F3: our NEWKEYS could still be queued when the next rekey began, and writing it unparked that rekey.
    [Fact]
    public async Task F3_back_to_back_rekeys_never_let_data_follow_KEXINIT()
    {
        (SshTransport client, SshTransport server) = await ConnectAsync(ClientOptions(kex: ["curve25519-sha256"]), ServerOptions(kex: ["curve25519-sha256"]), Ct);
        await using (client)
        await using (server)
        {
            MarkConnected(client, server);
            using CancellationTokenSource stop = CancellationTokenSource.CreateLinkedTokenSource(Ct);
            int received = 0;
            Task c = DrainAsync(client, null, stop.Token);
            Task s = DrainAsync(server, _ => Interlocked.Increment(ref received), stop.Token);

            const int Rounds = 300;
            byte[] data = [MessageNumber.ChannelData, 1];
            for (int i = 0; i < Rounds; i++)
            {
                client.RequestRekey();
                await client.SendAsync(data, Ct);
            }

            await WaitForAsync(() => Volatile.Read(ref received) == Rounds);
            await stop.CancelAsync();
            await Task.WhenAll(c, s);
            Assert.True(client.CompletedKeyExchanges > 2);
        }
    }

    // F4: shutdown used to free KEX state under the receive path, so a slow host key check got a NullReferenceException.
    [Fact]
    public async Task F4_a_host_key_check_that_outlasts_the_timeout_gives_an_SSH_exception()
    {
        (Stream a, Stream b) = DuplexStream.CreatePair();
        Task<SshTransport> serverTask = SshTransport.StartAsync(b, ServerOptions(), Ct);
        TransportOptions options = new()
        {
            Role = SshRole.Client,
            HandshakeTimeout = TimeSpan.FromMilliseconds(200),
            HostKeyValidator = async (_, ct) =>
            {
                await Task.Delay(700, CancellationToken.None);
                return true;
            },
        };

        await Assert.ThrowsAnyAsync<SshException>(() => SshTransport.StartAsync(a, options, Ct));
        await Assert.ThrowsAnyAsync<SshException>(() => serverTask);
    }

    // F5: shutdown used to wait for the send loop before closing the stream, so a stubborn stream hung dispose.
    [Fact]
    public async Task F5_a_stream_that_ignores_cancellation_cannot_hang_dispose()
    {
        (Stream a, Stream b) = DuplexStream.CreatePair();
        (SshTransport client, SshTransport server) = (await SshTransport.StartAsync(new StubbornStream(a), ClientOptionsConcurrent(b, out Task<SshTransport> serverTask), Ct), await Task.FromResult<SshTransport>(null!));
        server = await serverTask;
        await using (server)
        {
            StubbornStream.Stall = true;
            try
            {
                await client.SendAsync(new byte[] { MessageNumber.ChannelData }, Ct);
                await client.DisposeAsync().AsTask().WaitAsync(Limit, Ct);
            }
            finally
            {
                StubbornStream.Stall = false;
            }
        }

        static TransportOptions ClientOptionsConcurrent(Stream serverStream, out Task<SshTransport> serverTask)
        {
            serverTask = SshTransport.StartAsync(serverStream, ServerOptions(), Ct);
            return ClientOptions();
        }
    }

    // F11: dispose used to drop what SendAsync had already accepted.
    [Fact]
    public async Task F11_messages_accepted_before_dispose_are_delivered()
    {
        (SshTransport client, SshTransport server) = await ConnectAsync(ClientOptions(), ServerOptions(), Ct);
        await using (server)
        {
            MarkConnected(client, server);
            for (byte i = 0; i < 20; i++)
            {
                await client.SendAsync(new byte[] { MessageNumber.ChannelData, i }, Ct);
            }

            await client.DisposeAsync();
            for (byte i = 0; i < 20; i++)
            {
                Assert.Equal(i, (await server.ReceiveAsync(Ct)).Span[1]);
            }

            await Assert.ThrowsAnyAsync<SshConnectionException>(async () => await server.ReceiveAsync(Ct));
        }
    }

    // F12: invisible and line-breaking characters could hide or forge text.
    [Theory]
    [InlineData(0x2028)]
    [InlineData(0x2029)]
    [InlineData(0x202E)]
    [InlineData(0x200B)]
    public async Task F12_invisible_characters_are_removed_from_disconnect_text(int hostile)
    {
        (SshTransport client, SshTransport server) = await ConnectAsync(ClientOptions(), ServerOptions(), Ct);
        await using (client)
        await using (server)
        {
            MarkConnected(client, server);
            SshWriter writer = new();
            writer.WriteByte(MessageNumber.Disconnect);
            writer.WriteUInt32(2);
            writer.WriteUtf8String($"a{(char)hostile}b");
            writer.WriteUInt32(0);
            byte[] payload = writer.ToArray();
            writer.Dispose();
            await server.SendAsync(payload, Ct);

            SshDisconnectedException ex = await Assert.ThrowsAsync<SshDisconnectedException>(async () => await client.ReceiveAsync(Ct));
            Assert.Equal("ab", ex.Description);
        }
    }

    [Fact]
    public void F12_a_negotiation_failure_message_stays_short_whatever_the_peer_sent()
    {
        string[] names = [.. Enumerable.Repeat(new string('x', 1000), 256)];
        SshNegotiationException ex = new("cipher", ["aes128-ctr"], names);
        Assert.True(ex.Message.Length < 4000, $"{ex.Message.Length} characters.");
        Assert.Equal(256, ex.PeerAlgorithms.Count);
    }

    // S1: each rekey costs a signature, so an anonymous peer can't ask for them for ever.
    [Fact]
    public async Task S1_rekeys_before_login_are_limited()
    {
        (SshTransport client, SshTransport server) = await ConnectAsync(ClientOptions(), ServerOptions(), Ct);
        await using (client)
        await using (server)
        {
            // The client believes it's logged in; the server knows it isn't.
            client.SetPhase(TransportPhase.Connected);
            using CancellationTokenSource stop = CancellationTokenSource.CreateLinkedTokenSource(Ct);
            Task c = Task.Run(
                async () =>
                {
                    try
                    {
                        await DrainAsync(client, null, stop.Token);
                    }
                    catch (SshException)
                    {
                    }
                },
                Ct);

            Task serverFailure = Assert.ThrowsAnyAsync<SshProtocolException>(async () =>
            {
                while (true)
                {
                    await server.ReceiveAsync(Ct);
                }
            });

            for (int i = 0; i < 10 && !serverFailure.IsCompleted; i++)
            {
                try
                {
                    int done = client.CompletedKeyExchanges;
                    client.RequestRekey();
                    await WaitForAsync(() => client.CompletedKeyExchanges > done || serverFailure.IsCompleted);
                }
                catch (SshException)
                {
                    break;
                }
            }

            await serverFailure.WaitAsync(Limit, Ct);
            await stop.CancelAsync();
            await c;
        }
    }

    // S3: nothing but KEX may exceed the size we promise to send.
    [Fact]
    public async Task S3_an_oversized_message_is_refused()
    {
        (SshTransport client, SshTransport server) = await ConnectAsync(ClientOptions(), ServerOptions(), Ct);
        await using (client)
        await using (server)
        {
            await Assert.ThrowsAsync<ArgumentException>(async () => await client.SendAsync(new byte[100_000], Ct));
        }
    }

    [Fact]
    public async Task SendControl_never_waits_even_when_parked()
    {
        (SshTransport client, SshTransport server) = await ConnectAsync(ClientOptions(), ServerOptions(), Ct);
        await using (client)
        await using (server)
        {
            MarkConnected(client, server);
            client.RequestRekey();
            for (int i = 0; i < 256; i++)
            {
                client.SendControl([MessageNumber.RequestFailure]);
            }

            Assert.Throws<SshProtocolException>(() => client.SendControl([MessageNumber.RequestFailure]));
        }
    }

    /// <summary>Ignores cancellation on writes while <see cref="Stall"/> is set, like a stream with a broken cancel path.</summary>
    private sealed class StubbornStream(Stream inner) : Stream
    {
        public static bool Stall { get; set; }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() => inner.Flush();

        public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            inner.ReadAsync(buffer, cancellationToken);

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            while (Stall)
            {
                await Task.Delay(50, CancellationToken.None);
            }

            await inner.WriteAsync(buffer, cancellationToken);
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}

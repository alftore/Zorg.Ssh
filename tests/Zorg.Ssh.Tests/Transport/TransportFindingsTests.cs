using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Transport;
using static Zorg.Ssh.Tests.Transport.TransportHarness;

namespace Zorg.Ssh.Tests.Transport;

/// <summary>Regression tests for the transport findings of the pre-audit, and for transport advisories.</summary>
public sealed class TransportFindingsTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>Swallows writes once muted, so the observed side can't fail on its own writes to a closed pipe.</summary>
    private sealed class MuteStream(Stream inner) : Stream
    {
        public volatile bool Muted;

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

        public override Task FlushAsync(CancellationToken cancellationToken) => Muted ? Task.CompletedTask : inner.FlushAsync(cancellationToken);

        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            inner.ReadAsync(buffer, cancellationToken);

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
            Muted ? ValueTask.CompletedTask : inner.WriteAsync(buffer, cancellationToken);

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
            }

            base.Dispose(disposing);
        }
    }

    private static async Task DrainAsync(SshTransport transport, CancellationToken stop)
    {
        try
        {
            while (true)
            {
                await transport.ReceiveAsync(stop);
            }
        }
        catch (Exception ex) when (ex is SshDisconnectedException || (ex is OperationCanceledException && stop.IsCancellationRequested))
        {
        }
    }

    private static async Task ReceiveUntilFailureAsync(SshTransport transport)
    {
        while (true)
        {
            await transport.ReceiveAsync(Ct).AsTask().WaitAsync(TimeSpan.FromSeconds(30), Ct);
        }
    }

    // T1: DISCONNECT may precede NEWKEYS, so a close while our KEXINIT is out must send it, and must not wait for the grace time.
    [Fact]
    public async Task T1_a_close_during_a_key_exchange_sends_DISCONNECT_without_the_grace_wait()
    {
        (Stream clientStream, Stream serverStream) = DuplexStream.CreatePair();
        MuteStream mute = new(serverStream);
        Task<SshTransport> serverTask = SshTransport.StartAsync(mute, ServerOptions(), Ct);
        Task<SshTransport> clientTask = SshTransport.StartAsync(clientStream, ClientOptions(), Ct);
        SshTransport client = await clientTask;
        SshTransport server = await serverTask;
        await using (client)
        await using (server)
        {
            MarkConnected(client, server);

            // Our KEXINIT is out and the server hasn't read it, so the client stays parked.
            client.RequestRekey();
            Stopwatch watch = Stopwatch.StartNew();
            await client.CloseAsync();
            watch.Stop();
            Assert.True(watch.ElapsedMilliseconds < 900, $"CloseAsync took {watch.ElapsedMilliseconds} ms");

            mute.Muted = true;
            await Assert.ThrowsAsync<SshDisconnectedException>(async () => await ReceiveUntilFailureAsync(server));
        }
    }

    // T3, libssh CVE-2023-1667: a wrong first_kex_packet_follows guess during a rekey, on the server side.
    // Exactly one stray packet is dropped, and the exchange then completes.
    [Fact]
    public async Task T3_CVE_2023_1667_a_wrong_guess_in_a_server_side_rekey_drops_one_packet_and_the_rekey_completes()
    {
        (SshTransport client, SshTransport server) = await ConnectAsync(
            ClientOptions(kex: ["curve25519-sha256", "ecdh-sha2-nistp256"]),
            ServerOptions(kex: ["ecdh-sha2-nistp256", "curve25519-sha256"]),
            Ct);
        await using (client)
        await using (server)
        {
            MarkConnected(client, server);
            using CancellationTokenSource stop = CancellationTokenSource.CreateLinkedTokenSource(Ct);
            Task clientSide = DrainAsync(client, stop.Token);

            // The client's first choice differs from the server's, so its guessed packet is the stray one.
            client.NextKexInitFollowsForTests = true;
            client.RequestRekey();
            client.SendIgnoringKexForTests([MessageNumber.KexEcdhInit, 1, 2, 3]);

            Task serverSide = ReceiveUntilFailureAsync(server);
            using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(Ct);
            limit.CancelAfter(TimeSpan.FromSeconds(30));
            while (server.CompletedKeyExchanges < 2 || client.CompletedKeyExchanges < 2)
            {
                await Task.Delay(5, limit.Token);
                Assert.False(serverSide.IsCompleted, "the server ended the connection");
            }

            // The flag is spent: a further stray KEX packet is refused, not swallowed.
            client.SendIgnoringKexForTests([MessageNumber.KexEcdhInit, 1, 2, 3]);
            await Assert.ThrowsAsync<SshProtocolException>(async () => await serverSide);
            await stop.CancelAsync();
            await clientSide.WaitAsync(TimeSpan.FromSeconds(30), Ct);
        }
    }

    [Fact]
    public async Task T3_CVE_2023_1667_a_second_stray_packet_in_a_rekey_is_refused()
    {
        (SshTransport client, SshTransport server) = await ConnectAsync(
            ClientOptions(kex: ["curve25519-sha256", "ecdh-sha2-nistp256"]),
            ServerOptions(kex: ["ecdh-sha2-nistp256", "curve25519-sha256"]),
            Ct);
        await using (client)
        await using (server)
        {
            MarkConnected(client, server);
            client.NextKexInitFollowsForTests = true;
            client.RequestRekey();
            client.SendIgnoringKexForTests([MessageNumber.KexEcdhInit, 1, 2, 3]);
            client.SendIgnoringKexForTests([MessageNumber.KexEcdhInit, 1, 2, 3]);
            await Assert.ThrowsAnyAsync<SshProtocolException>(async () => await ReceiveUntilFailureAsync(server));
        }
    }

    // OpenSSH CVE-2025-26466: ping@openssh.com (message 192) before auth or during a rekey must not be answered
    // with a PONG, or queue replies for ever. Zorg.Ssh doesn't implement it, and the policy treats it as unknown.
    [Theory]
    [InlineData((int)TransportPhase.AwaitService)]
    [InlineData((int)TransportPhase.Auth)]
    [InlineData((int)TransportPhase.Connected)]
    public async Task CVE_2025_26466_a_PING_is_answered_only_with_UNIMPLEMENTED_never_a_PONG(int phaseValue)
    {
        (SshTransport client, SshTransport server) = await ConnectAsync(ClientOptions(), ServerOptions(), Ct);
        await using (client)
        await using (server)
        {
            server.SetPhase((TransportPhase)phaseValue);
            client.SetPhase(TransportPhase.Connected);
            TaskCompletionSource<uint> rejected = new(TaskCreationOptions.RunContinuationsAsynchronously);
            client.UnimplementedObserver = r => rejected.TrySetResult(r);
            using CancellationTokenSource stop = CancellationTokenSource.CreateLinkedTokenSource(Ct);
            Task serverSide = DrainAsync(server, stop.Token);
            Task clientSide = DrainAsync(client, stop.Token);

            await client.SendAsync([192, 0, 0, 0, 0], Ct);
            await rejected.Task.WaitAsync(TimeSpan.FromSeconds(10), Ct);

            // A PONG (193) would end the client's connection, because nothing allows it.
            await client.SendAsync([MessageNumber.Ignore, 0, 0, 0, 0], Ct);
            await Task.Delay(100, Ct);
            Assert.False(serverSide.IsCompleted);
            Assert.False(clientSide.IsCompleted);
            await stop.CancelAsync();
            await Task.WhenAll(serverSide, clientSide);
        }
    }

    [Theory]
    [InlineData((int)TransportPhase.InitialKex)]
    [InlineData((int)TransportPhase.Connected)]
    public void CVE_2025_26466_a_PING_in_a_key_exchange_ends_the_connection(int phaseValue)
    {
        foreach (SshRole role in new[] { SshRole.Client, SshRole.Server })
        {
            MessageContext context = new(role, (TransportPhase)phaseValue, PeerKexRunning: true, StrictKex: true,
                FirstPacketAfterNewKeys: false, SecondExtInfoAllowed: false);
            Assert.Equal(MessageDecision.Disconnect, MessagePolicy.Evaluate(context, 192));
            Assert.Equal(MessageDecision.Disconnect, MessagePolicy.Evaluate(context, 193));
        }
    }

    // libssh2 CVE-2026-55199: an EXT_INFO parser looping on a count the packet can't hold.
    [Theory]
    [InlineData(0xFFFFFFFFu, 0)]
    [InlineData(65u, 0)]
    [InlineData(2u, 0)]
    [InlineData(1u, 1)]
    public async Task CVE_2026_55199_an_EXT_INFO_count_the_packet_cant_hold_ends_the_connection_quickly(uint count, int bodyBytes)
    {
        (SshTransport client, SshTransport server) = await ConnectAsync(ClientOptions(), ServerOptions(), Ct);
        await using (client)
        await using (server)
        {
            // The server's own EXT_INFO comes first. A client in the auth phase accepts one more.
            client.SetPhase(TransportPhase.Auth);
            byte[] hostile = new byte[5 + bodyBytes];
            hostile[0] = MessageNumber.ExtInfo;
            BinaryPrimitives.WriteUInt32BigEndian(hostile.AsSpan(1), count);
            await server.SendAsync(hostile, Ct);

            Stopwatch watch = Stopwatch.StartNew();
            await Assert.ThrowsAsync<SshProtocolException>(async () => await ReceiveUntilFailureAsync(client));
            Assert.True(watch.ElapsedMilliseconds < 5000);
        }
    }
}

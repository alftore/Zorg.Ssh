using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Connection;
using Zorg.Ssh.Tests.Transport;
using Zorg.Ssh.Transport;

namespace Zorg.Ssh.Tests.Connection;

/// <summary>How a connection ends when its receive loop can't: dispose must still end it, and everything it held.</summary>
public sealed class ConnectionEndTests
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(20);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Dispose_ends_the_connection_when_the_receive_loop_is_stuck_in_a_stream_that_ignores_cancellation()
    {
        (Stream ours, Stream theirs) = DuplexStream.CreatePair();
        DeafStream link = new(ours);
        Task<SshTransport> peerStart = SshTransport.StartAsync(theirs, TransportHarness.ServerOptions(), Ct);
        SshTransport transport = await SshTransport.StartAsync(link, TransportHarness.ClientOptions(), Ct);
        SshTransport peer = await peerStart;
        TransportHarness.MarkConnected(transport, peer);

        SshConnection connection = new(transport) { Grace = TimeSpan.FromMilliseconds(200) };
        connection.Start();
        try
        {
            // The peer answers nothing, so each of these waits on the connection.
            Task<SshChannel> open = connection.OpenChannelAsync("session", CancellationToken.None);
            Task<byte[]?> reply = await connection.StartGlobalRequestAsync("anything@example.com", [], null, Ct);
            await UntilAsync(() => connection.OpeningCount == 1 && connection.PendingGlobalRequests == 1);
            await UntilAsync(() => link.ReadsWaiting == 1);

            await connection.DisposeAsync().AsTask().WaitAsync(Limit, Ct);

            // The loop is still in its read, so only dispose can have ended the connection.
            Assert.Equal(1, link.ReadsWaiting);
            Assert.True(connection.Ended.IsCompleted);
            Assert.True(connection.Closed.IsCancellationRequested);

            // This side closed a healthy connection.
            Assert.Null(await connection.CloseReason);
            await Assert.ThrowsAnyAsync<SshConnectionException>(() => open.WaitAsync(Limit, Ct));
            await Assert.ThrowsAnyAsync<SshConnectionException>(() => reply.WaitAsync(Limit, Ct));
            await Assert.ThrowsAnyAsync<SshConnectionException>(() => connection.OpenChannelAsync("session", Ct));
        }
        finally
        {
            // The peer's side closing is what finally ends that read.
            await peer.DisposeAsync();
            await UntilAsync(() => link.ReadsWaiting == 0);
            await ours.DisposeAsync();
        }
    }

    // C3: a protocol error in a connection-layer message ended the connection through the polite close, so the peer was told
    // DISCONNECT_BY_APPLICATION, and the error was recorded only once the connection ended, which a dispose could slip ahead
    // of and report a healthy close. It's now recorded first, and the peer is told PROTOCOL_ERROR.
    [Fact]
    public async Task A_message_for_a_channel_that_isnt_open_disconnects_with_protocol_error()
    {
        await using ChannelRig rig = await ChannelRig.StartAsync(Ct);
        SshChannel channel = await rig.OpenAsync(1);

        await rig.SendDataAsync(channel.LocalId + 500, new byte[1]);

        await AssertProtocolErrorAsync(rig);
    }

    // C3, with the example from the finding: data past the window.
    [Fact]
    public async Task Data_past_the_window_disconnects_with_protocol_error()
    {
        await using ChannelRig rig = await ChannelRig.StartAsync(Ct);
        SshChannel channel = await rig.OpenAsync(1);
        int packets = (int)(SshChannel.DefaultWindow / SshChannel.MaxPacket) + 1;

        try
        {
            for (int i = 0; i < packets; i++)
            {
                await rig.SendDataAsync(channel.LocalId, new byte[SshChannel.MaxPacket]);
            }
        }
        catch (SshException)
        {
            // The connection ended under the last sends.
        }

        await AssertProtocolErrorAsync(rig);
    }

    private static async Task AssertProtocolErrorAsync(ChannelRig rig)
    {
        SshException? reason = await rig.Connection.CloseReason.WaitAsync(Limit, Ct);
        Assert.IsType<SshProtocolException>(reason);

        // Dispose after the failure doesn't turn it into a close of this side's own.
        await rig.Connection.DisposeAsync();
        Assert.IsType<SshProtocolException>(await rig.Connection.CloseReason);

        Exception? peer = await rig.PeerEnded.WaitAsync(Limit, Ct);
        SshDisconnectedException disconnected = Assert.IsType<SshDisconnectedException>(peer);
        Assert.Equal(SshDisconnectReason.ProtocolError, disconnected.Reason);
    }

    private static async Task UntilAsync(Func<bool> condition)
    {
        using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        limit.CancelAfter(Limit);
        while (!condition())
        {
            await Task.Delay(1, limit.Token);
        }
    }

    /// <summary>A stream whose reads ignore cancellation and survive dispose: one ends only when data or the end arrives.</summary>
    private sealed class DeafStream(Stream inner) : Stream
    {
        private int _readsWaiting;

        public int ReadsWaiting => Volatile.Read(ref _readsWaiting);

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _readsWaiting);
            try
            {
                return await inner.ReadAsync(buffer, CancellationToken.None);
            }
            finally
            {
                Interlocked.Decrement(ref _readsWaiting);
            }
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
            inner.WriteAsync(buffer, cancellationToken);

        public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);

        public override void Flush() => inner.Flush();

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        // Deliberately leaves the inner stream open: closing this one must not end a read.
    }
}

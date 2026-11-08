using System;
using System.Collections.Concurrent;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Connection;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Tests.Transport;
using Zorg.Ssh.Transport;
using static Zorg.Ssh.Tests.Forwarding.ScriptedServer;

namespace Zorg.Ssh.Tests.Connection;

/// <summary>
/// <see cref="SshClient.ConnectionClosed"/> and <see cref="SshClient.WaitForCloseAsync"/>: one moment for every way a
/// connection ends, the first cause as the reason, and user callbacks that can't hold the library up.
/// </summary>
public sealed class ConnectionClosedTests : IDisposable
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(20);
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(30);

    private readonly SshHostKey _hostKey = SshHostKey.GenerateEd25519();
    private readonly ManualClock _clock = new();
    private readonly TaskCompletionSource _handlerStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => _hostKey.Dispose();

    private SshServerOptions ServerOptions(bool directTcp = false) => new()
    {
        HostKeys = [_hostKey],
        PasswordHandler = (_, _) => ValueTask.FromResult(SshAuthDecision.Accept),
        SessionHandler = WaitForeverAsync,
        DirectTcpHandler = directTcp ? (_, _) => ValueTask.FromResult(SshForwardDecision.Allow) : null,
        KeepAliveInterval = TimeSpan.Zero,
    };

    private SshClientOptions ClientOptions(bool keepAlive = false) => new()
    {
        Host = "in-memory",
        UserName = "alice",
        Credentials = [SshCredential.FromPassword("pw")],
        HostKeyPolicy = HostKeyPolicy.Fingerprint(_hostKey.Sha256Fingerprint),
        KeepAliveInterval = keepAlive ? Interval : TimeSpan.Zero,
        TimeProvider = keepAlive ? _clock : TimeProvider.System,
    };

    /// <summary>Runs "wait" until its token fires. Anything else exits at once with 7.</summary>
    private async Task<int> WaitForeverAsync(SshServerSession session, CancellationToken cancellationToken)
    {
        if (session.Command != "wait")
        {
            return 7;
        }

        _handlerStarted.TrySetResult();
        await Task.Delay(Timeout.Infinite, cancellationToken);
        return 0;
    }

    /// <summary>Connects a client to <paramref name="server"/> in memory, over a link the test can cut.</summary>
    private static async Task<(SshClient Client, Link Link, Task Served)> ConnectAsync(SshServer server, SshClientOptions options)
    {
        (Stream clientSide, Stream serverSide) = DuplexStream.CreatePair();
        Link link = new(clientSide);
        Task served = server.ServeStreamAsync(serverSide, Ct);
        SshClient client = await SshClient.ConnectOverStreamAsync(link, options, Ct);
        return (client, link, served);
    }

    private static Task<SshException?> ClosedAsync(SshClient client) => client.WaitForCloseAsync(Ct).WaitAsync(Limit, Ct);

    [Fact]
    public async Task A_live_connection_has_neither_signalled()
    {
        await using SshServer server = SshServer.Create(ServerOptions());
        (SshClient client, _, _) = await ConnectAsync(server, ClientOptions());
        await using (client)
        {
            Task<SshException?> closed = client.WaitForCloseAsync(Ct);
            await Task.Delay(50, Ct);
            Assert.False(closed.IsCompleted);
            Assert.False(client.ConnectionClosed.IsCancellationRequested);
            Assert.True(client.ConnectionClosed.CanBeCanceled);
        }
    }

    [Fact]
    public async Task A_server_that_disconnects_gives_SshDisconnectedException_with_its_reason()
    {
        SshServer server = SshServer.Create(ServerOptions());
        (SshClient client, _, _) = await ConnectAsync(server, ClientOptions());
        await using (client)
        {
            // Stopping the server sends a DISCONNECT, by application.
            await server.DisposeAsync();

            SshDisconnectedException ex = Assert.IsType<SshDisconnectedException>(await ClosedAsync(client));
            Assert.Equal(SshDisconnectReason.ByApplication, ex.Reason);
            Assert.True(client.ConnectionClosed.IsCancellationRequested);
        }
    }

    [Fact]
    public async Task A_peer_disconnect_carries_its_code_and_text()
    {
        await using KeepAliveRig rig = await KeepAliveRig.StartAsync(SshRole.Client, Ct, interval: TimeSpan.Zero);

        await rig.Peer.SendAsync(
            Message(w =>
            {
                w.Byte(MessageNumber.Disconnect);
                w.UInt32((uint)SshDisconnectReason.TooManyConnections);
                w.String("come back later");
                w.String(string.Empty);
            }),
            Ct);

        SshDisconnectedException ex = Assert.IsType<SshDisconnectedException>(await rig.Connection.CloseReason.WaitAsync(Limit, Ct));
        Assert.Equal(SshDisconnectReason.TooManyConnections, ex.Reason);
        Assert.Equal("come back later", ex.Description);
        Assert.True(rig.Connection.Closed.IsCancellationRequested);
    }

    [Fact]
    public async Task A_protocol_error_gives_SshProtocolException()
    {
        await using KeepAliveRig rig = await KeepAliveRig.StartAsync(SshRole.Client, Ct, interval: TimeSpan.Zero);

        // EOF for a channel that was never opened.
        await rig.Peer.SendAsync(new byte[] { MessageNumber.ChannelEof, 0, 0, 0, 99 }, Ct);

        Assert.IsType<SshProtocolException>(await rig.Connection.CloseReason.WaitAsync(Limit, Ct));
        Assert.True(rig.Connection.Closed.IsCancellationRequested);
    }

    [Fact]
    public async Task A_lost_connection_gives_SshConnectionException()
    {
        await using SshServer server = SshServer.Create(ServerOptions());
        (SshClient client, Link link, _) = await ConnectAsync(server, ClientOptions());
        await using (client)
        {
            link.Sever();

            SshException? reason = await ClosedAsync(client);
            SshConnectionException ex = Assert.IsType<SshConnectionException>(reason);
            Assert.IsType<IOException>(ex.InnerException);
        }
    }

    [Fact]
    public async Task A_keepalive_timeout_gives_SshConnectionException()
    {
        await using SshServer server = SshServer.Create(ServerOptions());
        (SshClient client, Link link, _) = await ConnectAsync(server, ClientOptions(keepAlive: true));
        await using (client)
        {
            await _clock.WaitForTimerAsync();

            // Nothing written arrives, and nothing comes back: a pulled cable.
            link.Drop();
            for (int i = 0; i < 9 && !client.ConnectionClosed.IsCancellationRequested; i++)
            {
                await _clock.AdvanceAsync(Interval, () => client.Connection.Ended.IsCompleted);
            }

            SshConnectionException ex = Assert.IsType<SshConnectionException>(await ClosedAsync(client));
            Assert.Contains("The peer stopped", ex.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task Disposing_a_healthy_connection_gives_null_and_the_token_stays_readable()
    {
        await using SshServer server = SshServer.Create(ServerOptions());
        (SshClient client, _, _) = await ConnectAsync(server, ClientOptions());
        Task<SshException?> waiting = client.WaitForCloseAsync(Ct);
        CancellationToken token = client.ConnectionClosed;

        await client.DisposeAsync();

        Assert.Null(await waiting.WaitAsync(Limit, Ct));
        Assert.Null(await ClosedAsync(client));
        Assert.True(token.IsCancellationRequested);
        Assert.True(client.ConnectionClosed.IsCancellationRequested);
        Assert.True(client.ConnectionClosed.WaitHandle.WaitOne(0));

        // A registration on a token that has fired runs at once, where it's made.
        bool ran = false;
        using (client.ConnectionClosed.Register(() => ran = true))
        {
            Assert.True(ran);
        }

        await client.DisposeAsync();
        Assert.True(client.ConnectionClosed.IsCancellationRequested);
    }

    [Fact]
    public async Task A_failure_before_dispose_stays_the_reason()
    {
        await using SshServer server = SshServer.Create(ServerOptions());
        (SshClient client, Link link, _) = await ConnectAsync(server, ClientOptions());
        link.Sever();
        SshException? first = await ClosedAsync(client);

        await client.DisposeAsync();

        Assert.IsType<SshConnectionException>(first);
        Assert.Same(first, await ClosedAsync(client));
    }

    [Fact]
    public async Task A_failure_the_loop_hasnt_seen_yet_still_wins_over_dispose()
    {
        await using KeepAliveRig rig = await KeepAliveRig.StartAsync(SshRole.Client, Ct, interval: TimeSpan.Zero);

        // The transport records the failure at once. Dispose follows before the receive loop can act on it.
        rig.Connection.Transport.Abort(new SshConnectionException("The peer stopped answering keepalives. Connect again to continue."));
        await rig.Connection.DisposeAsync();

        SshConnectionException ex = Assert.IsType<SshConnectionException>(await rig.Connection.CloseReason.WaitAsync(Limit, Ct));
        Assert.Contains("stopped answering keepalives", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Everything_pending_has_failed_when_the_wait_ends()
    {
        await using SshServer server = SshServer.Create(ServerOptions());
        (SshClient client, Link link, _) = await ConnectAsync(server, ClientOptions());
        await using (client)
        {
            await using SshProcess process = await client.StartProcessAsync("wait", null, Ct);
            await _handlerStarted.Task.WaitAsync(Limit, Ct);
            Task<int> read = process.StandardOutput.ReadAsync(new byte[16], CancellationToken.None).AsTask();
            Task exit = process.WaitForExitAsync(CancellationToken.None);

            // Nothing answers these once the link is cut.
            link.Hold();
            Task<SshChannel> open = client.Connection.OpenChannelAsync("session", CancellationToken.None);
            Task<byte[]?> reply = await client.Connection.StartGlobalRequestAsync("anything@example.com", [], null, Ct);
            using (CancellationTokenSource limit = new(Limit))
            {
                while (client.Connection.OpeningCount == 0)
                {
                    await Task.Delay(1, limit.Token);
                }
            }

            link.Sever();
            Assert.NotNull(await ClosedAsync(client));

            // Failed by the time the wait ended, not some time after: the connection holds no waiter any more. The callers'
            // own tasks resume a moment later, on the thread pool.
            Assert.Equal(0, client.Connection.OpeningCount);
            Assert.Equal(0, client.Connection.PendingGlobalRequests);
            Assert.True(client.ConnectionClosed.IsCancellationRequested);

            await Assert.ThrowsAnyAsync<SshConnectionException>(() => open.WaitAsync(Limit, Ct));
            await Assert.ThrowsAnyAsync<SshConnectionException>(() => reply.WaitAsync(Limit, Ct));
            await Assert.ThrowsAnyAsync<SshConnectionException>(() => read.WaitAsync(Limit, Ct));
            await Assert.ThrowsAnyAsync<SshConnectionException>(() => exit.WaitAsync(Limit, Ct));
            await Assert.ThrowsAnyAsync<SshConnectionException>(() => client.ExecuteAsync("again", Ct));
        }
    }

    [Fact]
    public async Task Callbacks_that_block_or_throw_hold_up_nothing_and_leave_no_unobserved_task()
    {
        ConcurrentQueue<Exception> unobserved = new();
        EventHandler<UnobservedTaskExceptionEventArgs> watch = (_, e) =>
        {
            foreach (Exception inner in e.Exception.Flatten().InnerExceptions)
            {
                if (inner is CallbackFailure)
                {
                    unobserved.Enqueue(inner);
                    e.SetObserved();
                }
            }
        };

        TaskScheduler.UnobservedTaskException += watch;
        try
        {
            await using SshServer server = SshServer.Create(ServerOptions());
            (SshClient client, Link link, _) = await ConnectAsync(server, ClientOptions());
            (SshClient other, _, _) = await ConnectAsync(server, ClientOptions());
            await using (client)
            await using (other)
            {
                using ManualResetEventSlim release = new();
                TaskCompletionSource blocked = new(TaskCreationOptions.RunContinuationsAsynchronously);
                TaskCompletionSource threw = new(TaskCreationOptions.RunContinuationsAsynchronously);

                // Callbacks run last registered first, so the one that blocks goes first and the one that throws waits behind it.
                using CancellationTokenRegistration throwing = client.ConnectionClosed.Register(() =>
                {
                    threw.TrySetResult();
                    throw new CallbackFailure();
                });
                using CancellationTokenRegistration blocking = client.ConnectionClosed.Register(() =>
                {
                    blocked.TrySetResult();
                    release.Wait(Limit);
                });

                Task<SshChannel> open = client.Connection.OpenChannelAsync("session", CancellationToken.None);
                link.Sever();

                // While a callback is stuck, the connection has still ended, and other connections still work.
                await blocked.Task.WaitAsync(Limit, Ct);
                Assert.IsType<SshConnectionException>(await ClosedAsync(client));
                await Assert.ThrowsAnyAsync<SshException>(() => open.WaitAsync(Limit, Ct));
                Assert.Equal(7, (await other.ExecuteAsync("still here", Ct).WaitAsync(Limit, Ct)).ExitCode);
                Assert.False(release.IsSet);
                Assert.False(threw.Task.IsCompleted);

                release.Set();
                await threw.Task.WaitAsync(Limit, Ct);
            }

            // Lets the faulted cancellation task be collected, which is when an unobserved one would be reported.
            for (int i = 0; i < 10; i++)
            {
                await Task.Delay(20, Ct);
                GC.Collect();
                GC.WaitForPendingFinalizers();
            }
        }
        finally
        {
            TaskScheduler.UnobservedTaskException -= watch;
        }

        Assert.Empty(unobserved);
    }

    [Fact]
    public async Task WaitForCloseAsync_honours_its_own_token()
    {
        await using SshServer server = SshServer.Create(ServerOptions());
        (SshClient client, _, _) = await ConnectAsync(server, ClientOptions());
        await using (client)
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.WaitForCloseAsync(new CancellationToken(canceled: true)));

            using CancellationTokenSource later = new();
            Task<SshException?> waiting = client.WaitForCloseAsync(later.Token);
            await later.CancelAsync();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting.WaitAsync(Limit, Ct));

            // Only the wait ended, not the connection.
            Assert.False(client.ConnectionClosed.IsCancellationRequested);
            Assert.Equal(7, (await client.ExecuteAsync("still here", Ct)).ExitCode);
        }
    }

    [Fact]
    public async Task A_client_through_a_jump_host_closes_when_the_jump_connection_dies()
    {
        await using SshServer innerServer = await SshServer.StartAsync(ServerOptions(), Ct);
        await using SshServer bastionServer = await SshServer.StartAsync(ServerOptions(directTcp: true), Ct);
        (SshClient bastion, Link bastionLink, _) = await ConnectAsync(bastionServer, ClientOptions());
        await using (bastion)
        {
            await using SshClient inner = await SshClient.ConnectAsync(
                ClientOptions() with { Host = "127.0.0.1", Port = innerServer.LocalEndPoint.Port, JumpHost = bastion },
                Ct);

            bastionLink.Sever();

            Assert.IsType<SshConnectionException>(await ClosedAsync(bastion));
            Assert.IsAssignableFrom<SshConnectionException>(await ClosedAsync(inner));
            Assert.True(inner.ConnectionClosed.IsCancellationRequested);
            await Assert.ThrowsAnyAsync<SshConnectionException>(() => inner.ExecuteAsync("x", Ct));
        }
    }

    private sealed class CallbackFailure : Exception
    {
        public CallbackFailure()
            : base("A ConnectionClosed callback threw, as user code may.")
        {
        }
    }

    /// <summary>
    /// The client's end of an in-memory link. <see cref="Sever"/> fails every read at once, as a reset socket does;
    /// <see cref="Hold"/> keeps writes from arriving; <see cref="Drop"/> loses them.
    /// </summary>
    private sealed class Link(Stream inner) : Stream
    {
        private readonly TaskCompletionSource<int> _severed = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private volatile bool _dropping;
        private volatile bool _holding;

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public void Sever() => _severed.TrySetException(new IOException("An existing connection was forcibly closed by the remote host."));

        public void Drop() => _dropping = true;

        public void Hold() => _holding = true;

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_dropping)
            {
                // Nothing arrives on a dead path. The read ends only when the transport gives up on it.
                await Task.Delay(Timeout.Infinite, cancellationToken);
            }

            Task<int> read = inner.ReadAsync(buffer, cancellationToken).AsTask();
            Task<int> done = await Task.WhenAny(read, _severed.Task);
            return await done;
        }

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_severed.Task.IsFaulted)
            {
                await _severed.Task;
            }

            if (_dropping || _holding)
            {
                return;
            }

            await inner.WriteAsync(buffer, cancellationToken);
        }

        public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);

        public override void Flush() => inner.Flush();

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}

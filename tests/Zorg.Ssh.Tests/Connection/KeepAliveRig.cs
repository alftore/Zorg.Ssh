using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Connection;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Tests.Transport;
using Zorg.Ssh.Transport;
using static Zorg.Ssh.Tests.Forwarding.ScriptedServer;

namespace Zorg.Ssh.Tests.Connection;

/// <summary>A clock that moves only when told, so a test can cross minutes of keepalive without sleeping.</summary>
internal sealed class ManualClock : TimeProvider
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(20);

    private readonly Lock _lock = new();
    private readonly List<ManualTimer> _timers = [];
    private long _now = TimeSpan.TicksPerDay;
    private int _created;

    public override long TimestampFrequency => TimeSpan.TicksPerSecond;

    /// <summary>Gets how many timers are waiting to fire.</summary>
    public int ActiveTimers
    {
        get
        {
            lock (_lock)
            {
                return _timers.Count;
            }
        }
    }

    public override long GetTimestamp()
    {
        lock (_lock)
        {
            return _now;
        }
    }

    public override DateTimeOffset GetUtcNow() => DateTimeOffset.UnixEpoch.AddTicks(GetTimestamp());

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        Assert.Equal(Timeout.InfiniteTimeSpan, period);
        ManualTimer timer = new(this, callback, state);
        lock (_lock)
        {
            _created++;
            timer.Due = _now + dueTime.Ticks;
            _timers.Add(timer);
        }

        return timer;
    }

    /// <summary>Waits until something has armed a timer.</summary>
    public async Task WaitForTimerAsync()
    {
        using CancellationTokenSource limit = new(Limit);
        while (ActiveTimers == 0)
        {
            await Task.Delay(1, limit.Token);
        }
    }

    /// <summary>Waits until a timer is armed to fire <paramref name="due"/> after the clock's current time.</summary>
    public async Task WaitForTimerDueAsync(TimeSpan due)
    {
        using CancellationTokenSource limit = new(Limit);
        while (true)
        {
            lock (_lock)
            {
                if (_timers.Any(t => t.Due == _now + due.Ticks))
                {
                    return;
                }
            }

            await Task.Delay(1, limit.Token);
        }
    }

    /// <summary>
    /// Moves the clock, stopping at each timer on the way. After a timer fires, this waits for its owner to arm the
    /// next one or for <paramref name="finished"/>, so a tick is never skipped because the test ran ahead of it.
    /// </summary>
    public async Task AdvanceAsync(TimeSpan by, Func<bool> finished, Func<Task>? settled = null)
    {
        long end = GetTimestamp() + by.Ticks;
        while (true)
        {
            int created;
            ManualTimer? next;
            lock (_lock)
            {
                created = _created;
                next = _timers.Where(t => t.Due <= end).MinBy(t => t.Due);
                if (next is null)
                {
                    _now = end;
                    return;
                }

                _now = Math.Max(_now, next.Due);
                _timers.Remove(next);
            }

            next.Fire();
            using CancellationTokenSource limit = new(Limit);
            while (Volatile.Read(ref _created) == created && !finished())
            {
                await Task.Delay(1, limit.Token);
            }

            if (settled is not null)
            {
                await settled();
            }
        }
    }

    private void Remove(ManualTimer timer)
    {
        lock (_lock)
        {
            _timers.Remove(timer);
        }
    }

    private sealed class ManualTimer(ManualClock clock, TimerCallback callback, object? state) : ITimer
    {
        public long Due { get; set; }

        public void Fire() => callback(state);

        public bool Change(TimeSpan dueTime, TimeSpan period) => throw new NotSupportedException();

        public void Dispose() => clock.Remove(this);

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }
}

/// <summary>A stream a test can break. Writes can vanish, as on a dead path, or wait, as when the far end stops reading.</summary>
internal sealed class FaultStream(Stream inner) : Stream
{
#pragma warning disable CA2213 // A write can still be waiting on it when the stream closes.
    private readonly SemaphoreSlim _passes = new(0);
#pragma warning restore CA2213
    private volatile bool _dropping;
    private volatile bool _held;
    private volatile bool _ignoreCancellation;
    private int _writesBeforeDrop = -1;
    private int _waiting;

    /// <summary>Gets how many writes are held right now.</summary>
    public int WritesWaiting => Volatile.Read(ref _waiting);

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    /// <summary>From now on, nothing written arrives.</summary>
    public void Drop() => _dropping = true;

    /// <summary>Lets this many more writes through, and drops the rest.</summary>
    public void DropAfter(int writes) => Volatile.Write(ref _writesBeforeDrop, writes);

    /// <summary>From now on, writes wait. Like a stream that won't cancel, if <paramref name="ignoreCancellation"/> is set.</summary>
    public void Hold(bool ignoreCancellation = false)
    {
        while (_passes.Wait(0))
        {
            // Left over from the last Open.
        }

        _ignoreCancellation = ignoreCancellation;
        _held = true;
    }

    /// <summary>Lets one held write through. The next one waits again.</summary>
    public void ReleaseOne() => _passes.Release();

    /// <summary>Stops holding writes.</summary>
    public void Open()
    {
        _held = false;
        _passes.Release(Volatile.Read(ref _waiting) + 1);
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (_held)
        {
            Interlocked.Increment(ref _waiting);
            try
            {
                await _passes.WaitAsync(_ignoreCancellation ? CancellationToken.None : cancellationToken);
            }
            finally
            {
                Interlocked.Decrement(ref _waiting);
            }
        }

        int left = Volatile.Read(ref _writesBeforeDrop);
        if (left == 0 || _dropping)
        {
            return;
        }

        if (left > 0)
        {
            Interlocked.Decrement(ref _writesBeforeDrop);
        }

        await inner.WriteAsync(buffer, cancellationToken);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
        inner.ReadAsync(buffer, cancellationToken);

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        inner.ReadAsync(buffer, offset, count, cancellationToken);

    public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override void Flush() => inner.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            Open();
            inner.Dispose();
        }

        base.Dispose(disposing);
    }
}

/// <summary>
/// A real <see cref="SshConnection"/>, in either role, on a manual clock, against a peer transport that does only
/// what the test says. What the peer receives goes to <see cref="NextGlobalRequestAsync"/> and <see cref="NextOpenAsync"/>.
/// </summary>
internal sealed class KeepAliveRig : IAsyncDisposable
{
    public static readonly TimeSpan Interval = TimeSpan.FromSeconds(5);

    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(20);

    private readonly Channel<string> _globalRequests = Channel.CreateUnbounded<string>();
    private readonly Channel<uint> _opens = Channel.CreateUnbounded<uint>();
    private readonly Task _reading;
    private readonly CancellationToken _token;
    private int _requestsSeen;
    private uint _lastRequestSequence;

    private KeepAliveRig(ManualClock clock, FaultStream link, FaultStream peerLink, SshConnection connection, SshTransport peer, CancellationToken token)
    {
        Clock = clock;
        Link = link;
        PeerLink = peerLink;
        Connection = connection;
        Peer = peer;
        _token = token;
        _reading = Task.Run(ReadAsync, CancellationToken.None);
    }

    public ManualClock Clock { get; }

    /// <summary>Gets what the connection writes to.</summary>
    public FaultStream Link { get; }

    /// <summary>Gets what the peer writes to.</summary>
    public FaultStream PeerLink { get; }

    public SshConnection Connection { get; }

    public SshTransport Peer { get; }

    /// <summary>Gets or sets whether the peer answers every global request at once, as OpenSSH does.</summary>
    public bool AutoAnswer { get; set; }

    /// <summary>Gets or sets whether the peer answers every global request with UNIMPLEMENTED, as a build without them does.</summary>
    public bool AutoUnimplemented { get; set; }

    /// <summary>Gets the sequence number of the last global request the peer received.</summary>
    public uint LastRequestSequence => Volatile.Read(ref _lastRequestSequence);

    /// <summary>Gets how many global requests the peer has received.</summary>
    public int RequestsSeen => Volatile.Read(ref _requestsSeen);

    public bool Ended => Connection.Ended.IsCompleted;

    public KeepAliveMonitor Monitor => Connection.KeepAlive!;

    public static async Task<KeepAliveRig> StartAsync(SshRole role, CancellationToken token, TimeSpan? interval = null, int countMax = 3, int queueCapacity = 64)
    {
        ManualClock clock = new();
        (Stream ours, Stream theirs) = DuplexStream.CreatePair();
        FaultStream link = new(ours);
        FaultStream peerLink = new(theirs);
        TransportOptions client = TransportHarness.ClientOptions();
        TransportOptions server = TransportHarness.ServerOptions();
        TransportOptions options = new()
        {
            Role = role,
            KexAlgorithms = client.KexAlgorithms,
            Ciphers = client.Ciphers,
            Macs = client.Macs,
            HandshakeTimeout = client.HandshakeTimeout,
            HostKeyValidator = role == SshRole.Client ? client.HostKeyValidator : null,
            HostKeys = role == SshRole.Server ? server.HostKeys : [],
            SendQueueCapacity = queueCapacity,
            KeepAliveInterval = interval ?? Interval,
            KeepAliveCountMax = countMax,
            TimeProvider = clock,
        };

        Task<SshTransport> peerStart = SshTransport.StartAsync(peerLink, role == SshRole.Client ? server : client, token);
        SshTransport ourTransport = await SshTransport.StartAsync(link, options, token);
        SshTransport peer = await peerStart;
        TransportHarness.MarkConnected(ourTransport, peer);

        SshConnection connection = new(ourTransport);
        connection.Start();
        if (options.KeepAliveInterval > TimeSpan.Zero)
        {
            // The monitor's first sleep starts on its own task. If the clock moved before it began, its timer would
            // be due an interval after that later time, and the test would stop advancing short of it. Another timer
            // (a key exchange deadline) may exist too, so wait for the one that's due an interval from now.
            await clock.WaitForTimerDueAsync(options.KeepAliveInterval);
        }

        // The send loop clears the transport's key exchange hold only after our NEWKEYS is on the wire, which can be
        // a moment after the peer has seen it and StartAsync has returned. The monitor sends no probe while the hold
        // is up, so a test that moved the clock first would find its one probe skipped and nothing to prompt another.
        using (CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(token))
        {
            limit.CancelAfter(Limit);
            while (ourTransport.KeyExchangeRunning)
            {
                await Task.Delay(1, limit.Token);
            }
        }

        return new KeepAliveRig(clock, link, peerLink, connection, peer, token);
    }

    /// <summary>Moves time on, letting every tick on the way finish, and every probe be answered if <see cref="AutoAnswer"/> is set.</summary>
    public async Task ElapseAsync(TimeSpan by)
    {
        await SettleAsync();
        await Clock.AdvanceAsync(by, () => Ended, SettleAsync);
    }

    public Task IntervalsAsync(double intervals) => ElapseAsync(Interval * intervals);

    /// <summary>Waits until the connection has ended, and returns why.</summary>
    public async Task<string> FailureAsync()
    {
        await Connection.Ended.WaitAsync(Limit, _token);
        SshConnectionException ex = await Assert.ThrowsAsync<SshConnectionException>(() => Connection.OpenChannelAsync("session", _token));
        return Assert.IsType<SshConnectionException>(ex.InnerException).Message;
    }

    public async Task<string> NextGlobalRequestAsync()
    {
        try
        {
            return await _globalRequests.Reader.ReadAsync(_token).AsTask().WaitAsync(Limit, _token);
        }
        catch (TimeoutException)
        {
            // Say where the connection was, because a probe that never came leaves nothing else to go on.
            throw new TimeoutException(
                $"No global request arrived. Probes sent {Monitor.ProbesSent}, one outstanding {Monitor.ProbeOutstanding}, ended {Ended}, " +
                $"key exchange running {Connection.Transport.KeyExchangeRunning}, write pending for {Connection.Transport.WritePendingFor}.");
        }
    }

    public async Task<uint> NextOpenAsync() =>
        await _opens.Reader.ReadAsync(_token).AsTask().WaitAsync(Limit, _token);

    public Task AnswerAsync(byte number, params byte[] data) =>
        Peer.SendAsync([number, .. data], _token).AsTask();

    /// <summary>Sends an UNIMPLEMENTED naming <paramref name="sequence"/>.</summary>
    public Task UnimplementedAsync(uint sequence)
    {
        byte[] payload = new byte[5];
        payload[0] = MessageNumber.Unimplemented;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1), sequence);
        return Peer.SendAsync(payload, _token).AsTask();
    }

    /// <summary>
    /// Waits until everything the peer sent so far has been handled. Packets arrive in order, and the clock moves
    /// first, so the timestamp can only match once the last one is through.
    /// </summary>
    public async Task SyncAsync()
    {
        await ElapseAsync(TimeSpan.FromMilliseconds(1));
        await PeerSpeaksAsync();
    }

    /// <summary>Sends an IGNORE, and waits for it to reach the connection, so the clock can't run ahead of it.</summary>
    public async Task PeerSpeaksAsync()
    {
        await Peer.SendAsync(new byte[] { MessageNumber.Ignore, 0, 0, 0, 0 }, _token);
        await UntilAsync(() => Connection.Transport.LastReceivedTimestamp == Clock.GetTimestamp());
    }

    /// <summary>Opens a channel the peer knows as <paramref name="remoteId"/>, with the given window.</summary>
    public async Task<SshChannel> OpenAsync(uint remoteId, uint window)
    {
        Task<SshChannel> open = Connection.OpenChannelAsync("session", _token);
        uint local = await NextOpenAsync();
        await Peer.SendAsync(
            Message(w =>
            {
                w.Byte(MessageNumber.ChannelOpenConfirmation);
                w.UInt32(local);
                w.UInt32(remoteId);
                w.UInt32(window);
                w.UInt32(ChannelRig.PacketSize);
            }),
            _token);
        return await open.WaitAsync(Limit, _token);
    }

    public async Task UntilAsync(Func<bool> condition)
    {
        using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(_token);
        limit.CancelAfter(Limit);
        while (!condition())
        {
            await Task.Delay(1, limit.Token);
        }
    }

    public async ValueTask DisposeAsync()
    {
        Link.Open();
        PeerLink.Open();
        await Connection.DisposeAsync();
        await Peer.CloseAsync();
        await _reading;
        await Peer.DisposeAsync();
    }

    /// <summary>
    /// Lets real work finish before the clock moves. This clock can cross an interval in microseconds, so a write
    /// that's merely preempted would look stalled. One a test is holding is left alone.
    /// </summary>
    private async Task SettleAsync()
    {
        await UntilAsync(() => Connection.Transport.WritePendingFor == TimeSpan.Zero || Link.WritesWaiting > 0 || Ended);
        if ((AutoAnswer || AutoUnimplemented) && !Ended)
        {
            await UntilAsync(() => (Connection.PendingGlobalRequests == 0 && !Monitor.ProbeOutstanding) || Ended);
        }
    }

    private async Task ReadAsync()
    {
        try
        {
            while (true)
            {
                ReadOnlyMemory<byte> message = await Peer.ReceiveAsync(CancellationToken.None);
                switch (message.Span[0])
                {
                    case MessageNumber.GlobalRequest:
                        SshReader request = new(message.Span);
                        request.ReadByte();
                        string name = request.ReadUtf8String();
                        Volatile.Write(ref _lastRequestSequence, Peer.LastReceivedSequence);
                        Interlocked.Increment(ref _requestsSeen);
                        _globalRequests.Writer.TryWrite(name);
                        if (AutoUnimplemented)
                        {
                            Peer.SendUnimplementedForLastPacket();
                        }
                        else if (AutoAnswer)
                        {
                            Peer.SendControl([MessageNumber.RequestFailure]);
                        }

                        break;
                    case MessageNumber.ChannelOpen:
                        SshReader open = new(message.Span);
                        open.ReadByte();
                        open.ReadUtf8String();
                        _opens.Writer.TryWrite(open.ReadUInt32());
                        break;
                }
            }
        }
        catch (Exception ex) when (ex is SshException or OperationCanceledException)
        {
            // The connection has ended, and that's the end of this loop.
        }
    }
}

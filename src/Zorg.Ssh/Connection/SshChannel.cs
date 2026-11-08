using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.IO.Pipelines;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Connection;

/// <summary>A channel request from the peer, waiting for the application side of a server.</summary>
internal sealed record IncomingChannelRequest(string Type, bool WantReply, byte[] Data);

/// <summary>
/// One SSH channel (RFC 4254 section 5), for either role. The On* methods run in the connection's receive
/// loop, so they copy data and return: they never wait on application code. Received data is bounded by the
/// window we granted, and a peer that exceeds it is disconnected.
/// <para>
/// Everything this channel sends goes through <see cref="_sendLock"/>, and nothing is sent after CLOSE.
/// OpenSSH ends the whole connection over a message for a channel it has closed, so one stray packet here
/// would take every other session with it.
/// </para>
/// <para>
/// The peer waits for EOF and CLOSE, so neither is lost when a send is given up: each is recorded as owed, and the
/// connection's sender loop finishes it. EOF goes after every write that started before it, and CLOSE sends an owed
/// EOF first. Both of those happen under <see cref="_sendLock"/>, so nothing can pass the CLOSE.
/// </para>
/// </summary>
internal sealed class SshChannel : IAsyncDisposable
{
    /// <summary>The window we grant. Large enough to keep a fast link busy at a sensible memory cost.</summary>
    public const uint DefaultWindow = 2 * 1024 * 1024;

    /// <summary>The largest data packet we accept and send.</summary>
    public const uint MaxPacket = 32 * 1024;

    /// <summary>
    /// The most that peer requests waiting for the application may cost. A request costs its data plus a fixed overhead, so
    /// this bounds the count too. A client sends pty-req, an env request per variable and shell without waiting for any reply,
    /// and OpenSSH's <c>SendEnv *</c> can make that well over a hundred, so a limit by count small enough to matter cut off real
    /// clients (C2). Requests are small, and this is half the window a channel grants for data.
    /// </summary>
    internal const int MaxQueuedRequestBytes = 1024 * 1024;

    private const int RequestOverhead = 128;
    private const int MaxExitSignalLength = 64;

    private readonly SshConnection _connection;
    private readonly Lock _gate = new();
    private readonly Pipe _output = NewPipe();
    private readonly Pipe _errorOutput = NewPipe();

    // Neither is disposed: without AvailableWaitHandle they hold nothing, and a late writer must get a clean error.
#pragma warning disable CA2213
    private readonly SemaphoreSlim _requestLock = new(1, 1);
    private readonly SemaphoreSlim _sendLock = new(1, 1);
#pragma warning restore CA2213
    private readonly TaskCompletionSource _closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    // Unbounded in type only: what it holds is limited by _queuedRequestBytes.
    private readonly Channel<IncomingChannelRequest> _requests =
        System.Threading.Channels.Channel.CreateUnbounded<IncomingChannelRequest>();

    private long _sendWindow;
    private uint _remoteMaxPacket;
    private long _receiveWindow = DefaultWindow;
    private uint _consumed;
    private long _queuedRequestBytes;

    // Bytes written to each output pipe and not yet read, and whether that pipe's reader has gone. When a reader goes, what it
    // left is credited at once, and later data is credited as it arrives, so a dropped stream can't shrink the shared window (C1).
    private long _outputBuffered;
    private long _errorBuffered;
    private bool _outputDropped;
    private bool _errorDropped;
    private bool _creditQueued;
    private TaskCompletionSource? _windowWaiter;
    private TaskCompletionSource<bool>? _requestReply;
    private bool _inputClosed;

    // Set while _inputClosed is true but the EOF isn't queued yet. It never outlives the CLOSE, and the peer's CLOSE clears it.
    private bool _eofOwed;

    // Writes that started before the input closed. An owed EOF waits for them, so it can't pass their data.
    private int _writers;
    private bool _eofReceived;
    private bool _closeSent;

    // Set while _closeSent is true but the CLOSE isn't queued yet. The channel is shut for everything except that CLOSE.
    private bool _closeOwed;
    private bool _closeReceived;

    // Set while the sender loop has an entry waiting for this channel, so asking again adds nothing.
    private bool _eofDeferred;
    private bool _closeDeferred;
    private Exception? _failure;

    public SshChannel(SshConnection connection, uint localId)
    {
        _connection = connection;
        LocalId = localId;
        Output = new ChannelReadStream(this, _output.Reader, extended: false);
        ErrorOutput = new ChannelReadStream(this, _errorOutput.Reader, extended: true);
        Input = new ChannelWriteStream(this);
        ErrorInput = new ChannelWriteStream(this, extendedType: 1);
        Requests = new RequestReader(this, _requests.Reader);
    }

    public uint LocalId { get; }

    public uint RemoteId { get; private set; }

    /// <summary>Gets the stream of channel data.</summary>
    public Stream Output { get; }

    /// <summary>Gets the stream of extended data: stderr for a session.</summary>
    public Stream ErrorOutput { get; }

    /// <summary>Gets the stream that sends channel data. Disposing it sends EOF.</summary>
    public Stream Input { get; }

    /// <summary>Gets the stream that sends extended data: stderr, for a server.</summary>
    public Stream ErrorInput { get; }

    /// <summary>Gets the exit status, once the peer has sent one.</summary>
    public int? ExitCode { get; private set; }

    /// <summary>Gets the name of the signal that ended the process, once the peer has sent one.</summary>
    public string? ExitSignal { get; private set; }

    /// <summary>Gets a task that completes when both sides have closed. It never faults.</summary>
    public Task Closed => _closed.Task;

    /// <summary>Gets how much more data the peer may send. For tests: it stays between zero and <see cref="DefaultWindow"/>.</summary>
    internal long ReceiveWindowRemaining
    {
        get
        {
            lock (_gate)
            {
                return _receiveWindow;
            }
        }
    }

    /// <summary>Gets how many peer requests wait for the application. For tests.</summary>
    internal int QueuedRequestCount => _requests.Reader.Count;

    /// <summary>Gets what the peer requests waiting for the application cost. For tests: it stays within <see cref="MaxQueuedRequestBytes"/>.</summary>
    internal long QueuedRequestBytes
    {
        get
        {
            lock (_gate)
            {
                return _queuedRequestBytes;
            }
        }
    }

    /// <summary>Gets whether an EOF is still to be queued.</summary>
    public bool EofOwed
    {
        get
        {
            lock (_gate)
            {
                return _eofOwed;
            }
        }
    }

    /// <summary>Gets the failure, if the connection was lost rather than the channel closing normally.</summary>
    public Exception? ConnectionFailure { get; private set; }

    /// <summary>Gets requests the peer sent, for a server. Clients handle theirs inside the channel.</summary>
    public ChannelReader<IncomingChannelRequest> Requests { get; }

    /// <summary>Gets or sets whether requests go to <see cref="Requests"/>. Clients leave this off.</summary>
    public bool QueueIncomingRequests { get; set; }

    /// <summary>Gets or sets whether this side opened the channel as a session, which is what the peer's exit-status is about.</summary>
    public bool IsOwnSession { get; set; }

    /// <summary>Records what the peer told us when the channel opened.</summary>
    public void SetRemote(uint remoteId, uint window, uint maxPacket)
    {
        if (maxPacket == 0)
        {
            throw new SshProtocolException("The peer sent a channel maximum packet size of zero.");
        }

        RemoteId = remoteId;
        _sendWindow = window;
        _remoteMaxPacket = Math.Min(maxPacket, MaxPacket);
    }

    /// <summary>Sends data, waiting for window as needed, in packets the peer accepts.</summary>
    public async ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken, uint? extendedType = null)
    {
        if (data.IsEmpty)
        {
            return;
        }

        lock (_gate)
        {
            ThrowIfUnusable();
            if (_inputClosed)
            {
                throw new SshConnectionException("The channel's input is closed.");
            }

            _writers++;
        }

        try
        {
            while (!data.IsEmpty)
            {
                int chunk = await ReserveWindowAsync(data.Length, cancellationToken).ConfigureAwait(false);
                try
                {
                    await SendDataAsync(data[..chunk], extendedType, cancellationToken).ConfigureAwait(false);
                }
                catch
                {
                    // The packet never reached the queue, and the peer still counts this credit as unused.
                    ReturnWindow(chunk);
                    throw;
                }

                data = data[chunk..];
            }
        }
        finally
        {
            bool eofNext;
            lock (_gate)
            {
                _writers--;
                eofNext = _writers == 0 && _eofOwed;
            }

            if (eofNext)
            {
                _connection.QueueEof(this);
            }
        }
    }

    /// <summary>
    /// Sends EOF, after any write still running. Safe to call more than once. Cancelling gives up the wait, not the
    /// EOF: the peer may wait for ever without it, so the connection's sender loop finishes it.
    /// </summary>
    public async ValueTask SendEofAsync(CancellationToken cancellationToken)
    {
        if (CloseInput())
        {
            await SendOwedEofAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Hands EOF to the connection's sender loop without waiting, so a peer that has stopped reading can't hold up the caller.</summary>
    public void QueueEof()
    {
        if (CloseInput())
        {
            _connection.QueueEof(this);
        }
    }

    /// <summary>Claims the sender loop's entry for EOF. Returns false if one is waiting already.</summary>
    public bool ClaimDeferredEof()
    {
        lock (_gate)
        {
            bool claimed = !_eofDeferred;
            _eofDeferred = true;
            return claimed;
        }
    }

    /// <summary>Claims the sender loop's entry for CLOSE. Returns false if one is waiting already.</summary>
    public bool ClaimDeferredClose()
    {
        lock (_gate)
        {
            bool claimed = !_closeDeferred;
            _closeDeferred = true;
            return claimed;
        }
    }

    /// <summary>Runs the sender loop's entry for EOF.</summary>
    public ValueTask SendDeferredEofAsync(CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            _eofDeferred = false;
        }

        return SendOwedEofAsync(cancellationToken);
    }

    /// <summary>Runs the sender loop's entry for CLOSE.</summary>
    public ValueTask SendDeferredCloseAsync(CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            _closeDeferred = false;
        }

        return CloseAsync(cancellationToken);
    }

    /// <summary>
    /// Sends CLOSE, after anything already queued for this channel and any EOF still owed. A write still running
    /// fails instead of holding this up, because it may never get window. Safe to call more than once. Cancelling
    /// gives up the wait, not the close: the peer holds resources until it hears, so the connection's sender loop
    /// finishes it.
    /// </summary>
    public async ValueTask CloseAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                bool eof;
                TaskCompletionSource? window;
                lock (_gate)
                {
                    if (_closeSent && !_closeOwed)
                    {
                        return;
                    }

                    _closeSent = true;
                    _closeOwed = true;
                    eof = _eofOwed;
                    window = _windowWaiter;
                    _windowWaiter = null;
                }

                // A writer parked in a zero window finds the channel closed now, without waiting for the peer.
                window?.TrySetResult();

                if (eof)
                {
                    await SendEofNowAsync(cancellationToken).ConfigureAwait(false);
                }

                await _connection.SendAsync(SimpleMessage(MessageNumber.ChannelClose), cancellationToken).ConfigureAwait(false);
                lock (_gate)
                {
                    _closeOwed = false;
                }
            }
            finally
            {
                _sendLock.Release();
            }
        }
        catch (OperationCanceledException)
        {
            _connection.QueueClose(this);
            throw;
        }

        FinishIfClosed();
    }

    /// <summary>
    /// Sends a request and waits for the reply. <paramref name="data"/> is what follows <c>want reply</c>.
    /// If the wait is cancelled after sending, the channel closes: a late reply could otherwise be taken
    /// for the answer to the next request.
    /// </summary>
    public async ValueTask<bool> SendRequestAsync(string type, byte[] data, CancellationToken cancellationToken)
    {
        await _requestLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        bool sent = false;
        try
        {
            TaskCompletionSource<bool> reply = new(TaskCreationOptions.RunContinuationsAsynchronously);

            // If the send fails, the end of the connection can still fail this reply, and nobody will be waiting for it.
            SshConnection.ObserveFailure(reply.Task);
            lock (_gate)
            {
                ThrowIfUnusable();
                _requestReply = reply;
            }

            await SendRequestMessageAsync(type, wantReply: true, data, cancellationToken).ConfigureAwait(false);
            sent = true;
            return await reply.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (sent)
        {
            _connection.QueueClose(this);
            throw;
        }
        finally
        {
            lock (_gate)
            {
                _requestReply = null;
            }

            _requestLock.Release();
        }
    }

    /// <summary>Sends a request that wants no reply.</summary>
    public ValueTask SendRequestNoReplyAsync(string type, byte[] data, CancellationToken cancellationToken) =>
        SendRequestMessageAsync(type, wantReply: false, data, cancellationToken);

    /// <summary>Answers a request taken from <see cref="Requests"/>.</summary>
    public ValueTask ReplyAsync(bool success, CancellationToken cancellationToken) =>
        SendOrderedAsync(SimpleMessage(success ? MessageNumber.ChannelSuccess : MessageNumber.ChannelFailure), cancellationToken);

    /// <summary>
    /// Gives back window reserved for a packet that was never queued. It isn't a WINDOW_ADJUST from the peer: it only
    /// restores what the peer granted, so the overflow check doesn't apply.
    /// </summary>
    private void ReturnWindow(int bytes)
    {
        TaskCompletionSource? waiter;
        lock (_gate)
        {
            _sendWindow += bytes;
            waiter = _windowWaiter;
            _windowWaiter = null;
        }

        waiter?.TrySetResult();
    }

    public void OnWindowAdjust(uint bytes)
    {
        TaskCompletionSource? waiter;
        lock (_gate)
        {
            _sendWindow += bytes;
            if (_sendWindow > uint.MaxValue)
            {
                throw new SshProtocolException("The peer grew a channel window past its limit.");
            }

            waiter = _windowWaiter;
            _windowWaiter = null;
        }

        waiter?.TrySetResult();
    }

    public void OnData(ReadOnlySpan<byte> data, bool extended)
    {
        bool dropped;
        lock (_gate)
        {
            if (_eofReceived || _closeReceived)
            {
                // After CLOSE the output pipes are completed, and the write below would throw InvalidOperationException from the pipe: not a
                // protocol error the peer is told about, but a "bug in Zorg.Ssh" that ends the connection with the wrong reason.
                throw new SshProtocolException("The peer sent channel data after EOF or CLOSE.");
            }

            if (data.Length > _receiveWindow)
            {
                throw new SshProtocolException("The peer sent more channel data than its window allows.");
            }

            _receiveWindow -= data.Length;
            if (_closeSent)
            {
                return;
            }

            dropped = extended ? _errorDropped : _outputDropped;
            if (!dropped)
            {
                // Counted before the write, so a reader that goes between here and the write credits this too.
                if (extended)
                {
                    _errorBuffered += data.Length;
                }
                else
                {
                    _outputBuffered += data.Length;
                }
            }
        }

        if (dropped)
        {
            // Nobody will read this stream any more, so the data is consumed as it arrives.
            OnConsumed(data.Length);
            return;
        }

        // No pause threshold is set, so this flush completes at once. The window is what bounds the pipe. If the reader went after
        // the count above, the pipe drops this data, and the reader's going has already credited it.
        PipeWriter writer = (extended ? _errorOutput : _output).Writer;
        writer.Write(data);
        ValueTask<FlushResult> flush = writer.FlushAsync(CancellationToken.None);
        if (!flush.IsCompleted)
        {
            _ = flush.AsTask();
        }
    }

    /// <summary>Credits data the application read from one of the output streams.</summary>
    public void OnRead(int bytes, bool extended)
    {
        lock (_gate)
        {
            if (extended)
            {
                _errorBuffered -= bytes;
            }
            else
            {
                _outputBuffered -= bytes;
            }
        }

        OnConsumed(bytes);
    }

    /// <summary>
    /// Records that an output stream's reader has completed its pipe, and credits what it left unread. Its stream calls this once,
    /// after its last read has credited what it took, so nothing is credited twice (C1).
    /// </summary>
    public void OnReaderCompleted(bool extended)
    {
        long unread;
        lock (_gate)
        {
            if (extended)
            {
                unread = _errorBuffered;
                _errorBuffered = 0;
                _errorDropped = true;
            }
            else
            {
                unread = _outputBuffered;
                _outputBuffered = 0;
                _outputDropped = true;
            }
        }

        if (unread != 0)
        {
            OnConsumed((int)unread);
        }
    }

    public void OnEof()
    {
        lock (_gate)
        {
            _eofReceived = true;
        }

        _output.Writer.Complete();
        _errorOutput.Writer.Complete();
    }

    /// <summary>Returns true if we must answer with our own CLOSE, which has to go behind queued data.</summary>
    public bool OnClose()
    {
        bool reply;
        TaskCompletionSource? window;
        lock (_gate)
        {
            if (_closeReceived)
            {
                throw new SshProtocolException("The peer closed a channel twice.");
            }

            _closeReceived = true;

            // The peer has finished with the channel, so it's no longer waiting to hear this.
            _eofOwed = false;
            reply = !_closeSent;
            window = _windowWaiter;
            _windowWaiter = null;
        }

        window?.TrySetResult();
        _output.Writer.Complete();
        _errorOutput.Writer.Complete();
        _requests.Writer.TryComplete();
        if (!reply)
        {
            FinishIfClosed();
        }

        return reply;
    }

    public void OnRequestReply(bool success)
    {
        TaskCompletionSource<bool>? reply;
        lock (_gate)
        {
            reply = _requestReply;
            _requestReply = null;
        }

        // A reply nobody asked for is dropped: it costs nothing, and can't block the loop (Go CVE-2026-39830).
        reply?.TrySetResult(success);
    }

    /// <summary>Handles an incoming request. Returns true if the caller must send CHANNEL_FAILURE.</summary>
    public bool OnRequest(string type, bool wantReply, ReadOnlySpan<byte> data)
    {
        // RFC 4254 section 6.10: only a server sends these, about a session the client opened. Anywhere else they go the way of any
        // other request this side doesn't handle, so a client can't set what a server's channel reports (C5).
        bool exitAllowed = IsOwnSession && !QueueIncomingRequests;
        if (type == "exit-status" && exitAllowed)
        {
            SshReader reader = new(data);
            uint status = reader.ReadUInt32();
            ExitCode = unchecked((int)status);
            return false;
        }

        if (type == "exit-signal" && exitAllowed)
        {
            SshReader reader = new(data);
            ExitSignal = PeerText.Clean(reader.ReadUtf8String(), MaxExitSignalLength);
            return false;
        }

        if (QueueIncomingRequests)
        {
            long cost = Cost(type, data.Length);
            lock (_gate)
            {
                if (_queuedRequestBytes + cost > MaxQueuedRequestBytes)
                {
                    throw new SshProtocolException("The peer sent more channel requests than the server could handle in time: over 1 MiB of them were waiting.");
                }

                _queuedRequestBytes += cost;
            }

            if (!_requests.Writer.TryWrite(new IncomingChannelRequest(type, wantReply, data.ToArray())))
            {
                // Only a completed queue refuses, and that comes from the peer's CLOSE or the end of the connection.
                lock (_gate)
                {
                    _queuedRequestBytes -= cost;
                }

                throw new SshProtocolException("The peer sent a channel request after closing the channel.");
            }

            return false;
        }

        lock (_gate)
        {
            // The request crossed our CLOSE, and nothing is sent after that.
            return wantReply && !_closeSent;
        }
    }

    /// <summary>Fails everything waiting on this channel, because the connection has ended.</summary>
    public void OnConnectionFailed(Exception failure)
    {
        lock (_gate)
        {
            _failure ??= failure;
            ConnectionFailure = _closeReceived && _closeSent ? null : failure;
            _closeSent = true;
            _closeOwed = false;
            _eofOwed = false;
            _closeReceived = true;
        }

        _output.Writer.Complete(failure);
        _errorOutput.Writer.Complete(failure);
        _requests.Writer.TryComplete();
        ReleaseWaiters(failure);
        _closed.TrySetResult();
    }

    /// <summary>Credits data the application has read, and grows the window once half of it is used.</summary>
    private void OnConsumed(int bytes)
    {
        bool queue = false;
        lock (_gate)
        {
            _consumed += (uint)bytes;
            if (_consumed >= DefaultWindow / 2 && !_closeSent && !_creditQueued)
            {
                _creditQueued = true;
                queue = true;
            }
        }

        if (queue)
        {
            _connection.QueueWindowAdjust(this);
        }
    }

    /// <summary>Grants everything read so far back to the peer. Each channel is queued for this once at most.</summary>
    public async ValueTask GrantCreditAsync(CancellationToken cancellationToken)
    {
        uint credit;
        lock (_gate)
        {
            _creditQueued = false;
            if (_closeSent)
            {
                return;
            }

            credit = _consumed;
            _consumed = 0;
            _receiveWindow += credit;
        }

        if (credit != 0)
        {
            byte[] payload = new byte[9];
            payload[0] = MessageNumber.ChannelWindowAdjust;
            BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1), RemoteId);
            BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(5), credit);
            await SendOrderedAsync(payload, cancellationToken).ConfigureAwait(false);
        }
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            using CancellationTokenSource limit = new(TimeSpan.FromSeconds(5));
            await CloseAsync(limit.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SshException or OperationCanceledException)
        {
            // The connection has gone, or the sender loop finishes the close once the queue has room.
        }

        await Output.DisposeAsync().ConfigureAwait(false);
        await ErrorOutput.DisposeAsync().ConfigureAwait(false);
        await Input.DisposeAsync().ConfigureAwait(false);
        await ErrorInput.DisposeAsync().ConfigureAwait(false);
    }

    private static long Cost(string type, int dataLength) => RequestOverhead + ((long)type.Length * sizeof(char)) + dataLength;

    private void OnRequestTaken(IncomingChannelRequest request)
    {
        lock (_gate)
        {
            _queuedRequestBytes -= Cost(request.Type, request.Data.Length);
        }
    }

    private static Pipe NewPipe() => new(new PipeOptions(pauseWriterThreshold: 0, useSynchronizationContext: false));

    /// <summary>
    /// Refuses further writes, and records that EOF is owed unless the channel is closing anyway. Returns true if the
    /// caller is to see it sent. Otherwise the last write still running does that, or nothing is owed.
    /// </summary>
    private bool CloseInput()
    {
        lock (_gate)
        {
            if (_inputClosed)
            {
                return false;
            }

            _inputClosed = true;
            _eofOwed = !_closeSent && !_closeReceived;
            return _eofOwed && _writers == 0;
        }
    }

    /// <summary>Sends the EOF that's owed, if it still is. Only called once no write is running.</summary>
    private async ValueTask SendOwedEofAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                bool owed;
                lock (_gate)
                {
                    owed = _eofOwed;
                }

                if (owed)
                {
                    await SendEofNowAsync(cancellationToken).ConfigureAwait(false);
                }
            }
            finally
            {
                _sendLock.Release();
            }
        }
        catch (OperationCanceledException)
        {
            _connection.QueueEof(this);
            throw;
        }
    }

    /// <summary>Queues the owed EOF. The caller holds <see cref="_sendLock"/>. If this is cancelled, the EOF stays owed.</summary>
    private async ValueTask SendEofNowAsync(CancellationToken cancellationToken)
    {
        await _connection.SendAsync(SimpleMessage(MessageNumber.ChannelEof), cancellationToken).ConfigureAwait(false);
        lock (_gate)
        {
            _eofOwed = false;
        }
    }

    private void FinishIfClosed()
    {
        bool done;
        lock (_gate)
        {
            done = _closeSent && !_closeOwed && _closeReceived;
            _failure ??= done ? new SshConnectionException("The channel is closed.") : null;
        }

        if (done)
        {
            ReleaseWaiters(_failure!);
            _connection.Forget(this);
            _closed.TrySetResult();
        }
    }

    private void ReleaseWaiters(Exception failure)
    {
        TaskCompletionSource? window;
        TaskCompletionSource<bool>? reply;
        lock (_gate)
        {
            window = _windowWaiter;
            reply = _requestReply;
            _windowWaiter = null;
            _requestReply = null;
        }

        window?.TrySetResult();
        reply?.TrySetException(failure);
    }

    private void ThrowIfUnusable()
    {
        if (_failure is { } failure)
        {
            throw new SshConnectionException("The channel is closed.", failure);
        }

        if (_closeSent || _closeReceived)
        {
            throw new SshConnectionException("The channel is closed.");
        }
    }

    private async ValueTask<int> ReserveWindowAsync(int wanted, CancellationToken cancellationToken)
    {
        while (true)
        {
            Task wait;
            lock (_gate)
            {
                ThrowIfUnusable();
                if (_sendWindow > 0)
                {
                    int chunk = (int)Math.Min(Math.Min(_sendWindow, _remoteMaxPacket), wanted);
                    _sendWindow -= chunk;
                    return chunk;
                }

                _windowWaiter ??= new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                wait = _windowWaiter.Task;
            }

            await wait.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private async ValueTask SendDataAsync(ReadOnlyMemory<byte> data, uint? extendedType, CancellationToken cancellationToken)
    {
        await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (_gate)
            {
                ThrowIfUnusable();
            }

            ValueTask send;
            SshWriter writer = new(data.Length + 16);
            try
            {
                writer.WriteByte(extendedType is null ? MessageNumber.ChannelData : MessageNumber.ChannelExtendedData);
                writer.WriteUInt32(RemoteId);
                if (extendedType is { } type)
                {
                    writer.WriteUInt32(type);
                }

                writer.WriteBinary(data.Span);
                send = _connection.SendAsync(writer.Written, cancellationToken);
            }
            finally
            {
                writer.Dispose();
            }

            await send.ConfigureAwait(false);
        }
        finally
        {
            _sendLock.Release();
        }
    }

    private byte[] SimpleMessage(byte message)
    {
        byte[] payload = new byte[5];
        payload[0] = message;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1), RemoteId);
        return payload;
    }

    /// <summary>Sends a small message unless this side has closed. After CLOSE it has nowhere to go, so it's dropped.</summary>
    private async ValueTask SendOrderedAsync(byte[] payload, CancellationToken cancellationToken)
    {
        await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (_gate)
            {
                if (_closeSent)
                {
                    return;
                }
            }

            await _connection.SendAsync(payload, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _sendLock.Release();
        }
    }

    private async ValueTask SendRequestMessageAsync(string type, bool wantReply, byte[] data, CancellationToken cancellationToken)
    {
        byte[] payload;
        SshWriter writer = new(data.Length + type.Length + 16);
        try
        {
            writer.WriteByte(MessageNumber.ChannelRequest);
            writer.WriteUInt32(RemoteId);
            writer.WriteUtf8String(type);
            writer.WriteBoolean(wantReply);
            writer.WriteRaw(data);
            payload = writer.ToArray();
        }
        finally
        {
            writer.Dispose();
        }

        await SendOrderedAsync(payload, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The application's side of the request queue. Taking a request gives back what it cost.</summary>
    private sealed class RequestReader(SshChannel owner, ChannelReader<IncomingChannelRequest> inner) : ChannelReader<IncomingChannelRequest>
    {
        public override Task Completion => inner.Completion;

        public override bool CanCount => inner.CanCount;

        public override int Count => inner.Count;

        public override bool CanPeek => inner.CanPeek;

        public override bool TryPeek([MaybeNullWhen(false)] out IncomingChannelRequest item) => inner.TryPeek(out item);

        public override bool TryRead([MaybeNullWhen(false)] out IncomingChannelRequest item)
        {
            if (!inner.TryRead(out item))
            {
                return false;
            }

            owner.OnRequestTaken(item);
            return true;
        }

        public override ValueTask<bool> WaitToReadAsync(CancellationToken cancellationToken = default) => inner.WaitToReadAsync(cancellationToken);
    }
}

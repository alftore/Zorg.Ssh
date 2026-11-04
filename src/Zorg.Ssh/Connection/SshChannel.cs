using System;
using System.Buffers;
using System.Buffers.Binary;
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
/// </summary>
internal sealed class SshChannel : IAsyncDisposable
{
    /// <summary>The window we grant. Large enough to keep a fast link busy at a sensible memory cost.</summary>
    public const uint DefaultWindow = 2 * 1024 * 1024;

    /// <summary>The largest data packet we accept and send.</summary>
    public const uint MaxPacket = 32 * 1024;

    private const int MaxQueuedRequests = 16;

    private readonly SshConnection _connection;
    private readonly Lock _gate = new();
    private readonly Pipe _output = NewPipe();
    private readonly Pipe _errorOutput = NewPipe();
    private readonly SemaphoreSlim _requestLock = new(1, 1);
    private readonly TaskCompletionSource _closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Channel<IncomingChannelRequest> _requests = System.Threading.Channels.Channel.CreateBounded<IncomingChannelRequest>(MaxQueuedRequests);

    private long _sendWindow;
    private uint _remoteMaxPacket;
    private long _receiveWindow = DefaultWindow;
    private uint _consumed;
    private TaskCompletionSource? _windowWaiter;
    private TaskCompletionSource<bool>? _requestReply;
    private bool _eofSent;
    private bool _eofReceived;
    private bool _closeSent;
    private bool _closeReceived;
    private Exception? _failure;

    public SshChannel(SshConnection connection, uint localId)
    {
        _connection = connection;
        LocalId = localId;
        Output = new ChannelReadStream(this, _output.Reader);
        ErrorOutput = new ChannelReadStream(this, _errorOutput.Reader);
        Input = new ChannelWriteStream(this);
    }

    public uint LocalId { get; }

    public uint RemoteId { get; private set; }

    /// <summary>Gets the stream of channel data.</summary>
    public Stream Output { get; }

    /// <summary>Gets the stream of extended data: stderr for a session.</summary>
    public Stream ErrorOutput { get; }

    /// <summary>Gets the stream that sends channel data. Disposing it sends EOF.</summary>
    public Stream Input { get; }

    /// <summary>Gets the exit status, once the peer has sent one.</summary>
    public int? ExitCode { get; private set; }

    /// <summary>Gets the name of the signal that ended the process, once the peer has sent one.</summary>
    public string? ExitSignal { get; private set; }

    /// <summary>Gets a task that completes when both sides have closed. It never faults.</summary>
    public Task Closed => _closed.Task;

    /// <summary>Gets requests the peer sent, for a server. Clients handle theirs inside the channel.</summary>
    public ChannelReader<IncomingChannelRequest> Requests => _requests.Reader;

    /// <summary>Gets or sets whether requests go to <see cref="Requests"/>. Clients leave this off.</summary>
    public bool QueueIncomingRequests { get; set; }

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
        while (!data.IsEmpty)
        {
            int chunk = await ReserveWindowAsync(data.Length, cancellationToken).ConfigureAwait(false);
            await SendDataAsync(data[..chunk], extendedType, cancellationToken).ConfigureAwait(false);
            data = data[chunk..];
        }
    }

    /// <summary>Sends EOF. Safe to call more than once.</summary>
    public async ValueTask SendEofAsync(CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            if (_eofSent || _closeSent)
            {
                return;
            }

            _eofSent = true;
        }

        await SendSimpleAsync(MessageNumber.ChannelEof, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Sends CLOSE. Safe to call more than once. The channel ends when the peer's CLOSE arrives.</summary>
    public async ValueTask CloseAsync(CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            if (_closeSent)
            {
                return;
            }

            _closeSent = true;
        }

        await SendSimpleAsync(MessageNumber.ChannelClose, cancellationToken).ConfigureAwait(false);
        FinishIfClosed();
    }

    /// <summary>Sends a request and waits for the reply. <paramref name="data"/> is what follows <c>want reply</c>.</summary>
    public async ValueTask<bool> SendRequestAsync(string type, byte[] data, CancellationToken cancellationToken)
    {
        await _requestLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            TaskCompletionSource<bool> reply = new(TaskCreationOptions.RunContinuationsAsynchronously);
            lock (_gate)
            {
                ThrowIfFailed();
                _requestReply = reply;
            }

            await SendRequestMessageAsync(type, wantReply: true, data, cancellationToken).ConfigureAwait(false);
            return await reply.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
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
        SendSimpleAsync(success ? MessageNumber.ChannelSuccess : MessageNumber.ChannelFailure, cancellationToken);

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
        lock (_gate)
        {
            if (_eofReceived)
            {
                throw new SshProtocolException("The peer sent channel data after EOF.");
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
        }

        // No pause threshold is set, so this flush completes at once. The window is what bounds the pipe.
        PipeWriter writer = (extended ? _errorOutput : _output).Writer;
        writer.Write(data);
        ValueTask<FlushResult> flush = writer.FlushAsync(CancellationToken.None);
        if (flush.IsCompletedSuccessfully && flush.Result.IsCompleted)
        {
            // Nobody will read this stream any more, so the data is consumed as it arrives.
            OnConsumed(data.Length);
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

    /// <summary>Returns true if we must answer with our own CLOSE.</summary>
    public bool OnClose()
    {
        bool reply;
        lock (_gate)
        {
            if (_closeReceived)
            {
                throw new SshProtocolException("The peer closed a channel twice.");
            }

            _closeReceived = true;
            reply = !_closeSent;
            _closeSent = true;
        }

        _output.Writer.Complete();
        _errorOutput.Writer.Complete();
        _requests.Writer.TryComplete();
        if (!reply)
        {
            FinishIfClosed();
        }

        return reply;
    }

    /// <summary>Marks the end of the exchange of CLOSE messages when we've answered in the receive loop.</summary>
    public void FinishIfClosed()
    {
        bool done;
        lock (_gate)
        {
            done = _closeSent && _closeReceived;
            _failure ??= done ? new SshConnectionException("The channel is closed.") : null;
        }

        if (done)
        {
            ReleaseWaiters(_failure!);
            _connection.Forget(this);
            _closed.TrySetResult();
        }
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
        if (type == "exit-status")
        {
            SshReader reader = new(data);
            uint status = reader.ReadUInt32();
            ExitCode = unchecked((int)status);
            return false;
        }

        if (type == "exit-signal")
        {
            SshReader reader = new(data);
            ExitSignal = reader.ReadUtf8String();
            return false;
        }

        if (QueueIncomingRequests)
        {
            if (!_requests.Writer.TryWrite(new IncomingChannelRequest(type, wantReply, data.ToArray())))
            {
                throw new SshProtocolException("The peer sent too many channel requests at once.");
            }

            return false;
        }

        return wantReply;
    }

    /// <summary>Fails everything waiting on this channel, because the connection has ended.</summary>
    public void OnConnectionFailed(Exception failure)
    {
        lock (_gate)
        {
            _failure ??= failure;
            _closeSent = true;
            _closeReceived = true;
        }

        _output.Writer.Complete(failure);
        _errorOutput.Writer.Complete(failure);
        _requests.Writer.TryComplete();
        ReleaseWaiters(failure);
        _closed.TrySetResult();
    }

    /// <summary>Credits data the application has read, and grows the window once half of it is used.</summary>
    public void OnConsumed(int bytes)
    {
        uint credit = 0;
        lock (_gate)
        {
            _consumed += (uint)bytes;
            if (_consumed >= DefaultWindow / 2 && !_closeSent)
            {
                credit = _consumed;
                _consumed = 0;
                _receiveWindow += credit;
            }
        }

        if (credit != 0)
        {
            _connection.QueueWindowAdjust(this, credit);
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
            // The channel can't be closed politely, because the connection has gone.
        }

        await Output.DisposeAsync().ConfigureAwait(false);
        await ErrorOutput.DisposeAsync().ConfigureAwait(false);
        await Input.DisposeAsync().ConfigureAwait(false);
        _requestLock.Dispose();
    }

    private static Pipe NewPipe() => new(new PipeOptions(pauseWriterThreshold: 0, useSynchronizationContext: false));

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

    private void ThrowIfFailed()
    {
        if (_failure is { } failure)
        {
            throw new SshConnectionException("The channel is closed.", failure);
        }
    }

    private async ValueTask<int> ReserveWindowAsync(int wanted, CancellationToken cancellationToken)
    {
        while (true)
        {
            Task wait;
            lock (_gate)
            {
                ThrowIfFailed();
                if (_eofSent || _closeSent)
                {
                    throw new SshConnectionException("The channel's input is closed.");
                }

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

    private ValueTask SendSimpleAsync(byte message, CancellationToken cancellationToken)
    {
        Span<byte> payload = stackalloc byte[5];
        payload[0] = message;
        BinaryPrimitives.WriteUInt32BigEndian(payload[1..], RemoteId);
        return _connection.SendAsync(payload, cancellationToken);
    }

    private async ValueTask SendRequestMessageAsync(string type, bool wantReply, byte[] data, CancellationToken cancellationToken)
    {
        ValueTask send;
        SshWriter writer = new(data.Length + type.Length + 16);
        try
        {
            writer.WriteByte(MessageNumber.ChannelRequest);
            writer.WriteUInt32(RemoteId);
            writer.WriteUtf8String(type);
            writer.WriteBoolean(wantReply);
            writer.WriteRaw(data);
            send = _connection.SendAsync(writer.Written, cancellationToken);
        }
        finally
        {
            writer.Dispose();
        }

        await send.ConfigureAwait(false);
    }
}

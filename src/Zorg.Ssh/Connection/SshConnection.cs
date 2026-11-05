using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Transport;

namespace Zorg.Ssh.Connection;

/// <summary>
/// The connection protocol (RFC 4254), for either role, on an authenticated transport. It owns the one
/// receive loop. Everything the loop runs is synchronous: it parses, copies into bounded per-channel buffers,
/// and sends replies with <see cref="SshTransport.SendControl"/>. So nothing can stop it reading, not a slow
/// reader, a full send queue or a parked rekey (Go CVE-2026-39830, and design rule T1).
/// </summary>
internal sealed class SshConnection : IAsyncDisposable
{
    public const int OpenFailureProhibited = 1;
    public const int OpenFailureConnectFailed = 2;
    public const int OpenFailureUnknownType = 3;
    public const int OpenFailureResourceShortage = 4;

    private const string SessionChannel = "session";
    private const string DirectTcpChannel = "direct-tcpip";
    private const string ForwardedTcpChannel = "forwarded-tcpip";
    private const int MaxPendingOpens = 16;
    private const int MaxPendingGlobalRequests = 32;

    private static readonly TimeSpan Grace = TimeSpan.FromSeconds(5);

    private readonly SshTransport _transport;
    private readonly int _maxChannels;
    private readonly Lock _gate = new();
    private readonly Dictionary<uint, SshChannel> _channels = [];
    private readonly Dictionary<uint, TaskCompletionSource<SshChannel>> _opening = [];

    // Replies carry no id, so they're matched by order: first sent, first answered (RFC 4254 section 4).
    private readonly LinkedList<PendingGlobalRequest> _globalRequests = new();

    // Not disposed, like the channel's: it holds nothing without AvailableWaitHandle, and a late caller must get a clean error.
#pragma warning disable CA2213
    private readonly SemaphoreSlim _globalRequestOrder = new(1, 1);
#pragma warning restore CA2213

    // Unbounded in type only: a channel has two entries at most, a credit and a close.
    private readonly Channel<(SshChannel Channel, bool Close)> _deferred =
        System.Threading.Channels.Channel.CreateUnbounded<(SshChannel, bool)>(new UnboundedChannelOptions { SingleReader = true });
    private readonly Channel<IncomingChannelOpen> _incoming =
        System.Threading.Channels.Channel.CreateBounded<IncomingChannelOpen>(MaxPendingOpens);
    private readonly CancellationTokenSource _stop = new();
    private readonly CancellationToken _stopToken;
    private readonly TaskCompletionSource _ended = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private uint _nextId;
    private int _incomingSessions;
    private Task? _loop;
    private Task? _senderLoop;
    private Exception? _failure;

    public SshConnection(SshTransport transport, int maxChannels = 256)
    {
        _transport = transport;
        _maxChannels = maxChannels;

        // Kept apart from the source, which is gone by the time a late accept might ask for it.
        _stopToken = _stop.Token;
    }

    /// <summary>Gets or sets whether the peer may open session channels. A client leaves this off.</summary>
    public bool AcceptIncomingChannels { get; init; }

    /// <summary>Gets or sets whether the peer may open direct-tcpip channels, for a server that has a handler for them.</summary>
    public bool AcceptDirectTcp { get; init; }

    /// <summary>
    /// Gets or sets who decides a forwarded-tcpip open, for a client. It runs in the receive loop, so it must not
    /// wait. It returns 0 if it took the open, and must then answer with <see cref="AcceptIncomingAsync"/> or
    /// <see cref="RefuseIncomingAsync"/>, or else the reason to refuse with. Without it, every such open is refused.
    /// </summary>
    public Func<IncomingChannelOpen, int>? ForwardedChannelHandler { get; init; }

    /// <summary>
    /// Gets what the peer opened, for a server. A session arrives confirmed, with its <see cref="IncomingChannelOpen.Channel"/>.
    /// A direct-tcpip open arrives without one, waiting for <see cref="AcceptIncomingAsync"/> or <see cref="RefuseIncomingAsync"/>.
    /// </summary>
    public ChannelReader<IncomingChannelOpen> IncomingChannels => _incoming.Reader;

    /// <summary>Gets a task that completes when the connection ends. It never faults.</summary>
    public Task Ended => _ended.Task;

    /// <summary>Gets the transport.</summary>
    public SshTransport Transport => _transport;

    /// <summary>Starts the receive loop. Call once, after auth.</summary>
    public void Start()
    {
        _loop = Task.Run(ReceiveLoopAsync, CancellationToken.None);
        _senderLoop = Task.Run(SenderLoopAsync, CancellationToken.None);
    }

    /// <summary>Opens a channel and waits for the peer to confirm it. <paramref name="extra"/> is what the channel type adds to the message.</summary>
    public async Task<SshChannel> OpenChannelAsync(string type, CancellationToken cancellationToken, byte[]? extra = null)
    {
        SshChannel channel;
        TaskCompletionSource<SshChannel> confirmed = new(TaskCreationOptions.RunContinuationsAsynchronously);
        lock (_gate)
        {
            if (_failure is { } failure)
            {
                throw new SshConnectionException("The connection has ended. Connect again to continue.", failure);
            }

            channel = Register();
            _opening.Add(channel.LocalId, confirmed);
        }

        ValueTask send;
        SshWriter writer = new(64 + (extra?.Length ?? 0));
        try
        {
            writer.WriteByte(MessageNumber.ChannelOpen);
            writer.WriteUtf8String(type);
            writer.WriteUInt32(channel.LocalId);
            writer.WriteUInt32(SshChannel.DefaultWindow);
            writer.WriteUInt32(SshChannel.MaxPacket);
            writer.WriteRaw(extra);
            send = SendAsync(writer.Written, cancellationToken);
        }
        finally
        {
            writer.Dispose();
        }

        try
        {
            await send.ConfigureAwait(false);
        }
        catch
        {
            // The peer never heard of it, so there's nothing to wait for.
            lock (_gate)
            {
                _opening.Remove(channel.LocalId);
                _channels.Remove(channel.LocalId);
            }

            throw;
        }

        try
        {
            return await confirmed.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // The peer's answer is still on its way, and the slot stays taken until it arrives.
            _ = CloseWhenConfirmedAsync(confirmed.Task);
            throw;
        }
    }

    /// <summary>
    /// Confirms a channel the peer opened, and returns it. Until now it had no local id, so nothing the peer
    /// sends can reach it early. A failure here ends only this open.
    /// </summary>
    public async Task<SshChannel> AcceptIncomingAsync(IncomingChannelOpen open)
    {
        SshChannel? channel = null;
        lock (_gate)
        {
            if (_failure is { } failure)
            {
                throw new SshConnectionException("The connection has ended. Connect again to continue.", failure);
            }

            if (_channels.Count < _maxChannels)
            {
                channel = Register();
            }
        }

        if (channel is null)
        {
            await RefuseIncomingAsync(open, OpenFailureResourceShortage, "too many channels").ConfigureAwait(false);
            throw new SshException("Too many channels are open on this connection, so a forwarded connection was refused.");
        }

        ValueTask send;
        SshWriter writer = new(32);
        try
        {
            channel.SetRemote(open.RemoteId, open.Window, open.MaxPacket);
            WriteConfirmation(ref writer, open.RemoteId, channel.LocalId);
            send = SendAsync(writer.Written, _stopToken);
        }
        catch
        {
            Forget(channel);
            throw;
        }
        finally
        {
            writer.Dispose();
        }

        try
        {
            await send.ConfigureAwait(false);
        }
        catch
        {
            Forget(channel);
            throw;
        }

        return channel;
    }

    /// <summary>Refuses a channel the peer opened. It goes through the send queue, so it isn't for the receive loop.</summary>
    public async ValueTask RefuseIncomingAsync(IncomingChannelOpen open, int reason, string text)
    {
        ValueTask send;
        SshWriter writer = new(64);
        try
        {
            WriteOpenFailure(ref writer, open.RemoteId, reason, text);
            send = SendAsync(writer.Written, _stopToken);
        }
        finally
        {
            writer.Dispose();
        }

        await send.ConfigureAwait(false);
    }

    /// <summary>
    /// Sends a global request that wants a reply, and returns once it's on its way. The task it returns ends with
    /// the data of a success reply, or null for a failure. If nobody awaits that task, the request still holds its
    /// place in the line, so later replies still find their own requests.
    /// <paramref name="onReply"/> runs in the receive loop before the task completes, so whatever it does happens
    /// before the next message is read. It must not wait.
    /// </summary>
    public async Task<Task<byte[]?>> StartGlobalRequestAsync(string name, byte[] data, Action<byte[]?>? onReply, CancellationToken cancellationToken)
    {
        byte[] payload;
        SshWriter writer = new(32 + name.Length + data.Length);
        try
        {
            writer.WriteByte(MessageNumber.GlobalRequest);
            writer.WriteUtf8String(name);
            writer.WriteBoolean(true);
            writer.WriteRaw(data);
            payload = writer.ToArray();
        }
        finally
        {
            writer.Dispose();
        }

        PendingGlobalRequest pending = new(onReply);

        // Held across the send, so the order of the line is the order on the wire.
        await _globalRequestOrder.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (_gate)
            {
                if (_failure is { } failure)
                {
                    throw new SshConnectionException("The connection has ended. Connect again to continue.", failure);
                }

                if (_globalRequests.Count >= MaxPendingGlobalRequests)
                {
                    throw new SshException("Too many requests are waiting for the server. It may have stopped answering.");
                }

                _globalRequests.AddLast(pending);
            }

            try
            {
                await SendAsync(payload, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                // Never sent, so no reply will come for it.
                lock (_gate)
                {
                    _globalRequests.Remove(pending);
                }

                throw;
            }
        }
        finally
        {
            _globalRequestOrder.Release();
        }

        return pending.Reply.Task;
    }

    public ValueTask SendAsync(scoped ReadOnlySpan<byte> payload, CancellationToken cancellationToken) =>
        _transport.SendAsync(payload, cancellationToken);

    /// <summary>Asks for a channel's pending credit to be sent. Called at most once until it's taken.</summary>
    public void QueueWindowAdjust(SshChannel channel) => _deferred.Writer.TryWrite((channel, false));

    /// <summary>Asks for a CLOSE, which goes behind anything queued for the channel. The receive loop can't wait for that itself.</summary>
    public void QueueClose(SshChannel channel) => _deferred.Writer.TryWrite((channel, true));

    /// <summary>Frees a session slot taken when the peer opened a channel. Called when the whole session is over.</summary>
    public void ReleaseIncomingSession()
    {
        lock (_gate)
        {
            _incomingSessions--;
        }
    }

    /// <summary>Forgets a fully closed channel, so its id can't be used again.</summary>
    public void Forget(SshChannel channel)
    {
        lock (_gate)
        {
            _channels.Remove(channel.LocalId);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync().ConfigureAwait(false);

        // Closing first unblocks a receive loop stuck in a stream that ignores cancellation.
        await _transport.CloseAsync().ConfigureAwait(false);
        _deferred.Writer.TryComplete();
        await WaitForAsync(_loop).ConfigureAwait(false);
        await WaitForAsync(_senderLoop).ConfigureAwait(false);
        await _transport.DisposeAsync().ConfigureAwait(false);
        _stop.Dispose();
    }

    private static async Task WaitForAsync(Task? task)
    {
        if (task is null)
        {
            return;
        }

        try
        {
            await task.WaitAsync(Grace).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            // The transport keeps what that loop might still be using.
        }
    }

    private static async Task CloseWhenConfirmedAsync(Task<SshChannel> confirmed)
    {
        try
        {
            SshChannel channel = await confirmed.ConfigureAwait(false);
            await channel.DisposeAsync().ConfigureAwait(false);
        }
        catch (SshException)
        {
            // Refused, or the connection ended. Either way the slot has been freed.
        }
    }

    private SshChannel Register()
    {
        if (_channels.Count >= _maxChannels)
        {
            throw new SshException("Too many channels are open on this connection. Close one first.");
        }

        while (_channels.ContainsKey(_nextId))
        {
            _nextId++;
        }

        SshChannel channel = new(this, _nextId++);
        _channels.Add(channel.LocalId, channel);
        return channel;
    }

    private async Task SenderLoopAsync()
    {
        try
        {
            await foreach ((SshChannel channel, bool close) in _deferred.Reader.ReadAllAsync(_stop.Token).ConfigureAwait(false))
            {
                if (close)
                {
                    await channel.CloseAsync(_stop.Token).ConfigureAwait(false);
                }
                else
                {
                    await channel.GrantCreditAsync(_stop.Token).ConfigureAwait(false);
                }
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or SshException)
        {
            // The receive loop reports the failure.
        }
    }

    private async Task ReceiveLoopAsync()
    {
        Exception failure;
        try
        {
            while (true)
            {
                ReadOnlyMemory<byte> message = await _transport.ReceiveAsync(_stop.Token).ConfigureAwait(false);
                Dispatch(message.Span);
            }
        }
        catch (OperationCanceledException ex) when (_stop.IsCancellationRequested)
        {
            failure = new SshConnectionException("The connection was closed by this side. Connect again to continue.", ex);
        }
        catch (SshException ex)
        {
            failure = ex;
        }
#pragma warning disable CA1031 // A bug here must end the connection, not leave every caller waiting.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            failure = new SshException("The connection failed unexpectedly. This is a bug in Zorg.Ssh.", ex);
        }

        await EndAsync(failure).ConfigureAwait(false);
    }

    private async ValueTask EndAsync(Exception failure)
    {
        SshChannel[] channels;
        TaskCompletionSource<SshChannel>[] opening;
        PendingGlobalRequest[] requests;
        lock (_gate)
        {
            _failure ??= failure;
            channels = [.. _channels.Values];
            opening = [.. _opening.Values];
            requests = [.. _globalRequests];
            _channels.Clear();
            _opening.Clear();
            _globalRequests.Clear();
        }

        foreach (SshChannel channel in channels)
        {
            channel.OnConnectionFailed(failure);
        }

        foreach (TaskCompletionSource<SshChannel> open in opening)
        {
            open.TrySetException(new SshConnectionException("The connection ended while opening a channel.", failure));
        }

        foreach (PendingGlobalRequest request in requests)
        {
            request.Reply.TrySetException(new SshConnectionException("The connection ended before the server answered.", failure));
        }

        _incoming.Writer.TryComplete();
        _ended.TrySetResult();

        // Tells the peer if we can, and closes the socket, so a failure can't leave a half-open connection.
        await _transport.CloseAsync().ConfigureAwait(false);
    }

    private void Dispatch(ReadOnlySpan<byte> message)
    {
        switch (message[0])
        {
            case MessageNumber.GlobalRequest:
                HandleGlobalRequest(message);
                break;
            case MessageNumber.RequestSuccess:
            case MessageNumber.RequestFailure:
                HandleGlobalReply(message);
                break;
            case MessageNumber.ChannelOpen:
                HandleChannelOpen(message);
                break;
            case MessageNumber.ChannelOpenConfirmation:
                HandleOpenConfirmation(message);
                break;
            case MessageNumber.ChannelOpenFailure:
                HandleOpenFailure(message);
                break;
            case MessageNumber.ChannelWindowAdjust:
                HandleWindowAdjust(message);
                break;
            case MessageNumber.ChannelData:
                HandleData(message, extended: false);
                break;
            case MessageNumber.ChannelExtendedData:
                HandleData(message, extended: true);
                break;
            case MessageNumber.ChannelEof:
                FindChannel(message).OnEof();
                break;
            case MessageNumber.ChannelClose:
                HandleClose(message);
                break;
            case MessageNumber.ChannelRequest:
                HandleChannelRequest(message);
                break;
            case MessageNumber.ChannelSuccess:
                FindChannel(message).OnRequestReply(true);
                break;
            case MessageNumber.ChannelFailure:
                FindChannel(message).OnRequestReply(false);
                break;
            default:
                // A number in the connection range with no meaning.
                _transport.SendUnimplementedForLastPacket();
                break;
        }
    }

    private void HandleGlobalRequest(ReadOnlySpan<byte> message)
    {
        SshReader reader = new(message);
        reader.ReadByte();
        reader.ReadBinary();
        if (reader.ReadBoolean())
        {
            _transport.SendControl([MessageNumber.RequestFailure]);
        }
    }

    /// <summary>
    /// Hands a reply to the oldest waiting request. A reply with no request waiting is dropped, never queued: it
    /// costs nothing, and can't block this loop or answer a later request (Go CVE-2026-39830).
    /// </summary>
    private void HandleGlobalReply(ReadOnlySpan<byte> message)
    {
        PendingGlobalRequest? pending;
        lock (_gate)
        {
            pending = _globalRequests.First?.Value;
            if (pending is null)
            {
                return;
            }

            _globalRequests.RemoveFirst();
        }

        byte[]? reply = message[0] == MessageNumber.RequestSuccess ? message[1..].ToArray() : null;
        try
        {
            pending.OnReply?.Invoke(reply);
        }
        catch (SshException ex)
        {
            pending.Reply.TrySetException(ex);
            throw;
        }

        pending.Reply.TrySetResult(reply);
    }

    private void HandleChannelOpen(ReadOnlySpan<byte> message)
    {
        SshReader reader = new(message);
        reader.ReadByte();
        string type = reader.ReadUtf8String();
        uint remoteId = reader.ReadUInt32();
        uint window = reader.ReadUInt32();
        uint maxPacket = reader.ReadUInt32();

        if (type == ForwardedTcpChannel && ForwardedChannelHandler is { } handler)
        {
            int refusal = handler(NewDeferredOpen(type, remoteId, window, maxPacket, reader));
            if (refusal != 0)
            {
                SendOpenFailure(remoteId, refusal, "not allowed");
            }

            return;
        }

        if (!AcceptIncomingChannels)
        {
            SendOpenFailure(remoteId, OpenFailureProhibited, "not allowed");
            return;
        }

        switch (type)
        {
            case SessionChannel:
                OpenIncomingSession(remoteId, window, maxPacket);
                break;
            case DirectTcpChannel when AcceptDirectTcp:
                QueueDirectTcpOpen(NewDeferredOpen(type, remoteId, window, maxPacket, reader));
                break;
            case DirectTcpChannel:
                SendOpenFailure(remoteId, OpenFailureProhibited, "not allowed");
                break;
            default:
                SendOpenFailure(remoteId, OpenFailureUnknownType, "unsupported channel type");
                break;
        }
    }

    private static IncomingChannelOpen NewDeferredOpen(string type, uint remoteId, uint window, uint maxPacket, SshReader reader)
    {
        // Checked here, because the channel itself comes later, and away from this loop.
        if (maxPacket == 0)
        {
            throw new SshProtocolException("The peer sent a channel maximum packet size of zero.");
        }

        return new IncomingChannelOpen(type, remoteId, window, maxPacket, reader.RemainingSpan.ToArray());
    }

    private bool TryTakeIncomingSlot()
    {
        lock (_gate)
        {
            // Counted by session, not by channel: a closed channel can still have its handler running.
            if (_incomingSessions < _maxChannels)
            {
                _incomingSessions++;
                return true;
            }
        }

        return false;
    }

    private void QueueDirectTcpOpen(IncomingChannelOpen open)
    {
        if (!TryTakeIncomingSlot())
        {
            SendOpenFailure(open.RemoteId, OpenFailureResourceShortage, "too many channels");
        }
        else if (!_incoming.Writer.TryWrite(open))
        {
            ReleaseIncomingSession();
            SendOpenFailure(open.RemoteId, OpenFailureResourceShortage, "busy");
        }
    }

    private void OpenIncomingSession(uint remoteId, uint window, uint maxPacket)
    {
        if (!TryTakeIncomingSlot())
        {
            SendOpenFailure(remoteId, OpenFailureResourceShortage, "too many channels");
            return;
        }

        SshChannel channel;
        lock (_gate)
        {
            channel = Register();
        }

        channel.SetRemote(remoteId, window, maxPacket);
        channel.QueueIncomingRequests = true;
        if (!_incoming.Writer.TryWrite(new IncomingChannelOpen(SessionChannel, remoteId, window, maxPacket, []) { Channel = channel }))
        {
            Forget(channel);
            ReleaseIncomingSession();
            SendOpenFailure(remoteId, OpenFailureResourceShortage, "busy");
            return;
        }

        SshWriter writer = new(32);
        try
        {
            WriteConfirmation(ref writer, remoteId, channel.LocalId);
            _transport.SendControl(writer.Written);
        }
        finally
        {
            writer.Dispose();
        }
    }

    private static void WriteConfirmation(ref SshWriter writer, uint remoteId, uint localId)
    {
        writer.WriteByte(MessageNumber.ChannelOpenConfirmation);
        writer.WriteUInt32(remoteId);
        writer.WriteUInt32(localId);
        writer.WriteUInt32(SshChannel.DefaultWindow);
        writer.WriteUInt32(SshChannel.MaxPacket);
    }

    private static void WriteOpenFailure(ref SshWriter writer, uint remoteId, int reason, string text)
    {
        writer.WriteByte(MessageNumber.ChannelOpenFailure);
        writer.WriteUInt32(remoteId);
        writer.WriteUInt32((uint)reason);
        writer.WriteUtf8String(text);
        writer.WriteUtf8String(string.Empty);
    }

    private void SendOpenFailure(uint remoteId, int reason, string text)
    {
        SshWriter writer = new(64);
        try
        {
            WriteOpenFailure(ref writer, remoteId, reason, text);
            _transport.SendControl(writer.Written);
        }
        finally
        {
            writer.Dispose();
        }
    }

    private void HandleOpenConfirmation(ReadOnlySpan<byte> message)
    {
        SshReader reader = new(message);
        reader.ReadByte();
        uint localId = reader.ReadUInt32();
        uint remoteId = reader.ReadUInt32();
        uint window = reader.ReadUInt32();
        uint maxPacket = reader.ReadUInt32();

        TaskCompletionSource<SshChannel>? waiter;
        SshChannel? channel;
        lock (_gate)
        {
            _opening.Remove(localId, out waiter);
            _channels.TryGetValue(localId, out channel);
        }

        if (waiter is null || channel is null)
        {
            throw new SshProtocolException("The peer confirmed a channel that isn't being opened.");
        }

        channel.SetRemote(remoteId, window, maxPacket);
        waiter.TrySetResult(channel);
    }

    private void HandleOpenFailure(ReadOnlySpan<byte> message)
    {
        SshReader reader = new(message);
        reader.ReadByte();
        uint localId = reader.ReadUInt32();
        uint code = reader.ReadUInt32();

        TaskCompletionSource<SshChannel>? waiter;
        lock (_gate)
        {
            _opening.Remove(localId, out waiter);
            _channels.Remove(localId);
        }

        if (waiter is null)
        {
            throw new SshProtocolException("The peer refused a channel that isn't being opened.");
        }

        waiter.TrySetException(new SshException($"The server refused to open the channel (reason {code}). It may have reached its session limit."));
    }

    private void HandleWindowAdjust(ReadOnlySpan<byte> message)
    {
        SshChannel channel = FindChannel(message);
        SshReader reader = new(message);
        reader.ReadRaw(5);
        channel.OnWindowAdjust(reader.ReadUInt32());
    }

    private void HandleData(ReadOnlySpan<byte> message, bool extended)
    {
        SshChannel channel = FindChannel(message);
        SshReader reader = new(message);
        reader.ReadRaw(5);
        if (extended)
        {
            reader.ReadUInt32();
        }

        ReadOnlySpan<byte> data = reader.ReadBinary();
        if (data.Length > SshChannel.MaxPacket)
        {
            throw new SshProtocolException("The peer sent a channel packet larger than the agreed maximum.");
        }

        channel.OnData(data, extended);
    }

    private void HandleClose(ReadOnlySpan<byte> message)
    {
        SshChannel channel = FindChannel(message);
        if (channel.OnClose())
        {
            QueueClose(channel);
        }
    }

    private void HandleChannelRequest(ReadOnlySpan<byte> message)
    {
        SshChannel channel = FindChannel(message);
        SshReader reader = new(message);
        reader.ReadRaw(5);
        string type = reader.ReadUtf8String();
        bool wantReply = reader.ReadBoolean();
        if (channel.OnRequest(type, wantReply, reader.RemainingSpan))
        {
            SendChannelMessage(MessageNumber.ChannelFailure, channel);
        }
    }

    private void SendChannelMessage(byte number, SshChannel channel)
    {
        Span<byte> payload = stackalloc byte[5];
        payload[0] = number;
        BinaryPrimitives.WriteUInt32BigEndian(payload[1..], channel.RemoteId);
        _transport.SendControl(payload);
    }

    private SshChannel FindChannel(ReadOnlySpan<byte> message)
    {
        SshReader reader = new(message);
        reader.ReadByte();
        uint id = reader.ReadUInt32();
        lock (_gate)
        {
            if (_channels.TryGetValue(id, out SshChannel? channel) && !_opening.ContainsKey(id))
            {
                return channel;
            }
        }

        throw new SshProtocolException("The peer sent a message for a channel that isn't open.");
    }
}

/// <summary>A channel the peer opened. <paramref name="Extra"/> is what its type adds to the message.</summary>
internal sealed record IncomingChannelOpen(string Type, uint RemoteId, uint Window, uint MaxPacket, byte[] Extra)
{
    /// <summary>Gets the channel, if it has been confirmed already.</summary>
    public SshChannel? Channel { get; init; }
}

/// <summary>A global request waiting for its reply.</summary>
internal sealed class PendingGlobalRequest(Action<byte[]?>? onReply)
{
    public Action<byte[]?>? OnReply { get; } = onReply;

    public TaskCompletionSource<byte[]?> Reply { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
}

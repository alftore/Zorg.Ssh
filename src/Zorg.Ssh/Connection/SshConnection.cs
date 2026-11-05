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
    private const int OpenFailureProhibited = 1;
    private const int OpenFailureUnknownType = 3;
    private const int OpenFailureResourceShortage = 4;
    private const int MaxPendingOpens = 16;

    private static readonly TimeSpan Grace = TimeSpan.FromSeconds(5);

    private readonly SshTransport _transport;
    private readonly int _maxChannels;
    private readonly Lock _gate = new();
    private readonly Dictionary<uint, SshChannel> _channels = [];
    private readonly Dictionary<uint, TaskCompletionSource<SshChannel>> _opening = [];

    // Unbounded in type only: a channel has two entries at most, a credit and a close.
    private readonly Channel<(SshChannel Channel, bool Close)> _deferred =
        System.Threading.Channels.Channel.CreateUnbounded<(SshChannel, bool)>(new UnboundedChannelOptions { SingleReader = true });
    private readonly Channel<IncomingChannelOpen> _incoming =
        System.Threading.Channels.Channel.CreateBounded<IncomingChannelOpen>(MaxPendingOpens);
    private readonly CancellationTokenSource _stop = new();
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
    }

    /// <summary>Gets or sets whether the peer may open channels. A client refuses them until forwarding exists.</summary>
    public bool AcceptIncomingChannels { get; init; }

    /// <summary>Gets channels the peer opened and we've confirmed, for a server.</summary>
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

    /// <summary>Opens a channel and waits for the peer to confirm it.</summary>
    public async Task<SshChannel> OpenChannelAsync(string type, CancellationToken cancellationToken)
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
        SshWriter writer = new(64);
        try
        {
            writer.WriteByte(MessageNumber.ChannelOpen);
            writer.WriteUtf8String(type);
            writer.WriteUInt32(channel.LocalId);
            writer.WriteUInt32(SshChannel.DefaultWindow);
            writer.WriteUInt32(SshChannel.MaxPacket);
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
        lock (_gate)
        {
            _failure ??= failure;
            channels = [.. _channels.Values];
            opening = [.. _opening.Values];
            _channels.Clear();
            _opening.Clear();
        }

        foreach (SshChannel channel in channels)
        {
            channel.OnConnectionFailed(failure);
        }

        foreach (TaskCompletionSource<SshChannel> open in opening)
        {
            open.TrySetException(new SshConnectionException("The connection ended while opening a channel.", failure));
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
                // We send no global requests with a reply yet, so any reply is unsolicited. Dropped, never queued.
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

    private void HandleChannelOpen(ReadOnlySpan<byte> message)
    {
        SshReader reader = new(message);
        reader.ReadByte();
        string type = reader.ReadUtf8String();
        uint remoteId = reader.ReadUInt32();
        uint window = reader.ReadUInt32();
        uint maxPacket = reader.ReadUInt32();
        byte[] extra = reader.RemainingSpan.ToArray();

        if (!AcceptIncomingChannels)
        {
            SendOpenFailure(remoteId, OpenFailureProhibited, "not allowed");
            return;
        }

        if (type != "session")
        {
            SendOpenFailure(remoteId, OpenFailureUnknownType, "unsupported channel type");
            return;
        }

        SshChannel? channel = null;
        lock (_gate)
        {
            // Counted by session, not by channel: a closed channel can still have its handler running.
            if (_incomingSessions < _maxChannels)
            {
                _incomingSessions++;
                channel = Register();
            }
        }

        if (channel is null)
        {
            SendOpenFailure(remoteId, OpenFailureResourceShortage, "too many channels");
            return;
        }

        channel.SetRemote(remoteId, window, maxPacket);
        channel.QueueIncomingRequests = true;
        if (!_incoming.Writer.TryWrite(new IncomingChannelOpen(channel, type, extra)))
        {
            Forget(channel);
            ReleaseIncomingSession();
            SendOpenFailure(remoteId, OpenFailureResourceShortage, "busy");
            return;
        }

        SshWriter writer = new(32);
        try
        {
            writer.WriteByte(MessageNumber.ChannelOpenConfirmation);
            writer.WriteUInt32(remoteId);
            writer.WriteUInt32(channel.LocalId);
            writer.WriteUInt32(SshChannel.DefaultWindow);
            writer.WriteUInt32(SshChannel.MaxPacket);
            _transport.SendControl(writer.Written);
        }
        finally
        {
            writer.Dispose();
        }
    }

    private void SendOpenFailure(uint remoteId, int reason, string text)
    {
        SshWriter writer = new(64);
        try
        {
            writer.WriteByte(MessageNumber.ChannelOpenFailure);
            writer.WriteUInt32(remoteId);
            writer.WriteUInt32((uint)reason);
            writer.WriteUtf8String(text);
            writer.WriteUtf8String(string.Empty);
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

/// <summary>A channel the peer opened.</summary>
internal sealed record IncomingChannelOpen(SshChannel Channel, string Type, byte[] Extra);

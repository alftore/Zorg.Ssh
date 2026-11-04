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
/// receive loop. The loop parses, copies into bounded per-channel buffers, and moves on: application code
/// runs elsewhere, so a slow reader can't stall rekeying or other channels (Go CVE-2026-39830).
/// </summary>
internal sealed class SshConnection : IAsyncDisposable
{
    private const int OpenFailureProhibited = 1;
    private const int OpenFailureUnknownType = 3;
    private const int OpenFailureResourceShortage = 4;
    private const int MaxPendingOpens = 16;

    private readonly SshTransport _transport;
    private readonly int _maxChannels;
    private readonly Lock _gate = new();
    private readonly Dictionary<uint, SshChannel> _channels = [];
    private readonly Dictionary<uint, TaskCompletionSource<SshChannel>> _opening = [];
    private readonly Channel<(SshChannel Channel, uint Credit)> _windowAdjusts =
        System.Threading.Channels.Channel.CreateUnbounded<(SshChannel, uint)>(new UnboundedChannelOptions { SingleReader = true });
    private readonly Channel<IncomingChannelOpen> _incoming =
        System.Threading.Channels.Channel.CreateBounded<IncomingChannelOpen>(MaxPendingOpens);
    private readonly CancellationTokenSource _stop = new();
    private readonly TaskCompletionSource _ended = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private uint _nextId;
    private Task? _loop;
    private Task? _windowLoop;
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
        _windowLoop = Task.Run(WindowLoopAsync, CancellationToken.None);
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

        await send.ConfigureAwait(false);
        return await confirmed.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    public ValueTask SendAsync(scoped ReadOnlySpan<byte> payload, CancellationToken cancellationToken) =>
        _transport.SendAsync(payload, cancellationToken);

    /// <summary>Queues a window grant. The number of entries is bounded by channels and the data they've received.</summary>
    public void QueueWindowAdjust(SshChannel channel, uint credit) => _windowAdjusts.Writer.TryWrite((channel, credit));

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
        if (_loop is not null)
        {
            await _loop.ConfigureAwait(false);
        }

        _windowAdjusts.Writer.TryComplete();
        if (_windowLoop is not null)
        {
            await _windowLoop.ConfigureAwait(false);
        }

        await _transport.DisposeAsync().ConfigureAwait(false);
        _stop.Dispose();
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

    private async Task WindowLoopAsync()
    {
        byte[] payload = new byte[9];
        try
        {
            await foreach ((SshChannel channel, uint credit) in _windowAdjusts.Reader.ReadAllAsync(_stop.Token).ConfigureAwait(false))
            {
                payload[0] = MessageNumber.ChannelWindowAdjust;
                BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1), channel.RemoteId);
                BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(5), credit);
                await SendAsync(payload, _stop.Token).ConfigureAwait(false);
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
                await DispatchAsync(message).ConfigureAwait(false);
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
        await _transport.DisposeAsync().ConfigureAwait(false);
    }

    private async ValueTask DispatchAsync(ReadOnlyMemory<byte> message)
    {
        byte number = message.Span[0];
        switch (number)
        {
            case MessageNumber.GlobalRequest:
                await HandleGlobalRequestAsync(message).ConfigureAwait(false);
                break;
            case MessageNumber.RequestSuccess:
            case MessageNumber.RequestFailure:
                // We send no global requests with a reply yet, so any reply is unsolicited. Dropped, never queued.
                break;
            case MessageNumber.ChannelOpen:
                await HandleChannelOpenAsync(message).ConfigureAwait(false);
                break;
            case MessageNumber.ChannelOpenConfirmation:
                HandleOpenConfirmation(message.Span);
                break;
            case MessageNumber.ChannelOpenFailure:
                HandleOpenFailure(message.Span);
                break;
            case MessageNumber.ChannelWindowAdjust:
                HandleWindowAdjust(message.Span);
                break;
            case MessageNumber.ChannelData:
                HandleData(message.Span, extended: false);
                break;
            case MessageNumber.ChannelExtendedData:
                HandleData(message.Span, extended: true);
                break;
            case MessageNumber.ChannelEof:
                FindChannel(message.Span).OnEof();
                break;
            case MessageNumber.ChannelClose:
                await HandleCloseAsync(message).ConfigureAwait(false);
                break;
            case MessageNumber.ChannelRequest:
                await HandleChannelRequestAsync(message).ConfigureAwait(false);
                break;
            case MessageNumber.ChannelSuccess:
                FindChannel(message.Span).OnRequestReply(true);
                break;
            case MessageNumber.ChannelFailure:
                FindChannel(message.Span).OnRequestReply(false);
                break;
            default:
                await SendUnimplementedAsync().ConfigureAwait(false);
                break;
        }
    }

    private ValueTask SendUnimplementedAsync()
    {
        // A number in the connection range with no meaning. The transport has the sequence number, and
        // the RFC reply carries it, so the transport sends this one.
        return _transport.SendUnimplementedForLastPacketAsync(_stop.Token);
    }

    private async ValueTask HandleGlobalRequestAsync(ReadOnlyMemory<byte> message)
    {
        bool wantReply;
        {
            SshReader reader = new(message.Span);
            reader.ReadByte();
            reader.ReadBinary();
            wantReply = reader.ReadBoolean();
        }

        if (wantReply)
        {
            await SendAsync([MessageNumber.RequestFailure], _stop.Token).ConfigureAwait(false);
        }
    }

    private async ValueTask HandleChannelOpenAsync(ReadOnlyMemory<byte> message)
    {
        string type;
        uint remoteId;
        uint window;
        uint maxPacket;
        byte[] extra;
        {
            SshReader reader = new(message.Span);
            reader.ReadByte();
            type = reader.ReadUtf8String();
            remoteId = reader.ReadUInt32();
            window = reader.ReadUInt32();
            maxPacket = reader.ReadUInt32();
            extra = reader.RemainingSpan.ToArray();
        }

        if (!AcceptIncomingChannels)
        {
            await SendOpenFailureAsync(remoteId, OpenFailureProhibited, "not allowed").ConfigureAwait(false);
            return;
        }

        if (type != "session")
        {
            await SendOpenFailureAsync(remoteId, OpenFailureUnknownType, "unsupported channel type").ConfigureAwait(false);
            return;
        }

        SshChannel channel;
        lock (_gate)
        {
            if (_channels.Count >= _maxChannels)
            {
                channel = null!;
            }
            else
            {
                channel = Register();
            }
        }

        if (channel is null)
        {
            await SendOpenFailureAsync(remoteId, OpenFailureResourceShortage, "too many channels").ConfigureAwait(false);
            return;
        }

        channel.SetRemote(remoteId, window, maxPacket);
        channel.QueueIncomingRequests = true;
        if (!_incoming.Writer.TryWrite(new IncomingChannelOpen(channel, type, extra)))
        {
            Forget(channel);
            await SendOpenFailureAsync(remoteId, OpenFailureResourceShortage, "busy").ConfigureAwait(false);
            return;
        }

        ValueTask send;
        SshWriter writer = new(32);
        try
        {
            writer.WriteByte(MessageNumber.ChannelOpenConfirmation);
            writer.WriteUInt32(remoteId);
            writer.WriteUInt32(channel.LocalId);
            writer.WriteUInt32(SshChannel.DefaultWindow);
            writer.WriteUInt32(SshChannel.MaxPacket);
            send = SendAsync(writer.Written, _stop.Token);
        }
        finally
        {
            writer.Dispose();
        }

        await send.ConfigureAwait(false);
    }

    private async ValueTask SendOpenFailureAsync(uint remoteId, int reason, string text)
    {
        ValueTask send;
        SshWriter writer = new(64);
        try
        {
            writer.WriteByte(MessageNumber.ChannelOpenFailure);
            writer.WriteUInt32(remoteId);
            writer.WriteUInt32((uint)reason);
            writer.WriteUtf8String(text);
            writer.WriteUtf8String(string.Empty);
            send = SendAsync(writer.Written, _stop.Token);
        }
        finally
        {
            writer.Dispose();
        }

        await send.ConfigureAwait(false);
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

    private async ValueTask HandleCloseAsync(ReadOnlyMemory<byte> message)
    {
        SshChannel channel = FindChannel(message.Span);
        if (channel.OnClose())
        {
            byte[] payload = new byte[5];
            payload[0] = MessageNumber.ChannelClose;
            BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1), channel.RemoteId);
            await SendAsync(payload, _stop.Token).ConfigureAwait(false);
            channel.FinishIfClosed();
        }
    }

    private async ValueTask HandleChannelRequestAsync(ReadOnlyMemory<byte> message)
    {
        SshChannel channel = FindChannel(message.Span);
        bool fail;
        {
            SshReader reader = new(message.Span);
            reader.ReadRaw(5);
            string type = reader.ReadUtf8String();
            bool wantReply = reader.ReadBoolean();
            fail = channel.OnRequest(type, wantReply, reader.RemainingSpan);
        }

        if (fail)
        {
            await channel.ReplyAsync(false, _stop.Token).ConfigureAwait(false);
        }
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

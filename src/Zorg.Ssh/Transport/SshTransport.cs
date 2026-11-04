using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Transport;

/// <summary>
/// The SSH transport for one connection, in either role. See <c>.tmp/design/02-transport.md</c>.
/// <see cref="ReceiveAsync"/> is the only reader and must not be called concurrently. It handles every
/// transport message itself, so whoever drives it also drives key exchange. <see cref="SendAsync"/> may be
/// called from any thread.
/// </summary>
internal sealed partial class SshTransport : IAsyncDisposable
{
    private const int KexQueueCapacity = 16;
    private const int MaxDisconnectText = 256;

    private readonly Stream _stream;
    private readonly TransportOptions _options;
    private readonly PacketReader _reader;
    private readonly Channel<OutgoingPacket> _sendQueue;
    private readonly Channel<OutgoingPacket> _kexQueue;
    private readonly Channel<bool> _wake;
    private readonly CancellationTokenSource _closing = new();
    private readonly Lock _kexLock = new();
    private readonly TaskCompletionSource _sendLoopDone = new(TaskCreationOptions.RunContinuationsAsynchronously);

    // Owned by the send loop.
#pragma warning disable CA2213 // The send loop disposes it when it ends, because only that loop may touch it.
    private PacketCipher _sendCipher = NoneCipher.Instance;
#pragma warning restore CA2213
    private uint _sendSequence;
    private long _bytesSent;
    private long _packetsSent;

    // Owned by the receive path.
    private PacketCipher _receiveCipher = NoneCipher.Instance;
    private uint _receiveSequence;
    private bool _anyPacketReceived;
    private long _bytesReceived;
    private long _packetsReceived;
    private bool _firstPacketAfterNewKeys;
    private bool _secondExtInfoAllowed = true;

    // Shared.
    private volatile bool _parked;
    private Exception? _failureSlot;
    private volatile TransportPhase _phase = TransportPhase.InitialKex;
    private volatile int _sendLoopStarted;
    private long _lastKexTimestamp;
    private ITimer? _deadline;

    private Exception? Failure => Volatile.Read(ref _failureSlot);

    private SshTransport(Stream stream, TransportOptions options)
    {
        _stream = stream;
        _options = options;
        _reader = new PacketReader(stream, options.MaxPacketLength);
        _sendQueue = Channel.CreateBounded<OutgoingPacket>(new BoundedChannelOptions(options.SendQueueCapacity)
        {
            SingleReader = true,
            FullMode = BoundedChannelFullMode.Wait,
        });
        _kexQueue = Channel.CreateBounded<OutgoingPacket>(new BoundedChannelOptions(KexQueueCapacity)
        {
            SingleReader = true,
            FullMode = BoundedChannelFullMode.Wait,
        });
        _wake = Channel.CreateBounded<bool>(new BoundedChannelOptions(1)
        {
            SingleReader = true,
            FullMode = BoundedChannelFullMode.DropWrite,
        });
    }

    /// <summary>Gets the session identifier, the exchange hash of the first key exchange.</summary>
    public ReadOnlyMemory<byte> SessionId => _sessionId;

    /// <summary>Gets the peer's identification string.</summary>
    public string PeerIdentification { get; private set; } = string.Empty;

    /// <summary>Gets the extensions the peer listed in EXT_INFO. Values are raw bytes.</summary>
    public IReadOnlyDictionary<string, byte[]> PeerExtensions => _peerExtensions;

    /// <summary>Gets our side of the connection.</summary>
    public SshRole Role => _options.Role;

    /// <summary>Gets how many key exchanges have finished, counting the first.</summary>
    public int CompletedKeyExchanges => Volatile.Read(ref _completedKeyExchanges);

    /// <summary>Gets the host key the server proved it holds. Null on a server.</summary>
    public SshPublicKey? PeerHostKey => _peerHostKey;

    /// <summary>
    /// Runs the version exchange and the first key exchange over a connected stream. The stream belongs to
    /// the transport from here on, including on failure.
    /// </summary>
    public static async Task<SshTransport> StartAsync(Stream stream, TransportOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(options);
        if (options.Role == SshRole.Client && options.HostKeyValidator is null)
        {
            throw new ArgumentException("A client needs a host key validator.", nameof(options));
        }

        if (options.Role == SshRole.Server && options.HostKeys.Count == 0)
        {
            throw new ArgumentException("A server needs at least one host key.", nameof(options));
        }

        SshTransport transport = new(stream, options);
        try
        {
            await transport.HandshakeAsync(cancellationToken).ConfigureAwait(false);
            return transport;
        }
        catch
        {
            await transport.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>Moves the connection to the next phase. Called by the auth layer, which owns those steps.</summary>
    public void SetPhase(TransportPhase phase) => _phase = phase;

    /// <summary>
    /// Returns the next message for the layers above, including its message number. The result is valid
    /// until the next call. Every message has already passed <see cref="MessagePolicy"/>.
    /// </summary>
    public async ValueTask<ReadOnlyMemory<byte>> ReceiveAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            ReadOnlyMemory<byte>? message = await ReceiveOneAsync(cancellationToken).ConfigureAwait(false);
            if (message is { } payload)
            {
                return payload;
            }
        }
    }

    /// <summary>
    /// Queues a message, waiting while the queue is full. Non-KEX traffic stays queued during a key exchange.
    /// <paramref name="payload"/> is copied, so it can be reused when this returns.
    /// </summary>
    public ValueTask SendAsync(scoped ReadOnlySpan<byte> payload, CancellationToken cancellationToken)
    {
        ThrowIfFailed();
        OutgoingPacket packet = OutgoingPacket.Create(payload);
        return EnqueueAsync(packet, cancellationToken);
    }

    /// <summary>Asks for a rekey now. Does nothing if one is already running.</summary>
    public void RequestRekey()
    {
        ThrowIfFailed();
        StartKex();
    }

    /// <summary>Sends DISCONNECT if possible, then closes the stream and releases everything.</summary>
    public async ValueTask DisposeAsync()
    {
        Exception closed = new SshConnectionException("The connection was closed by this side. Connect again to continue.");
        if (Interlocked.CompareExchange(ref _failureSlot, closed, null) is null)
        {
            TryQueueDisconnect(DisconnectReason.ByApplication, "closed");
        }

        await ShutdownAsync().ConfigureAwait(false);
        _reader.Dispose();
        DisposeCipher(_receiveCipher);
        _receiveCipher = NoneCipher.Instance;
        _closing.Dispose();
    }

    private static void DisposeCipher(PacketCipher cipher)
    {
        if (!ReferenceEquals(cipher, NoneCipher.Instance))
        {
            cipher.Dispose();
        }
    }

    /// <summary>Removes control characters and caps the length, so peer text can't forge log lines or bloat messages.</summary>
    private static string Sanitise(string text)
    {
        StringBuilder clean = new(Math.Min(text.Length, MaxDisconnectText));
        foreach (char c in text)
        {
            if (clean.Length == MaxDisconnectText)
            {
                break;
            }

            if (!char.IsControl(c))
            {
                clean.Append(c);
            }
        }

        return clean.ToString();
    }

    private async Task HandshakeAsync(CancellationToken cancellationToken)
    {
        SetDeadline(_options.HandshakeTimeout);
        byte[] ourIdentification = Encoding.ASCII.GetBytes(_options.Identification);
        byte[] line = new byte[ourIdentification.Length + 2];
        ourIdentification.CopyTo(line, 0);
        line[^2] = (byte)'\r';
        line[^1] = (byte)'\n';

        try
        {
            using CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _closing.Token);
            await _stream.WriteAsync(line, linked.Token).ConfigureAwait(false);
            await _stream.FlushAsync(linked.Token).ConfigureAwait(false);
            byte[] peerIdentification = await _reader
                .ReadIdentificationAsync(allowPreamble: _options.Role == SshRole.Client, linked.Token)
                .ConfigureAwait(false);
            PeerIdentification = Encoding.ASCII.GetString(peerIdentification);
            TransportLog.PeerIdentified(_options.Logger, PeerIdentification);
            InitialiseKex(ourIdentification, peerIdentification);
        }
        catch (Exception ex) when (ex is not SshException && !cancellationToken.IsCancellationRequested)
        {
            throw Fail(Translate(ex), null);
        }
        catch (SshException ex)
        {
            throw Fail(ex, null);
        }

        _sendLoopStarted = 1;
        _ = Task.Run(SendLoopAsync, CancellationToken.None);
        StartKex();

        while (!_firstKexComplete)
        {
            // No upper-layer message can arrive here: the policy refuses them during the initial KEX.
            await ReceiveOneAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Reads one packet and handles it. Returns a payload only for the layers above.</summary>
    private async ValueTask<ReadOnlyMemory<byte>?> ReceiveOneAsync(CancellationToken cancellationToken)
    {
        ThrowIfFailed();
        try
        {
            // A token that can't fire needs no linked source, which saves an allocation per packet.
            using CancellationTokenSource? linked = cancellationToken.CanBeCanceled
                ? CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _closing.Token)
                : null;
            CancellationToken token = linked?.Token ?? _closing.Token;
            uint sequence = _receiveSequence;
            ReadOnlyMemory<byte> payload = await _reader.ReadPacketAsync(_receiveCipher, sequence, token).ConfigureAwait(false);
            AdvanceReceiveSequence();
            bool first = !_anyPacketReceived;
            _anyPacketReceived = true;
            _bytesReceived += payload.Length;
            _packetsReceived++;
            CheckRekeyLimits(_bytesReceived, _packetsReceived);

            byte message = payload.Span[0];
            MessageContext context = new(
                _options.Role,
                _phase,
                _peerKexRunning,
                _strictKex,
                _firstPacketAfterNewKeys,
                _secondExtInfoAllowed);
            MessageDecision decision = MessagePolicy.Evaluate(context, message);
            bool firstAfterNewKeys = _firstPacketAfterNewKeys;
            _firstPacketAfterNewKeys = false;

            // Once started, a rekey must finish whatever the caller does with its token, or the two
            // sides fall out of step. Only the first exchange can be abandoned, because that ends the connection.
            CancellationToken kexToken = _firstKexComplete ? _closing.Token : token;

            switch (decision)
            {
                case MessageDecision.Unimplemented:
                    await SendUnimplementedAsync(sequence, kexToken).ConfigureAwait(false);
                    return null;
                case MessageDecision.Disconnect:
                    throw new SshProtocolException($"The peer sent message {message}, which isn't allowed in this state.");
            }

            switch (message)
            {
                case MessageNumber.Disconnect:
                    throw ParseDisconnect(payload.Span);
                case MessageNumber.Ignore:
                case MessageNumber.Debug:
                case MessageNumber.Unimplemented:
                    return null;
                case MessageNumber.ExtInfo:
                    if (!firstAfterNewKeys)
                    {
                        _secondExtInfoAllowed = false;
                    }

                    ParseExtInfo(payload.Span);
                    return null;
                case MessageNumber.KexInit:
                    await HandleKexInitAsync(payload, first, kexToken).ConfigureAwait(false);
                    return null;
                case MessageNumber.NewKeys:
                case >= 30 and <= 49:
                    await HandleKexMessageAsync(payload, kexToken).ConfigureAwait(false);
                    return null;
                default:
                    return payload;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (SshConnectionException ex)
        {
            throw Fail(ex, null);
        }
        catch (SshHostKeyException ex)
        {
            throw Fail(ex, DisconnectReason.HostKeyNotVerifiable);
        }
        catch (SshNegotiationException ex)
        {
            throw Fail(ex, DisconnectReason.KeyExchangeFailed);
        }
        catch (SshException ex)
        {
            throw Fail(ex, DisconnectReason.ProtocolError);
        }
        catch (CryptographicException ex)
        {
            throw Fail(new SshProtocolException("The peer sent key exchange data that failed a cryptographic check.", ex), DisconnectReason.KeyExchangeFailed);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or OperationCanceledException)
        {
            throw Fail(Translate(ex), null);
        }
    }

    private void AdvanceReceiveSequence()
    {
        // T10: under strict KEX a wrap before the first NEWKEYS means the peer has flooded the handshake.
        if (++_receiveSequence == 0 && !_firstKexComplete && _strictKex)
        {
            throw new SshProtocolException("The sequence number wrapped during the initial key exchange.");
        }
    }

    private void CheckRekeyLimits(long bytes, long packets)
    {
        if (!_options.RekeyEnabled || !_firstKexComplete || _kexStep != KexStep.Idle)
        {
            return;
        }

        long elapsed = _options.TimeProvider.GetElapsedTime(Volatile.Read(ref _lastKexTimestamp)).Ticks;
        if (bytes >= _options.RekeyBytes || packets >= _options.RekeyPackets || elapsed >= _options.RekeyInterval.Ticks)
        {
            TransportLog.RekeyStarting(_options.Logger, bytes, packets);
            StartKex();
        }
    }

    private static SshDisconnectedException ParseDisconnect(ReadOnlySpan<byte> payload)
    {
        SshReader reader = new(payload);
        reader.ReadByte();
        uint code = reader.ReadUInt32();
        string description;
        try
        {
            description = Sanitise(reader.ReadUtf8String());
        }
        catch (SshProtocolException)
        {
            description = string.Empty;
        }

        return new SshDisconnectedException(code, description);
    }

    private void ParseExtInfo(ReadOnlySpan<byte> payload)
    {
        const int MaxExtensions = 64;
        SshReader reader = new(payload);
        reader.ReadByte();
        uint count = reader.ReadUInt32();
        if (count > MaxExtensions)
        {
            throw new SshProtocolException("The peer sent too many extensions.");
        }

        Dictionary<string, byte[]> extensions = new(_peerExtensions, StringComparer.Ordinal);
        for (uint i = 0; i < count; i++)
        {
            string name = reader.ReadUtf8String();
            extensions[name] = reader.ReadBinary().ToArray();
        }

        reader.EnsureEnd();
        _peerExtensions = extensions;
    }

    private async ValueTask SendUnimplementedAsync(uint sequence, CancellationToken cancellationToken)
    {
        byte[] payload = new byte[5];
        payload[0] = MessageNumber.Unimplemented;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1), sequence);
        await EnqueueKexAsync(OutgoingPacket.Create(payload), cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask EnqueueAsync(OutgoingPacket packet, CancellationToken cancellationToken)
    {
        try
        {
            await _sendQueue.Writer.WriteAsync(packet, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is ChannelClosedException or OperationCanceledException)
        {
            packet.Discard();
            ThrowIfFailed();
            throw;
        }

        _wake.Writer.TryWrite(true);
    }

    private async ValueTask EnqueueKexAsync(OutgoingPacket packet, CancellationToken cancellationToken)
    {
        try
        {
            await _kexQueue.Writer.WriteAsync(packet, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is ChannelClosedException or OperationCanceledException)
        {
            packet.Discard();
            ThrowIfFailed();
            throw;
        }

        _wake.Writer.TryWrite(true);
    }

    /// <summary>The one writer of the stream. Owns sequence numbers and the send cipher.</summary>
    private async Task SendLoopAsync()
    {
        try
        {
            while (true)
            {
                OutgoingPacket packet;
                if (_kexQueue.Reader.TryRead(out packet))
                {
                    // Served even while parked.
                }
                else if (Failure is not null)
                {
                    return;
                }
                else if (!_parked && _sendQueue.Reader.TryRead(out packet))
                {
                    // T3: checked before every take, so nothing non-KEX can follow our KEXINIT.
                }
                else
                {
                    await _wake.Reader.ReadAsync(_closing.Token).ConfigureAwait(false);
                    continue;
                }

                bool terminal = packet.IsTerminal;
                await WritePacketAsync(packet).ConfigureAwait(false);
                if (terminal)
                {
                    return;
                }
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or IOException or ObjectDisposedException or ChannelClosedException)
        {
            Fail(Translate(ex), null);
        }
        catch (SshException ex)
        {
            Fail(ex, null);
        }
        finally
        {
            DisposeCipher(_sendCipher);
            _sendCipher = NoneCipher.Instance;
            _sendLoopDone.TrySetResult();
        }
    }

    private async ValueTask WritePacketAsync(OutgoingPacket packet)
    {
        bool installed = false;
        try
        {
            PacketCipher cipher = _sendCipher;
            int length = packet.Frame(cipher);
            cipher.Seal(packet.Buffer.AsSpan(0, length + cipher.TagLength), _sendSequence);
            await _stream.WriteAsync(packet.Buffer.AsMemory(0, length + cipher.TagLength), _closing.Token).ConfigureAwait(false);
            await _stream.FlushAsync(_closing.Token).ConfigureAwait(false);
            _sendSequence++;
            _bytesSent += packet.PayloadLength;
            _packetsSent++;

            if (packet.NextCipher is { } next)
            {
                DisposeCipher(cipher);
                _sendCipher = next;
                installed = true;
                if (packet.ResetSequence)
                {
                    _sendSequence = 0;
                }

                _bytesSent = 0;
                _packetsSent = 0;
                _parked = false;
                _wake.Writer.TryWrite(true);
            }
            else
            {
                CheckRekeyLimits(_bytesSent, _packetsSent);
            }
        }
        finally
        {
            if (installed)
            {
                packet.Release();
            }
            else
            {
                packet.Discard();
            }
        }
    }

    private void SetDeadline(TimeSpan timeout)
    {
        _deadline?.Dispose();
        if (timeout == Timeout.InfiniteTimeSpan)
        {
            return;
        }

        _deadline = _options.TimeProvider.CreateTimer(
            static state =>
            {
                SshTransport self = (SshTransport)state!;
                self.Fail(new SshConnectionException("The key exchange timed out. Check that the peer is a responsive SSH implementation."), DisconnectReason.KeyExchangeFailed);
            },
            this,
            timeout,
            Timeout.InfiniteTimeSpan);
    }

    private void ClearDeadline()
    {
        _deadline?.Dispose();
        _deadline = null;
    }

    private void ThrowIfFailed()
    {
        if (Failure is { } failure)
        {
            throw Wrap(failure);
        }
    }

    /// <summary>Gives each waiter its own exception object, with the first failure as the cause, so stack traces stay meaningful.</summary>
    private static SshException Wrap(Exception failure) => failure switch
    {
        SshDisconnectedException e => new SshDisconnectedException(e.ReasonCode, e.Description),
        SshConnectionException e => new SshConnectionException(e.Message, e),
        SshHostKeyException e => new SshHostKeyException(e.Message, e),
        SshProtocolException e => new SshProtocolException(e.Message, e),
        _ => new SshException(failure.Message, failure),
    };

    private static SshConnectionException Translate(Exception ex) =>
        ex is SshConnectionException connection
            ? connection
            : new SshConnectionException("The connection was lost. Connect again to continue.", ex);

    /// <summary>Records the first failure, tells the peer if we can, and shuts everything down.</summary>
    private SshException Fail(SshException failure, uint? disconnectReason)
    {
        if (Interlocked.CompareExchange(ref _failureSlot, failure, null) is null)
        {
            TransportLog.Failed(_options.Logger, failure);
            if (disconnectReason is { } reason)
            {
                // The text is ours, and fixed: no peer data or secret reaches the wire.
                TryQueueDisconnect(reason, "protocol error");
            }

            // Always: a read or write waiting on the stream only ends when the shutdown cancels it.
            _wake.Writer.TryWrite(true);
            _ = Task.Run(ShutdownAsync, CancellationToken.None);
        }

        return Failure as SshException ?? failure;
    }

    private void TryQueueDisconnect(uint reason, string text)
    {
        SshWriter writer = new(64);
        try
        {
            writer.WriteByte(MessageNumber.Disconnect);
            writer.WriteUInt32(reason);
            writer.WriteUtf8String(text);
            writer.WriteUInt32(0);
            OutgoingPacket packet = OutgoingPacket.Create(writer.Written, isTerminal: true);
            if (!_kexQueue.Writer.TryWrite(packet))
            {
                packet.Release();
            }
        }
        finally
        {
            writer.Dispose();
        }

        _wake.Writer.TryWrite(true);
    }

    private async Task ShutdownAsync()
    {
        if (Interlocked.Exchange(ref _shutdownStarted, 1) != 0)
        {
            await _shutdownDone.Task.ConfigureAwait(false);
            return;
        }

        try
        {
            ClearDeadline();
            if (_sendLoopStarted != 0)
            {
                // Give the DISCONNECT a moment, but a peer that doesn't read can't hold us here.
                using CancellationTokenSource grace = new(TimeSpan.FromSeconds(1), _options.TimeProvider);
                try
                {
                    await _sendLoopDone.Task.WaitAsync(grace.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                }
            }

            try
            {
                await _closing.CancelAsync().ConfigureAwait(false);
            }
            catch (ObjectDisposedException)
            {
            }

            if (_sendLoopStarted != 0)
            {
                await _sendLoopDone.Task.ConfigureAwait(false);
            }

            _sendQueue.Writer.TryComplete();
            _kexQueue.Writer.TryComplete();
            while (_sendQueue.Reader.TryRead(out OutgoingPacket packet) || _kexQueue.Reader.TryRead(out packet))
            {
                packet.Discard();
            }

            await _stream.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
            // Closing a broken stream can fail. It's closed either way.
        }
        finally
        {
            lock (_kexLock)
            {
                ReleaseKexState();
            }

            _shutdownDone.TrySetResult();
        }
    }

    private readonly TaskCompletionSource _shutdownDone = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _shutdownStarted;
}

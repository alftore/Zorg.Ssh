using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;
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
/// <para>
/// T1, the rule everything here rests on: the receive path never waits on the send side. What it has to send
/// goes to a small queue with a non-blocking write, and a full queue means the peer has stopped reading,
/// which ends the connection. Otherwise a peer, or just a full send queue during a rekey, could stop us
/// reading the very message that would free it.
/// </para>
/// </summary>
internal sealed partial class SshTransport : IAsyncDisposable
{
    private const int KexQueueCapacity = 16;
    private const int ControlQueueCapacity = 256;
    private const int MaxDisconnectText = 256;
    private const int MaxSendPayload = 40 * 1024;
    private const long NoWriteRunning = long.MinValue;

    /// <summary>The most packets under one key. Past this the sequence number repeats, and with it the ChaCha20 nonce.</summary>
    private const long MaxPacketsPerKey = (1L << 32) - 2;

    private static readonly TimeSpan Grace = TimeSpan.FromSeconds(1);

    private readonly Stream _stream;
    private readonly TransportOptions _options;
    private readonly PacketReader _reader;
    private readonly Channel<OutgoingPacket> _sendQueue;
    private readonly Channel<OutgoingPacket> _controlQueue;
    private readonly Channel<OutgoingPacket> _kexQueue;
    private readonly Channel<bool> _wake;
    private readonly CancellationTokenSource _closing = new();
    private readonly Lock _kexLock = new();
    private readonly TaskCompletionSource _sendLoopDone = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _shutdownDone = new(TaskCreationOptions.RunContinuationsAsynchronously);

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
    private uint _lastReceivedSequence;
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
    private long _lastReceivedTimestamp;
    private long _writeStartedTimestamp = NoWriteRunning;
    private ITimer? _deadline;
    private int _shutdownStarted;
    private int _receiving;
    private CancellationTokenSource? _receiveLinked;
    private CancellationToken _receiveLinkedFor;

    private SshTransport(Stream stream, TransportOptions options)
    {
        _stream = stream;
        _options = options;
        _lastReceivedTimestamp = options.TimeProvider.GetTimestamp();
        _reader = new PacketReader(stream, options.MaxPacketLength);
        _sendQueue = Channel.CreateBounded<OutgoingPacket>(new BoundedChannelOptions(options.SendQueueCapacity)
        {
            SingleReader = true,
            FullMode = BoundedChannelFullMode.Wait,
        });
        _controlQueue = Channel.CreateBounded<OutgoingPacket>(new BoundedChannelOptions(ControlQueueCapacity)
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
    /// Gets or sets who hears the sequence number in each UNIMPLEMENTED. It runs in the receive path, so it must not
    /// wait. Set it before the receive path starts. Nothing is listening during the handshake or auth.
    /// </summary>
    public Action<uint>? UnimplementedHandler { get; set; }

    /// <summary>Gets or sets a hearer of every UNIMPLEMENTED in any phase. Only for tests that script a peer through the login.</summary>
    internal Action<uint>? UnimplementedObserver { get; set; }

    /// <summary>Gets the sequence number of the last packet received.</summary>
    internal uint LastReceivedSequence => _lastReceivedSequence;

    /// <summary>Gets the options this transport runs with.</summary>
    public TransportOptions Options => _options;

    /// <summary>Gets when the last whole packet arrived, of any type, on the clock of <see cref="TransportOptions.TimeProvider"/>.</summary>
    public long LastReceivedTimestamp => Volatile.Read(ref _lastReceivedTimestamp);

    /// <summary>Gets how long the socket write now running has taken, or zero if none is running.</summary>
    public TimeSpan WritePendingFor
    {
        get
        {
            long started = Volatile.Read(ref _writeStartedTimestamp);
            return started == NoWriteRunning ? TimeSpan.Zero : _options.TimeProvider.GetElapsedTime(started);
        }
    }

    /// <summary>Gets whether a key exchange is running, which holds back everything but its own messages.</summary>
    public bool KeyExchangeRunning
    {
        get
        {
            lock (_kexLock)
            {
                return _parked || _kexStep != KexStep.Idle;
            }
        }
    }

    private Exception? Failure => Volatile.Read(ref _failureSlot);

    /// <summary>Gets the first failure, as a new exception of its own, or null while the transport hasn't failed or closed.</summary>
    internal SshException? RecordedFailure => Failure is { } failure ? Wrap(failure) : null;

    /// <summary>Gets whether the transport has failed or closed.</summary>
    internal bool HasFailed => Failure is not null;

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
    // Runs once per packet or reply, so its state machine comes from a pool instead of a new allocation each time.
    [AsyncMethodBuilder(typeof(PoolingAsyncValueTaskMethodBuilder<>))]
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
    /// <paramref name="payload"/> is copied, so it can be reused when this returns. The receive path must
    /// use <see cref="SendControl"/> instead.
    /// </summary>
    public ValueTask SendAsync(scoped ReadOnlySpan<byte> payload, CancellationToken cancellationToken, SentSequence? sent = null)
    {
        ThrowIfFailed();
        if (payload.Length > MaxSendPayload)
        {
            throw new ArgumentException("The message is larger than the transport sends.", nameof(payload));
        }

        OutgoingPacket packet = OutgoingPacket.Create(payload, sent: sent);
        return EnqueueAsync(packet, cancellationToken);
    }

    /// <summary>
    /// Queues a small reply without ever waiting, for use in the receive path. It's sent ahead of queued data,
    /// and held back during a key exchange. A full queue means the peer has asked for replies it isn't
    /// reading, which ends the connection.
    /// </summary>
    public void SendControl(scoped ReadOnlySpan<byte> payload)
    {
        ThrowIfFailed();
        OutgoingPacket packet = OutgoingPacket.Create(payload);
        if (!_controlQueue.Writer.TryWrite(packet))
        {
            packet.Discard();
            throw new SshProtocolException("The peer isn't reading the replies to its requests.");
        }

        _wake.Writer.TryWrite(true);
    }

    /// <summary>
    /// Ends the connection from outside the two loops, without waiting and without a DISCONNECT, because a peer
    /// that got here isn't listening. A stuck write ends when the shutdown cancels it. The receive loop then
    /// wakes with this failure, or with an earlier one.
    /// </summary>
    public void Abort(SshConnectionException failure) => Fail(failure, null);

    /// <summary>Replies UNIMPLEMENTED to the packet just returned by <see cref="ReceiveAsync"/>.</summary>
    public void SendUnimplementedForLastPacket() => SendUnimplemented(_lastReceivedSequence);

    /// <summary>
    /// Asks for a rekey now. Does nothing if one is already running, or before auth has finished: OpenSSH
    /// servers refuse KEXINIT until then, so we never start one earlier. We still answer a peer that does.
    /// </summary>
    public void RequestRekey()
    {
        ThrowIfFailed();
        if (_phase == TransportPhase.Connected)
        {
            StartKex();
        }
    }

    /// <summary>
    /// Sends what's queued and a DISCONNECT if that's possible within a moment, then closes the stream. Any
    /// <see cref="ReceiveAsync"/> running ends. Nothing is released yet: that's <see cref="DisposeAsync"/>,
    /// which comes after the caller has stopped reading.
    /// </summary>
    public async ValueTask CloseAsync()
    {
        if (Failure is null && _sendLoopStarted != 0)
        {
            OutgoingPacket goodbye = BuildDisconnect(DisconnectReason.ByApplication, "closed");
            if (!_sendQueue.Writer.TryWrite(goodbye) && !_kexQueue.Writer.TryWrite(goodbye))
            {
                goodbye.Discard();
            }

            _wake.Writer.TryWrite(true);
            await WaitBrieflyAsync(_sendLoopDone.Task).ConfigureAwait(false);
        }

        Exception closed = new SshConnectionException("The connection was closed by this side. Connect again to continue.");
        Interlocked.CompareExchange(ref _failureSlot, closed, null);
        await ShutdownAsync().ConfigureAwait(false);
    }

    /// <summary>Closes the connection and releases everything. Call it after the receive path has stopped.</summary>
    public async ValueTask DisposeAsync()
    {
        await CloseAsync().ConfigureAwait(false);

        // A reader stuck in a stream that ignores cancellation still owns these, so they go to the GC instead.
        if (Volatile.Read(ref _receiving) == 0)
        {
            _reader.Dispose();
            DisposeCipher(_receiveCipher);
            _receiveCipher = NoneCipher.Instance;
            lock (_kexLock)
            {
                ReleaseKexState();
            }

            _receiveLinked?.Dispose();
            _closing.Dispose();
        }
    }

    private static void DisposeCipher(PacketCipher cipher)
    {
        if (!ReferenceEquals(cipher, NoneCipher.Instance))
        {
            cipher.Dispose();
        }
    }

    /// <summary>Gives each waiter its own exception object, with the first failure as the cause, so stack traces stay meaningful.</summary>
    private static SshException Wrap(Exception failure) => failure switch
    {
        SshDisconnectedException e => new SshDisconnectedException(e.Reason, e.Description),
        SshConnectionException e => new SshConnectionException(e.Message, e),
        SshHostKeyException e => new SshHostKeyException(e.Message, e),
        SshProtocolException e => new SshProtocolException(e.Message, e),
        _ => new SshException(failure.Message, failure),
    };

    private static SshConnectionException Translate(Exception ex) =>
        ex is SshConnectionException connection
            ? connection
            : new SshConnectionException("The connection was lost. Connect again to continue.", ex);

    private static SshDisconnectedException ParseDisconnect(ReadOnlySpan<byte> payload)
    {
        SshReader reader = new(payload);
        reader.ReadByte();
        uint code = reader.ReadUInt32();
        string description;
        try
        {
            description = PeerText.Clean(reader.ReadUtf8String(), MaxDisconnectText);
        }
        catch (SshProtocolException)
        {
            description = string.Empty;
        }

        return new SshDisconnectedException((SshDisconnectReason)code, description);
    }

    private static OutgoingPacket BuildDisconnect(uint reason, string text)
    {
        SshWriter writer = new(64);
        try
        {
            writer.WriteByte(MessageNumber.Disconnect);
            writer.WriteUInt32(reason);
            writer.WriteUtf8String(text);
            writer.WriteUInt32(0);
            return OutgoingPacket.Create(writer.Written, isTerminal: true);
        }
        finally
        {
            writer.Dispose();
        }
    }

    /// <summary>Waits a short time. A peer or stream that won't cooperate can't hold us longer than that.</summary>
    private static async Task WaitBrieflyAsync(Task task)
    {
        try
        {
            await task.WaitAsync(Grace).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
        }
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

            // KEXINIT goes out now rather than after the peer's identification, as RFC 4253 allows. That saves a round
            // trip, and the packet also carries the ACK for the peer's line, which otherwise costs a delayed-ACK stall.
            ThrowIfFailed();
            _sendLoopStarted = 1;
            _ = Task.Run(SendLoopAsync, CancellationToken.None);
            StartKex();

            byte[] peerIdentification = await _reader
                .ReadIdentificationAsync(allowPreamble: _options.Role == SshRole.Client, linked.Token)
                .ConfigureAwait(false);
            PeerIdentification = Encoding.ASCII.GetString(peerIdentification);
            TransportLog.PeerIdentified(_options.Logger, PeerIdentification);
            InitialiseKex(ourIdentification, peerIdentification);
        }
        catch (SshException ex)
        {
            throw Fail(ex, null);
        }
        catch (Exception ex) when (ex is not SshException && !cancellationToken.IsCancellationRequested)
        {
            throw Fail(Translate(ex), null);
        }

        while (!_firstKexComplete)
        {
            // No upper-layer message can arrive here: the policy refuses them during the initial KEX.
            await ReceiveOneAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Gets a token that fires with <paramref name="cancellationToken"/> or when the transport closes. The linked source
    /// is kept for as long as callers pass the same token, which the connection's receive loop does for every packet,
    /// instead of one being made and disposed per packet. Only one receive runs at a time, so nothing else uses it.
    /// </summary>
    private CancellationToken LinkedReceiveToken(CancellationToken cancellationToken)
    {
        if (_receiveLinked is null || _receiveLinkedFor != cancellationToken)
        {
            _receiveLinked?.Dispose();
            _receiveLinked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _closing.Token);
            _receiveLinkedFor = cancellationToken;
        }

        return _receiveLinked.Token;
    }

    /// <summary>Reads one packet and handles it. Returns a payload only for the layers above.</summary>
    // Runs once per packet or reply, so its state machine comes from a pool instead of a new allocation each time.
    [AsyncMethodBuilder(typeof(PoolingAsyncValueTaskMethodBuilder<>))]
    private async ValueTask<ReadOnlyMemory<byte>?> ReceiveOneAsync(CancellationToken cancellationToken)
    {
        ThrowIfFailed();
        Interlocked.Increment(ref _receiving);
        try
        {
            // A token that can't fire needs no linked source, and the connection passes the same token for every packet.
            CancellationToken token = cancellationToken.CanBeCanceled ? LinkedReceiveToken(cancellationToken) : _closing.Token;
            uint sequence = _receiveSequence;
            _lastReceivedSequence = sequence;
            ReadOnlyMemory<byte> payload = await _reader.ReadPacketAsync(_receiveCipher, sequence, token).ConfigureAwait(false);
            Volatile.Write(ref _lastReceivedTimestamp, _options.TimeProvider.GetTimestamp());
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

            switch (decision)
            {
                case MessageDecision.Unimplemented:
                    SendUnimplemented(sequence);
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
                    return null;
                case MessageNumber.Unimplemented:
                    // Malformed ones stay ignored, as they always were: there's nothing to act on.
                    if (payload.Length >= 5)
                    {
                        uint rejected = BinaryPrimitives.ReadUInt32BigEndian(payload.Span[1..]);
                        UnimplementedObserver?.Invoke(rejected);

                        // It can complete a global request, so only once connected (MessagePolicy says why it is also legal during a rekey).
                        if (_phase == TransportPhase.Connected)
                        {
                            UnimplementedHandler?.Invoke(rejected);
                        }
                    }

                    return null;
                case MessageNumber.ExtInfo:
                    if (!firstAfterNewKeys)
                    {
                        _secondExtInfoAllowed = false;
                    }

                    ParseExtInfo(payload.Span);
                    return null;
                case MessageNumber.KexInit:
                    HandleKexInit(payload, first);
                    return null;
                case MessageNumber.NewKeys:
                case >= 30 and <= 49:
                    await HandleKexMessageAsync(payload, token).ConfigureAwait(false);
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
#pragma warning disable CA1031 // Guarantee 3: even a bug in here reaches callers as an SshException, and ends the connection.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            throw Fail(new SshException("The connection failed unexpectedly. This is a bug in Zorg.Ssh.", ex), DisconnectReason.ProtocolError);
        }
        finally
        {
            Interlocked.Decrement(ref _receiving);
        }
    }

    private void AdvanceReceiveSequence()
    {
        // T10: under strict KEX a wrap before the first NEWKEYS means the peer has flooded the handshake.
        if (++_receiveSequence == 0 && !_firstKexComplete && _strictKex)
        {
            throw new SshProtocolException("The sequence number wrapped during the initial key exchange.");
        }

        if (_packetsReceived >= MaxPacketsPerKey)
        {
            throw new SshProtocolException("The peer sent too many packets under one key.");
        }
    }

    private void CheckRekeyLimits(long bytes, long packets)
    {
        if (!_options.RekeyEnabled || _phase != TransportPhase.Connected || _kexStep != KexStep.Idle)
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

    private void SendUnimplemented(uint sequence)
    {
        Span<byte> payload = stackalloc byte[5];
        payload[0] = MessageNumber.Unimplemented;
        BinaryPrimitives.WriteUInt32BigEndian(payload[1..], sequence);
        SendControl(payload);
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

    /// <summary>
    /// Queues a KEX message without waiting. An exchange holds a few at most, so a full queue means the
    /// peer has stopped reading, and the exchange can't finish anyway.
    /// </summary>
    private void EnqueueKex(OutgoingPacket packet)
    {
        if (!_kexQueue.Writer.TryWrite(packet))
        {
            packet.Discard();
            throw new SshConnectionException("The peer stopped reading during a key exchange. Connect again to continue.");
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
                else if (!_parked && (_controlQueue.Reader.TryRead(out packet) || _sendQueue.Reader.TryRead(out packet)))
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
        catch (SshException ex)
        {
            Fail(ex, null);
        }
#pragma warning disable CA1031 // Whatever ends this loop must be recorded, or senders wait for ever.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            Fail(Translate(ex), null);
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
            if (_packetsSent >= MaxPacketsPerKey)
            {
                throw new SshConnectionException("Too many packets went out under one key, and a rekey isn't allowed here. Connect again to continue.");
            }

            PacketCipher cipher = _sendCipher;
            int length = packet.Frame(cipher);
            cipher.Seal(packet.Buffer.AsSpan(0, length + cipher.TagLength), _sendSequence);
            packet.Sent?.Record(_sendSequence);

            // One write that never ends is what a peer that stopped reading looks like. A slow reader still finishes them.
            Volatile.Write(ref _writeStartedTimestamp, _options.TimeProvider.GetTimestamp());
            await _stream.WriteAsync(packet.Buffer.AsMemory(0, length + cipher.TagLength), _closing.Token).ConfigureAwait(false);
            await _stream.FlushAsync(_closing.Token).ConfigureAwait(false);
            Volatile.Write(ref _writeStartedTimestamp, NoWriteRunning);
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
                OnNewKeysWritten(packet.ParkGeneration);
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

    /// <summary>Records the first failure, tells the peer if we can, and shuts everything down.</summary>
    private SshException Fail(SshException failure, uint? disconnectReason)
    {
        if (Interlocked.CompareExchange(ref _failureSlot, failure, null) is null)
        {
            TransportLog.Failed(_options.Logger, failure);
            if (disconnectReason is { } reason)
            {
                // The text is ours, and fixed: no peer data or secret reaches the wire.
                OutgoingPacket goodbye = BuildDisconnect(reason, "protocol error");
                if (!_kexQueue.Writer.TryWrite(goodbye))
                {
                    goodbye.Discard();
                }
            }

            // Always: a read or write waiting on the stream only ends when the shutdown cancels it.
            _wake.Writer.TryWrite(true);
            _ = Task.Run(ShutdownAsync, CancellationToken.None);
        }

        return Failure as SshException ?? failure;
    }

    /// <summary>
    /// Stops the loops and closes the stream. Every wait here is short and bounded, because the stream may be
    /// one that ignores cancellation. It frees nothing the receive path could be using: that's for dispose.
    /// </summary>
    private async Task ShutdownAsync()
    {
        if (Interlocked.Exchange(ref _shutdownStarted, 1) != 0)
        {
            await _shutdownDone.Task.ConfigureAwait(false);
            return;
        }

        try
        {
            lock (_kexLock)
            {
                ClearDeadline();
            }

            if (_sendLoopStarted != 0)
            {
                // Lets a DISCONNECT out, but a peer that doesn't read can't hold us here.
                await WaitBrieflyAsync(_sendLoopDone.Task).ConfigureAwait(false);
            }

            await _closing.CancelAsync().ConfigureAwait(false);
            _sendQueue.Writer.TryComplete();
            _controlQueue.Writer.TryComplete();
            _kexQueue.Writer.TryComplete();
            await WaitBrieflyAsync(_stream.DisposeAsync().AsTask()).ConfigureAwait(false);

            if (_sendLoopStarted != 0)
            {
                await WaitBrieflyAsync(_sendLoopDone.Task).ConfigureAwait(false);
            }

            if (_sendLoopStarted == 0 || _sendLoopDone.Task.IsCompleted)
            {
                while (_sendQueue.Reader.TryRead(out OutgoingPacket packet)
                    || _controlQueue.Reader.TryRead(out packet)
                    || _kexQueue.Reader.TryRead(out packet))
                {
                    packet.Discard();
                }
            }
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
            // Closing a broken stream can fail. It's closed either way.
        }
        finally
        {
            _shutdownDone.TrySetResult();
        }
    }
}

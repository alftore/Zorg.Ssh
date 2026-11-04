using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Transport;

/// <summary>The key exchange half of the transport. It's role-neutral: the role only picks who speaks first.</summary>
internal sealed partial class SshTransport
{
    private byte[] _ourIdentification = [];
    private byte[] _peerIdentification = [];
    private byte[] _sessionId = [];
    private bool _firstKexComplete;
    private int _completedKeyExchanges;
    private bool _strictKex;
    private bool _peerOffersExtInfo;
    private bool _peerKexRunning;
    private bool _ignoreNextKexPacket;
    private KexStep _kexStep = KexStep.Idle;
    private byte[]? _ourKexInit;
    private byte[]? _peerKexInit;
    private KexInitMessage? _ourKexInitMessage;
    private NegotiatedAlgorithms? _negotiated;
    private KeyExchangeMethod? _kexMethod;
    private byte[]? _clientPublicValue;
    private PacketCipher? _nextReceiveCipher;
    private SshPublicKey? _peerHostKey;
    private Dictionary<string, byte[]> _peerExtensions = new(StringComparer.Ordinal);

    private enum KexStep
    {
        /// <summary>No exchange running.</summary>
        Idle,

        /// <summary>Our KEXINIT is out, and the peer's hasn't arrived.</summary>
        AwaitPeerInit,

        /// <summary>Both KEXINITs seen, and the public value exchange is running.</summary>
        AwaitExchange,

        /// <summary>Our NEWKEYS is queued, and the peer's hasn't arrived.</summary>
        AwaitNewKeys,
    }

    private void InitialiseKex(byte[] ourIdentification, byte[] peerIdentification)
    {
        _ourIdentification = ourIdentification;
        _peerIdentification = peerIdentification;
    }

    /// <summary>
    /// Test hook: queues a message past the parking rule, so a test can act as a peer that breaks it.
    /// Nothing in the library calls this.
    /// </summary>
    internal ValueTask SendIgnoringKexForTestsAsync(byte[] payload, CancellationToken cancellationToken) =>
        EnqueueKexAsync(OutgoingPacket.Create(payload), cancellationToken);

    /// <summary>Sends our KEXINIT if no exchange is running. Safe from either loop.</summary>
    private void StartKex()
    {
        lock (_kexLock)
        {
            if (_kexStep != KexStep.Idle || Failure is not null)
            {
                return;
            }

            KexInitMessage message = BuildKexInit();
            byte[] encoded = message.Encode();
            OutgoingPacket packet = OutgoingPacket.Create(encoded);

            // T3: park first, so that the send loop can't take non-KEX traffic after this KEXINIT.
            _parked = true;
            if (!_kexQueue.Writer.TryWrite(packet))
            {
                // The queue only fills if the peer has stopped reading. A later packet tries again.
                packet.Release();
                _parked = false;
                return;
            }

            _ourKexInitMessage = message;
            _ourKexInit = encoded;
            _kexStep = KexStep.AwaitPeerInit;
            if (_firstKexComplete)
            {
                SetDeadline(_options.RekeyTimeout);
            }
        }

        _wake.Writer.TryWrite(true);
    }

    private KexInitMessage BuildKexInit()
    {
        bool client = _options.Role == SshRole.Client;
        List<string> kex = [.. _options.KexAlgorithms];
        if (!_firstKexComplete)
        {
            // Markers count only in the first KEXINIT, so they're only sent there.
            kex.Add(client ? KexMarkers.ExtInfoClient : KexMarkers.ExtInfoServer);
            kex.Add(client ? KexMarkers.StrictClientV00 : KexMarkers.StrictServerV00);
            kex.Add(client ? KexMarkers.StrictClient : KexMarkers.StrictServer);
        }

        IReadOnlyList<string> hostKeys = client
            ? _options.HostKeyAlgorithms
            : [.. _options.HostKeyAlgorithms.Where(a => _options.HostKeys.Any(k => k.SignatureAlgorithms.Contains(a)))];

        return new KexInitMessage
        {
            KexAlgorithms = kex,
            HostKeyAlgorithms = hostKeys,
            CiphersClientToServer = _options.Ciphers,
            CiphersServerToClient = _options.Ciphers,
            MacsClientToServer = _options.Macs,
            MacsServerToClient = _options.Macs,
            CompressionClientToServer = ["none"],
            CompressionServerToClient = ["none"],
        };
    }

    private async ValueTask HandleKexInitAsync(ReadOnlyMemory<byte> payload, bool wasFirstPacket, CancellationToken cancellationToken)
    {
        _peerKexRunning = true;
        StartKex();
        KexInitMessage peer = KexInitMessage.Parse(payload.Span);
        _peerKexInit = payload.ToArray();

        NegotiatedAlgorithms negotiated;
        lock (_kexLock)
        {
            if (_kexStep != KexStep.AwaitPeerInit || _ourKexInitMessage is null)
            {
                throw new SshConnectionException("The key exchange couldn't start because the peer isn't reading. Connect again.");
            }

            negotiated = AlgorithmNegotiation.Negotiate(
                _options.Role,
                _ourKexInitMessage,
                peer,
                static name => PacketCipherCatalog.FindCipher(name)?.IsAead == true);
            _kexStep = KexStep.AwaitExchange;
        }

        if (!_firstKexComplete)
        {
            _strictKex = KexMarkers.PeerOffersStrict(_options.Role, peer.KexAlgorithms);
            _peerOffersExtInfo = KexMarkers.PeerOffersExtInfo(_options.Role, peer.KexAlgorithms);
            if (_strictKex && !wasFirstPacket)
            {
                throw new SshProtocolException("Strict key exchange requires KEXINIT to be the peer's first packet.");
            }
        }

        _negotiated = negotiated;
        _ignoreNextKexPacket = negotiated.PeerGuessWrong;
        _kexMethod?.Dispose();
        _kexMethod = KeyExchangeCatalog.Create(negotiated.Kex)
            ?? throw new SshNegotiationException($"The negotiated key exchange {negotiated.Kex} isn't available.");

        bool client = _options.Role == SshRole.Client;
        TransportLog.Negotiated(
            _options.Logger,
            negotiated.Kex,
            negotiated.HostKey,
            client ? negotiated.CipherClientToServer : negotiated.CipherServerToClient,
            client ? negotiated.CipherServerToClient : negotiated.CipherClientToServer,
            _strictKex);

        if (client)
        {
            _clientPublicValue = _kexMethod.CreateClientPublicValue();
            await SendKexAsync(MessageNumber.KexEcdhInit, _clientPublicValue, cancellationToken).ConfigureAwait(false);
        }
    }

    private async ValueTask SendKexAsync(byte message, byte[] publicValue, CancellationToken cancellationToken)
    {
        byte[] encoded;
        SshWriter writer = new(publicValue.Length + 16);
        try
        {
            writer.WriteByte(message);
            writer.WriteBinary(publicValue);
            encoded = writer.ToArray();
        }
        finally
        {
            writer.Dispose();
        }

        await EnqueueKexAsync(OutgoingPacket.Create(encoded), cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask HandleKexMessageAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        byte message = payload.Span[0];

        // RFC 4253 section 7: a wrong guess means the peer's first KEX packet is dropped unread.
        if (_ignoreNextKexPacket && message != MessageNumber.NewKeys)
        {
            _ignoreNextKexPacket = false;
            return;
        }

        switch (_kexStep)
        {
            case KexStep.AwaitExchange when message == MessageNumber.KexEcdhInit && _options.Role == SshRole.Server:
                await ServerExchangeAsync(payload, cancellationToken).ConfigureAwait(false);
                break;
            case KexStep.AwaitExchange when message == MessageNumber.KexEcdhReply && _options.Role == SshRole.Client:
                await ClientExchangeAsync(payload, cancellationToken).ConfigureAwait(false);
                break;
            case KexStep.AwaitNewKeys when message == MessageNumber.NewKeys:
                CompleteKex(payload.Span);
                break;
            default:
                throw new SshProtocolException($"The peer sent key exchange message {message} out of order.");
        }
    }

    private async ValueTask ServerExchangeAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        byte[] clientPublic;
        {
            SshReader reader = new(payload.Span);
            reader.ReadByte();
            clientPublic = reader.ReadBinary().ToArray();
            reader.EnsureEnd();
        }

        NegotiatedAlgorithms negotiated = _negotiated!;
        SshPrivateKey hostKey = _options.HostKeys.First(k => k.SignatureAlgorithms.Contains(negotiated.HostKey));
        byte[] hostKeyBlob = hostKey.PublicKey.Blob.ToArray();
        byte[] serverPublic = _kexMethod!.ServerRespond(clientPublic, out byte[] sharedSecret);
        try
        {
            byte[] exchangeHash = ComputeExchangeHash(hostKeyBlob, clientPublic, serverPublic, sharedSecret);
            byte[] signature = hostKey.Sign(negotiated.HostKey, exchangeHash);

            byte[] reply;
            SshWriter writer = new(hostKeyBlob.Length + serverPublic.Length + signature.Length + 32);
            try
            {
                writer.WriteByte(MessageNumber.KexEcdhReply);
                writer.WriteBinary(hostKeyBlob);
                writer.WriteBinary(serverPublic);
                writer.WriteBinary(signature);
                reply = writer.ToArray();
            }
            finally
            {
                writer.Dispose();
            }

            await EnqueueKexAsync(OutgoingPacket.Create(reply), cancellationToken).ConfigureAwait(false);
            await InstallKeysAsync(sharedSecret, exchangeHash, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }

    private async ValueTask ClientExchangeAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        byte[] hostKeyBlob;
        byte[] serverPublic;
        byte[] signature;
        {
            SshReader reader = new(payload.Span);
            reader.ReadByte();
            hostKeyBlob = reader.ReadBinary().ToArray();
            serverPublic = reader.ReadBinary().ToArray();
            signature = reader.ReadBinary().ToArray();
            reader.EnsureEnd();
        }

        NegotiatedAlgorithms negotiated = _negotiated!;
        SshPublicKey hostKey = SshPublicKey.Parse(hostKeyBlob);
        if (!hostKey.SupportsSignatureAlgorithm(negotiated.HostKey))
        {
            throw new SshHostKeyException($"The server sent a {hostKey.KeyType} key, which doesn't match the negotiated {negotiated.HostKey}. This can mean an attack.");
        }

        byte[] sharedSecret = _kexMethod!.ClientComputeSharedSecret(serverPublic);
        try
        {
            byte[] exchangeHash = ComputeExchangeHash(hostKeyBlob, _clientPublicValue!, serverPublic, sharedSecret);

            // Guarantee 2: the signature proves the server holds the key, and then the key itself must be trusted.
            if (!hostKey.Verify(negotiated.HostKey, exchangeHash, signature))
            {
                throw new SshHostKeyException("The server's signature over the key exchange is invalid. This can mean an attack, so the connection was closed.");
            }

            await CheckHostKeyAsync(hostKey, cancellationToken).ConfigureAwait(false);
            await InstallKeysAsync(sharedSecret, exchangeHash, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }

    private async ValueTask CheckHostKeyAsync(SshPublicKey hostKey, CancellationToken cancellationToken)
    {
        if (_peerHostKey is not null)
        {
            // T6: a rekey must keep the same host key, and no application code runs in the receive path.
            if (!_peerHostKey.Blob.Span.SequenceEqual(hostKey.Blob.Span))
            {
                throw new SshHostKeyException("The server changed its host key during a rekey. This can mean an attack, so the connection was closed.");
            }

            return;
        }

        if (!await _options.HostKeyValidator!(hostKey, cancellationToken).ConfigureAwait(false))
        {
            throw new SshHostKeyException($"The server's {hostKey.KeyType} host key isn't trusted. Check the key with the server's administrator before trusting it.");
        }

        _peerHostKey = hostKey;
    }

    /// <summary>H = HASH(V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K), with K already encoded.</summary>
    private byte[] ComputeExchangeHash(byte[] hostKeyBlob, byte[] clientPublic, byte[] serverPublic, byte[] encodedSharedSecret)
    {
        bool client = _options.Role == SshRole.Client;
        SshWriter writer = new(4096);
        try
        {
            writer.WriteBinary(client ? _ourIdentification : _peerIdentification);
            writer.WriteBinary(client ? _peerIdentification : _ourIdentification);
            writer.WriteBinary(client ? _ourKexInit! : _peerKexInit!);
            writer.WriteBinary(client ? _peerKexInit! : _ourKexInit!);
            writer.WriteBinary(hostKeyBlob);
            writer.WriteBinary(clientPublic);
            writer.WriteBinary(serverPublic);
            writer.WriteRaw(encodedSharedSecret);
            return _kexMethod!.Hash(writer.Written);
        }
        finally
        {
            writer.Dispose();
        }
    }

    /// <summary>Derives both directions, queues NEWKEYS carrying the send cipher, and holds the receive cipher for the peer's NEWKEYS.</summary>
    private async ValueTask InstallKeysAsync(byte[] encodedSharedSecret, byte[] exchangeHash, CancellationToken cancellationToken)
    {
        if (_sessionId.Length == 0)
        {
            _sessionId = exchangeHash;
        }

        NegotiatedAlgorithms negotiated = _negotiated!;
        bool client = _options.Role == SshRole.Client;
        PacketCipher clientToServer = CreateCipher(negotiated.CipherClientToServer, negotiated.MacClientToServer, encodedSharedSecret, exchangeHash, 'A', 'C', 'E');
        PacketCipher serverToClient = CreateCipher(negotiated.CipherServerToClient, negotiated.MacServerToClient, encodedSharedSecret, exchangeHash, 'B', 'D', 'F');
        PacketCipher send = client ? clientToServer : serverToClient;
        _nextReceiveCipher = client ? serverToClient : clientToServer;

        // The transition to AwaitNewKeys comes first: the send loop can't race ahead of us here.
        lock (_kexLock)
        {
            _kexStep = KexStep.AwaitNewKeys;
        }

        OutgoingPacket newKeys = OutgoingPacket.Create([MessageNumber.NewKeys], nextCipher: send, resetSequence: _strictKex);
        await EnqueueKexAsync(newKeys, cancellationToken).ConfigureAwait(false);

        if (!_firstKexComplete && !client && _peerOffersExtInfo)
        {
            await SendExtInfoAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private async ValueTask SendExtInfoAsync(CancellationToken cancellationToken)
    {
        byte[] encoded;
        SshWriter writer = new(256);
        try
        {
            writer.WriteByte(MessageNumber.ExtInfo);
            writer.WriteUInt32(1);
            writer.WriteUtf8String("server-sig-algs");
            writer.WriteUtf8String(string.Join(',', _options.ServerSignatureAlgorithms));
            encoded = writer.ToArray();
        }
        finally
        {
            writer.Dispose();
        }

        await EnqueueKexAsync(OutgoingPacket.Create(encoded), cancellationToken).ConfigureAwait(false);
    }

    private PacketCipher CreateCipher(string cipherName, string? macName, byte[] encodedSharedSecret, byte[] exchangeHash, char ivLetter, char keyLetter, char macLetter)
    {
        CipherInfo cipher = PacketCipherCatalog.FindCipher(cipherName)
            ?? throw new SshNegotiationException($"The negotiated cipher {cipherName} isn't available.");
        int macLength = 0;
        if (macName is not null)
        {
            macLength = (PacketCipherCatalog.FindMac(macName)
                ?? throw new SshNegotiationException($"The negotiated MAC {macName} isn't available.")).KeyLength;
        }

        byte[] iv = DeriveKey(encodedSharedSecret, exchangeHash, ivLetter, cipher.IvLength);
        byte[] key = DeriveKey(encodedSharedSecret, exchangeHash, keyLetter, cipher.KeyLength);
        byte[] macKey = DeriveKey(encodedSharedSecret, exchangeHash, macLetter, macLength);
        try
        {
            return PacketCipherCatalog.Create(cipherName, macName, key, iv, macKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(iv);
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(macKey);
        }
    }

    /// <summary>RFC 4253 section 7.2: HASH(K || H || letter || session_id), extended with HASH(K || H || K1 ...).</summary>
    private byte[] DeriveKey(byte[] encodedSharedSecret, byte[] exchangeHash, char letter, int length)
    {
        byte[] result = new byte[length];
        if (length == 0)
        {
            return result;
        }

        SshWriter writer = new(encodedSharedSecret.Length + exchangeHash.Length + 1 + _sessionId.Length);
        try
        {
            writer.WriteRaw(encodedSharedSecret);
            writer.WriteRaw(exchangeHash);
            writer.WriteByte((byte)letter);
            writer.WriteRaw(_sessionId);
            byte[] block = _kexMethod!.Hash(writer.Written);
            int filled = Math.Min(block.Length, length);
            block.AsSpan(0, filled).CopyTo(result);
            CryptographicOperations.ZeroMemory(block);

            while (filled < length)
            {
                SshWriter extend = new(encodedSharedSecret.Length + exchangeHash.Length + filled);
                try
                {
                    extend.WriteRaw(encodedSharedSecret);
                    extend.WriteRaw(exchangeHash);
                    extend.WriteRaw(result.AsSpan(0, filled));
                    block = _kexMethod.Hash(extend.Written);
                    int take = Math.Min(block.Length, length - filled);
                    block.AsSpan(0, take).CopyTo(result.AsSpan(filled));
                    CryptographicOperations.ZeroMemory(block);
                    filled += take;
                }
                finally
                {
                    extend.Dispose();
                }
            }

            return result;
        }
        finally
        {
            writer.Dispose();
        }
    }

    /// <summary>The peer's NEWKEYS: from the next packet on, its traffic uses the new keys.</summary>
    private void CompleteKex(ReadOnlySpan<byte> payload)
    {
        if (payload.Length != 1)
        {
            throw new SshProtocolException("The peer sent a malformed NEWKEYS.");
        }

        DisposeCipher(_receiveCipher);
        _receiveCipher = _nextReceiveCipher!;
        _nextReceiveCipher = null;
        if (_strictKex)
        {
            _receiveSequence = 0;
        }

        _bytesReceived = 0;
        _packetsReceived = 0;
        Volatile.Write(ref _lastKexTimestamp, _options.TimeProvider.GetTimestamp());

        lock (_kexLock)
        {
            ReleaseKexState();
            ClearDeadline();
            _kexStep = KexStep.Idle;
            _peerKexRunning = false;
        }

        if (!_firstKexComplete)
        {
            _firstKexComplete = true;
            _firstPacketAfterNewKeys = true;
            _phase = TransportPhase.AwaitService;
        }

        Interlocked.Increment(ref _completedKeyExchanges);
        TransportLog.KexFinished(_options.Logger);
    }

    /// <summary>Frees everything one exchange held (libssh CVE-2025-8277). Caller holds the KEX lock.</summary>
    private void ReleaseKexState()
    {
        _kexMethod?.Dispose();
        _kexMethod = null;
        _clientPublicValue = null;
        _ourKexInit = null;
        _peerKexInit = null;
        _ourKexInitMessage = null;
        _negotiated = null;
        _ignoreNextKexPacket = false;
        _nextReceiveCipher?.Dispose();
        _nextReceiveCipher = null;
    }
}

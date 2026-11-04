using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Zorg.Ssh.Crypto.Ciphers;

/// <summary>
/// <c>chacha20-poly1305@openssh.com</c>, as OpenSSH's PROTOCOL.chacha20poly1305 describes. The first 32 key bytes
/// encrypt the body and give the per-packet Poly1305 key from block 0. The last 32 encrypt only the length.
/// Poly1305 covers the encrypted length and the encrypted body.
/// </summary>
/// <remarks>
/// OpenSSH runs ChaCha20 with a 64-bit counter and a 64-bit IV holding the sequence number. RFC 8439's 32-bit counter
/// and 96-bit nonce fill the same state words, so a nonce of four zero bytes and the 8-byte big-endian sequence number
/// is the same cipher, as long as the counter stays under 2^32. Packets are far too small to reach that.
/// <para>
/// Each packet allocates one BouncyCastle <see cref="KeyParameter"/>, the only way to key its Poly1305. That also
/// leaves the one-time Poly1305 key on the heap until collected. The key authenticates that single packet, which by
/// then has been sent or accepted.
/// </para>
/// </remarks>
internal sealed class ChaCha20Poly1305Cipher : PacketCipher
{
    private const int HalfKeySize = 32;
    private const int Block = 8;
    private const int Tag = 16;
    private const int BodyOffset = 4;
    private const int ChaChaBlockSize = 64;
    private const int PolyKeySize = 32;
    private const int NonceSize = 12;
    private const int SequenceOffset = 8;

    private readonly ReseatableChaCha _bodyCipher;
    private readonly ReseatableChaCha _lengthCipher;
    private readonly Poly1305 _poly = new();
    private readonly byte[] _nonce = new byte[NonceSize];
    private bool _disposed;

    public ChaCha20Poly1305Cipher(ReadOnlySpan<byte> key)
    {
        _bodyCipher = new ReseatableChaCha(key[..HalfKeySize]);
        _lengthCipher = new ReseatableChaCha(key[HalfKeySize..]);
    }

    public override int BlockSize => Block;

    public override int TagLength => Tag;

    public override bool LengthExcludedFromPadding => true;

    public override uint ReadPacketLength(ReadOnlySpan<byte> header, uint sequenceNumber)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        // The value here is still encrypted. The call is for its rejection of a short header.
        _ = PacketChecks.ReadLength(header);

        Span<byte> length = stackalloc byte[BodyOffset];
        CryptLength(header[..BodyOffset], length, sequenceNumber);
        return BinaryPrimitives.ReadUInt32BigEndian(length);
    }

    public override void Open(Span<byte> packet, uint sequenceNumber)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        PacketChecks.CheckSize(packet.Length, Block, Tag);

        KeyPoly(sequenceNumber);
        _poly.BlockUpdate(packet[..^Tag]);
        Span<byte> expectedTag = stackalloc byte[Tag];
        _poly.DoFinal(expectedTag);
        bool authentic = CryptographicOperations.FixedTimeEquals(expectedTag, packet[^Tag..]);
        CryptographicOperations.ZeroMemory(expectedTag);
        if (!authentic)
        {
            PacketChecks.ThrowAuthenticationFailed();
        }

        // Plaintext from here on. The length ends up decrypted too, so it reads the same after Open for every cipher.
        Span<byte> lengthField = packet[..BodyOffset];
        CryptLength(lengthField, lengthField, sequenceNumber);
        PacketChecks.CheckLength(BinaryPrimitives.ReadUInt32BigEndian(lengthField), packet.Length, Tag);

        Span<byte> body = packet[BodyOffset..^Tag];
        _bodyCipher.ProcessBytes(body, body);
        PacketChecks.CheckPadding(body);
    }

    public override void Seal(Span<byte> packet, uint sequenceNumber)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        PacketChecks.CheckOutgoing(packet, Block, Tag);

        KeyPoly(sequenceNumber);

        Span<byte> body = packet[BodyOffset..^Tag];
        _bodyCipher.ProcessBytes(body, body);

        Span<byte> lengthField = packet[..BodyOffset];
        CryptLength(lengthField, lengthField, sequenceNumber);

        _poly.BlockUpdate(packet[..^Tag]);
        _poly.DoFinal(packet[^Tag..]);
    }

    protected override void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            _disposed = true;
            if (disposing)
            {
                _bodyCipher.Wipe();
                _lengthCipher.Wipe();

                // Replaces the last one-time key held in the MAC's state.
                _poly.Init(new KeyParameter(new byte[PolyKeySize]));
                Array.Clear(_nonce);
            }
        }

        base.Dispose(disposing);
    }

    /// <summary>
    /// Keys Poly1305 from block 0 of the body cipher. The whole block is consumed, which leaves the cipher at block 1
    /// for the body.
    /// </summary>
    private void KeyPoly(uint sequenceNumber)
    {
        BinaryPrimitives.WriteUInt32BigEndian(_nonce.AsSpan(SequenceOffset), sequenceNumber);
        _bodyCipher.Reseat(_nonce);

        Span<byte> block = stackalloc byte[ChaChaBlockSize];
        block.Clear();
        _bodyCipher.ProcessBytes(block, block);
        _poly.Init(new KeyParameter(block[..PolyKeySize]));
        CryptographicOperations.ZeroMemory(block);
    }

    private void CryptLength(ReadOnlySpan<byte> input, Span<byte> output, uint sequenceNumber)
    {
        BinaryPrimitives.WriteUInt32BigEndian(_nonce.AsSpan(SequenceOffset), sequenceNumber);
        _lengthCipher.Reseat(_nonce);
        _lengthCipher.ProcessBytes(input, output);
    }

    /// <summary>
    /// A ChaCha20 engine that takes a new nonce without the two allocations of <c>Init</c>, and that can be wiped.
    /// </summary>
    private sealed class ReseatableChaCha : ChaCha7539Engine
    {
        public ReseatableChaCha(ReadOnlySpan<byte> key)
        {
            byte[] nonce = new byte[NonceSize];

            // Only Init marks an engine as ready, and Init would leave a copy of its key in a KeyParameter that can't
            // be zeroed. So it gets a key of zeros, and the real key goes in through SetKey from a copy that can be.
            Init(forEncryption: true, new ParametersWithIV(new KeyParameter(new byte[HalfKeySize]), nonce));

            byte[] copy = key.ToArray();
            try
            {
                SetKey(copy, nonce);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(copy);
            }

            Reset();
        }

        /// <summary>Selects a nonce with the key unchanged, and returns to block 0.</summary>
        public void Reseat(byte[] nonce)
        {
            SetKey(null, nonce);
            Reset();
        }

        /// <summary>Replaces the key in the engine's state, then overwrites its last keystream block.</summary>
        public void Wipe()
        {
            SetKey(new byte[HalfKeySize], new byte[NonceSize]);
            Reset();

            Span<byte> scratch = stackalloc byte[1];
            ProcessBytes(scratch, scratch);
        }
    }
}

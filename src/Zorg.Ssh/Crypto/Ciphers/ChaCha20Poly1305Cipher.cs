using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Zorg.Ssh.Crypto.Ciphers;

/// <summary>
/// <c>chacha20-poly1305@openssh.com</c>, as OpenSSH's PROTOCOL.chacha20poly1305 describes. The first 32 key bytes
/// encrypt the body and give the per-packet Poly1305 key from block 0. The last 32 encrypt only the length.
/// Poly1305 covers the encrypted length and the encrypted body.
/// </summary>
/// <remarks>
/// ChaCha20 is <see cref="ChaCha20Simd"/>, which runs OpenSSH's layout directly: a 64-bit block counter and a 64-bit
/// IV holding the sequence number. Poly1305 is BouncyCastle's.
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
    private const int PolyKeySize = 32;

    private readonly uint[] _bodyKey = new uint[ChaCha20Simd.KeyWords];
    private readonly uint[] _lengthKey = new uint[ChaCha20Simd.KeyWords];
    private readonly Poly1305 _poly = new();
    private bool _disposed;

    public ChaCha20Poly1305Cipher(ReadOnlySpan<byte> key)
    {
        ChaCha20Simd.LoadKey(key[..HalfKeySize], _bodyKey);
        ChaCha20Simd.LoadKey(key[HalfKeySize..], _lengthKey);
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
        ChaCha20Simd.Crypt(_bodyKey, counter: 1, nonce0: 0, Nonce(sequenceNumber), body, body);
        PacketChecks.CheckPadding(body);
    }

    public override void Seal(Span<byte> packet, uint sequenceNumber)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        PacketChecks.CheckOutgoing(packet, Block, Tag);

        KeyPoly(sequenceNumber);

        Span<byte> body = packet[BodyOffset..^Tag];
        ChaCha20Simd.Crypt(_bodyKey, counter: 1, nonce0: 0, Nonce(sequenceNumber), body, body);

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
                CryptographicOperations.ZeroMemory(MemoryMarshalBytes(_bodyKey));
                CryptographicOperations.ZeroMemory(MemoryMarshalBytes(_lengthKey));

                // Replaces the last one-time key held in the MAC's state.
                _poly.Init(new KeyParameter(new byte[PolyKeySize]));
            }
        }

        base.Dispose(disposing);
    }

    private static Span<byte> MemoryMarshalBytes(uint[] words) => System.Runtime.InteropServices.MemoryMarshal.AsBytes(words.AsSpan());

    /// <summary>
    /// State word 15. The IV is the sequence number as 8 big-endian bytes, whose first four are zero, so word 14 is zero
    /// and word 15 is the last four bytes read as a little-endian word.
    /// </summary>
    private static uint Nonce(uint sequenceNumber) => BinaryPrimitives.ReverseEndianness(sequenceNumber);

    /// <summary>
    /// Keys Poly1305 from block 0 of the body cipher. The whole block is consumed, so the body starts at block 1.
    /// </summary>
    private void KeyPoly(uint sequenceNumber)
    {
        Span<byte> block = stackalloc byte[ChaCha20Simd.BlockSize];
        ChaCha20Simd.Keystream(_bodyKey, counter: 0, nonce0: 0, Nonce(sequenceNumber), block);
        _poly.Init(new KeyParameter(block[..PolyKeySize]));
        CryptographicOperations.ZeroMemory(block);
    }

    private void CryptLength(ReadOnlySpan<byte> input, Span<byte> output, uint sequenceNumber)
    {
        Span<byte> block = stackalloc byte[ChaCha20Simd.BlockSize];
        ChaCha20Simd.Keystream(_lengthKey, counter: 0, nonce0: 0, Nonce(sequenceNumber), block);
        for (int i = 0; i < BodyOffset; i++)
        {
            output[i] = (byte)(input[i] ^ block[i]);
        }

        CryptographicOperations.ZeroMemory(block);
    }
}

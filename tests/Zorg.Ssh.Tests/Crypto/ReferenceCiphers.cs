using System;
using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Zorg.Ssh.Tests.Crypto;

/// <summary>
/// Slow, obvious versions of each packet format, written from the specifications and sharing no code with the library.
/// ChaCha20 follows Bernstein's layout, as OpenSSH uses it, rather than RFC 8439's. Poly1305 is the RFC's arithmetic on
/// big integers. GCM is BouncyCastle's, where the library uses the BCL. CTR is single AES blocks and one-shot HMAC.
/// KnownAnswerTests pins each of these to published vectors.
/// </summary>
internal static class ReferenceCiphers
{
    private const int LengthField = 4;

    public static byte[] ChaChaBlock(ReadOnlySpan<byte> key, ulong counter, uint sequenceNumber)
    {
        uint[] state = new uint[16];
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;
        for (int i = 0; i < 8; i++)
        {
            state[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key[(i * 4)..]);
        }

        // Words 12 and 13 are a 64-bit counter, and 14 and 15 a 64-bit IV: the sequence number as a uint64 on the wire.
        state[12] = (uint)counter;
        state[13] = (uint)(counter >> 32);
        Span<byte> iv = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(iv, sequenceNumber);
        state[14] = BinaryPrimitives.ReadUInt32LittleEndian(iv);
        state[15] = BinaryPrimitives.ReadUInt32LittleEndian(iv[4..]);

        uint[] x = (uint[])state.Clone();
        for (int round = 0; round < 10; round++)
        {
            QuarterRound(x, 0, 4, 8, 12);
            QuarterRound(x, 1, 5, 9, 13);
            QuarterRound(x, 2, 6, 10, 14);
            QuarterRound(x, 3, 7, 11, 15);
            QuarterRound(x, 0, 5, 10, 15);
            QuarterRound(x, 1, 6, 11, 12);
            QuarterRound(x, 2, 7, 8, 13);
            QuarterRound(x, 3, 4, 9, 14);
        }

        byte[] output = new byte[64];
        for (int i = 0; i < 16; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(i * 4), x[i] + state[i]);
        }

        return output;
    }

    public static byte[] Poly1305(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message)
    {
        BigInteger clamp = BigInteger.Parse("0ffffffc0ffffffc0ffffffc0fffffff", System.Globalization.NumberStyles.HexNumber, null);
        BigInteger r = new BigInteger(key[..16], isUnsigned: true) & clamp;
        BigInteger s = new(key[16..32], isUnsigned: true);
        BigInteger p = (BigInteger.One << 130) - 5;

        BigInteger accumulator = BigInteger.Zero;
        for (int offset = 0; offset < message.Length; offset += 16)
        {
            ReadOnlySpan<byte> chunk = message[offset..Math.Min(offset + 16, message.Length)];
            BigInteger n = new BigInteger(chunk, isUnsigned: true) + (BigInteger.One << (8 * chunk.Length));
            accumulator = (accumulator + n) * r % p;
        }

        BigInteger tag = (accumulator + s) & ((BigInteger.One << 128) - 1);
        byte[] output = new byte[16];
        tag.TryWriteBytes(output, out _, isUnsigned: true);
        return output;
    }

    /// <summary>Seals a length field and body, neither of which needs to be well formed.</summary>
    public static byte[] SealChaCha(ReadOnlySpan<byte> key, uint sequenceNumber, uint lengthField, ReadOnlySpan<byte> body)
    {
        ReadOnlySpan<byte> bodyKey = key[..32];
        ReadOnlySpan<byte> lengthKey = key[32..];
        byte[] packet = new byte[LengthField + body.Length + 16];

        BinaryPrimitives.WriteUInt32BigEndian(packet, lengthField);
        byte[] lengthStream = ChaChaBlock(lengthKey, 0, sequenceNumber);
        for (int i = 0; i < LengthField; i++)
        {
            packet[i] ^= lengthStream[i];
        }

        for (int i = 0; i < body.Length; i++)
        {
            byte[] block = ChaChaBlock(bodyKey, 1 + ((ulong)i / 64), sequenceNumber);
            packet[LengthField + i] = (byte)(body[i] ^ block[i % 64]);
        }

        byte[] polyKey = ChaChaBlock(bodyKey, 0, sequenceNumber).AsSpan(0, 32).ToArray();
        Poly1305(polyKey, packet.AsSpan(0, LengthField + body.Length)).CopyTo(packet, LengthField + body.Length);
        return packet;
    }

    /// <summary>Seals a length field and body, neither of which needs to be well formed, with an explicit nonce.</summary>
    public static byte[] SealGcm(byte[] key, byte[] nonce, uint lengthField, ReadOnlySpan<byte> body)
    {
        byte[] aad = new byte[LengthField];
        BinaryPrimitives.WriteUInt32BigEndian(aad, lengthField);
        byte[] sealedBody = Gcm(key, nonce, aad, body.ToArray());

        byte[] packet = new byte[LengthField + sealedBody.Length];
        aad.CopyTo(packet, 0);
        sealedBody.CopyTo(packet, LengthField);
        return packet;
    }

    /// <summary>BouncyCastle's AES-GCM: returns the ciphertext followed by a 16-byte tag.</summary>
    public static byte[] Gcm(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext)
    {
        GcmBlockCipher gcm = new(new AesEngine());
        gcm.Init(forEncryption: true, new AeadParameters(new KeyParameter(key), 128, nonce, aad));
        byte[] output = new byte[gcm.GetOutputSize(plaintext.Length)];
        int written = gcm.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
        gcm.DoFinal(output, written);
        return output;
    }

    /// <summary>
    /// Seals a length field and body, neither of which needs to be well formed. <paramref name="counter"/> is the
    /// 128-bit counter's value, and moves on by the number of blocks used.
    /// </summary>
    public static byte[] SealCtrEtm(byte[] key, ref BigInteger counter, bool sha512, byte[] macKey, uint sequenceNumber, uint lengthField, ReadOnlySpan<byte> body)
    {
        using Aes aes = Aes.Create();
        aes.Key = key;

        BigInteger modulus = BigInteger.One << 128;
        byte[] ciphertext = new byte[body.Length];
        for (int offset = 0; offset < body.Length; offset += 16)
        {
            byte[] counterBlock = new byte[16];
            counter.TryWriteBytes(counterBlock, out int written, isUnsigned: true, isBigEndian: true);
            Array.Copy(counterBlock, 0, counterBlock, 16 - written, written);
            Array.Clear(counterBlock, 0, 16 - written);

            byte[] stream = aes.EncryptEcb(counterBlock, PaddingMode.None);
            for (int i = 0; i < 16 && offset + i < body.Length; i++)
            {
                ciphertext[offset + i] = (byte)(body[offset + i] ^ stream[i]);
            }

            counter = (counter + 1) % modulus;
        }

        byte[] macInput = new byte[4 + LengthField + body.Length];
        BinaryPrimitives.WriteUInt32BigEndian(macInput, sequenceNumber);
        BinaryPrimitives.WriteUInt32BigEndian(macInput.AsSpan(4), lengthField);
        ciphertext.CopyTo(macInput, 8);
        byte[] tag = sha512 ? HMACSHA512.HashData(macKey, macInput) : HMACSHA256.HashData(macKey, macInput);

        byte[] packet = new byte[LengthField + body.Length + tag.Length];
        macInput.AsSpan(4).CopyTo(packet);
        tag.CopyTo(packet, LengthField + body.Length);
        return packet;
    }

    private static void QuarterRound(uint[] x, int a, int b, int c, int d)
    {
        x[a] += x[b];
        x[d] = BitOperations.RotateLeft(x[d] ^ x[a], 16);
        x[c] += x[d];
        x[b] = BitOperations.RotateLeft(x[b] ^ x[c], 12);
        x[a] += x[b];
        x[d] = BitOperations.RotateLeft(x[d] ^ x[a], 8);
        x[c] += x[d];
        x[b] = BitOperations.RotateLeft(x[b] ^ x[c], 7);
    }
}

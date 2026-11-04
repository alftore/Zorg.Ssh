using System;
using System.Buffers.Binary;
using Xunit;
using Zorg.Ssh.Crypto;

namespace Zorg.Ssh.Tests.Crypto;

/// <summary>Key material and packet building for the cipher tests.</summary>
internal static class CipherHarness
{
    public const string Aes128Gcm = "aes128-gcm@openssh.com";
    public const string Aes256Gcm = "aes256-gcm@openssh.com";
    public const string ChaCha = "chacha20-poly1305@openssh.com";
    public const string Aes128Ctr = "aes128-ctr";
    public const string Aes256Ctr = "aes256-ctr";
    public const string Sha256Etm = "hmac-sha2-256-etm@openssh.com";
    public const string Sha512Etm = "hmac-sha2-512-etm@openssh.com";

    /// <summary>Every cipher and MAC pairing the catalog can build.</summary>
    public static TheoryData<string, string?> AllSuites =>
        new()
        {
            { Aes128Gcm, null },
            { Aes256Gcm, null },
            { ChaCha, null },
            { Aes128Ctr, Sha256Etm },
            { Aes128Ctr, Sha512Etm },
            { Aes256Ctr, Sha256Etm },
            { Aes256Ctr, Sha512Etm },
        };

    /// <summary>The suites that send the length in clear.</summary>
    public static TheoryData<string, string?> ClearLengthSuites =>
        new()
        {
            { Aes128Gcm, null },
            { Aes256Gcm, null },
            { Aes128Ctr, Sha256Etm },
            { Aes256Ctr, Sha512Etm },
        };

    /// <summary>The suites that take the sequence number into the packet's authentication.</summary>
    public static TheoryData<string, string?> SequencedSuites =>
        new()
        {
            { ChaCha, null },
            { Aes128Ctr, Sha256Etm },
            { Aes128Ctr, Sha512Etm },
            { Aes256Ctr, Sha256Etm },
            { Aes256Ctr, Sha512Etm },
        };

    public static byte[] Pattern(int length, byte seed)
    {
        byte[] data = new byte[length];
        for (int i = 0; i < length; i++)
        {
            data[i] = (byte)((i * 31) + seed);
        }

        return data;
    }

    public static byte[] KeyFor(string cipherName) =>
        Pattern(PacketCipherCatalog.FindCipher(cipherName)!.KeyLength, 0x11);

    public static byte[] IvFor(string cipherName) =>
        Pattern(PacketCipherCatalog.FindCipher(cipherName)!.IvLength, 0x22);

    public static byte[] MacKeyFor(string? macName) =>
        macName is null ? [] : Pattern(PacketCipherCatalog.FindMac(macName)!.KeyLength, 0x33);

    public static PacketCipher Create(string cipherName, string? macName) =>
        PacketCipherCatalog.Create(cipherName, macName, KeyFor(cipherName), IvFor(cipherName), MacKeyFor(macName));

    /// <summary>Builds a plaintext packet as RFC 4253 section 6 lays it out, with room for the tag.</summary>
    public static byte[] Plain(PacketCipher cipher, int payloadLength, byte seed = 0x44)
    {
        int padding = cipher.BlockSize - ((1 + payloadLength) % cipher.BlockSize);
        if (padding < 4)
        {
            padding += cipher.BlockSize;
        }

        int bodyLength = 1 + payloadLength + padding;
        byte[] packet = new byte[4 + bodyLength + cipher.TagLength];
        BinaryPrimitives.WriteUInt32BigEndian(packet, (uint)bodyLength);
        packet[4] = (byte)padding;
        Pattern(payloadLength, seed).CopyTo(packet, 5);
        return packet;
    }

    /// <summary>Wraps a body in a packet buffer with a correct length field.</summary>
    public static byte[] PlainFromBody(ReadOnlySpan<byte> body, int tagLength)
    {
        byte[] packet = new byte[4 + body.Length + tagLength];
        BinaryPrimitives.WriteUInt32BigEndian(packet, (uint)body.Length);
        body.CopyTo(packet.AsSpan(4));
        return packet;
    }

    public static byte[] BodyOf(byte[] packet, PacketCipher cipher) =>
        packet.AsSpan(4, packet.Length - 4 - cipher.TagLength).ToArray();
}

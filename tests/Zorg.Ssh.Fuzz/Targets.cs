using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Threading;
using SharpFuzz;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Sftp;
using Zorg.Ssh.Transport;

namespace Zorg.Ssh.Fuzz;

/// <summary>
/// The fuzz targets. A peer-caused failure must be an <see cref="SshException"/>, so that is the only
/// exception swallowed. Anything else escapes, and libFuzzer saves the input as a crash.
/// </summary>
internal static class Targets
{
    private const int MaxPacketLength = 262144;
    private const int MaxNames = 4096;

    public static bool TryGet(string name, [NotNullWhen(true)] out ReadOnlySpanAction? target)
    {
        target = name switch
        {
            "packet-reader" => PacketReaderTarget,
            "packet-reader-ctr-eam" => EamPacketReaderTarget,
            "kex-init" => KexInitTarget,
            "sftp-response" => SftpResponseTarget,
            _ => null,
        };
        return target is not null;
    }

    /// <summary>Feeds the bytes to the identification reader and then the packet reader, as a stream of plaintext packets.</summary>
    private static void PacketReaderTarget(ReadOnlySpan<byte> data)
    {
        // The first byte picks whether the stream starts with an identification line.
        bool identification = data.Length > 0 && (data[0] & 1) == 0;
        using MemoryStream stream = new(data.ToArray());
        using PacketReader reader = new(stream, MaxPacketLength);
        try
        {
            if (identification)
            {
                reader.ReadIdentificationAsync(allowPreamble: true, CancellationToken.None).AsTask().GetAwaiter().GetResult();
            }

            uint sequence = 0;
            while (true)
            {
                reader.ReadPacketAsync(NoneCipher.Instance, sequence++, CancellationToken.None).AsTask().GetAwaiter().GetResult();
            }
        }
        catch (SshException)
        {
        }
    }

    /// <summary>
    /// Feeds the bytes to the packet reader through AES-128-CTR with encrypt-and-MAC HMAC-SHA-256 and a fixed key, where the
    /// length is encrypted and the reader decrypts the first block to learn it. The first byte picks the form: even is
    /// ciphertext as it is, odd is plaintext packets, each sealed with the fixed key when its length makes a valid shape,
    /// so that mutated lengths and padding get past the MAC.
    /// </summary>
    private static void EamPacketReaderTarget(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0)
        {
            return;
        }

        byte[] stream = (data[0] & 1) == 0 ? data[1..].ToArray() : SealEam(data[1..]);
        using MemoryStream input = new(stream);
        using PacketReader reader = new(input, MaxPacketLength);
        using PacketCipher cipher = EamCipher();
        try
        {
            uint sequence = 0;
            while (true)
            {
                reader.ReadPacketAsync(cipher, sequence++, CancellationToken.None).AsTask().GetAwaiter().GetResult();
            }
        }
        catch (SshException)
        {
        }
    }

    /// <summary>The fixed key of the encrypt-and-MAC target. Seeds are sealed with it.</summary>
    internal static PacketCipher EamCipher()
    {
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        byte[] macKey = new byte[32];
        for (int i = 0; i < macKey.Length; i++)
        {
            macKey[i] = (byte)(i * 7);
            if (i < 16)
            {
                key[i] = (byte)(i * 5);
                iv[i] = (byte)(0xf0 + i);
            }
        }

        return PacketCipherCatalog.Create("aes128-ctr", "hmac-sha2-256", key, iv, macKey);
    }

    /// <summary>Seals each plaintext packet whose length field gives a valid shape. The rest of the input goes as it is.</summary>
    internal static byte[] SealEam(ReadOnlySpan<byte> plain)
    {
        using PacketCipher cipher = EamCipher();
        using MemoryStream output = new();
        uint sequence = 0;
        while (plain.Length >= 4)
        {
            uint length = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(plain);
            long covered = 4L + length;
            if (covered % 16 != 0 || covered > plain.Length || length > MaxPacketLength)
            {
                break;
            }

            byte[] packet = new byte[covered + cipher.TagLength];
            plain[..(int)covered].CopyTo(packet);
            cipher.Seal(packet, sequence++);
            output.Write(packet);
            plain = plain[(int)covered..];
        }

        output.Write(plain);
        return output.ToArray();
    }

    private static void KexInitTarget(ReadOnlySpan<byte> data)
    {
        try
        {
            KexInitMessage.Parse(data);
        }
        catch (SshException)
        {
        }
    }

    /// <summary>The first byte picks the reader and the packet type. The rest is the body.</summary>
    private static void SftpResponseTarget(ReadOnlySpan<byte> data)
    {
        if (data.Length < 1)
        {
            return;
        }

        byte selector = data[0];

        // SftpResponse returns its buffer to the shared pool on Dispose, so the buffer has to come from there.
        ReadOnlySpan<byte> bodyBytes = data[1..];
        byte[] body = ArrayPool<byte>.Shared.Rent(Math.Max(bodyBytes.Length, 1));
        bodyBytes.CopyTo(body);
        using SftpResponse response = new(selector, body, bodyBytes.Length);
        try
        {
            switch (selector % 6)
            {
                case 0:
                    SftpParser.ReadStatus(response);
                    break;
                case 1:
                    SftpParser.ReadHandle(response);
                    break;
                case 2:
                    SftpParser.ReadData(response, 32768);
                    break;
                case 3:
                    SftpParser.ReadNames(response, MaxNames);
                    break;
                case 4:
                    SftpParser.ReadAttributes(response);
                    break;
                default:
                    SftpParser.ReadFileSystemInfo(response);
                    break;
            }
        }
        catch (SshException)
        {
        }
    }
}

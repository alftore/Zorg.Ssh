using System;
using System.Buffers.Binary;
using Zorg.Ssh.Crypto;

namespace Zorg.Ssh.AotSmoke;

/// <summary>Round-trips every cipher and MAC, so Native AOT trimming keeps and runs each one.</summary>
internal static class CipherSmoke
{
    public static void Run(Action<string, bool> check)
    {
        ArgumentNullException.ThrowIfNull(check);

        foreach (string cipher in PacketCipherCatalog.DefaultCiphers)
        {
            if (PacketCipherCatalog.FindCipher(cipher)!.IsAead)
            {
                check(cipher, RoundTrips(cipher, macName: null));
                continue;
            }

            foreach (string mac in PacketCipherCatalog.DefaultMacs)
            {
                check($"{cipher} with {mac}", RoundTrips(cipher, mac));
            }
        }
    }

    private static bool RoundTrips(string cipherName, string? macName)
    {
        CipherInfo cipher = PacketCipherCatalog.FindCipher(cipherName)!;
        byte[] key = Filled(cipher.KeyLength, 1);
        byte[] iv = Filled(cipher.IvLength, 2);
        byte[] macKey = Filled(macName is null ? 0 : PacketCipherCatalog.FindMac(macName)!.KeyLength, 3);

        using PacketCipher sender = PacketCipherCatalog.Create(cipherName, macName, key, iv, macKey);
        using PacketCipher receiver = PacketCipherCatalog.Create(cipherName, macName, key, iv, macKey);

        const int BodyLength = 64;
        const int PaddingLength = 7;
        byte[] packet = new byte[4 + BodyLength + sender.TagLength];
        BinaryPrimitives.WriteUInt32BigEndian(packet, BodyLength);
        packet[4] = PaddingLength;
        for (int i = 5; i < 4 + BodyLength; i++)
        {
            packet[i] = (byte)i;
        }

        byte[] plain = packet.AsSpan(4, BodyLength).ToArray();

        // Two packets, so the counters and sequence numbers have to stay in step.
        for (uint sequence = 0; sequence < 2; sequence++)
        {
            sender.Seal(packet, sequence);
            if (packet.AsSpan(4, BodyLength).SequenceEqual(plain)
                || receiver.ReadPacketLength(packet, sequence) != BodyLength)
            {
                return false;
            }

            receiver.Open(packet, sequence);
            if (!packet.AsSpan(4, BodyLength).SequenceEqual(plain))
            {
                return false;
            }
        }

        return true;
    }

    private static byte[] Filled(int length, byte value)
    {
        byte[] data = new byte[length];
        Array.Fill(data, value);
        return data;
    }
}

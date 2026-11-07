using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.Ciphers;
using Zorg.Ssh.Transport;
using static Zorg.Ssh.Tests.Crypto.CipherHarness;

namespace Zorg.Ssh.Tests.Crypto;

/// <summary>
/// AES-CTR with encrypt-and-MAC HMAC (RFC 4253 section 6.4). The length field is encrypted, so the reader decrypts the first
/// block to learn it: this is the hostile-input path, and most of these tests drive it with a length chosen by the peer.
/// </summary>
public class EncryptAndMacTests
{
    private const int MaxPacketLength = 262144;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public static TheoryData<string, string> Suites => new()
    {
        { Aes128Ctr, Sha256Eam },
        { Aes128Ctr, Sha512Eam },
        { Aes256Ctr, Sha256Eam },
        { Aes256Ctr, Sha512Eam },
    };

    [Theory]
    [MemberData(nameof(Suites))]
    public void Sealing_matches_the_reference_over_several_packets(string cipherName, string macName)
    {
        byte[] key = KeyFor(cipherName);
        byte[] iv = IvFor(cipherName);
        byte[] macKey = MacKeyFor(macName);
        using PacketCipher sender = PacketCipherCatalog.Create(cipherName, macName, key, iv, macKey);
        using PacketCipher receiver = PacketCipherCatalog.Create(cipherName, macName, key, iv, macKey);
        BigInteger counter = new(iv, isUnsigned: true, isBigEndian: true);
        uint sequenceNumber = uint.MaxValue - 2;

        // 5000 and 9000 span more than one pass through the keystream buffer. The sequence number wraps on the way.
        foreach (int payload in new[] { 1, 11, 12, 5000, 200, 9000, 27 })
        {
            byte[] packet = Plain(sender, payload);
            uint length = BinaryPrimitives.ReadUInt32BigEndian(packet);
            byte[] body = BodyOf(packet, sender);
            byte[] expected = ReferenceCiphers.SealCtrEam(key, ref counter, PacketCipherCatalog.FindMac(macName)!.Hash, macKey, sequenceNumber, length, body);

            sender.Seal(packet, sequenceNumber);
            Assert.Equal(Convert.ToHexString(expected), Convert.ToHexString(packet));

            Assert.Equal(length, receiver.ReadPacketLength(expected, sequenceNumber));
            receiver.Open(expected, sequenceNumber);
            Assert.Equal(Convert.ToHexString(body), Convert.ToHexString(BodyOf(expected, sender)));
            sequenceNumber++;
        }
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public void Every_size_round_trips_and_the_length_field_is_padded_and_encrypted(string cipherName, string macName)
    {
        using PacketCipher sender = Create(cipherName, macName);
        using PacketCipher receiver = Create(cipherName, macName);
        Assert.False(sender.LengthExcludedFromPadding);
        Assert.Equal(16, sender.LengthBlockSize);
        Assert.Equal(PacketCipherCatalog.FindMac(macName)!.KeyLength, sender.TagLength);
        uint sequenceNumber = 0;

        foreach (int payload in new[] { 1, 2, 7, 11, 12, 15, 16, 17, 31, 32, 33, 255, 1000, 4095, 4096, 4097, 35_000, 262_000 })
        {
            byte[] packet = Plain(sender, payload);
            byte[] original = (byte[])packet.Clone();
            int covered = packet.Length - sender.TagLength;
            Assert.Equal(0, covered % 16);

            sender.Seal(packet, sequenceNumber);
            Assert.False(packet.AsSpan(0, covered).SequenceEqual(original.AsSpan(0, covered)));
            Assert.Equal(BinaryPrimitives.ReadUInt32BigEndian(original), receiver.ReadPacketLength(packet, sequenceNumber));

            receiver.Open(packet, sequenceNumber);
            Assert.True(packet.AsSpan(0, covered).SequenceEqual(original.AsSpan(0, covered)));
            sequenceNumber++;
        }
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public void Reading_the_length_does_not_move_the_counter(string cipherName, string macName)
    {
        using PacketCipher sender = Create(cipherName, macName);
        using PacketCipher receiver = Create(cipherName, macName);
        byte[] first = Plain(sender, 40);
        byte[] second = Plain(sender, 70);
        uint firstLength = BinaryPrimitives.ReadUInt32BigEndian(first);
        sender.Seal(first, 0);
        sender.Seal(second, 1);

        Assert.Equal(firstLength, receiver.ReadPacketLength(first, 0));
        Assert.Equal(firstLength, receiver.ReadPacketLength(first, 0));
        receiver.Open(first, 0);
        receiver.ReadPacketLength(second, 1);
        receiver.Open(second, 1);
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public void Changing_any_byte_fails_authentication_and_leaves_no_plaintext(string cipherName, string macName)
    {
        using PacketCipher sender = Create(cipherName, macName);
        byte[] packet = Plain(sender, 20);
        sender.Seal(packet, 9);

        // Covers the encrypted length, the body and the tag. Each try needs a fresh receiver: a failed packet ends the connection,
        // and decryption has moved the counter on, so the cipher is spent.
        for (int i = 0; i < packet.Length; i++)
        {
            using PacketCipher receiver = Create(cipherName, macName);
            byte[] tampered = (byte[])packet.Clone();
            tampered[i] ^= 0x01;
            SshProtocolException failure = Assert.Throws<SshProtocolException>(() => receiver.Open(tampered, 9));

            Assert.Contains("authentication", failure.Message, StringComparison.Ordinal);
            Assert.All(tampered[..^sender.TagLength], b => Assert.Equal(0, b));
        }
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public void A_wrong_sequence_number_fails(string cipherName, string macName)
    {
        using PacketCipher sender = Create(cipherName, macName);
        using PacketCipher receiver = Create(cipherName, macName);
        byte[] packet = Plain(sender, 20);
        sender.Seal(packet, 7);

        Assert.Throws<SshProtocolException>(() => receiver.Open(packet, 8));
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public void The_MAC_is_checked_before_the_padding_is_looked_at(string cipherName, string macName)
    {
        // Authentic but with padding_length 0, then with its tag broken: the second must fail on the tag, so nothing in the
        // plaintext was acted on before the MAC check.
        byte[] body = new byte[28];
        byte[] packet = SealReference(cipherName, macName, 28, body);
        using (PacketCipher receiver = Create(cipherName, macName))
        {
            SshProtocolException malformed = Assert.Throws<SshProtocolException>(() => receiver.Open((byte[])packet.Clone(), 0));
            Assert.Contains("malformed", malformed.Message, StringComparison.Ordinal);
        }

        packet[^1] ^= 1;
        using (PacketCipher receiver = Create(cipherName, macName))
        {
            SshProtocolException failure = Assert.Throws<SshProtocolException>(() => receiver.Open(packet, 0));
            Assert.Contains("authentication", failure.Message, StringComparison.Ordinal);
            Assert.Null(failure.InnerException);
        }
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public void Authentic_packets_with_bad_padding_are_rejected(string cipherName, string macName)
    {
        // Go CVE-2026-46597 is the 255 case: padding_length + 1 summed in a byte wrapped to 0.
        foreach (byte padding in new byte[] { 0, 1, 2, 3, 27, 28, 200, 254, 255 })
        {
            byte[] body = new byte[28];
            body[0] = padding;
            byte[] packet = SealReference(cipherName, macName, 28, body);
            using PacketCipher receiver = Create(cipherName, macName);

            Assert.Throws<SshProtocolException>(() => receiver.Open(packet, 0));
        }

        // The largest padding that leaves one payload byte is fine.
        byte[] good = new byte[28];
        good[0] = 26;
        using PacketCipher accepting = Create(cipherName, macName);
        accepting.Open(SealReference(cipherName, macName, 28, good), 0);
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public void An_authentic_length_that_disagrees_with_the_packet_is_rejected(string cipherName, string macName)
    {
        foreach (uint length in new uint[] { 0, 12, 44, 27, uint.MaxValue })
        {
            byte[] body = new byte[28];
            body[0] = 4;
            byte[] packet = SealReference(cipherName, macName, length, body);
            using PacketCipher receiver = Create(cipherName, macName);

            Assert.Throws<SshProtocolException>(() => receiver.Open(packet, 0));
        }
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public void A_packet_that_is_not_whole_blocks_is_rejected_before_decryption(string cipherName, string macName)
    {
        using PacketCipher sender = Create(cipherName, macName);
        byte[] packet = Plain(sender, 40);
        sender.Seal(packet, 0);

        for (int length = 0; length < packet.Length; length++)
        {
            using PacketCipher receiver = Create(cipherName, macName);
            Assert.Throws<SshProtocolException>(() => receiver.Open(packet.AsSpan(0, length).ToArray(), 0));
        }

        foreach (int extra in new[] { 1, 8, 15, 16, 64 })
        {
            using PacketCipher receiver = Create(cipherName, macName);
            byte[] extended = new byte[packet.Length + extra];
            packet.CopyTo(extended, 0);
            Assert.Throws<SshProtocolException>(() => receiver.Open(extended, 0));
        }
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public void A_header_shorter_than_one_block_is_rejected(string cipherName, string macName)
    {
        using PacketCipher cipher = Create(cipherName, macName);

        for (int length = 0; length < 16; length++)
        {
            Assert.Throws<SshProtocolException>(() => cipher.ReadPacketLength(new byte[length], 0));
        }
    }

    public static TheoryData<uint> HostileLengths() =>
    [
        0, 1, 4, 5, 11, // too short to fill a block, or under the reader's minimum
        13, 27, 100, 1001, // not whole blocks with the length field
        MaxPacketLength + 12, // whole blocks, over the limit
        0x0100_000c, 0x7fff_fffc, 0x8000_000c, 0xffff_fffc, // whole blocks, huge
        0x7fff_ffff, 0x8000_0000, 0xffff_fff0, uint.MaxValue,
    ];

    [Theory]
    [MemberData(nameof(HostileLengths))]
    public async Task A_length_that_decrypts_to_a_huge_or_invalid_value_is_refused_from_the_first_block(uint length)
    {
        // The stream holds the first block and nothing more. If the reader tried to wait for the packet the length names,
        // or grew its buffer for it, the stream would end and the failure would be SshConnectionException instead.
        byte[] packet = SealReference(Aes128Ctr, Sha256Eam, length, new byte[12]);
        using PacketCipher cipher = Create(Aes128Ctr, Sha256Eam);
        using PacketReader reader = new(new MemoryStream(packet[..16]), MaxPacketLength);
        long before = GC.GetAllocatedBytesForCurrentThread();

        SshProtocolException failure = await Assert.ThrowsAsync<SshProtocolException>(async () => await reader.ReadPacketAsync(cipher, 0, Ct));

        Assert.DoesNotContain(length.ToString(System.Globalization.CultureInfo.InvariantCulture), failure.Message, StringComparison.Ordinal);
        Assert.InRange(GC.GetAllocatedBytesForCurrentThread() - before, 0, 64 * 1024);
    }

    [Fact]
    public async Task The_largest_valid_length_is_read()
    {
        // 262140 + 4 is whole blocks, and the payload is as large as the limit allows.
        const uint Length = MaxPacketLength - 4;
        byte[] body = new byte[Length];
        body[0] = 4;
        byte[] packet = SealReference(Aes128Ctr, Sha256Eam, Length, body);
        using PacketCipher cipher = Create(Aes128Ctr, Sha256Eam);
        using PacketReader reader = new(new MemoryStream(packet), MaxPacketLength);

        ReadOnlyMemory<byte> payload = await reader.ReadPacketAsync(cipher, 0, Ct);

        Assert.Equal((int)Length - 5, payload.Length);
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public async Task A_truncated_stream_ends_with_the_connection_exception_and_nothing_else(string cipherName, string macName)
    {
        using PacketCipher sender = Create(cipherName, macName);
        List<byte> stream = [];
        for (uint sequence = 0; sequence < 3; sequence++)
        {
            byte[] packet = Plain(sender, 30 + (int)sequence * 17);
            sender.Seal(packet, sequence);
            stream.AddRange(packet);
        }

        byte[] all = [.. stream];
        for (int cut = 0; cut < all.Length; cut++)
        {
            using PacketCipher receiver = Create(cipherName, macName);
            using PacketReader reader = new(new MemoryStream(all[..cut]), MaxPacketLength);
            int read = 0;
            await Assert.ThrowsAsync<SshConnectionException>(async () =>
            {
                for (uint sequence = 0; ; sequence++)
                {
                    await reader.ReadPacketAsync(receiver, sequence, Ct);
                    read++;
                }
            });
            Assert.InRange(read, 0, 2);
        }

        using PacketCipher whole = Create(cipherName, macName);
        using PacketReader wholeReader = new(new MemoryStream(all), MaxPacketLength);
        for (uint sequence = 0; sequence < 3; sequence++)
        {
            ReadOnlyMemory<byte> payload = await wholeReader.ReadPacketAsync(whole, sequence, Ct);
            Assert.Equal(30 + ((int)sequence * 17), payload.Length);
        }
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public async Task A_MAC_failure_through_the_reader_is_the_protocol_exception(string cipherName, string macName)
    {
        using PacketCipher sender = Create(cipherName, macName);
        byte[] packet = Plain(sender, 64);
        sender.Seal(packet, 0);
        packet[^3] ^= 0x40;
        using PacketCipher receiver = Create(cipherName, macName);
        using PacketReader reader = new(new MemoryStream(packet), MaxPacketLength);

        SshProtocolException failure = await Assert.ThrowsAsync<SshProtocolException>(async () => await reader.ReadPacketAsync(receiver, 0, Ct));

        Assert.Contains("authentication", failure.Message, StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public void Seal_rejects_a_buffer_of_the_wrong_shape(string cipherName, string macName)
    {
        using PacketCipher cipher = Create(cipherName, macName);
        byte[] good = Plain(cipher, 20);
        byte[] tooShort = good[..^1];
        byte[] notBlocks = new byte[4 + 13 + cipher.TagLength];
        BinaryPrimitives.WriteUInt32BigEndian(notBlocks, 13);
        byte[] wrongLength = (byte[])good.Clone();
        wrongLength[3] ^= 0x10;

        Assert.Throws<ArgumentException>(() => cipher.Seal(tooShort, 0));
        Assert.Throws<ArgumentException>(() => cipher.Seal(new byte[3], 0));
        Assert.Throws<ArgumentException>(() => cipher.Seal(notBlocks, 0));
        Assert.Throws<ArgumentException>(() => cipher.Seal(wrongLength, 0));
    }

    [Fact]
    public void Disposing_zeroes_the_keystream_and_refuses_further_use()
    {
        AesCtrEamCipher cipher = (AesCtrEamCipher)Create(Aes128Ctr, Sha256Eam);
        byte[] packet = Plain(cipher, 100);
        cipher.Seal(packet, 0);
        object keystream = PrivateField(cipher, "_keystream");
        byte[] blocks = (byte[])PrivateField(keystream, "_keystream");
        byte[] counters = (byte[])PrivateField(keystream, "_counterBlocks");
        Assert.All(blocks, b => Assert.Equal(0, b));
        Assert.Contains(counters, b => b != 0);

        cipher.Dispose();
        cipher.Dispose();

        Assert.All(blocks, b => Assert.Equal(0, b));
        Assert.All(counters, b => Assert.Equal(0, b));
        Assert.Throws<ObjectDisposedException>(() => cipher.Seal(packet, 0));
        Assert.Throws<ObjectDisposedException>(() => cipher.Open(packet, 0));
        Assert.Throws<ObjectDisposedException>(() => cipher.ReadPacketLength(packet, 0));
    }

    [Fact]
    public void Reading_the_length_clears_the_keystream_it_used()
    {
        using AesCtrEamCipher cipher = (AesCtrEamCipher)Create(Aes256Ctr, Sha512Eam);
        using PacketCipher sender = Create(Aes256Ctr, Sha512Eam);
        byte[] packet = Plain(sender, 20);
        sender.Seal(packet, 0);

        cipher.ReadPacketLength(packet, 0);

        byte[] blocks = (byte[])PrivateField(PrivateField(cipher, "_keystream"), "_keystream");
        Assert.All(blocks.Take(16), b => Assert.Equal(0, b));
    }

    [Fact]
    public void The_hot_path_does_not_allocate()
    {
        using PacketCipher sender = Create(Aes128Ctr, Sha256Eam);
        using PacketCipher receiver = Create(Aes128Ctr, Sha256Eam);
        byte[] packet = Plain(sender, 1000);
        byte[] plain = (byte[])packet.Clone();
        uint sequenceNumber = 0;
        void RoundTrip()
        {
            plain.CopyTo(packet, 0);
            sender.Seal(packet, sequenceNumber);
            receiver.ReadPacketLength(packet, sequenceNumber);
            receiver.Open(packet, sequenceNumber);
            sequenceNumber++;
        }

        for (int i = 0; i < 2000; i++)
        {
            RoundTrip();
        }

        long before = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < 2000; i++)
        {
            RoundTrip();
        }

        Assert.InRange((GC.GetAllocatedBytesForCurrentThread() - before) / 4000, 0, 8);
    }

    [Fact]
    public void The_outgoing_framing_pads_the_length_field_too()
    {
        using PacketCipher cipher = Create(Aes128Ctr, Sha256Eam);
        for (int payload = 1; payload < 80; payload++)
        {
            OutgoingPacket outgoing = OutgoingPacket.Create(new byte[payload]);
            try
            {
                int length = outgoing.Frame(cipher);
                Assert.Equal(0, length % 16);
                Assert.InRange(outgoing.Buffer[4], 4, 19);
                byte[] packet = new byte[length + cipher.TagLength];
                outgoing.Buffer.AsSpan(0, length).CopyTo(packet);
                cipher.Seal(packet, (uint)payload);
            }
            finally
            {
                outgoing.Release();
            }
        }
    }

    /// <summary>A packet with a valid tag for the first use of a cipher from the harness keys, whatever its shape.</summary>
    private static byte[] SealReference(string cipherName, string macName, uint lengthField, byte[] body)
    {
        byte[] iv = IvFor(cipherName);
        BigInteger counter = new(iv, isUnsigned: true, isBigEndian: true);
        return ReferenceCiphers.SealCtrEam(KeyFor(cipherName), ref counter, PacketCipherCatalog.FindMac(macName)!.Hash, MacKeyFor(macName), 0, lengthField, body);
    }

    private static object PrivateField(object target, string name) =>
        target.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(target)!;
}

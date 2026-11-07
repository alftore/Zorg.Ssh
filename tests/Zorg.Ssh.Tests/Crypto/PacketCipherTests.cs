using System;
using System.Buffers.Binary;
using System.Linq;
using System.Numerics;
using System.Reflection;
using Xunit;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.Ciphers;
using static Zorg.Ssh.Tests.Crypto.CipherHarness;

namespace Zorg.Ssh.Tests.Crypto;

public class PacketCipherTests
{
    private const int MaxPacketPayload = 262_000;

    public static TheoryData<string, string?> AllSuites => CipherHarness.AllSuites;

    public static TheoryData<string, string?> ClearLengthSuites => CipherHarness.ClearLengthSuites;

    public static TheoryData<string, string?> SequencedSuites => CipherHarness.SequencedSuites;

    [Theory]
    [MemberData(nameof(AllSuites))]
    public void Round_trip_restores_every_size(string cipherName, string? macName)
    {
        using PacketCipher sender = Create(cipherName, macName);
        using PacketCipher receiver = Create(cipherName, macName);
        uint sequenceNumber = 0;

        foreach (int payload in new[] { 1, 2, 3, 7, 8, 11, 12, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 1000, 4095, 4096, 4097, 35_000, MaxPacketPayload })
        {
            byte[] packet = Plain(sender, payload);
            byte[] original = (byte[])packet.Clone();
            uint length = BinaryPrimitives.ReadUInt32BigEndian(packet);

            sender.Seal(packet, sequenceNumber);
            Assert.False(packet.AsSpan(4, (int)length).SequenceEqual(original.AsSpan(4, (int)length)));
            Assert.Equal(length, receiver.ReadPacketLength(packet, sequenceNumber));

            receiver.Open(packet, sequenceNumber);
            Assert.True(packet.AsSpan(0, 4 + (int)length).SequenceEqual(original.AsSpan(0, 4 + (int)length)));
            sequenceNumber++;
        }
    }

    [Theory]
    [MemberData(nameof(AllSuites))]
    public void The_reported_shape_matches_the_algorithm(string cipherName, string? macName)
    {
        using PacketCipher cipher = Create(cipherName, macName);

        Assert.True(cipher.LengthExcludedFromPadding);
        Assert.Equal(string.Equals(cipherName, ChaCha, StringComparison.Ordinal) ? 8 : 16, cipher.BlockSize);

        int expectedTag = macName switch
        {
            Sha256Etm => 32,
            Sha512Etm => 64,
            _ => 16,
        };
        Assert.Equal(expectedTag, cipher.TagLength);
    }

    [Theory]
    [MemberData(nameof(AllSuites))]
    public void Seal_and_Open_work_in_place_and_touch_nothing_else(string cipherName, string? macName)
    {
        using PacketCipher sender = Create(cipherName, macName);
        using PacketCipher receiver = Create(cipherName, macName);

        byte[] packet = Plain(sender, 100);
        byte[] original = (byte[])packet.Clone();
        int bodyEnd = packet.Length - sender.TagLength;

        // An odd offset also covers unaligned buffers.
        const int Offset = 13;
        byte[] buffer = new byte[Offset + packet.Length + 21];
        Array.Fill(buffer, (byte)0xc3);
        packet.CopyTo(buffer, Offset);
        Span<byte> slice = buffer.AsSpan(Offset, packet.Length);

        sender.Seal(slice, 3);
        receiver.Open(slice, 3);

        Assert.True(slice[..bodyEnd].SequenceEqual(original.AsSpan(0, bodyEnd)));
        Assert.All(buffer.Take(Offset), b => Assert.Equal(0xc3, b));
        Assert.All(buffer.Skip(Offset + packet.Length), b => Assert.Equal(0xc3, b));
    }

    [Theory]
    [MemberData(nameof(AllSuites))]
    public void Changing_any_byte_fails_authentication(string cipherName, string? macName)
    {
        using PacketCipher sender = Create(cipherName, macName);
        using PacketCipher receiver = Create(cipherName, macName);
        byte[] packet = Plain(sender, 20);
        sender.Seal(packet, 9);

        // Covers the length field, the body and the tag, one byte at a time.
        for (int i = 0; i < packet.Length; i++)
        {
            byte[] tampered = (byte[])packet.Clone();
            tampered[i] ^= 0x01;
            Assert.Throws<SshProtocolException>(() => receiver.Open(tampered, 9));
        }

        // Failed attempts leave the receiver able to take the real packet.
        receiver.Open(packet, 9);
    }

    [Theory]
    [MemberData(nameof(AllSuites))]
    public void A_failure_message_holds_no_packet_data(string cipherName, string? macName)
    {
        using PacketCipher sender = Create(cipherName, macName);
        using PacketCipher receiver = Create(cipherName, macName);
        byte[] packet = Plain(sender, 20);
        sender.Seal(packet, 0);
        packet[^1] ^= 1;

        SshProtocolException failure = Assert.Throws<SshProtocolException>(() => receiver.Open(packet, 0));

        Assert.Null(failure.InnerException);
        Assert.DoesNotMatch("[0-9a-fA-F]{8}", failure.Message);
    }

    [Theory]
    [MemberData(nameof(SequencedSuites))]
    public void A_wrong_sequence_number_fails(string cipherName, string? macName)
    {
        using PacketCipher sender = Create(cipherName, macName);
        using PacketCipher receiver = Create(cipherName, macName);
        byte[] packet = Plain(sender, 20);
        sender.Seal(packet, 5);

        foreach (uint wrong in new uint[] { 4, 6, 5 + (1u << 24), uint.MaxValue })
        {
            byte[] copy = (byte[])packet.Clone();
            Assert.Throws<SshProtocolException>(() => receiver.Open(copy, wrong));
        }
    }

    [Theory]
    [InlineData(Aes128Gcm)]
    [InlineData(Aes256Gcm)]
    public void GCM_ignores_the_sequence_number_and_uses_its_invocation_counter(string cipherName)
    {
        // RFC 5647 leaves the sequence number out, so the counter is what catches a lost or reordered packet.
        using PacketCipher sender = Create(cipherName, null);
        using PacketCipher receiver = Create(cipherName, null);

        byte[] first = Plain(sender, 20);
        byte[] second = Plain(sender, 20);
        byte[] third = Plain(sender, 20);
        sender.Seal(first, 5);
        sender.Seal(second, 5);
        sender.Seal(third, 5);

        receiver.Open(first, 1000);
        Assert.Throws<SshProtocolException>(() => receiver.Open(third, 6));
        receiver.Open(second, 6);
    }

    [Theory]
    [MemberData(nameof(AllSuites))]
    public void A_replayed_packet_fails(string cipherName, string? macName)
    {
        using PacketCipher sender = Create(cipherName, macName);
        using PacketCipher receiver = Create(cipherName, macName);
        byte[] packet = Plain(sender, 20);
        sender.Seal(packet, 0);
        byte[] replay = (byte[])packet.Clone();

        receiver.Open(packet, 0);
        Assert.Throws<SshProtocolException>(() => receiver.Open(replay, 1));
    }

    [Theory]
    [InlineData(Aes128Gcm)]
    [InlineData(Aes256Gcm)]
    public void GCM_counter_advances_once_per_packet_with_the_fixed_field_unchanged(string cipherName)
    {
        byte[] key = KeyFor(cipherName);
        byte[] iv = Convert.FromHexString("aabbccdd00000000000000fe");
        using PacketCipher cipher = PacketCipherCatalog.Create(cipherName, null, key, iv, []);

        // 0xfe, 0xff and then a carry into the next byte.
        foreach (string nonce in new[] { "aabbccdd00000000000000fe", "aabbccdd00000000000000ff", "aabbccdd0000000000000100" })
        {
            AssertSealsWithNonce(cipher, key, nonce);
        }
    }

    [Fact]
    public void GCM_counter_wraps_modulo_2_to_the_64_without_touching_the_fixed_field()
    {
        // The start comes from the key exchange, so it can legitimately be this close to the top.
        byte[] key = KeyFor(Aes128Gcm);
        byte[] iv = Convert.FromHexString("00000001ffffffffffffffff");
        using PacketCipher cipher = PacketCipherCatalog.Create(Aes128Gcm, null, key, iv, []);

        AssertSealsWithNonce(cipher, key, "00000001ffffffffffffffff");
        AssertSealsWithNonce(cipher, key, "000000010000000000000000");
        AssertSealsWithNonce(cipher, key, "000000010000000000000001");
    }

    [Theory]
    [MemberData(nameof(AllSuites))]
    public void A_truncated_or_extended_packet_fails_with_the_protocol_exception(string cipherName, string? macName)
    {
        using PacketCipher sender = Create(cipherName, macName);
        using PacketCipher receiver = Create(cipherName, macName);
        byte[] packet = Plain(sender, 40);
        sender.Seal(packet, 0);

        for (int length = 0; length < packet.Length; length++)
        {
            byte[] truncated = packet.AsSpan(0, length).ToArray();
            Assert.Throws<SshProtocolException>(() => receiver.Open(truncated, 0));
        }

        foreach (int extra in new[] { 1, 8, 16, 64 })
        {
            byte[] extended = new byte[packet.Length + extra];
            packet.CopyTo(extended, 0);
            Assert.Throws<SshProtocolException>(() => receiver.Open(extended, 0));
        }
    }

    [Theory]
    [MemberData(nameof(AllSuites))]
    public void A_short_header_fails_with_the_protocol_exception(string cipherName, string? macName)
    {
        using PacketCipher cipher = Create(cipherName, macName);

        for (int length = 0; length < 4; length++)
        {
            byte[] header = new byte[length];
            Assert.Throws<SshProtocolException>(() => cipher.ReadPacketLength(header, 0));
        }
    }

    [Theory]
    [MemberData(nameof(ClearLengthSuites))]
    public void A_hostile_clear_length_fails_with_the_protocol_exception(string cipherName, string? macName)
    {
        using PacketCipher sender = Create(cipherName, macName);
        using PacketCipher receiver = Create(cipherName, macName);
        byte[] packet = Plain(sender, 40);
        sender.Seal(packet, 0);

        foreach (uint length in new uint[] { 0, 1, 15, 16, 47, 49, 0x7fffffff, 0x80000000, 0xfffffff0, uint.MaxValue })
        {
            byte[] hostile = (byte[])packet.Clone();
            BinaryPrimitives.WriteUInt32BigEndian(hostile, length);
            Assert.Throws<SshProtocolException>(() => receiver.Open(hostile, 0));
        }
    }

    [Theory]
    [MemberData(nameof(AllSuites))]
    public void The_authentic_control_packet_is_accepted(string cipherName, string? macName)
    {
        // Shows that the rejections below come from the shape of the packet, not from a bad reference seal.
        using PacketCipher receiver = Create(cipherName, macName);
        byte[] body = new byte[16];
        body[0] = 6;
        byte[] packet = SealAuthentic(cipherName, macName, 16, body);

        receiver.Open(packet, 0);

        Assert.Equal(body, packet.AsSpan(4, 16).ToArray());
    }

    [Theory]
    [MemberData(nameof(AllSuites))]
    public void An_authentic_packet_with_a_bad_shape_is_rejected(string cipherName, string? macName)
    {
        // These carry valid tags, as any peer that finished key exchange can produce them.
        (uint Length, int BodySize)[] shapes =
        [
            (0, 0), // nothing at all, so no padding_length to read
            (0, 16), // a length that disagrees with what arrived
            (16, 0),
            (8, 16),
            (32, 16),
            (uint.MaxValue, 16),
            (13, 13), // not whole blocks, for any block size
            (17, 17),
            (4, 4), // smaller than a block
            (1, 1),
        ];

        foreach ((uint length, int bodySize) in shapes)
        {
            using PacketCipher receiver = Create(cipherName, macName);
            byte[] body = new byte[bodySize];
            if (bodySize > 0)
            {
                body[0] = 4;
            }

            byte[] packet = SealAuthentic(cipherName, macName, length, body);
            Assert.Throws<SshProtocolException>(() => receiver.Open(packet, 0));
        }
    }

    [Theory]
    [MemberData(nameof(AllSuites))]
    public void Regression_Go_CVE_2026_46597_authentic_padding_that_overruns_the_body_is_an_error(string cipherName, string? macName)
    {
        // Go summed padding_length + 1 in a byte, so 255 wrapped to 0 and passed its check, then panicked.
        foreach (byte padding in new byte[] { 255, 254, 16, 15 })
        {
            using PacketCipher sender = Create(cipherName, macName);
            using PacketCipher receiver = Create(cipherName, macName);
            byte[] packet = PlainFromBody(new byte[16], sender.TagLength);
            packet[4] = padding;
            sender.Seal(packet, 0);

            Assert.Throws<SshProtocolException>(() => receiver.Open(packet, 0));
        }
    }

    [Theory]
    [MemberData(nameof(AllSuites))]
    public void Padding_under_four_bytes_is_an_error(string cipherName, string? macName)
    {
        foreach (byte padding in new byte[] { 0, 1, 2, 3 })
        {
            using PacketCipher sender = Create(cipherName, macName);
            using PacketCipher receiver = Create(cipherName, macName);
            byte[] packet = PlainFromBody(new byte[16], sender.TagLength);
            packet[4] = padding;
            sender.Seal(packet, 0);

            Assert.Throws<SshProtocolException>(() => receiver.Open(packet, 0));
        }
    }

    [Theory]
    [MemberData(nameof(AllSuites))]
    public void The_largest_padding_that_leaves_one_payload_byte_is_accepted(string cipherName, string? macName)
    {
        using PacketCipher sender = Create(cipherName, macName);
        using PacketCipher receiver = Create(cipherName, macName);
        byte[] packet = PlainFromBody(new byte[16], sender.TagLength);
        packet[4] = 14;
        sender.Seal(packet, 0);

        receiver.Open(packet, 0);

        Assert.Equal(14, packet[4]);
    }

    [Theory]
    [MemberData(nameof(AllSuites))]
    public void Seal_rejects_a_buffer_of_the_wrong_shape(string cipherName, string? macName)
    {
        using PacketCipher cipher = Create(cipherName, macName);
        byte[] good = Plain(cipher, 20);

        byte[] tooShort = good.AsSpan(0, good.Length - 1).ToArray();
        byte[] tooSmall = new byte[3];
        byte[] notBlocks = new byte[4 + cipher.BlockSize + 1 + cipher.TagLength];
        BinaryPrimitives.WriteUInt32BigEndian(notBlocks, (uint)cipher.BlockSize + 1);
        byte[] wrongLength = (byte[])good.Clone();
        wrongLength[3] ^= 0x10;

        Assert.Throws<ArgumentException>(() => cipher.Seal(tooShort, 0));
        Assert.Throws<ArgumentException>(() => cipher.Seal(tooSmall, 0));
        Assert.Throws<ArgumentException>(() => cipher.Seal(notBlocks, 0));
        Assert.Throws<ArgumentException>(() => cipher.Seal(wrongLength, 0));
    }

    [Theory]
    [MemberData(nameof(AllSuites))]
    public void A_disposed_cipher_refuses_to_work_rather_than_use_a_zeroed_key(string cipherName, string? macName)
    {
        PacketCipher cipher = Create(cipherName, macName);
        byte[] packet = Plain(cipher, 20);
        cipher.Dispose();
        cipher.Dispose();

        Assert.Throws<ObjectDisposedException>(() => cipher.Seal(packet, 0));
        Assert.Throws<ObjectDisposedException>(() => cipher.Open(packet, 0));
        Assert.Throws<ObjectDisposedException>(() => cipher.ReadPacketLength(packet, 0));
    }

    [Theory]
    [MemberData(nameof(AllSuites))]
    public void A_cipher_keeps_its_own_copy_of_the_keys(string cipherName, string? macName)
    {
        // The transport zeroes derived keys straight after Create.
        byte[] key = KeyFor(cipherName);
        byte[] iv = IvFor(cipherName);
        byte[] macKey = MacKeyFor(macName);
        using PacketCipher sender = PacketCipherCatalog.Create(cipherName, macName, key, iv, macKey);
        Array.Clear(key);
        Array.Clear(iv);
        Array.Clear(macKey);

        using PacketCipher receiver = Create(cipherName, macName);
        byte[] packet = Plain(sender, 20);
        sender.Seal(packet, 0);
        receiver.Open(packet, 0);
    }

    [Fact]
    public void Disposing_ChaCha_zeroes_its_key_words()
    {
        ChaCha20Poly1305Cipher cipher = (ChaCha20Poly1305Cipher)Create(ChaCha, null);
        byte[] packet = Plain(cipher, 20);
        cipher.Seal(packet, 0);

        uint[][] keys = [(uint[])PrivateField(cipher, "_bodyKey"), (uint[])PrivateField(cipher, "_lengthKey")];
        Assert.All(keys, key => Assert.Contains(key, word => word != 0));

        cipher.Dispose();

        Assert.All(keys, key => Assert.All(key, word => Assert.Equal(0u, word)));
    }

    [Theory]
    [InlineData(Aes128Ctr, Sha256Etm)]
    [InlineData(Aes256Ctr, Sha512Etm)]
    public void CTR_clears_the_keystream_after_every_packet(string cipherName, string macName)
    {
        using PacketCipher sender = Create(cipherName, macName);
        using PacketCipher receiver = Create(cipherName, macName);

        // More than one chunk, so the loop runs twice, and a short one after it.
        foreach (int size in new[] { 100, 9000, 20 })
        {
            byte[] packet = Plain(sender, size);
            sender.Seal(packet, 0);
            Assert.All((byte[])PrivateField(PrivateField(sender, "_keystream"), "_keystream"), b => Assert.Equal(0, b));

            receiver.Open(packet, 0);
            Assert.All((byte[])PrivateField(PrivateField(receiver, "_keystream"), "_keystream"), b => Assert.Equal(0, b));
        }
    }

    [Fact]
    public void Disposing_CTR_zeroes_its_buffers()
    {
        AesCtrEtmCipher cipher = (AesCtrEtmCipher)Create(Aes128Ctr, Sha256Etm);
        byte[] packet = Plain(cipher, 100);
        cipher.Seal(packet, 0);

        object ctr = PrivateField(cipher, "_keystream");
        byte[] keystream = (byte[])PrivateField(ctr, "_keystream");
        byte[] counters = (byte[])PrivateField(ctr, "_counterBlocks");
        Assert.Contains(counters, b => b != 0);

        cipher.Dispose();

        Assert.All(keystream, b => Assert.Equal(0, b));
        Assert.All(counters, b => Assert.Equal(0, b));
    }

    [Theory]
    [InlineData(Aes256Gcm, null, 0)]
    [InlineData(Aes128Ctr, Sha256Etm, 0)]
    [InlineData(Aes256Ctr, Sha512Etm, 0)]
    [InlineData(ChaCha, null, 80)] // BouncyCastle's Poly1305 can only be keyed through a new KeyParameter
    public void The_hot_path_does_not_allocate_beyond_the_known_cost(string cipherName, string? macName, int allowedPerOperation)
    {
        using PacketCipher sender = Create(cipherName, macName);
        using PacketCipher receiver = Create(cipherName, macName);
        byte[] packet = Plain(sender, 1000);
        byte[] plain = (byte[])packet.Clone();

        const int Rounds = 2000;
        uint sequenceNumber = 0;
        void RoundTrip()
        {
            plain.CopyTo(packet, 0);
            sender.Seal(packet, sequenceNumber);
            receiver.ReadPacketLength(packet, sequenceNumber);
            receiver.Open(packet, sequenceNumber);
            sequenceNumber++;
        }

        // Past the JIT's tiering, which allocates by itself.
        for (int i = 0; i < Rounds; i++)
        {
            RoundTrip();
        }

        long before = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < Rounds; i++)
        {
            RoundTrip();
        }

        long perOperation = (GC.GetAllocatedBytesForCurrentThread() - before) / (Rounds * 2);

        // A little slack: the runtime itself occasionally allocates on this thread. A real allocation is 24 bytes or more.
        Assert.InRange(perOperation, 0, allowedPerOperation + 8);
    }

    private static void AssertSealsWithNonce(PacketCipher cipher, byte[] key, string nonceHex)
    {
        byte[] packet = Plain(cipher, 20);
        byte[] body = BodyOf(packet, cipher);
        byte[] expected = ReferenceCiphers.SealGcm(key, Convert.FromHexString(nonceHex), (uint)body.Length, body);

        // A constant sequence number: only the invocation counter may move the nonce.
        cipher.Seal(packet, 0);

        Assert.Equal(expected, packet);
    }

    /// <summary>Builds a packet with a valid tag for the first use of a cipher from the harness keys, whatever its shape.</summary>
    private static byte[] SealAuthentic(string cipherName, string? macName, uint lengthField, byte[] body)
    {
        byte[] key = KeyFor(cipherName);
        byte[] iv = IvFor(cipherName);
        if (string.Equals(cipherName, ChaCha, StringComparison.Ordinal))
        {
            return ReferenceCiphers.SealChaCha(key, 0, lengthField, body);
        }

        if (macName is null)
        {
            return ReferenceCiphers.SealGcm(key, iv, lengthField, body);
        }

        BigInteger counter = new(iv, isUnsigned: true, isBigEndian: true);
        bool sha512 = string.Equals(macName, Sha512Etm, StringComparison.Ordinal);
        return ReferenceCiphers.SealCtrEtm(key, ref counter, sha512, MacKeyFor(macName), 0, lengthField, body);
    }

    private static object PrivateField(object target, string name) =>
        target.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(target)!;
}

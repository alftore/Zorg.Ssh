using System;
using System.Buffers.Binary;
using System.Numerics;
using Xunit;
using Zorg.Ssh.Crypto;
using static Zorg.Ssh.Tests.Crypto.CipherHarness;

namespace Zorg.Ssh.Tests.Crypto;

/// <summary>
/// Expected values come from outside this code: RFC 8439, NIST SP 800-38A, NIST CAVS GCM vectors, and the OpenSSL 3.5
/// command line (<c>openssl enc</c>, <c>openssl mac</c>) for assembled SSH packets. ReferenceCiphers extends these to
/// more inputs, and is itself pinned to the published vectors here.
/// </summary>
public class KnownAnswerTests
{
    // RFC 8439 appendix A.2 test vector 2, whose key and nonce fit the packet path: key ..01 and sequence number 2.
    // Its first 368 bytes are a whole number of 8-byte blocks, and its first byte makes a valid padding_length.
    private const string Rfc8439Plaintext =
        """
        41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74
        6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e
        64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72
        69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69
        63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72
        20 70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46
        20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20
        6f 72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73
        74 61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69
        74 68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74
        20 6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69
        76 69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72
        65 64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74
        72 69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20
        73 74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75
        64 65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e
        74 73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69
        6f 6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20
        77 72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63
        74 72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61
        74 69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e
        79 20 74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c
        20 77 68 69 63 68 20 61 72 65 20 61 64 64 72 65
        """;

    private const string Rfc8439Ciphertext =
        """
        a3 fb f0 7d f3 fa 2f de 4f 37 6c a2 3e 82 73 70
        41 60 5d 9f 4f 4f 57 bd 8c ff 2c 1d 4b 79 55 ec
        2a 97 94 8b d3 72 29 15 c8 f3 d3 37 f7 d3 70 05
        0e 9e 96 d6 47 b7 c3 9f 56 e0 31 ca 5e b6 25 0d
        40 42 e0 27 85 ec ec fa 4b 4b b5 e8 ea d0 44 0e
        20 b6 e8 db 09 d8 81 a7 c6 13 2f 42 0e 52 79 50
        42 bd fa 77 73 d8 a9 05 14 47 b3 29 1c e1 41 1c
        68 04 65 55 2a a6 c4 05 b7 76 4d 5e 87 be a8 5a
        d0 0f 84 49 ed 8f 72 d0 d6 62 ab 05 26 91 ca 66
        42 4b c8 6d 2d f8 0e a4 1f 43 ab f9 37 d3 25 9d
        c4 b2 d0 df b4 8a 6c 91 39 dd d7 f7 69 66 e9 28
        e6 35 55 3b a7 6c 5c 87 9d 7b 35 d4 9e b2 e6 2b
        08 71 cd ac 63 89 39 e2 5e 8a 1e 0e f9 d5 28 0f
        a8 ca 32 8b 35 1c 3c 76 59 89 cb cf 3d aa 8b 6c
        cc 3a af 9f 39 79 c9 2b 37 20 fc 88 dc 95 ed 84
        a1 be 05 9c 64 99 b9 fd a2 36 e7 e8 18 b0 4b 0b
        c3 9c 1e 87 6b 19 3b fe 55 69 75 3f 88 12 8c c0
        8a aa 9b 63 d1 a1 6f 80 ef 25 54 d7 18 9c 41 1f
        58 69 ca 52 c5 b8 3f a3 6f f2 16 b9 c1 d3 00 62
        be bc fd 2d c5 bc e0 91 19 34 fd a7 9a 86 f6 e6
        98 ce d7 59 c3 ff 9b 64 77 33 8f 3d a4 f9 cd 85
        14 ea 99 82 cc af b3 41 b2 38 4d d9 02 f3 d1 ab
        7a c6 1d d2 9c 6f 21 ba 5b 86 2f 37 30 e3 7c fd
        """;

    // RFC 8439 appendix A.4 test vector 2: same key and nonce.
    private const string Rfc8439PolyKey = "ecfa254f845f647473d3cb140da9e87606cb33066c447b87bc2666dde3fbb739";

    private const string Sp80038APlaintext =
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";

    private const string Sp80038ACounter = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

    [Theory]
    [InlineData(0u, "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586")] // A.1 vector 1
    [InlineData(2u, "c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c78a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d")] // A.1 vector 5
    public void Reference_ChaCha_matches_RFC_8439(uint nonce, string keystreamHex) =>
        Assert.Equal(keystreamHex, Hex(ReferenceCiphers.ChaChaBlock(new byte[32], 0, nonce)));

    [Fact]
    public void Reference_Poly1305_matches_RFC_8439()
    {
        // Section 2.5.2.
        byte[] key = Convert.FromHexString("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        byte[] message = "Cryptographic Forum Research Group"u8.ToArray();
        Assert.Equal("a8061dc1305136c6c22b8baf0c0127a9", Hex(ReferenceCiphers.Poly1305(key, message)));
    }

    [Fact]
    public void ChaCha_packet_is_assembled_from_RFC_8439_values()
    {
        byte[] key = new byte[64];
        key[31] = 1; // K_main is the RFC's key. The length key stays zero, the key of its vector A.1 5.
        byte[] body = FromSpacedHex(Rfc8439Plaintext);
        byte[] expectedBody = FromSpacedHex(Rfc8439Ciphertext);

        // 0x00000170 XOR the first keystream bytes of A.1 vector 5.
        byte[] expectedLength = Convert.FromHexString("c2c64c47");
        byte[] authenticated = [.. expectedLength, .. expectedBody];
        byte[] expectedTag = ReferenceCiphers.Poly1305(Convert.FromHexString(Rfc8439PolyKey), authenticated);

        using PacketCipher cipher = PacketCipherCatalog.Create(ChaCha, null, key, [], []);
        byte[] packet = PlainFromBody(body, cipher.TagLength);
        cipher.Seal(packet, 2);

        Assert.Equal(Hex([.. authenticated, .. expectedTag]), Hex(packet));
        Assert.Equal(368u, cipher.ReadPacketLength(packet, 2));

        cipher.Open(packet, 2);
        Assert.Equal(Hex(body), Hex(BodyOf(packet, cipher)));
    }

    [Fact]
    public void ChaCha_packet_matches_OpenSSL()
    {
        // openssl enc -chacha20, IV = 8-byte little-endian block counter then the 8-byte big-endian sequence number.
        // That's the OpenSSH layout, with no 32-bit counter involved. Tag from openssl mac Poly1305.
        byte[] key = Convert.FromHexString(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
        byte[] body = Convert.FromHexString("0a5e0102030405060708090a0b0c0ddddddddddddddddddd");
        const string Expected = "081cfb85" + "adcbf402f9cf19f010ab45b77c6d7a5396406b5637b4fdcf" + "b02e2436743a8f9bdda82b24a9a3106e";

        using PacketCipher cipher = PacketCipherCatalog.Create(ChaCha, null, key, [], []);
        byte[] packet = PlainFromBody(body, cipher.TagLength);
        cipher.Seal(packet, 0xdeadbeef);
        Assert.Equal(Expected, Hex(packet));

        Assert.Equal(24u, cipher.ReadPacketLength(packet, 0xdeadbeef));
        cipher.Open(packet, 0xdeadbeef);
        Assert.Equal(Hex(body), Hex(BodyOf(packet, cipher)));
    }

    [Theory]
    [InlineData(0u)]
    [InlineData(1u)]
    [InlineData(0xffu)]
    [InlineData(0x100u)]
    [InlineData(0x01000000u)]
    [InlineData(0xfedcba98u)]
    [InlineData(uint.MaxValue)]
    public void ChaCha_matches_the_reference_in_both_directions(uint sequenceNumber)
    {
        byte[] key = KeyFor(ChaCha);
        using PacketCipher cipher = PacketCipherCatalog.Create(ChaCha, null, key, [], []);

        // 300 covers several ChaCha blocks with a partial last one.
        foreach (int payload in new[] { 1, 59, 60, 300 })
        {
            byte[] packet = Plain(cipher, payload);
            byte[] body = BodyOf(packet, cipher);
            byte[] expected = ReferenceCiphers.SealChaCha(key, sequenceNumber, (uint)body.Length, body);

            cipher.Seal(packet, sequenceNumber);
            Assert.Equal(Hex(expected), Hex(packet));

            cipher.Open(expected, sequenceNumber);
            Assert.Equal(Hex(body), Hex(BodyOf(expected, cipher)));
        }
    }

    // NIST CAVS vectors, as Go's crypto/cipher carries them in gcm_test.go.
    [Theory]
    [InlineData("7fddb57453c241d03efbed3ac44e371c", "ee283a3fc75575e33efd4887", "d5de42b461646c255c87bd2962d3b9a2", "", "2ccda4a5415cb91e135c2a0f78c9b2fdb36d1df9b9d5e596f83e8b7f52971cb3")]
    [InlineData("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", "54cc7dc2c37ec006bcc6d1da", "007c5e5b3e59df24a7c355584fc1518d", "", "d50b9e252b70945d4240d351677eb10f937cdaef6f2822b6a3191654ba41b197")]
    [InlineData("fbe3467cc254f81be8e78d765a2e6333", "c6697351ff4aec29cdbaabf2", "", "67", "3659cdc25288bf499ac736c03bfc1159")]
    [InlineData("77be63708971c4e240d1cb79e8d77feb", "e0e00f19fed7ba0136a797f3", "", "7a43ec1d9c0a5a78a0b16533a6213cab", "209fcc8d3675ed938e9c7166709dd946")]
    public void Reference_GCM_matches_NIST(string key, string nonce, string plaintext, string aad, string expected)
    {
        byte[] output = ReferenceCiphers.Gcm(
            Convert.FromHexString(key), Convert.FromHexString(nonce), Convert.FromHexString(aad), Convert.FromHexString(plaintext));
        Assert.Equal(expected, Hex(output));
    }

    [Theory]
    [InlineData(Aes128Gcm, "7fddb57453c241d03efbed3ac44e371c", "ee283a3fc75575e33efd4887", "d5de42b461646c255c87bd2962d3b9a2", "2ccda4a5415cb91e135c2a0f78c9b2fd")]
    [InlineData(Aes256Gcm, "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", "54cc7dc2c37ec006bcc6d1da", "007c5e5b3e59df24a7c355584fc1518d", "d50b9e252b70945d4240d351677eb10f")]
    public void GCM_packet_ciphertext_matches_NIST(string cipherName, string keyHex, string ivHex, string bodyHex, string ciphertextHex)
    {
        // GCM ciphertext doesn't depend on the associated data, so a published vector applies to the body as it stands.
        // Its tag does depend on it, and no published vector has a 4-byte AAD equal to the length, so the tag is
        // compared with BouncyCastle, which the test above pins to NIST.
        byte[] key = Convert.FromHexString(keyHex);
        byte[] iv = Convert.FromHexString(ivHex);
        byte[] body = Convert.FromHexString(bodyHex);

        using PacketCipher cipher = PacketCipherCatalog.Create(cipherName, null, key, iv, []);
        byte[] packet = PlainFromBody(body, cipher.TagLength);
        cipher.Seal(packet, 0);

        Assert.Equal(ciphertextHex, Hex(BodyOf(packet, cipher)));
        Assert.Equal(Hex(ReferenceCiphers.SealGcm(key, iv, 16, body)), Hex(packet));
    }

    [Theory]
    [InlineData(Aes128Gcm)]
    [InlineData(Aes256Gcm)]
    public void GCM_packets_match_the_reference_in_both_directions(string cipherName)
    {
        byte[] key = KeyFor(cipherName);
        byte[] iv = IvFor(cipherName);
        using PacketCipher sender = PacketCipherCatalog.Create(cipherName, null, key, iv, []);
        using PacketCipher receiver = PacketCipherCatalog.Create(cipherName, null, key, iv, []);

        ulong counter = BinaryPrimitives.ReadUInt64BigEndian(iv.AsSpan(4));
        foreach (int payload in new[] { 1, 11, 12, 100, 1000 })
        {
            byte[] packet = Plain(sender, payload);
            byte[] body = BodyOf(packet, sender);
            byte[] expected = ReferenceCiphers.SealGcm(key, NonceFor(iv, counter++), (uint)body.Length, body);

            sender.Seal(packet, 0);
            Assert.Equal(Hex(expected), Hex(packet));

            receiver.Open(expected, 0);
            Assert.Equal(Hex(body), Hex(BodyOf(expected, sender)));
        }
    }

    [Theory]
    [InlineData(Aes128Ctr, "2b7e151628aed2a6abf7158809cf4f3c", "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee")] // F.5.1
    [InlineData(Aes256Ctr, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6")] // F.5.5
    public void CTR_packet_ciphertext_matches_SP_800_38A(string cipherName, string keyHex, string ciphertextHex)
    {
        byte[] key = Convert.FromHexString(keyHex);
        byte[] iv = Convert.FromHexString(Sp80038ACounter);
        byte[] macKey = MacKeyFor(Sha256Etm);

        // Seal only: this plaintext's first byte isn't a valid padding_length for its size, which Open would reject.
        using PacketCipher cipher = PacketCipherCatalog.Create(cipherName, Sha256Etm, key, iv, macKey);
        byte[] packet = PlainFromBody(Convert.FromHexString(Sp80038APlaintext), cipher.TagLength);
        cipher.Seal(packet, 0);

        Assert.Equal(ciphertextHex, Hex(BodyOf(packet, cipher)));
    }

    [Fact]
    public void CTR_EtM_packets_match_OpenSSL_across_the_128_bit_wrap()
    {
        // openssl enc -aes-128-ctr over both bodies in one run, then openssl mac HMAC over seq || length || ciphertext.
        byte[] key = Convert.FromHexString("00112233445566778899aabbccddeeff");
        byte[] iv = Convert.FromHexString("fffffffffffffffffffffffffffffffe");
        byte[] macKey = Convert.FromHexString("a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5");
        byte[] body1 = Convert.FromHexString("0b4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
        byte[] body2 = Convert.FromHexString("0761626364656667686970717273747576777879808182838485868788899091");
        const string Expected1 = "00000020" + "20f7de7d195ad7c61422cdeb99f6a43e34e0c147974fa20d9486246711eac152"
            + "db7d219f18eb13d20311e2cdb49284b9f405c616782924a3f534c19daeb6f332";
        const string Expected2 = "00000020" + "fa8599cd2e6c8647879e52e7edf0f75ef2a3b1b90bcecaabe5662f414bd25448"
            + "01829a04887cd788ad1d48f967b7593d7409ef8d12fe6eacd9af26daf60347d9";

        using PacketCipher sender = PacketCipherCatalog.Create(Aes128Ctr, Sha256Etm, key, iv, macKey);
        using PacketCipher receiver = PacketCipherCatalog.Create(Aes128Ctr, Sha256Etm, key, iv, macKey);

        byte[] packet1 = PlainFromBody(body1, sender.TagLength);
        byte[] packet2 = PlainFromBody(body2, sender.TagLength);
        sender.Seal(packet1, 7);
        sender.Seal(packet2, 8);
        Assert.Equal(Expected1, Hex(packet1));
        Assert.Equal(Expected2, Hex(packet2));

        receiver.Open(packet1, 7);
        receiver.Open(packet2, 8);
        Assert.Equal(Hex(body1), Hex(BodyOf(packet1, sender)));
        Assert.Equal(Hex(body2), Hex(BodyOf(packet2, sender)));
    }

    [Fact]
    public void CTR_EtM_packet_matches_OpenSSL_across_the_64_bit_carry_with_SHA_512()
    {
        byte[] key = Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] iv = Convert.FromHexString("0123456789abcdefffffffffffffffff");
        byte[] macKey = new byte[64];
        Array.Fill(macKey, (byte)0x5a);
        byte[] body = Convert.FromHexString(
            "0b4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
            + "0761626364656667686970717273747576777879808182838485868788899091");
        const string Expected = "00000040"
            + "d24f5c05a76d4a2653af099647f362f6b23558da5f48b7494a85754e698628ea"
            + "0c268ec82e3e517233a0aa8f289cc39ee3db07f2e9be249ffe100a77c96a3115"
            + "2f70e5fdc07c4bf557114db71e17d702c57ade645c064a0bcf15ae177952a46f"
            + "612b4c0d5dcb9313d9cbe7554f1d7669343686c843e04a7d7eeabb6e33fc8fd1";

        using PacketCipher cipher = PacketCipherCatalog.Create(Aes256Ctr, Sha512Etm, key, iv, macKey);
        byte[] packet = PlainFromBody(body, cipher.TagLength);
        cipher.Seal(packet, uint.MaxValue);
        Assert.Equal(Expected, Hex(packet));
    }

    [Theory]
    [InlineData(Aes128Ctr, Sha256Etm)]
    [InlineData(Aes128Ctr, Sha512Etm)]
    [InlineData(Aes256Ctr, Sha256Etm)]
    [InlineData(Aes256Ctr, Sha512Etm)]
    public void CTR_EtM_matches_the_reference_over_several_packets(string cipherName, string macName)
    {
        byte[] key = KeyFor(cipherName);
        byte[] iv = IvFor(cipherName);
        byte[] macKey = MacKeyFor(macName);
        using PacketCipher sender = PacketCipherCatalog.Create(cipherName, macName, key, iv, macKey);
        using PacketCipher receiver = PacketCipherCatalog.Create(cipherName, macName, key, iv, macKey);

        BigInteger counter = new(iv, isUnsigned: true, isBigEndian: true);
        uint sequenceNumber = 40;

        // 5000 and 9000 span more than one pass through the keystream buffer.
        foreach (int payload in new[] { 1, 11, 12, 5000, 200, 9000, 27 })
        {
            byte[] packet = Plain(sender, payload);
            byte[] body = BodyOf(packet, sender);
            byte[] expected = ReferenceCiphers.SealCtrEtm(
                key, ref counter, string.Equals(macName, Sha512Etm, StringComparison.Ordinal), macKey, sequenceNumber, (uint)body.Length, body);

            sender.Seal(packet, sequenceNumber);
            Assert.Equal(Hex(expected), Hex(packet));

            receiver.Open(expected, sequenceNumber);
            Assert.Equal(Hex(body), Hex(BodyOf(expected, sender)));
            sequenceNumber++;
        }
    }

    [Fact]
    public void Reference_CTR_is_not_circular_with_SP_800_38A()
    {
        BigInteger counter = new(Convert.FromHexString(Sp80038ACounter), isUnsigned: true, isBigEndian: true);
        byte[] macKey = new byte[32];
        byte[] body = Convert.FromHexString(Sp80038APlaintext);

        byte[] sealedPacket = ReferenceCiphers.SealCtrEtm(
            Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c"), ref counter, sha512: false, macKey, 0, 64, body);

        Assert.StartsWith("00000040874d6191b620e3261bef6864990db6ce", Hex(sealedPacket), StringComparison.Ordinal);
    }

    private static byte[] NonceFor(byte[] iv, ulong counter)
    {
        byte[] nonce = (byte[])iv.Clone();
        BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(4), counter);
        return nonce;
    }

    private static byte[] FromSpacedHex(string text) =>
        Convert.FromHexString(text.Replace(" ", "", StringComparison.Ordinal).ReplaceLineEndings(""));

    private static string Hex(ReadOnlySpan<byte> data) => Convert.ToHexStringLower(data);
}

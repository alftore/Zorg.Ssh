using System;
using System.Buffers.Binary;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Xunit;
using Zorg.Ssh.Crypto.Ciphers;
using static Zorg.Ssh.Tests.Crypto.CipherHarness;

namespace Zorg.Ssh.Tests.Crypto;

/// <summary>
/// The vectorised ChaCha20 against RFC 8439, against BouncyCastle's engine on random input, and against the slow
/// reference for the 64-bit counter. Each test runs every path the machine can run. The CI scripts also run the
/// whole class with <c>DOTNET_EnableAVX2=0</c>, <c>DOTNET_EnableSSE41=0</c> and <c>DOTNET_EnableHWIntrinsic=0</c>, which
/// changes what <c>Path.Auto</c> picks and what is supported.
/// </summary>
public class ChaCha20SimdTests
{
    private static readonly ChaCha20Simd.Path[] Paths =
        [ChaCha20Simd.Path.Auto, ChaCha20Simd.Path.Scalar, ChaCha20Simd.Path.Vector128, ChaCha20Simd.Path.Vector256];

    public static TheoryData<string> SupportedPaths()
    {
        TheoryData<string> data = [];
        foreach (ChaCha20Simd.Path path in Paths)
        {
            if (ChaCha20Simd.IsSupported(path))
            {
                data.Add(path.ToString());
            }
        }

        return data;
    }

    private static uint[] Words(byte[] key)
    {
        uint[] words = new uint[ChaCha20Simd.KeyWords];
        ChaCha20Simd.LoadKey(key, words);
        return words;
    }

    [Theory]
    [MemberData(nameof(SupportedPaths))]
    public void RFC_8439_section_2_3_2_block_function(string pathName)
    {
        ChaCha20Simd.Path path = Enum.Parse<ChaCha20Simd.Path>(pathName);
        byte[] key = new byte[32];
        for (int i = 0; i < key.Length; i++)
        {
            key[i] = (byte)i;
        }

        // Nonce 00:00:00:09:00:00:00:4a:00:00:00:00 and counter 1: word 13 is the first nonce word.
        ulong counter = 1 | ((ulong)0x09000000 << 32);
        byte[] block = new byte[64];
        ChaCha20Simd.Keystream(Words(key), counter, 0x4a000000, 0, block, path);

        Assert.Equal(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
            Convert.ToHexStringLower(block));
    }

    [Theory]
    [MemberData(nameof(SupportedPaths))]
    public void RFC_8439_section_2_4_2_encryption(string pathName)
    {
        ChaCha20Simd.Path path = Enum.Parse<ChaCha20Simd.Path>(pathName);
        byte[] key = new byte[32];
        for (int i = 0; i < key.Length; i++)
        {
            key[i] = (byte)i;
        }

        const string Text = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        byte[] plain = System.Text.Encoding.ASCII.GetBytes(Text);
        byte[] actual = new byte[plain.Length];

        // Nonce 00:00:00:00:00:00:00:4a:00:00:00:00, counter 1.
        ChaCha20Simd.Crypt(Words(key), 1, 0x4a000000, 0, plain, actual, path);

        // The RFC's ciphertext, which is also what BouncyCastle gives.
        Assert.Equal(
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d",
            Convert.ToHexStringLower(actual).Replace(" ", string.Empty, StringComparison.Ordinal));
    }

    [Theory]
    [MemberData(nameof(SupportedPaths))]
    public void Matches_BouncyCastle_for_every_length_up_to_4096(string pathName)
    {
        ChaCha20Simd.Path path = Enum.Parse<ChaCha20Simd.Path>(pathName);
        Random random = new(8439);
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        random.NextBytes(key);
        random.NextBytes(nonce);
        nonce.AsSpan(0, 8).Clear();
        byte[] data = new byte[4096];
        random.NextBytes(data);

        uint[] words = Words(key);
        for (int length = 0; length <= 4096; length++)
        {
            // OpenSSH: the nonce is four zero bytes and an 8-byte big-endian sequence number.
            uint sequence = (uint)random.Next();
            BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(4), sequence);
            uint nonce1 = BinaryPrimitives.ReadUInt32LittleEndian(nonce.AsSpan(8));

            // Counter 0 is the whole stream, and counter 1 is what the body of a packet uses.
            ChaCha7539Engine engine = new();
            engine.Init(forEncryption: true, new ParametersWithIV(new KeyParameter(key), nonce));
            byte[] expected = new byte[length];
            engine.ProcessBytes(data, 0, length, expected, 0);
            byte[] actual = new byte[length];
            ChaCha20Simd.Crypt(words, 0, 0, nonce1, data.AsSpan(0, length), actual, path);
            Assert.True(expected.AsSpan().SequenceEqual(actual), $"Counter 0, length {length}, {path}.");

            if (length > 64)
            {
                byte[] expectedFrom1 = new byte[length - 64];
                engine.Init(forEncryption: true, new ParametersWithIV(new KeyParameter(key), nonce));
                byte[] skip = new byte[64];
                engine.ProcessBytes(skip, 0, 64, skip, 0);
                engine.ProcessBytes(data, 0, length - 64, expectedFrom1, 0);
                byte[] actualFrom1 = new byte[length - 64];
                ChaCha20Simd.Crypt(words, 1, 0, nonce1, data.AsSpan(0, length - 64), actualFrom1, path);
                Assert.True(expectedFrom1.AsSpan().SequenceEqual(actualFrom1), $"Counter 1, length {length}, {path}.");
            }
        }
    }

    [Theory]
    [MemberData(nameof(SupportedPaths))]
    public void Works_in_place_and_with_random_keys(string pathName)
    {
        ChaCha20Simd.Path path = Enum.Parse<ChaCha20Simd.Path>(pathName);
        Random random = new(99);
        for (int round = 0; round < 200; round++)
        {
            byte[] key = new byte[32];
            byte[] nonce = new byte[12];
            random.NextBytes(key);
            random.NextBytes(nonce);
            byte[] data = new byte[random.Next(0, 2000)];
            random.NextBytes(data);

            ChaCha7539Engine engine = new();
            engine.Init(forEncryption: true, new ParametersWithIV(new KeyParameter(key), nonce));
            byte[] expected = new byte[data.Length];
            engine.ProcessBytes(data, 0, data.Length, expected, 0);

            // A 12-byte nonce with a non-zero first word is the same state: that word is the counter's high half.
            ulong counter = (ulong)BinaryPrimitives.ReadUInt32LittleEndian(nonce) << 32;
            byte[] inPlace = (byte[])data.Clone();
            ChaCha20Simd.Crypt(
                Words(key),
                counter,
                BinaryPrimitives.ReadUInt32LittleEndian(nonce.AsSpan(4)),
                BinaryPrimitives.ReadUInt32LittleEndian(nonce.AsSpan(8)),
                inPlace,
                inPlace,
                path);
            Assert.True(expected.AsSpan().SequenceEqual(inPlace), $"Round {round}, length {data.Length}, {path}.");
        }
    }

    [Theory]
    [MemberData(nameof(SupportedPaths))]
    public void The_64_bit_counter_carries_into_word_13_and_wraps(string pathName)
    {
        ChaCha20Simd.Path path = Enum.Parse<ChaCha20Simd.Path>(pathName);
        byte[] key = Pattern(32, 5);
        uint[] words = Words(key);
        const uint Sequence = 0xFEDCBA98;
        uint nonce1 = BinaryPrimitives.ReverseEndianness(Sequence);

        // Starts just under 2^32, just under 2^64, and in between. 20 blocks cross a vector boundary at every offset.
        ulong[] starts = [0xFFFFFFFEUL, 0xFFFFFFFFUL, 0x1_FFFF_FFFDUL, ulong.MaxValue - 2, ulong.MaxValue - 9, ulong.MaxValue];
        foreach (ulong start in starts)
        {
            for (int blocks = 1; blocks <= 20; blocks++)
            {
                byte[] zeros = new byte[blocks * 64];
                byte[] actual = new byte[zeros.Length];
                ChaCha20Simd.Crypt(words, start, 0, nonce1, zeros, actual, path);

                byte[] expected = new byte[zeros.Length];
                for (int b = 0; b < blocks; b++)
                {
                    unchecked
                    {
                        ReferenceCiphers.ChaChaBlock(key, start + (ulong)b, Sequence).CopyTo(expected, b * 64);
                    }
                }

                Assert.True(expected.AsSpan().SequenceEqual(actual), $"Start {start:X}, {blocks} blocks, {path}.");
            }
        }
    }

    [Fact]
    public void Rejects_a_wrong_key_or_output_length()
    {
        Assert.Throws<ArgumentException>(() => ChaCha20Simd.LoadKey(new byte[31], new uint[8]));
        Assert.Throws<ArgumentException>(() => ChaCha20Simd.Crypt(new uint[7], 0, 0, 0, new byte[4], new byte[4]));
        Assert.Throws<ArgumentException>(() => ChaCha20Simd.Crypt(new uint[8], 0, 0, 0, new byte[4], new byte[5]));
    }

    [Fact]
    public void The_cipher_matches_the_slow_reference_for_every_body_size_and_sequence()
    {
        Random random = new(2024);
        byte[] key = new byte[64];
        random.NextBytes(key);
        using ChaCha20Poly1305Cipher subject = new(key);
        uint[] sequences = [0, 1, 255, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF];

        foreach (uint sequence in sequences)
        {
            for (int bodyLength = 8; bodyLength <= 1400; bodyLength += 8)
            {
                byte[] body = new byte[bodyLength];
                random.NextBytes(body);
                body[0] = 4;
                byte[] expected = ReferenceCiphers.SealChaCha(key, sequence, (uint)bodyLength, body);

                byte[] packet = new byte[4 + bodyLength + 16];
                BinaryPrimitives.WriteUInt32BigEndian(packet, (uint)bodyLength);
                body.CopyTo(packet, 4);
                subject.Seal(packet, sequence);
                Assert.True(expected.AsSpan().SequenceEqual(packet), $"Seal, body {bodyLength}, sequence {sequence}.");

                Assert.Equal((uint)bodyLength, subject.ReadPacketLength(packet, sequence));
                subject.Open(packet, sequence);
                Assert.True(body.AsSpan().SequenceEqual(packet.AsSpan(4, bodyLength)), $"Open, body {bodyLength}.");
            }
        }
    }
}

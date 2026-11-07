using System;
using System.Numerics;
using System.Reflection;
using System.Security.Cryptography;
using Xunit;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.KeyExchange;

namespace Zorg.Ssh.Tests.Crypto;

/// <summary>Finite-field Diffie-Hellman: agreement, known answers against BigInteger, the mpint encoding of K, and peer values.</summary>
public class FiniteFieldDhTests
{
    public static TheoryData<string> Names => new(LegacyAlgorithms.KeyExchange);

    [Theory]
    [MemberData(nameof(Names))]
    public void Both_sides_agree(string name)
    {
        using KeyExchangeMethod client = FiniteFieldDhExtension.Instance.Create(name, 32)!;
        using KeyExchangeMethod server = FiniteFieldDhExtension.Instance.Create(name, 32)!;

        byte[] e = client.CreateClientPublicValue();
        byte[] f = server.ServerRespond(e, out byte[] serverSecret);
        byte[] clientSecret = client.ClientComputeSharedSecret(f);

        Assert.Equal(serverSecret, clientSecret);
        Assert.Equal(name.EndsWith("sha1", StringComparison.Ordinal) ? HashAlgorithmName.SHA1 : name.EndsWith("sha512", StringComparison.Ordinal) ? HashAlgorithmName.SHA512 : HashAlgorithmName.SHA256, client.HashAlgorithm);
        AssertMinimalMPIntBody(e);
        AssertMinimalMPIntBody(f);
    }

    [Fact]
    public void Names_outside_the_extension_are_not_created()
    {
        Assert.Null(FiniteFieldDhExtension.Instance.Create("diffie-hellman-group1-sha1", 32));
        Assert.Null(FiniteFieldDhExtension.Instance.Create("diffie-hellman-group-exchange-sha256", 32));
        Assert.Null(FiniteFieldDhExtension.Instance.Create("diffie-hellman-group18-sha512", 32));
        Assert.Null(KeyExchangeCatalog.Create(LegacyAlgorithms.DhGroup14Sha256));
    }

    [Theory]
    [InlineData(2048, 16, 512)] // aes128-gcm: OpenSSH's floor of 256 bits, doubled
    [InlineData(2048, 32, 512)] // aes256-ctr with hmac-sha2-256
    [InlineData(2048, 64, 1024)] // chacha20-poly1305, or hmac-sha2-512
    [InlineData(4096, 64, 1024)]
    [InlineData(2048, 200, 2047)] // never as wide as the prime
    public void The_exponent_has_OpenSSHs_size(int primeBits, int need, int expected) =>
        Assert.Equal(expected, FiniteFieldDhKeyExchange.ExponentBits(primeBits, need));

    [Theory]
    [InlineData(16, 512)]
    [InlineData(64, 1024)]
    public void The_exponent_is_random_with_its_top_bit_set_and_is_zeroed_after_use(int need, int bits)
    {
        using FiniteFieldDhKeyExchange client = new(DiffieHellmanGroup.Group14, HashAlgorithmName.SHA256, need);
        using FiniteFieldDhKeyExchange server = new(DiffieHellmanGroup.Group14, HashAlgorithmName.SHA256, need);
        byte[] e = client.CreateClientPublicValue();
        ulong[] exponent = Exponent(client)!;
        BigInteger x = Big(exponent);
        Assert.Equal(bits, (int)x.GetBitLength());

        // e really is g^x mod p for that exponent.
        BigInteger p = new(DiffieHellmanGroup.Group14.Prime, isUnsigned: true, isBigEndian: true);
        Assert.Equal(BigInteger.ModPow(2, x, p), new BigInteger(e, isUnsigned: true, isBigEndian: true));

        byte[] f = server.ServerRespond(e, out _);
        Assert.Null(Exponent(server));
        client.ClientComputeSharedSecret(f);

        Assert.All(exponent, limb => Assert.Equal(0UL, limb));
        Assert.Null(Exponent(client));
    }

    [Fact]
    public void Dispose_zeroes_an_exponent_that_was_never_used()
    {
        FiniteFieldDhKeyExchange client = new(DiffieHellmanGroup.Group14, HashAlgorithmName.SHA256, 32);
        client.CreateClientPublicValue();
        ulong[] exponent = Exponent(client)!;

        client.Dispose();

        Assert.All(exponent, limb => Assert.Equal(0UL, limb));
    }

    [Fact]
    public void An_instance_runs_one_exchange()
    {
        using KeyExchangeMethod client = FiniteFieldDhExtension.Instance.Create(LegacyAlgorithms.DhGroup14Sha256, 32)!;
        client.CreateClientPublicValue();
        Assert.Throws<InvalidOperationException>(() => client.CreateClientPublicValue());

        using KeyExchangeMethod unused = FiniteFieldDhExtension.Instance.Create(LegacyAlgorithms.DhGroup14Sha256, 32)!;
        Assert.Throws<InvalidOperationException>(() => unused.ClientComputeSharedSecret([2]));
    }

    [Theory]
    [InlineData(2048)]
    [InlineData(4096)]
    public void Known_answers_match_BigInteger_with_fixed_exponents(int bits)
    {
        DiffieHellmanGroup group = bits == 2048 ? DiffieHellmanGroup.Group14 : DiffieHellmanGroup.Group16;
        BigInteger p = new(group.Prime, isUnsigned: true, isBigEndian: true);
        byte[] x = SHA512.HashData("zorg client exponent"u8);
        byte[] y = SHA512.HashData("zorg server exponent"u8);

        using FiniteFieldDhKeyExchange client = new(group, HashAlgorithmName.SHA256, 32, x);
        using FiniteFieldDhKeyExchange server = new(group, HashAlgorithmName.SHA256, 32, y);
        byte[] e = client.CreateClientPublicValue();
        byte[] f = server.ServerRespond(e, out byte[] serverSecret);
        byte[] clientSecret = client.ClientComputeSharedSecret(f);

        BigInteger bx = new(x, isUnsigned: true, isBigEndian: true);
        BigInteger by = new(y, isUnsigned: true, isBigEndian: true);
        Assert.Equal(ReferenceMPIntBody(BigInteger.ModPow(2, bx, p)), e);
        Assert.Equal(ReferenceMPIntBody(BigInteger.ModPow(2, by, p)), f);
        byte[] expectedK = ReferenceMPInt(BigInteger.ModPow(2, bx * by, p));
        Assert.Equal(expectedK, serverSecret);
        Assert.Equal(expectedK, clientSecret);
    }

    [Fact]
    public void K_with_its_top_bit_set_gets_a_zero_byte_in_front()
    {
        (byte[] clientSecret, byte[] serverSecret, BigInteger k) = Exchange(found => (found.ToByteArray(isUnsigned: true, isBigEndian: true) is { Length: 256 } top && (top[0] & 0x80) != 0));

        byte[] magnitude = k.ToByteArray(isUnsigned: true, isBigEndian: true);
        Assert.Equal(257u, System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(clientSecret));
        Assert.Equal(0, clientSecret[4]);
        Assert.Equal(magnitude, clientSecret[5..]);
        Assert.Equal(clientSecret, serverSecret);
    }

    [Fact]
    public void K_with_a_leading_zero_byte_drops_it()
    {
        // Roughly one exchange in 256: K is one byte shorter than p, and must be encoded that way.
        (byte[] clientSecret, byte[] serverSecret, BigInteger k) = Exchange(found => found.GetBitLength() <= 2040);

        byte[] magnitude = k.ToByteArray(isUnsigned: true, isBigEndian: true);
        Assert.True(magnitude.Length <= 255);
        Assert.Equal(ReferenceMPInt(k), clientSecret);
        Assert.Equal((uint)(magnitude.Length + ((magnitude[0] & 0x80) != 0 ? 1 : 0)), System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(clientSecret));
        Assert.Equal(clientSecret, serverSecret);
    }

    [Fact]
    public void K_without_its_top_bit_and_full_width_has_no_padding()
    {
        (byte[] clientSecret, _, BigInteger k) = Exchange(found => found.ToByteArray(isUnsigned: true, isBigEndian: true) is { Length: 256 } top && (top[0] & 0x80) == 0);

        Assert.Equal(256u, System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(clientSecret));
        Assert.Equal(k.ToByteArray(isUnsigned: true, isBigEndian: true), clientSecret[4..]);
    }

    public static TheoryData<string> BadPeerValues()
    {
        BigInteger p = new(DiffieHellmanGroup.Group14.Prime, isUnsigned: true, isBigEndian: true);
        return
        [
            string.Empty, // zero
            "00", // zero, with a redundant byte
            "01",
            "0001",
            "80", // negative
            "ff" + new string('0', 510), // negative and wide
            Hex(ReferenceMPIntBody(p - 1)),
            Hex(ReferenceMPIntBody(p)),
            Hex(ReferenceMPIntBody(p + 1)),
            Hex(ReferenceMPIntBody(BigInteger.One << 2048)),
            Hex(ReferenceMPIntBody((BigInteger.One << 2056) - 1)), // wider than p plus a sign byte
            "0000" + Hex(ReferenceMPIntBody(p - 2)), // valid, but padded past p's width plus one byte
        ];
    }

    [Theory]
    [MemberData(nameof(BadPeerValues))]
    public void A_bad_peer_value_is_refused_on_both_sides(string hex)
    {
        byte[] value = Convert.FromHexString(hex);

        using KeyExchangeMethod client = FiniteFieldDhExtension.Instance.Create(LegacyAlgorithms.DhGroup14Sha256, 32)!;
        client.CreateClientPublicValue();
        SshProtocolException clientFailure = Assert.Throws<SshProtocolException>(() => client.ClientComputeSharedSecret(value));

        using KeyExchangeMethod server = FiniteFieldDhExtension.Instance.Create(LegacyAlgorithms.DhGroup14Sha256, 32)!;
        Assert.Throws<SshProtocolException>(() => server.ServerRespond(value, out _));

        Assert.Contains("Diffie-Hellman", clientFailure.Message, StringComparison.Ordinal);
        Assert.DoesNotMatch("[0-9a-fA-F]{16}", clientFailure.Message);
    }

    [Fact]
    public void Edge_values_inside_the_range_are_accepted()
    {
        BigInteger p = new(DiffieHellmanGroup.Group14.Prime, isUnsigned: true, isBigEndian: true);
        foreach (byte[] value in new[] { [2], ReferenceMPIntBody(p - 2), [0, 0x7f], [0, 0, 2] })
        {
            using KeyExchangeMethod server = FiniteFieldDhExtension.Instance.Create(LegacyAlgorithms.DhGroup14Sha1, 20)!;
            server.ServerRespond(value, out byte[] secret);
            Assert.NotEmpty(secret);
        }
    }

    [Fact]
    public void A_group16_value_too_wide_for_group14_is_refused_there()
    {
        using KeyExchangeMethod big = FiniteFieldDhExtension.Instance.Create(LegacyAlgorithms.DhGroup16Sha512, 64)!;
        byte[] e = big.CreateClientPublicValue();
        using KeyExchangeMethod small = FiniteFieldDhExtension.Instance.Create(LegacyAlgorithms.DhGroup14Sha256, 64)!;

        Assert.Throws<SshProtocolException>(() => small.ServerRespond(e, out _));
    }

    /// <summary>Runs exchanges with deterministic exponents until K satisfies <paramref name="wanted"/>.</summary>
    private static (byte[] Client, byte[] Server, BigInteger K) Exchange(Func<BigInteger, bool> wanted)
    {
        BigInteger p = new(DiffieHellmanGroup.Group14.Prime, isUnsigned: true, isBigEndian: true);
        BigInteger g = 2;
        byte[] x = SHA256.HashData("fixed client exponent"u8);
        BigInteger bx = new(x, isUnsigned: true, isBigEndian: true);
        BigInteger e = BigInteger.ModPow(g, bx, p);
        for (int i = 0; i < 20_000; i++)
        {
            byte[] y = SHA256.HashData(BitConverter.GetBytes(i));
            BigInteger by = new(y, isUnsigned: true, isBigEndian: true);
            BigInteger k = BigInteger.ModPow(e, by, p);
            if (!wanted(k))
            {
                continue;
            }

            using FiniteFieldDhKeyExchange client = new(DiffieHellmanGroup.Group14, HashAlgorithmName.SHA256, 32, x);
            using FiniteFieldDhKeyExchange server = new(DiffieHellmanGroup.Group14, HashAlgorithmName.SHA256, 32, y);
            byte[] clientPublic = client.CreateClientPublicValue();
            byte[] serverPublic = server.ServerRespond(clientPublic, out byte[] serverSecret);
            byte[] clientSecret = client.ClientComputeSharedSecret(serverPublic);
            return (clientSecret, serverSecret, k);
        }

        throw new InvalidOperationException("No exponent gave the wanted K.");
    }

    /// <summary>RFC 4251 section 5, written out: the shortest two's-complement big-endian form, then a uint32 length.</summary>
    private static byte[] ReferenceMPInt(BigInteger value)
    {
        byte[] body = ReferenceMPIntBody(value);
        byte[] encoded = new byte[4 + body.Length];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(encoded, (uint)body.Length);
        body.CopyTo(encoded, 4);
        return encoded;
    }

    private static byte[] ReferenceMPIntBody(BigInteger value) => value.IsZero ? [] : value.ToByteArray(isUnsigned: false, isBigEndian: true);

    private static void AssertMinimalMPIntBody(byte[] body)
    {
        Assert.NotEmpty(body);
        Assert.Equal(0, body[0] & 0x80);
        Assert.False(body.Length > 1 && body[0] == 0 && (body[1] & 0x80) == 0, "The mpint has a redundant zero byte.");
    }

    private static ulong[]? Exponent(FiniteFieldDhKeyExchange exchange) =>
        (ulong[]?)typeof(FiniteFieldDhKeyExchange).GetField("_exponent", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(exchange);

    private static BigInteger Big(ulong[] limbs)
    {
        BigInteger value = BigInteger.Zero;
        for (int i = limbs.Length - 1; i >= 0; i--)
        {
            value = (value << 64) | limbs[i];
        }

        return value;
    }

    private static string Hex(byte[] bytes) => Convert.ToHexString(bytes);
}

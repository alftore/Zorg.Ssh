using System;
using System.Numerics;
using System.Security.Cryptography;
using Xunit;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.KeyExchange;
using Zorg.Ssh.Crypto.Keys;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Tests.Crypto;

public class KeyExchangeTests
{
    private const string Sntrup = "sntrup761x25519-sha512";
    private const string MlKem = "mlkem768x25519-sha256";

    // Every input that gives the all-zero X25519 output: the small-order points, and their non-canonical forms.
    private static readonly string[] LowOrderPoints =
    [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ];

    public static TheoryData<string> Methods => [.. KeyExchangeCatalog.Default];

    public static TheoryData<string> LowOrder => [.. LowOrderPoints];

    public static TheoryData<string> Curve25519Methods => ["curve25519-sha256", "curve25519-sha256@libssh.org"];

    public static TheoryData<string> Hybrids => [MlKem, Sntrup, "sntrup761x25519-sha512@openssh.com"];

    public static TheoryData<string> EcdhMethods => ["ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521"];

    [Fact]
    public void Default_list_is_the_agreed_order() => Assert.Equal(
        [
            "mlkem768x25519-sha256",
            "sntrup761x25519-sha512",
            "sntrup761x25519-sha512@openssh.com",
            "curve25519-sha256",
            "curve25519-sha256@libssh.org",
            "ecdh-sha2-nistp256",
            "ecdh-sha2-nistp384",
            "ecdh-sha2-nistp521",
        ],
        KeyExchangeCatalog.Default);

    [Theory]
    [InlineData("")]
    [InlineData("diffie-hellman-group14-sha256")]
    [InlineData("CURVE25519-SHA256")]
    [InlineData("kex-strict-c-v00@openssh.com")]
    public void Unknown_names_give_null(string name)
    {
        using KeyExchangeMethod? method = KeyExchangeCatalog.Create(name);
        Assert.Null(method);
    }

    [Theory]
    [InlineData("mlkem768x25519-sha256", "SHA256")]
    [InlineData("sntrup761x25519-sha512", "SHA512")]
    [InlineData("sntrup761x25519-sha512@openssh.com", "SHA512")]
    [InlineData("curve25519-sha256", "SHA256")]
    [InlineData("curve25519-sha256@libssh.org", "SHA256")]
    [InlineData("ecdh-sha2-nistp256", "SHA256")]
    [InlineData("ecdh-sha2-nistp384", "SHA384")]
    [InlineData("ecdh-sha2-nistp521", "SHA512")]
    public void Each_method_uses_its_hash(string name, string hash)
    {
        using KeyExchangeMethod method = Create(name);
        Assert.Equal(hash, method.HashAlgorithm.Name);
    }

    [Theory]
    [MemberData(nameof(Methods))]
    public void Client_and_server_agree(string name)
    {
        using KeyExchangeMethod client = Create(name);
        using KeyExchangeMethod server = Create(name);
        byte[] clientValue = client.CreateClientPublicValue();
        byte[] serverValue = server.ServerRespond(clientValue, out byte[] serverSecret);
        byte[] clientSecret = client.ClientComputeSharedSecret(serverValue);
        Assert.Equal(serverSecret, clientSecret);
        Assert.NotEmpty(clientSecret);
    }

    [Theory]
    [InlineData("mlkem768x25519-sha256", 1216, 1120, 32)]
    [InlineData("sntrup761x25519-sha512", 1190, 1071, 64)]
    [InlineData("sntrup761x25519-sha512@openssh.com", 1190, 1071, 64)]
    public void Hybrid_values_have_the_wire_sizes_and_K_is_a_string(string name, int clientLength, int serverLength, int hashLength)
    {
        using KeyExchangeMethod client = Create(name);
        using KeyExchangeMethod server = Create(name);
        byte[] clientValue = client.CreateClientPublicValue();
        byte[] serverValue = server.ServerRespond(clientValue, out byte[] secret);
        Assert.Equal(clientLength, clientValue.Length);
        Assert.Equal(serverLength, serverValue.Length);
        SshReader reader = new(secret);
        Assert.Equal(hashLength, reader.ReadBinary().Length);
        reader.EnsureEnd();
    }

    // RFC 7748 section 6.1.
    [Fact]
    public void Curve25519_matches_the_RFC_7748_vector()
    {
        byte[] alicePrivate = Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] bobPrivate = Convert.FromHexString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        const string AlicePublic = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
        const string BobPublic = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";

        // The top bit of 0x4a is clear, so the mpint is the 32 bytes as they are.
        const string K = "000000204a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

        using Curve25519KeyExchange client = new(X25519Ephemeral.FromPrivateKey(alicePrivate));
        using Curve25519KeyExchange server = new(X25519Ephemeral.FromPrivateKey(bobPrivate));
        byte[] clientValue = client.CreateClientPublicValue();
        Assert.Equal(AlicePublic, Convert.ToHexStringLower(clientValue));
        byte[] serverValue = server.ServerRespond(clientValue, out byte[] serverSecret);
        Assert.Equal(BobPublic, Convert.ToHexStringLower(serverValue));
        Assert.Equal(K, Convert.ToHexStringLower(serverSecret));
        Assert.Equal(K, Convert.ToHexStringLower(client.ClientComputeSharedSecret(serverValue)));
    }

    [Fact]
    public void Curve25519_K_is_always_a_canonical_mpint()
    {
        bool sawSignPad = false;
        for (int i = 0; i < 64; i++)
        {
            using KeyExchangeMethod client = Create("curve25519-sha256");
            using KeyExchangeMethod server = Create("curve25519-sha256");
            server.ServerRespond(client.CreateClientPublicValue(), out byte[] secret);
            SshReader reader = new(secret);
            ReadOnlySpan<byte> raw = reader.ReadBinary();
            reader.EnsureEnd();
            Assert.False(raw[0] == 0 && (raw[1] & 0x80) == 0, "redundant leading zero");
            Assert.Equal(0, raw[0] & 0x80);
            sawSignPad |= raw.Length == 33;
        }

        Assert.True(sawSignPad, "half of all secrets need the sign byte, so 64 runs should show one");
    }

    // RFC 5903 sections 8.1 to 8.3: i is the client's key, r the server's, and g^ir x the shared secret.
    [Theory]
    [InlineData(
        "ecdh-sha2-nistp256",
        "C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433",
        "DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C3772581180",
        "5271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3",
        "C6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53",
        "D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63",
        "56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB",
        "D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE")]
    [InlineData(
        "ecdh-sha2-nistp384",
        "099F3C7034D4A2C699884D73A375A67F7624EF7C6B3C0F160647B67414DCE655E35B538041E649EE3FAEF896783AB194",
        "667842D7D180AC2CDE6F74F37551F55755C7645C20EF73E31634FE72B4C55EE6DE3AC808ACB4BDB4C88732AEE95F41AA",
        "9482ED1FC0EEB9CAFC4984625CCFC23F65032149E0E144ADA024181535A0F38EEB9FCFF3C2C947DAE69B4C634573A81C",
        "41CB0779B4BDB85D47846725FBEC3C9430FAB46CC8DC5060855CC9BDA0AA2942E0308312916B8ED2960E4BD55A7448FC",
        "E558DBEF53EECDE3D3FCCFC1AEA08A89A987475D12FD950D83CFA41732BC509D0D1AC43A0336DEF96FDA41D0774A3571",
        "DCFBEC7AACF3196472169E838430367F66EEBE3C6E70C416DD5F0C68759DD1FFF83FA40142209DFF5EAAD96DB9E6386C",
        "11187331C279962D93D604243FD592CB9D0A926F422E47187521287E7156C5C4D603135569B9E9D09CF5D4A270F59746")]
    [InlineData(
        "ecdh-sha2-nistp521",
        "0037ADE9319A89F4DABDB3EF411AACCCA5123C61ACAB57B5393DCE47608172A095AA85A30FE1C2952C6771D937BA9777F5957B2639BAB072462F68C27A57382D4A52",
        "0015417E84DBF28C0AD3C278713349DC7DF153C897A1891BD98BAB4357C9ECBEE1E3BF42E00B8E380AEAE57C2D107564941885942AF5A7F4601723C4195D176CED3E",
        "017CAE20B6641D2EEB695786D8C946146239D099E18E1D5A514C739D7CB4A10AD8A788015AC405D7799DC75E7B7D5B6CF2261A6A7F1507438BF01BEB6CA3926F9582",
        "0145BA99A847AF43793FDD0E872E7CDFA16BE30FDC780F97BCCC3F078380201E9C677D600B343757A3BDBF2A3163E4C2F869CCA7458AA4A4EFFC311F5CB151685EB9",
        "00D0B3975AC4B799F5BEA16D5E13E9AF971D5E9B984C9F39728B5E5739735A219B97C356436ADC6E95BB0352F6BE64A6C2912D4EF2D0433CED2B6171640012D9460F",
        "015C68226383956E3BD066E797B623C27CE0EAC2F551A10C2C724D9852077B87220B6536C5C408A1D2AEBB8E86D678AE49CB57091F4732296579AB44FCD17F0FC56A",
        "01144C7D79AE6956BC8EDB8E7C787C4521CB086FA64407F97894E5E6B2D79B04D1427E73CA4BAA240A34786859810C06B3C715A3A8CC3151F2BEE417996D19F3DDEA")]
    public void Ecdh_matches_the_RFC_5903_vectors(string name, string i, string ix, string iy, string r, string rx, string ry, string shared)
    {
        NistCurve curve = CurveOf(name);
        byte[] expected = SharedSecretEncoding.EncodeMPInt(Hex(shared));
        using ECDiffieHellman clientKey = ImportKey(curve, i, ix, iy);
        using ECDiffieHellman serverKey = ImportKey(curve, r, rx, ry);
        using EcdhKeyExchange client = new(curve, clientKey);
        using EcdhKeyExchange server = new(curve, serverKey);

        byte[] clientValue = client.CreateClientPublicValue();
        Assert.Equal([0x04, .. Hex(ix), .. Hex(iy)], clientValue);
        byte[] serverValue = server.ServerRespond(clientValue, out byte[] serverSecret);
        Assert.Equal([0x04, .. Hex(rx), .. Hex(ry)], serverValue);
        Assert.Equal(expected, serverSecret);
        Assert.Equal(expected, client.ClientComputeSharedSecret(serverValue));
    }

    [Theory]
    [MemberData(nameof(EcdhMethods))]
    public void Curve_constants_match_the_platform(string name)
    {
        NistCurve curve = CurveOf(name);
        using ECDiffieHellman key = ECDiffieHellman.Create(curve.Curve);
        ECCurve explicitCurve = key.ExportExplicitParameters(includePrivateParameters: false).Curve;
        BigInteger prime = new(explicitCurve.Prime, isUnsigned: true, isBigEndian: true);
        BigInteger a = new(explicitCurve.A, isUnsigned: true, isBigEndian: true);
        Assert.Equal(prime - 3, a);

        // The platform's generator must pass our on-curve check, which proves the prime and b together.
        byte[] generator = curve.EncodePoint(explicitCurve.G);
        Assert.True(curve.TryDecodePoint(generator, out _));
        Assert.Equal(curve.CoordinateLength, explicitCurve.Prime!.Length);
    }

    // RFC 9941 appendix A, which gives the KEM key, the X25519 secret and the final encoded K.
    [Fact]
    public void Sntrup_K_matches_the_RFC_9941_vector()
    {
        byte[] kemKey = Hex("2c0c5a36e67770b4d8ab389a92963acd1082383640be2d660802b817cfebb9be");
        byte[] x25519 = Hex("9b737d41d6cfbb1256c58cad0a6ae2c9bf84a90a7291eb52e4c181c8d2447b56");
        byte[] expected = Hex(
            "00000040425458446f22756304ded75a1f23fef9b18b36ebe0e6e260c3001263"
            + "b0183f424907e6d822b3b76c6c3837b5b41fb0d07635c757e65efbefcb5bc38a1a15a96d");
        Assert.Equal(expected, SharedSecretEncoding.EncodeHybrid(HashAlgorithmName.SHA512, kemKey, x25519));
    }

    [Theory]
    [MemberData(nameof(Curve25519Methods))]
    public void X25519_rejects_wrong_lengths(string name)
    {
        foreach (int length in new[] { 0, 1, 31, 33, 64 })
        {
            byte[] value = RandomNumberGenerator.GetBytes(length);
            AssertClientRejects(name, value);
            AssertServerRejects(name, value);
        }
    }

    [Theory]
    [MemberData(nameof(LowOrder))]
    public void X25519_rejects_low_order_points(string point)
    {
        AssertClientRejects("curve25519-sha256", Hex(point));
        AssertServerRejects("curve25519-sha256", Hex(point));
    }

    [Theory]
    [MemberData(nameof(LowOrder))]
    public void Hybrids_reject_low_order_points(string point)
    {
        AssertHybridRejectsPoint(MlKem, Hex(point));
        AssertHybridRejectsPoint(Sntrup, Hex(point));
    }

    [Theory]
    [MemberData(nameof(Hybrids))]
    public void Hybrids_reject_wrong_lengths(string name)
    {
        using KeyExchangeMethod honest = Create(name);
        using KeyExchangeMethod responder = Create(name);
        byte[] clientValue = honest.CreateClientPublicValue();
        byte[] serverValue = responder.ServerRespond(clientValue, out _);
        foreach (int delta in new[] { -1, 1, -32 })
        {
            AssertServerRejects(name, new byte[clientValue.Length + delta]);
            AssertClientRejects(name, new byte[serverValue.Length + delta]);
        }

        AssertServerRejects(name, []);
        AssertClientRejects(name, []);

        // A server reply is the wrong shape for a client value, and the other way round.
        AssertServerRejects(name, serverValue);
        AssertClientRejects(name, clientValue);
    }

    [Fact]
    public void Generated_ML_KEM_keys_pass_the_modulus_check()
    {
        for (int i = 0; i < 20; i++)
        {
            using KeyExchangeMethod method = Create(MlKem);
            Assert.True(MlKem768.IsValidEncapsulationKey(method.CreateClientPublicValue().AsSpan(0, MlKem768.PublicKeyLength)));
        }
    }

    // FIPS 203 section 7.2, required by RFC 10042 section 2.1. 3329 is q, the first value out of range.
    [Theory]
    [InlineData(0, true)]
    [InlineData(1, false)]
    [InlineData(1149, true)]
    [InlineData(1149, false)]
    public void Server_rejects_ML_KEM_keys_that_fail_the_modulus_check(int offset, bool firstCoefficient)
    {
        using KeyExchangeMethod honest = Create(MlKem);
        byte[] clientValue = honest.CreateClientPublicValue();
        int start = offset / 3 * 3;
        if (firstCoefficient)
        {
            clientValue[start] = 3329 & 0xFF;
            clientValue[start + 1] = (byte)((clientValue[start + 1] & 0xF0) | (3329 >> 8));
        }
        else
        {
            clientValue[start + 1] = (byte)((clientValue[start + 1] & 0x0F) | ((3329 & 0x0F) << 4));
            clientValue[start + 2] = 3329 >> 4;
        }

        AssertServerRejects(MlKem, clientValue);
    }

    [Fact]
    public void Coefficient_q_minus_one_passes_the_modulus_check()
    {
        byte[] key = new byte[MlKem768.PublicKeyLength];
        key[0] = 3328 & 0xFF;
        key[1] = 3328 >> 8;
        Assert.True(MlKem768.IsValidEncapsulationKey(key));
    }

    [Theory]
    [MemberData(nameof(Hybrids))]
    public void A_tampered_ciphertext_gives_a_different_K_and_no_other_failure(string name)
    {
        using KeyExchangeMethod client = Create(name);
        using KeyExchangeMethod server = Create(name);
        byte[] serverValue = server.ServerRespond(client.CreateClientPublicValue(), out byte[] serverSecret);
        serverValue[10] ^= 0x01;
        Assert.NotEqual(serverSecret, client.ClientComputeSharedSecret(serverValue));
    }

    [Fact]
    public void Junk_sntrup_values_raise_nothing_but_SshProtocolException()
    {
        foreach (byte fill in new byte[] { 0x00, 0xFF, 0x7F })
        {
            byte[] clientValue = new byte[1190];
            clientValue.AsSpan().Fill(fill);
            RandomNumberGenerator.Fill(clientValue.AsSpan(1158));
            AssertSucceedsOrRejects(() =>
            {
                using KeyExchangeMethod server = Create(Sntrup);
                server.ServerRespond(clientValue, out _);
            });

            byte[] serverValue = new byte[1071];
            serverValue.AsSpan().Fill(fill);
            RandomNumberGenerator.Fill(serverValue.AsSpan(1039));
            AssertSucceedsOrRejects(() =>
            {
                using KeyExchangeMethod client = Create(Sntrup);
                client.CreateClientPublicValue();
                client.ClientComputeSharedSecret(serverValue);
            });
        }
    }

    [Fact]
    public void Junk_ML_KEM_ciphertexts_raise_nothing_but_SshProtocolException()
    {
        foreach (byte fill in new byte[] { 0x00, 0xFF, 0x7F })
        {
            byte[] serverValue = new byte[1120];
            serverValue.AsSpan().Fill(fill);
            RandomNumberGenerator.Fill(serverValue.AsSpan(1088));
            AssertSucceedsOrRejects(() =>
            {
                using KeyExchangeMethod client = Create(MlKem);
                client.CreateClientPublicValue();
                client.ClientComputeSharedSecret(serverValue);
            });
        }
    }

    [Theory]
    [MemberData(nameof(EcdhMethods))]
    public void Ecdh_rejects_bad_points(string name)
    {
        NistCurve curve = CurveOf(name);
        int size = curve.CoordinateLength;
        byte[] valid = GeneratePoint(curve);

        byte[] offCurve = (byte[])valid.Clone();
        offCurve[^1] ^= 0x01;

        byte[] compressed = new byte[1 + size];
        valid.AsSpan(1, size).CopyTo(compressed.AsSpan(1));
        compressed[0] = (byte)(0x02 | (valid[^1] & 1));

        byte[] wrongPrefix = (byte[])valid.Clone();
        wrongPrefix[0] = 0x06;

        byte[] origin = new byte[1 + (2 * size)];
        origin[0] = 0x04;

        byte[] allOnes = new byte[1 + (2 * size)];
        allOnes.AsSpan().Fill(0xFF);
        allOnes[0] = 0x04;

        // A valid point, but on another curve: this is the shape of an invalid-curve attack.
        NistCurve other = curve == NistCurve.P256 ? NistCurve.P384 : NistCurve.P256;

        byte[][] hostile =
        [
            [],
            [0x00],
            [0x04],
            valid[..^1],
            [.. valid, 0x00],
            offCurve,
            compressed,
            wrongPrefix,
            origin,
            allOnes,
            GeneratePoint(other),
        ];

        foreach (byte[] value in hostile)
        {
            AssertClientRejects(name, value);
            AssertServerRejects(name, value);
        }
    }

    [Fact]
    public void Ecdh_rejects_a_coordinate_equal_to_the_prime()
    {
        // (p, y) is (0, y) mod p, and sqrt(b) gives a point that really is on P-256, so only the range check stops it.
        NistCurve curve = NistCurve.P256;
        byte[] prime = Hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
        BigInteger p = new(prime, isUnsigned: true, isBigEndian: true);
        BigInteger b = new(Hex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"), isUnsigned: true, isBigEndian: true);
        BigInteger y = BigInteger.ModPow(b, (p + 1) / 4, p);
        Assert.Equal(b, y * y % p);

        byte[] yBytes = new byte[32];
        y.TryWriteBytes(yBytes.AsSpan(32 - y.GetByteCount(isUnsigned: true)), out _, isUnsigned: true, isBigEndian: true);
        byte[] canonical = [0x04, .. new byte[32], .. yBytes];
        byte[] overflow = [0x04, .. prime, .. yBytes];

        Assert.True(curve.TryDecodePoint(canonical, out _));
        Assert.False(curve.TryDecodePoint(overflow, out _));
        AssertClientRejects("ecdh-sha2-nistp256", overflow);
        AssertServerRejects("ecdh-sha2-nistp256", overflow);
    }

    [Theory]
    [MemberData(nameof(Methods))]
    public void An_instance_runs_one_exchange(string name)
    {
        using KeyExchangeMethod client = Create(name);
        using KeyExchangeMethod server = Create(name);
        byte[] clientValue = client.CreateClientPublicValue();
        Assert.Throws<InvalidOperationException>(() => client.CreateClientPublicValue());
        byte[] serverValue = server.ServerRespond(clientValue, out _);
        Assert.Throws<InvalidOperationException>(() => server.ServerRespond(clientValue, out _));
        client.ClientComputeSharedSecret(serverValue);
        Assert.Throws<InvalidOperationException>(() => client.ClientComputeSharedSecret(serverValue));
    }

    [Theory]
    [MemberData(nameof(Methods))]
    public void The_client_secret_needs_a_client_value_first(string name)
    {
        using KeyExchangeMethod client = Create(name);
        Assert.Throws<InvalidOperationException>(() => client.ClientComputeSharedSecret(new byte[32]));
    }

    [Theory]
    [MemberData(nameof(Methods))]
    public void Dispose_ends_the_exchange(string name)
    {
        KeyExchangeMethod client = Create(name);
        client.CreateClientPublicValue();
        client.Dispose();
        Assert.Throws<InvalidOperationException>(() => client.ClientComputeSharedSecret(new byte[32]));
        client.Dispose();
    }

    [Fact]
    public void Disposing_an_X25519_key_zeroes_it()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(32);
        X25519Ephemeral key = X25519Ephemeral.FromPrivateKey(secret);
        byte[] held = (byte[])typeof(X25519Ephemeral)
            .GetField("_privateKey", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
            .GetValue(key)!;
        Assert.Equal(secret, held);
        key.Dispose();
        Assert.All(held, static b => Assert.Equal(0, b));
    }

    // Runs only where the platform has ML-KEM, which the development machine doesn't.
    [Fact]
    public void BCL_and_BouncyCastle_ML_KEM_interoperate()
    {
        if (!System.Security.Cryptography.MLKem.IsSupported)
        {
            Assert.Skip("This platform has no BCL ML-KEM, so that path is untested here.");
        }

        using BclMlKem768 bclClientKem = new();
        using BouncyCastleMlKem768 bcServerKem = new();
        using HybridKeyExchange bclClient = new(bclClientKem, HashAlgorithmName.SHA256);
        using HybridKeyExchange bcServer = new(bcServerKem, HashAlgorithmName.SHA256);
        byte[] serverValue = bcServer.ServerRespond(bclClient.CreateClientPublicValue(), out byte[] first);
        Assert.Equal(first, bclClient.ClientComputeSharedSecret(serverValue));

        using BouncyCastleMlKem768 bcClientKem = new();
        using BclMlKem768 bclServerKem = new();
        using HybridKeyExchange bcClient = new(bcClientKem, HashAlgorithmName.SHA256);
        using HybridKeyExchange bclServer = new(bclServerKem, HashAlgorithmName.SHA256);
        serverValue = bclServer.ServerRespond(bcClient.CreateClientPublicValue(), out byte[] second);
        Assert.Equal(second, bcClient.ClientComputeSharedSecret(serverValue));
    }

    private static KeyExchangeMethod Create(string name) => KeyExchangeCatalog.Create(name) ?? throw new ArgumentException(name, nameof(name));

    private static NistCurve CurveOf(string name) =>
        NistCurve.FromKeyType(name.Replace("ecdh-sha2-", "ecdsa-sha2-", StringComparison.Ordinal))!;

    private static byte[] Hex(string hex) => Convert.FromHexString(hex);

    private static ECDiffieHellman ImportKey(NistCurve curve, string d, string x, string y) => ECDiffieHellman.Create(new ECParameters
    {
        Curve = curve.Curve,
        D = Hex(d),
        Q = new ECPoint { X = Hex(x), Y = Hex(y) },
    });

    private static byte[] GeneratePoint(NistCurve curve)
    {
        using ECDiffieHellman key = ECDiffieHellman.Create(curve.Curve);
        return curve.EncodePoint(key.ExportParameters(includePrivateParameters: false).Q);
    }

    private static void AssertHybridRejectsPoint(string name, byte[] point)
    {
        using KeyExchangeMethod honest = Create(name);
        using KeyExchangeMethod responder = Create(name);
        byte[] clientValue = honest.CreateClientPublicValue();
        byte[] serverValue = responder.ServerRespond(clientValue, out _);
        point.CopyTo(clientValue, clientValue.Length - 32);
        point.CopyTo(serverValue, serverValue.Length - 32);
        AssertServerRejects(name, clientValue);
        Assert.Throws<SshProtocolException>(() => honest.ClientComputeSharedSecret(serverValue));
    }

    private static void AssertClientRejects(string name, byte[] serverValue)
    {
        using KeyExchangeMethod client = Create(name);
        client.CreateClientPublicValue();
        Assert.Throws<SshProtocolException>(() => client.ClientComputeSharedSecret(serverValue));
    }

    private static void AssertServerRejects(string name, byte[] clientValue)
    {
        using KeyExchangeMethod server = Create(name);
        Assert.Throws<SshProtocolException>(() => server.ServerRespond(clientValue, out _));
    }

    private static void AssertSucceedsOrRejects(Action action)
    {
        try
        {
            action();
        }
        catch (SshProtocolException)
        {
            // Allowed: anything else fails the test.
        }
    }
}

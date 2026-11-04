using System;
using System.Globalization;
using System.Numerics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Xunit;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.Keys;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Tests.Crypto;

public class SshKeyTests
{
    private static readonly byte[] Message = Encoding.ASCII.GetBytes("exchange hash stand-in");

    // One RSA key for all these tests: generating them is the slow part.
    private static readonly Lazy<SshPrivateKey> SharedRsa = new(() => SshPrivateKey.GenerateRsa(2048));

    public static TheoryData<string> SignatureAlgorithms => [.. HostKeyAlgorithms.Default];

    public static TheoryData<string> EcdsaTypes => ["ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"];

    [Fact]
    public void Default_list_is_the_agreed_order() => Assert.Equal(
        ["ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "rsa-sha2-512", "rsa-sha2-256"],
        HostKeyAlgorithms.Default);

    // RFC 8032 section 7.1, TESTs 1 to 3.
    [Theory]
    [InlineData(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")]
    [InlineData(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")]
    [InlineData(
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a")]
    public void Ed25519_matches_the_RFC_8032_vectors(string seed, string publicKey, string message, string signature)
    {
        byte[] data = Convert.FromHexString(message);
        byte[] expectedSignature = SignatureBlob.Write("ssh-ed25519", Convert.FromHexString(signature));
        byte[] expectedBlob = Blob(static (ref SshWriter w, string pk) =>
        {
            w.WriteUtf8String("ssh-ed25519");
            w.WriteBinary(Convert.FromHexString(pk));
        }, publicKey);

        using SshPrivateKey key = Ed25519PrivateKey.FromSeed(Convert.FromHexString(seed));
        Assert.Equal(expectedBlob, key.PublicKey.Blob.ToArray());
        Assert.Equal(expectedSignature, key.Sign("ssh-ed25519", data));

        SshPublicKey parsed = SshPublicKey.Parse(expectedBlob);
        Assert.True(parsed.Verify("ssh-ed25519", data, expectedSignature));
    }

    [Theory]
    [MemberData(nameof(SignatureAlgorithms))]
    public void Signatures_round_trip_through_a_parsed_key(string algorithm)
    {
        using KeyHolder holder = new(algorithm);
        byte[] signature = holder.Key.Sign(algorithm, Message);
        SshPublicKey parsed = SshPublicKey.Parse(holder.Key.PublicKey.Blob.Span);
        Assert.Equal(holder.Key.PublicKey.KeyType, parsed.KeyType);
        Assert.Equal(holder.Key.PublicKey.Blob.ToArray(), parsed.Blob.ToArray());
        Assert.Contains(algorithm, holder.Key.SignatureAlgorithms);
        Assert.True(parsed.SupportsSignatureAlgorithm(algorithm));
        Assert.True(parsed.Verify(algorithm, Message, signature));
        Assert.True(holder.Key.PublicKey.Verify(algorithm, Message, signature));
    }

    [Theory]
    [MemberData(nameof(SignatureAlgorithms))]
    public void Any_flipped_bit_in_a_signature_fails(string algorithm)
    {
        using KeyHolder holder = new(algorithm);
        byte[] signature = holder.Key.Sign(algorithm, Message);
        for (int i = 0; i < signature.Length; i++)
        {
            byte[] tampered = (byte[])signature.Clone();
            tampered[i] ^= (byte)(1 << (i % 8));
            Assert.False(holder.Key.PublicKey.Verify(algorithm, Message, tampered), $"byte {i}");
        }
    }

    [Theory]
    [MemberData(nameof(SignatureAlgorithms))]
    public void A_changed_message_fails(string algorithm)
    {
        using KeyHolder holder = new(algorithm);
        byte[] signature = holder.Key.Sign(algorithm, Message);
        byte[] other = (byte[])Message.Clone();
        other[0] ^= 1;
        Assert.False(holder.Key.PublicKey.Verify(algorithm, other, signature));
    }

    [Theory]
    [MemberData(nameof(SignatureAlgorithms))]
    public void Malformed_signature_blobs_give_false(string algorithm)
    {
        using KeyHolder holder = new(algorithm);
        byte[] signature = holder.Key.Sign(algorithm, Message);
        SshPublicKey key = holder.Key.PublicKey;

        for (int length = 0; length < signature.Length; length++)
        {
            Assert.False(key.Verify(algorithm, Message, signature.AsSpan(0, length)), $"cut to {length}");
        }

        Assert.False(key.Verify(algorithm, Message, [.. signature, 0x00]));

        byte[] hugeLength = (byte[])signature.Clone();
        hugeLength[0] = 0xFF;
        Assert.False(key.Verify(algorithm, Message, hugeLength));

        Assert.False(key.Verify(algorithm, Message, RandomNumberGenerator.GetBytes(signature.Length)));
        Assert.False(key.Verify(algorithm, Message, new byte[signature.Length]));
        Assert.False(key.Verify(algorithm, Message, SignatureBlob.Write(algorithm, [])));
        Assert.False(key.Verify(algorithm, Message, SignatureBlob.Write(algorithm, new byte[100_000])));
    }

    [Theory]
    [MemberData(nameof(SignatureAlgorithms))]
    public void The_wrong_algorithm_gives_false(string algorithm)
    {
        using KeyHolder holder = new(algorithm);
        byte[] signature = holder.Key.Sign(algorithm, Message);
        foreach (string other in HostKeyAlgorithms.Default)
        {
            if (other != algorithm)
            {
                Assert.False(holder.Key.PublicKey.Verify(other, Message, signature), other);
            }
        }

        Assert.False(holder.Key.PublicKey.Verify("ssh-rsa", Message, signature));
        Assert.False(holder.Key.PublicKey.Verify(string.Empty, Message, signature));
    }

    [Theory]
    [InlineData("rsa-sha2-256", "rsa-sha2-512")]
    [InlineData("rsa-sha2-512", "rsa-sha2-256")]
    public void An_RSA_blob_can_not_be_relabelled_as_the_other_hash(string signedWith, string claimed)
    {
        SshPrivateKey key = SharedRsa.Value;
        SshReader reader = new(key.Sign(signedWith, Message));
        reader.ReadBinary();
        byte[] relabelled = SignatureBlob.Write(claimed, reader.ReadBinary());
        Assert.False(key.PublicKey.Verify(claimed, Message, relabelled));
    }

    [Fact]
    public void RSA_never_offers_SHA_1()
    {
        SshPrivateKey key = SharedRsa.Value;
        Assert.Equal(["rsa-sha2-512", "rsa-sha2-256"], key.SignatureAlgorithms);
        Assert.False(key.PublicKey.SupportsSignatureAlgorithm("ssh-rsa"));
        Assert.Throws<ArgumentException>(() => key.Sign("ssh-rsa", Message));
        Assert.False(key.PublicKey.Verify("ssh-rsa", Message, SignatureBlob.Write("ssh-rsa", new byte[256])));
    }

    [Fact]
    public void A_short_RSA_signature_is_padded_as_OpenSSH_does()
    {
        SshPrivateKey key = SharedRsa.Value;
        for (int i = 0; i < 20_000; i++)
        {
            byte[] data = BitConverter.GetBytes(i);
            byte[] blob = key.Sign("rsa-sha2-256", data);
            SshReader reader = new(blob);
            reader.ReadBinary();
            ReadOnlySpan<byte> signature = reader.ReadBinary();
            if (signature[0] == 0)
            {
                Assert.True(key.PublicKey.Verify("rsa-sha2-256", data, SignatureBlob.Write("rsa-sha2-256", signature[1..])));
                return;
            }
        }

        Assert.Fail("no signature with a leading zero turned up");
    }

    [Fact]
    public void An_oversized_RSA_signature_gives_false()
    {
        SshPrivateKey key = SharedRsa.Value;
        SshReader reader = new(key.Sign("rsa-sha2-256", Message));
        reader.ReadBinary();
        byte[] padded = [0x00, .. reader.ReadBinary()];
        Assert.False(key.PublicKey.Verify("rsa-sha2-256", Message, SignatureBlob.Write("rsa-sha2-256", padded)));
    }

    [Theory]
    [MemberData(nameof(EcdsaTypes))]
    public void Bad_ECDSA_inner_values_give_false(string keyType)
    {
        using SshPrivateKey key = SshPrivateKey.GenerateEcdsa(keyType);
        SshReader outer = new(key.Sign(keyType, Message));
        outer.ReadBinary();
        SshReader inner = new(outer.ReadBinary());
        byte[] r = inner.ReadMPInt().ToArray();
        byte[] s = inner.ReadMPInt().ToArray();
        int size = NistCurve.FromKeyType(keyType)!.CoordinateLength;

        Assert.True(Check(r, s), "the untouched values must pass, or this test proves nothing");
        Assert.False(Check([], s), "r = 0");
        Assert.False(Check(r, []), "s = 0");
        Assert.False(Check(Ones(size), s), "r above the order");
        Assert.False(Check(r, Ones(size)), "s above the order");
        Assert.False(Check(Ones(size + 1), s), "r too wide");
        Assert.False(Check(r, Ones(size + 1)), "s too wide");
        Assert.False(Check(Ones(2000), s), "r huge");
        Assert.False(key.PublicKey.Verify(keyType, Message, Inner(keyType, static (ref SshWriter w) => w.WriteMPInt([1]))), "s missing");
        Assert.False(key.PublicKey.Verify(keyType, Message, Inner(keyType, (ref SshWriter w) =>
        {
            w.WriteMPInt(r);
            w.WriteMPInt(s);
            w.WriteByte(0);
        })), "trailing data inside");
        Assert.False(key.PublicKey.Verify(keyType, Message, Inner(keyType, (ref SshWriter w) =>
        {
            w.WriteBinary([0x80, 0x01]);
            w.WriteMPInt(s);
        })), "negative r");

        bool Check(byte[] rValue, byte[] sValue) => key.PublicKey.Verify(keyType, Message, Inner(keyType, (ref SshWriter w) =>
        {
            w.WriteMPInt(rValue);
            w.WriteMPInt(sValue);
        }));

        static byte[] Ones(int length)
        {
            byte[] value = new byte[length];
            value.AsSpan().Fill(0xFF);
            return value;
        }
    }

    [Theory]
    [MemberData(nameof(SignatureAlgorithms))]
    public void Every_truncation_of_a_key_blob_is_rejected(string algorithm)
    {
        using KeyHolder holder = new(algorithm);
        byte[] blob = holder.Key.PublicKey.Blob.ToArray();
        for (int length = 0; length < blob.Length; length++)
        {
            byte[] cut = blob[..length];
            Assert.Throws<SshProtocolException>(() => SshPublicKey.Parse(cut));
        }
    }

    [Theory]
    [MemberData(nameof(SignatureAlgorithms))]
    public void Trailing_data_after_a_key_is_rejected(string algorithm)
    {
        using KeyHolder holder = new(algorithm);
        byte[] blob = [.. holder.Key.PublicKey.Blob.Span, 0x00];
        Assert.Throws<SshProtocolException>(() => SshPublicKey.Parse(blob));
    }

    [Theory]
    [InlineData("ssh-dss")]
    [InlineData("ssh-ed448")]
    [InlineData("rsa-sha2-256")]
    [InlineData("ecdsa-sha2-nistp224")]
    [InlineData("ssh-ed25519-cert-v01@openssh.com")]
    [InlineData("")]
    public void Unsupported_key_types_are_rejected(string type)
    {
        byte[] blob = Blob(static (ref SshWriter w, string name) =>
        {
            w.WriteUtf8String(name);
            w.WriteBinary(new byte[32]);
        }, type);
        Assert.Throws<SshProtocolException>(() => SshPublicKey.Parse(blob));
    }

    [Fact]
    public void A_key_type_with_bad_UTF8_is_rejected()
    {
        byte[] blob = [0, 0, 0, 2, 0xC3, 0x28];
        Assert.Throws<SshProtocolException>(() => SshPublicKey.Parse(blob));
    }

    [Fact]
    public void The_peer_key_type_stays_out_of_the_message()
    {
        byte[] blob = Blob(static (ref SshWriter w, string name) => w.WriteUtf8String(name), "evil\r\nlog line");
        SshProtocolException ex = Assert.Throws<SshProtocolException>(() => SshPublicKey.Parse(blob));
        Assert.DoesNotContain("evil", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(0)]
    public void Ed25519_rejects_wrong_key_lengths(int length)
    {
        byte[] blob = Blob(static (ref SshWriter w, int n) =>
        {
            w.WriteUtf8String("ssh-ed25519");
            w.WriteBinary(new byte[n]);
        }, length);
        Assert.Throws<SshProtocolException>(() => SshPublicKey.Parse(blob));
    }

    // y = 1 is the identity, y = 0 has order 4, and y = 2 isn't on the curve at all.
    [Theory]
    [InlineData("0100000000000000000000000000000000000000000000000000000000000000")]
    [InlineData("0000000000000000000000000000000000000000000000000000000000000000")]
    [InlineData("0200000000000000000000000000000000000000000000000000000000000000")]
    public void Ed25519_rejects_bad_points(string key)
    {
        byte[] blob = Blob(static (ref SshWriter w, string hex) =>
        {
            w.WriteUtf8String("ssh-ed25519");
            w.WriteBinary(Convert.FromHexString(hex));
        }, key);
        Assert.Throws<SshProtocolException>(() => SshPublicKey.Parse(blob));
    }

    [Theory]
    [MemberData(nameof(EcdsaTypes))]
    public void ECDSA_rejects_a_mismatched_curve_name(string keyType)
    {
        using SshPrivateKey key = SshPrivateKey.GenerateEcdsa(keyType);
        SshReader reader = new(key.PublicKey.Blob.Span);
        reader.ReadBinary();
        reader.ReadBinary();
        byte[] point = reader.ReadBinary().ToArray();
        string wrongCurve = keyType.EndsWith("nistp256", StringComparison.Ordinal) ? "nistp384" : "nistp256";
        byte[] blob = EcdsaBlob(keyType, wrongCurve, point);
        Assert.Throws<SshProtocolException>(() => SshPublicKey.Parse(blob));
    }

    [Theory]
    [MemberData(nameof(EcdsaTypes))]
    public void ECDSA_rejects_bad_points(string keyType)
    {
        using SshPrivateKey key = SshPrivateKey.GenerateEcdsa(keyType);
        string curve = keyType["ecdsa-sha2-".Length..];
        SshReader reader = new(key.PublicKey.Blob.Span);
        reader.ReadBinary();
        reader.ReadBinary();
        byte[] point = reader.ReadBinary().ToArray();

        byte[] offCurve = (byte[])point.Clone();
        offCurve[^1] ^= 1;
        byte[] compressed = point[..((point.Length / 2) + 1)];
        compressed[0] = 0x02;

        foreach (byte[] bad in new[] { offCurve, compressed, new byte[point.Length], point[..^1], [.. point, 0], Array.Empty<byte>() })
        {
            byte[] blob = EcdsaBlob(keyType, curve, bad);
            Assert.Throws<SshProtocolException>(() => SshPublicKey.Parse(blob));
        }
    }

    [Theory]
    [InlineData(2047, false)]
    [InlineData(2048, true)]
    [InlineData(1024, false)]
    [InlineData(8, false)]
    [InlineData(16384, true)]
    [InlineData(16392, false)]
    public void RSA_modulus_limits_are_exact(int bits, bool accepted)
    {
        byte[] blob = RsaBlob([0x01, 0x00, 0x01], OddModulus(bits));
        if (accepted)
        {
            Assert.Equal("ssh-rsa", SshPublicKey.Parse(blob).KeyType);
        }
        else
        {
            Assert.Throws<SshProtocolException>(() => SshPublicKey.Parse(blob));
        }
    }

    [Theory]
    [InlineData("")] // zero
    [InlineData("01")] // a signature would be its own message
    [InlineData("02")]
    [InlineData("010000")] // even
    public void RSA_rejects_bad_exponents(string exponent)
    {
        byte[] blob = RsaBlob(Convert.FromHexString(exponent), OddModulus(2048));
        Assert.Throws<SshProtocolException>(() => SshPublicKey.Parse(blob));
    }

    // K_S is hashed as received, so Blob must not be a tidied-up copy of what the peer sent.
    [Fact]
    public void An_RSA_blob_with_redundant_zeros_keeps_the_peers_bytes()
    {
        SshPrivateKey key = SharedRsa.Value;
        SshReader reader = new(key.PublicKey.Blob.Span);
        reader.ReadBinary();
        byte[] exponent = reader.ReadMPInt().ToArray();
        byte[] modulus = reader.ReadMPInt().ToArray();
        byte[] blob = Blob(static (ref SshWriter w, (byte[] E, byte[] N) value) =>
        {
            w.WriteUtf8String("ssh-rsa");
            w.WriteBinary([0x00, 0x00, .. value.E]);
            w.WriteBinary([0x00, 0x00, .. value.N]);
        }, (exponent, modulus));

        SshPublicKey parsed = SshPublicKey.Parse(blob);
        Assert.Equal(blob, parsed.Blob.ToArray());
        Assert.NotEqual(key.PublicKey.Blob.ToArray(), parsed.Blob.ToArray());
        Assert.True(parsed.Verify("rsa-sha2-256", Message, key.Sign("rsa-sha2-256", Message)));
    }

    // RFC 8032 section 5.1.7 requires S < L. Without that check, S + L would be a second valid signature.
    [Fact]
    public void Ed25519_refuses_a_malleated_signature()
    {
        using SshPrivateKey key = SshPrivateKey.GenerateEd25519();
        SshReader reader = new(key.Sign("ssh-ed25519", Message));
        reader.ReadBinary();
        byte[] signature = reader.ReadBinary().ToArray();

        BigInteger order = BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493", CultureInfo.InvariantCulture);
        BigInteger malleated = new BigInteger(signature.AsSpan(32), isUnsigned: true) + order;
        Assert.True(malleated.GetByteCount(isUnsigned: true) <= 32);
        signature.AsSpan(32).Clear();
        Assert.True(malleated.TryWriteBytes(signature.AsSpan(32), out _, isUnsigned: true));

        Assert.False(key.PublicKey.Verify("ssh-ed25519", Message, SignatureBlob.Write("ssh-ed25519", signature)));
    }

    [Fact]
    public void RSA_rejects_an_even_modulus()
    {
        byte[] modulus = OddModulus(2048);
        modulus[^1] &= 0xFE;
        byte[] blob = RsaBlob([0x01, 0x00, 0x01], modulus);
        Assert.Throws<SshProtocolException>(() => SshPublicKey.Parse(blob));
    }

    [Fact]
    public void RSA_rejects_a_negative_modulus()
    {
        byte[] blob = Blob(static (ref SshWriter w, int _) =>
        {
            w.WriteUtf8String("ssh-rsa");
            w.WriteMPInt([0x01, 0x00, 0x01]);
            w.WriteBinary(OddModulus(2048));
        }, 0);
        Assert.Throws<SshProtocolException>(() => SshPublicKey.Parse(blob));
    }

    [Fact]
    public void Random_blobs_raise_nothing_but_SshProtocolException()
    {
        Random random = new(20261104);
        string[] types = ["ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp521"];
        for (int i = 0; i < 2000; i++)
        {
            byte[] junk = new byte[random.Next(0, 600)];
            random.NextBytes(junk);
            byte[] blob = Blob(static (ref SshWriter w, (string Name, byte[] Junk) input) =>
            {
                w.WriteUtf8String(input.Name);
                w.WriteRaw(input.Junk);
            }, (types[i % types.Length], junk));

            try
            {
                SshPublicKey.Parse(blob);
            }
            catch (SshProtocolException)
            {
                // The only allowed failure.
            }
        }
    }

    [Fact]
    public void Parse_keeps_its_own_copy()
    {
        using SshPrivateKey key = SshPrivateKey.GenerateEd25519();
        byte[] blob = key.PublicKey.Blob.ToArray();
        SshPublicKey parsed = SshPublicKey.Parse(blob);
        byte[] signature = key.Sign("ssh-ed25519", Message);
        Array.Clear(blob);
        Assert.True(parsed.Verify("ssh-ed25519", Message, signature));
        Assert.Equal(key.PublicKey.Blob.ToArray(), parsed.Blob.ToArray());
    }

    [Fact]
    public void Factories_reject_bad_arguments()
    {
        Assert.Throws<ArgumentException>(() => SshPrivateKey.GenerateEcdsa("nistp256"));
        Assert.Throws<ArgumentOutOfRangeException>(() => SshPrivateKey.GenerateRsa(1024));
        Assert.Throws<ArgumentException>(() => Ed25519PrivateKey.FromSeed(new byte[31]));
    }

    [Theory]
    [MemberData(nameof(SignatureAlgorithms))]
    public void Signing_with_a_foreign_algorithm_is_refused(string algorithm)
    {
        using KeyHolder holder = new(algorithm);
        Assert.Throws<ArgumentException>(() => holder.Key.Sign("no-such-algorithm", Message));
    }

    [Fact]
    public void Disposing_an_Ed25519_key_zeroes_the_seed()
    {
        byte[] seed = RandomNumberGenerator.GetBytes(32);
        SshPrivateKey key = Ed25519PrivateKey.FromSeed(seed);
        byte[] held = (byte[])typeof(Ed25519PrivateKey)
            .GetField("_seed", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(key)!;
        Assert.Equal(seed, held);
        key.Dispose();
        Assert.All(held, static b => Assert.Equal(0, b));
        Assert.Throws<ObjectDisposedException>(() => key.Sign("ssh-ed25519", Message));
    }

    [Theory]
    [InlineData("ecdsa-sha2-nistp256")]
    [InlineData("rsa")]
    public void A_disposed_BCL_key_can_not_sign(string kind)
    {
        SshPrivateKey key = kind == "rsa" ? SshPrivateKey.GenerateRsa(2048) : SshPrivateKey.GenerateEcdsa(kind);
        string algorithm = key.SignatureAlgorithms[0];
        key.Dispose();
        Assert.Throws<ObjectDisposedException>(() => key.Sign(algorithm, Message));
    }

    private static byte[] OddModulus(int bits)
    {
        int bytes = (bits + 7) / 8;
        byte[] modulus = RandomNumberGenerator.GetBytes(bytes);
        int topBits = bits - ((bytes - 1) * 8);
        modulus[0] = (byte)(1 << (topBits - 1));
        modulus[^1] |= 1;
        return modulus;
    }

    private static byte[] RsaBlob(byte[] exponent, byte[] modulus) => Blob(static (ref SshWriter w, (byte[] E, byte[] N) key) =>
    {
        w.WriteUtf8String("ssh-rsa");
        w.WriteMPInt(key.E);
        w.WriteMPInt(key.N);
    }, (exponent, modulus));

    private static byte[] EcdsaBlob(string keyType, string curve, byte[] point) => Blob(static (ref SshWriter w, (string Type, string Curve, byte[] Point) key) =>
    {
        w.WriteUtf8String(key.Type);
        w.WriteUtf8String(key.Curve);
        w.WriteBinary(key.Point);
    }, (keyType, curve, point));

    private static byte[] Inner(string algorithm, WriteBody body)
    {
        SshWriter writer = new();
        try
        {
            body(ref writer);
            return SignatureBlob.Write(algorithm, writer.Written);
        }
        finally
        {
            writer.Dispose();
        }
    }

    private static byte[] Blob<T>(WriteBody<T> body, T state)
    {
        SshWriter writer = new();
        try
        {
            body(ref writer, state);
            return writer.ToArray();
        }
        finally
        {
            writer.Dispose();
        }
    }

    private delegate void WriteBody(ref SshWriter writer);

    private delegate void WriteBody<in T>(ref SshWriter writer, T state);

    // Gives each algorithm a key, and disposes it unless it's the shared RSA key.
    private sealed class KeyHolder : IDisposable
    {
        private readonly bool _owned;

        public KeyHolder(string algorithm)
        {
            _owned = !algorithm.StartsWith("rsa-", StringComparison.Ordinal);
            Key = algorithm switch
            {
                "ssh-ed25519" => SshPrivateKey.GenerateEd25519(),
                "rsa-sha2-512" or "rsa-sha2-256" => SharedRsa.Value,
                _ => SshPrivateKey.GenerateEcdsa(algorithm),
            };
        }

        public SshPrivateKey Key { get; }

        public void Dispose()
        {
            if (_owned)
            {
                Key.Dispose();
            }
        }
    }
}

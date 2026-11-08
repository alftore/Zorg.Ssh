using System;
using System.Formats.Asn1;
using System.Security.Cryptography;
using Xunit;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.KeyFiles;
using Zorg.Ssh.Crypto.Keys;
using static Zorg.Ssh.Tests.KeyFiles.EcKeyFileWriter;

namespace Zorg.Ssh.Tests.KeyFiles;

/// <summary>
/// EC keys whose file spells the curve out instead of naming it. ssh-keygen on macOS writes its PEM and PKCS#8 ECDSA
/// keys this way, and OpenSSH reads them when the values are exactly one of its curves. Nothing else is accepted, and
/// the values themselves never reach the platform.
/// </summary>
public class ExplicitCurveKeyFileTests
{
    public static TheoryData<string> Curves => ["nistp256", "nistp384", "nistp521"];

    public static TheoryData<string, string> NearlyACurve => new()
    {
        { "prime", SshKeyFile.UnsupportedKey },
        { "a", SshKeyFile.UnsupportedKey },
        { "b", SshKeyFile.UnsupportedKey },
        { "generator", SshKeyFile.UnsupportedKey },
        { "compressed generator", SshKeyFile.UnsupportedKey },
        { "order", SshKeyFile.UnsupportedKey },
        { "cofactor", SshKeyFile.UnsupportedKey },
        { "binary field", SshKeyFile.UnsupportedKey },
        { "version", SshKeyFile.UnsupportedKey },
        { "hash", SshKeyFile.Malformed },
        { "another curve's values", SshKeyFile.UnsupportedKey },
    };

    [Theory]
    [MemberData(nameof(Curves))]
    public void A_spelled_out_known_curve_loads_from_SEC1_and_PKCS8(string name)
    {
        NistCurve curve = Curve(name);
        using ECDsa ecdsa = ECDsa.Create(curve.Curve);
        ECParameters key = ecdsa.ExportParameters(includePrivateParameters: true);
        byte[] blob = EcdsaPublicKey.FromPoint(curve, key.Q).Blob.ToArray();

        // With a seed, as OpenSSL writes it, and without.
        foreach (byte[]? seed in new[] { null, RandomNumberGenerator.GetBytes(20) })
        {
            Action<AsnWriter> spelled = Explicit(Domain.Of(curve, seed));
            AssertLoads(KeyFileTools.Armor("EC PRIVATE KEY", Sec1(key, spelled)), blob);
            AssertLoads(KeyFileTools.Armor("PRIVATE KEY", Pkcs8(Sec1(key, null), spelled)), blob);
            AssertLoads(KeyFileTools.Armor("PRIVATE KEY", Pkcs8(Sec1(key, spelled), spelled)), blob);
            AssertLoads(KeyFileTools.Armor("PRIVATE KEY", Pkcs8(Sec1(key, Named(Oid(name))), spelled)), blob);
        }
    }

    // The same files as the platform's own encoder writes them, so the writer above isn't the only witness.
    [Theory]
    [MemberData(nameof(Curves))]
    public void A_key_the_platform_wrote_with_its_curve_spelled_out_loads(string name)
    {
        Assert.SkipWhen(OperatingSystem.IsMacOS(), "macOS can't give a key's curve as explicit parameters ('Only named curves are supported').");
        NistCurve curve = Curve(name);
        using ECDsa named = ECDsa.Create(curve.Curve);
        byte[] blob = EcdsaPublicKey.FromPoint(curve, named.ExportParameters(false).Q).Blob.ToArray();
        using ECDsa spelled = ECDsa.Create();
        spelled.ImportParameters(named.ExportExplicitParameters(includePrivateParameters: true));

        string sec1 = spelled.ExportECPrivateKeyPem();
        string pkcs8 = spelled.ExportPkcs8PrivateKeyPem();
        // ECPrivateKey: version, scalar, then [0] with a SEQUENCE, not an OID.
        AsnReader written = new AsnReader(KeyFileTools.Unarmor(sec1), AsnEncodingRules.DER).ReadSequence();
        _ = written.ReadInteger();
        _ = written.ReadOctetString();
        Asn1Tag parameters = written.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)).PeekTag();
        Assert.True(parameters.HasSameClassAndValue(Asn1Tag.Sequence));

        AssertLoads(sec1, blob);
        AssertLoads(pkcs8, blob);
    }

    [Theory]
    [MemberData(nameof(NearlyACurve))]
    public void A_curve_that_differs_from_a_known_one_in_one_value_is_refused(string change, string message)
    {
        NistCurve curve = NistCurve.P256;
        Domain domain = Domain.Of(curve);
        domain = change switch
        {
            "prime" => domain with { Prime = Flip(domain.Prime) },
            "a" => domain with { A = Flip(domain.A) },
            "b" => domain with { B = Flip(domain.B) },
            "generator" => domain with { Generator = Flip(domain.Generator) },
            "compressed generator" => domain with { Generator = [(byte)(2 + (domain.Generator[^1] & 1)), .. domain.Generator.AsSpan(1, 32)] },
            "order" => domain with { Order = Flip(domain.Order) },
            "cofactor" => domain with { Cofactor = 2 },
            "binary field" => domain with { FieldType = "1.2.840.10045.1.2" },
            "version" => domain with { Version = 4 },
            "hash" => domain with { Hash = "2.16.840.1.101.3.4.2.1" },
            _ => Domain.Of(NistCurve.P384) with { Order = domain.Order },
        };

        using ECDsa ecdsa = ECDsa.Create(curve.Curve);
        ECParameters key = ecdsa.ExportParameters(includePrivateParameters: true);
        Assert.Equal(message, Refused(KeyFileTools.Armor("EC PRIVATE KEY", Sec1(key, Explicit(domain)))).Message);
        Assert.Equal(message, Refused(KeyFileTools.Armor("PRIVATE KEY", Pkcs8(Sec1(key, null), Explicit(domain)))).Message);
    }

    [Fact]
    public void A_PKCS8_key_whose_inner_curve_is_another_is_refused()
    {
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters key = ecdsa.ExportParameters(includePrivateParameters: true);
        byte[] file = Pkcs8(Sec1(key, Named(Oid("nistp384"))), Explicit(Domain.Of(NistCurve.P256)));
        Assert.Equal(SshKeyFile.Mismatch, Refused(KeyFileTools.Armor("PRIVATE KEY", file)).Message);
    }

    [Fact]
    public void A_spelled_out_key_without_its_public_key_is_refused()
    {
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters key = ecdsa.ExportParameters(includePrivateParameters: true);
        Action<AsnWriter> spelled = Explicit(Domain.Of(NistCurve.P256));
        Assert.Equal(SshKeyFile.Malformed, Refused(KeyFileTools.Armor("EC PRIVATE KEY", Sec1(key, spelled, withPublicKey: false))).Message);
    }

    [Fact]
    public void A_spelled_out_key_with_the_scalar_of_another_key_is_refused()
    {
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters key = ecdsa.ExportParameters(includePrivateParameters: true);
        key.D = other.ExportParameters(includePrivateParameters: true).D;
        Refused(KeyFileTools.Armor("EC PRIVATE KEY", Sec1(key, Explicit(Domain.Of(NistCurve.P256)))));
    }

    [Fact]
    public void A_spelled_out_key_with_a_point_off_the_curve_is_refused()
    {
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters key = ecdsa.ExportParameters(includePrivateParameters: true);
        key.Q.Y![^1] ^= 1;
        Assert.Equal(SshKeyFile.Malformed, Refused(KeyFileTools.Armor("EC PRIVATE KEY", Sec1(key, Explicit(Domain.Of(NistCurve.P256))))).Message);
    }

    private static void AssertLoads(string text, byte[] blob)
    {
        using SshPrivateKey loaded = SshKeyFile.Load(text);
        KeyFileTools.AssertSignsFor(loaded, blob);
    }

    private static SshKeyFileException Refused(string text) => Assert.Throws<SshKeyFileException>(() => SshKeyFile.Load(text));

    private static NistCurve Curve(string name) => NistCurve.FromKeyType("ecdsa-sha2-" + name)!;

    private static string Oid(string name) => name switch
    {
        "nistp256" => "1.2.840.10045.3.1.7",
        "nistp384" => "1.3.132.0.34",
        _ => "1.3.132.0.35",
    };

    private static byte[] Flip(byte[] value)
    {
        byte[] changed = (byte[])value.Clone();
        changed[^1] ^= 2;
        return changed;
    }
}

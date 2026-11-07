using System;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Security;
using Zorg.Ssh.Crypto.Keys;
using Zorg.Ssh.Tests.KeyFiles;
using BcInt = Org.BouncyCastle.Math.BigInteger;

namespace Zorg.Ssh.Tests.Fuzzing;

/// <summary>
/// The keys of the fuzz corpus, made at test time and the same every time: RSA from BouncyCastle's key generator driven by a
/// deterministic random generator with a fixed seed, ECDSA from a scalar that is a hash of a fixed label, and Ed25519 from a fixed
/// seed. Nothing here is a stored key, and none of it uses the platform's key generation, which is random. So a fuzz seed rebuilds
/// the same input on any machine, as long as BouncyCastle keeps its generator's output (a version bump can change the RSA key,
/// and old seeds then rebuild different inputs). Generated once per process.
/// </summary>
internal static class FuzzKeys
{
    private static readonly Lazy<Material> Cached = new(() => new Material());

    public static string RsaOpenSsh => Cached.Value.RsaOpenSsh;

    public static string RsaPkcs1 => Cached.Value.RsaPkcs1;

    public static string RsaPkcs8 => Cached.Value.RsaPkcs8;

    public static string EcdsaOpenSsh => Cached.Value.EcdsaOpenSsh;

    public static string EcdsaSec1 => Cached.Value.EcdsaSec1;

    public static string EcdsaPkcs8 => Cached.Value.EcdsaPkcs8;

    public static string Ed25519OpenSsh => Cached.Value.Ed25519OpenSsh;

    public static string Ed25519Pkcs8 => Cached.Value.Ed25519Pkcs8;

    public static string RsaPublicLine => Cached.Value.RsaPublicLine;

    public static string EcdsaPublicLine => Cached.Value.EcdsaPublicLine;

    public static string Ed25519PublicLine => Cached.Value.Ed25519PublicLine;

    /// <summary>Gets the RSA values, big-endian without leading zeros.</summary>
    public static RsaValues Rsa => Cached.Value.Rsa;

    /// <summary>Builds an openssh-key-v1 file for RSA values, which need not be the generated ones. The public key part holds <paramref name="publicExponent"/>, the private part the exponent in <paramref name="values"/>.</summary>
    public static byte[] RsaOpenSshFile(RsaValues values, byte[] publicExponent)
    {
        byte[] publicBlob = new FuzzBlob().String("ssh-rsa").MPInt(publicExponent).MPInt(values.N).ToArray();
        byte[] fields = new FuzzBlob().MPInt(values.N).MPInt(values.E).MPInt(values.D).MPInt(values.InverseQ).MPInt(values.P).MPInt(values.Q).ToArray();
        return new OpenSshFileBuilder { PublicBlob = publicBlob, Section = OpenSshFileBuilder.MakeSection("ssh-rsa", fields) }.ToBinary();
    }

    internal sealed record RsaValues(byte[] N, byte[] E, byte[] D, byte[] P, byte[] Q, byte[] DP, byte[] DQ, byte[] InverseQ);

    private sealed class Material
    {
        public Material()
        {
            Rsa = MakeRsa();
            byte[] rsaPublic = new FuzzBlob().String("ssh-rsa").MPInt(Rsa.E).MPInt(Rsa.N).ToArray();
            RsaOpenSsh = KeyFileTools.Armor("OPENSSH PRIVATE KEY", RsaOpenSshFile(Rsa, Rsa.E));
            byte[] pkcs1 = Pkcs1(Rsa);
            RsaPkcs1 = KeyFileTools.Armor("RSA PRIVATE KEY", pkcs1);
            RsaPkcs8 = KeyFileTools.Armor("PRIVATE KEY", Pkcs8("1.2.840.113549.1.1.1", asnNull: true, null, pkcs1));
            RsaPublicLine = PublicLine("ssh-rsa", rsaPublic);

            // ECDSA P-256: the scalar is a hash of a label, brought into range, and BouncyCastle works out the point.
            X9ECParameters curve = ECNamedCurveTable.GetByName("secp256r1");
            BcInt d = new BcInt(1, SHA256.HashData(Encoding.ASCII.GetBytes("zorg-ssh fuzz corpus ecdsa p256 v1"))).Mod(curve.N.Subtract(BcInt.One)).Add(BcInt.One);
            byte[] scalar = Pad(d.ToByteArrayUnsigned(), 32);
            byte[] point = curve.G.Multiply(d).Normalize().GetEncoded(false);
            byte[] ecPublic = new FuzzBlob().String("ecdsa-sha2-nistp256").String("nistp256").String(point).ToArray();
            byte[] ecFields = new FuzzBlob().String("nistp256").String(point).MPInt(scalar).ToArray();
            EcdsaOpenSsh = KeyFileTools.Armor("OPENSSH PRIVATE KEY", new OpenSshFileBuilder { PublicBlob = ecPublic, Section = OpenSshFileBuilder.MakeSection("ecdsa-sha2-nistp256", ecFields) }.ToBinary());
            EcdsaSec1 = KeyFileTools.Armor("EC PRIVATE KEY", Sec1(scalar, point, withParameters: true));
            EcdsaPkcs8 = KeyFileTools.Armor("PRIVATE KEY", Pkcs8("1.2.840.10045.2.1", asnNull: false, "1.2.840.10045.3.1.7", Sec1(scalar, point, withParameters: false)));
            EcdsaPublicLine = PublicLine("ecdsa-sha2-nistp256", ecPublic);

            // Ed25519: a fixed seed.
            byte[] seed = Enumerable.Range(7, 32).Select(i => (byte)(i * 5)).ToArray();
            byte[] edPublic;
            using (Ed25519PrivateKey key = Ed25519PrivateKey.FromSeed(seed))
            {
                edPublic = key.PublicKey.Blob.ToArray();
            }

            byte[] edValue = edPublic[^32..];
            byte[] edFields = new FuzzBlob().String(edValue).String([.. seed, .. edValue]).ToArray();
            Ed25519OpenSsh = KeyFileTools.Armor("OPENSSH PRIVATE KEY", new OpenSshFileBuilder { PublicBlob = edPublic, Section = OpenSshFileBuilder.MakeSection("ssh-ed25519", edFields) }.ToBinary());
            AsnWriter inner = new(AsnEncodingRules.DER);
            inner.WriteOctetString(seed);
            Ed25519Pkcs8 = KeyFileTools.Armor("PRIVATE KEY", Pkcs8("1.3.101.112", asnNull: false, null, inner.Encode()));
            Ed25519PublicLine = PublicLine("ssh-ed25519", edPublic);
        }

        public RsaValues Rsa { get; }

        public string RsaOpenSsh { get; }

        public string RsaPkcs1 { get; }

        public string RsaPkcs8 { get; }

        public string EcdsaOpenSsh { get; }

        public string EcdsaSec1 { get; }

        public string EcdsaPkcs8 { get; }

        public string Ed25519OpenSsh { get; }

        public string Ed25519Pkcs8 { get; }

        public string RsaPublicLine { get; }

        public string EcdsaPublicLine { get; }

        public string Ed25519PublicLine { get; }

        private static RsaValues MakeRsa()
        {
            // BouncyCastle's own digest-based generator, seeded with a constant: the same stream of bytes every time.
            DigestRandomGenerator generator = new(new Sha256Digest());
            generator.AddSeedMaterial(Encoding.ASCII.GetBytes("zorg-ssh fuzz corpus rsa 2048 v1"));
            SecureRandom random = new(generator);
            RsaKeyPairGenerator pairs = new();
            pairs.Init(new RsaKeyGenerationParameters(BcInt.ValueOf(65537), random, 2048, 100));
            AsymmetricCipherKeyPair pair = pairs.GenerateKeyPair();
            RsaPrivateCrtKeyParameters key = (RsaPrivateCrtKeyParameters)pair.Private;
            return new RsaValues(
                key.Modulus.ToByteArrayUnsigned(),
                key.PublicExponent.ToByteArrayUnsigned(),
                key.Exponent.ToByteArrayUnsigned(),
                key.P.ToByteArrayUnsigned(),
                key.Q.ToByteArrayUnsigned(),
                key.DP.ToByteArrayUnsigned(),
                key.DQ.ToByteArrayUnsigned(),
                key.QInv.ToByteArrayUnsigned());
        }

        private static byte[] Pkcs1(RsaValues v)
        {
            AsnWriter writer = new(AsnEncodingRules.DER);
            using (writer.PushSequence())
            {
                writer.WriteInteger(0);
                foreach (byte[] value in new[] { v.N, v.E, v.D, v.P, v.Q, v.DP, v.DQ, v.InverseQ })
                {
                    writer.WriteIntegerUnsigned(value);
                }
            }

            return writer.Encode();
        }

        private static byte[] Sec1(byte[] scalar, byte[] point, bool withParameters)
        {
            AsnWriter writer = new(AsnEncodingRules.DER);
            using (writer.PushSequence())
            {
                writer.WriteInteger(1);
                writer.WriteOctetString(scalar);
                if (withParameters)
                {
                    using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                    {
                        writer.WriteObjectIdentifier("1.2.840.10045.3.1.7");
                    }
                }

                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true)))
                {
                    writer.WriteBitString(point);
                }
            }

            return writer.Encode();
        }

        private static byte[] Pkcs8(string algorithm, bool asnNull, string? parameter, byte[] privateKey)
        {
            AsnWriter writer = new(AsnEncodingRules.DER);
            using (writer.PushSequence())
            {
                writer.WriteInteger(0);
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(algorithm);
                    if (asnNull)
                    {
                        writer.WriteNull();
                    }

                    if (parameter is not null)
                    {
                        writer.WriteObjectIdentifier(parameter);
                    }
                }

                writer.WriteOctetString(privateKey);
            }

            return writer.Encode();
        }

        private static string PublicLine(string type, byte[] blob) => type + " " + Convert.ToBase64String(blob);

        private static byte[] Pad(byte[] value, int length) => value.Length >= length ? value : [.. new byte[length - value.Length], .. value];
    }
}

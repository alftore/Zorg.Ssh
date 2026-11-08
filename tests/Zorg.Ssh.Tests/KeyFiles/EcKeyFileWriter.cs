using System;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using Zorg.Ssh.Crypto.Keys;

namespace Zorg.Ssh.Tests.KeyFiles;

/// <summary>
/// SEC 1 and PKCS#8 EC key files written field by field, with the curve named by OID or spelled out, so a test can
/// make a curve the platform can't, or one that is a known curve but for a single value.
/// </summary>
internal static class EcKeyFileWriter
{
    public const string EcPublicKey = "1.2.840.10045.2.1";
    public const string PrimeField = "1.2.840.10045.1.1";
    public const string BrainpoolP256r1 = "1.3.36.3.3.2.8.1.1.7";

    private static readonly Asn1Tag CurveTag = new(TagClass.ContextSpecific, 0, isConstructed: true);
    private static readonly Asn1Tag PublicKeyTag = new(TagClass.ContextSpecific, 1, isConstructed: true);

    /// <summary>Writes ECParameters as a named curve.</summary>
    public static Action<AsnWriter> Named(string oid) => writer => writer.WriteObjectIdentifier(oid);

    /// <summary>Writes ECParameters as a SpecifiedECDomain.</summary>
    public static Action<AsnWriter> Explicit(Domain domain) => writer =>
    {
        using (writer.PushSequence())
        {
            writer.WriteInteger(domain.Version);
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(domain.FieldType);
                writer.WriteIntegerUnsigned(domain.Prime);
            }

            using (writer.PushSequence())
            {
                writer.WriteOctetString(domain.A);
                writer.WriteOctetString(domain.B);
                if (domain.Seed is not null)
                {
                    writer.WriteBitString(domain.Seed);
                }
            }

            writer.WriteOctetString(domain.Generator);
            writer.WriteIntegerUnsigned(domain.Order);
            if (domain.Cofactor is { } cofactor)
            {
                writer.WriteInteger(cofactor);
            }

            if (domain.Hash is not null)
            {
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(domain.Hash);
                }
            }
        }
    };

    /// <summary>Writes ECPrivateKey (<c>BEGIN EC PRIVATE KEY</c>), with the curve if <paramref name="curve"/> is given.</summary>
    public static byte[] Sec1(ECParameters key, Action<AsnWriter>? curve, bool withPublicKey = true)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(1);
            writer.WriteOctetString(key.D);
            if (curve is not null)
            {
                using (writer.PushSequence(CurveTag))
                {
                    curve(writer);
                }
            }

            if (withPublicKey)
            {
                using (writer.PushSequence(PublicKeyTag))
                {
                    writer.WriteBitString([0x04, .. key.Q.X!, .. key.Q.Y!]);
                }
            }
        }

        return writer.Encode();
    }

    /// <summary>Writes PrivateKeyInfo (<c>BEGIN PRIVATE KEY</c>) around a SEC 1 key, with <paramref name="curve"/> in the algorithm.</summary>
    public static byte[] Pkcs8(byte[] sec1, Action<AsnWriter> curve)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(0);
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(EcPublicKey);
                curve(writer);
            }

            writer.WriteOctetString(sec1);
        }

        return writer.Encode();
    }

    /// <summary>A curve spelled out, as SEC 1 writes it. Each field can be changed to make a curve that is nearly a known one.</summary>
    internal sealed record Domain(
        byte[] Prime,
        byte[] A,
        byte[] B,
        byte[] Generator,
        byte[] Order,
        int? Cofactor = 1,
        byte[]? Seed = null,
        int Version = 1,
        string FieldType = PrimeField,
        string? Hash = null)
    {
        /// <summary>Spells out one of the NIST curves, with a = p - 3 as all three have.</summary>
        public static Domain Of(NistCurve curve, byte[]? seed = null)
        {
            byte[] prime = curve.Prime;
            BigInteger a = new BigInteger(prime, isUnsigned: true, isBigEndian: true) - 3;
            byte[] aBytes = new byte[prime.Length];
            byte[] raw = a.ToByteArray(isUnsigned: true, isBigEndian: true);
            raw.CopyTo(aBytes, aBytes.Length - raw.Length);
            return new Domain(prime, aBytes, curve.B, curve.Generator.ToArray(), curve.Order, Seed: seed);
        }
    }
}

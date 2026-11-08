using System;
using System.Formats.Asn1;
using System.Security.Cryptography;
using Zorg.Ssh.Crypto.Keys;

namespace Zorg.Ssh.Crypto.KeyFiles;

/// <summary>
/// The DER key formats: PKCS#1, SEC1, PKCS#8 and encrypted PKCS#8. RSA and ECDSA keys go through the BCL importers.
/// The BCL has no Ed25519, so that key is read here.
/// </summary>
/// <remarks>
/// Encrypted PKCS#8 is decrypted here rather than by <c>ImportEncryptedPkcs8PrivateKey</c>, for three reasons. That
/// importer has no limit on the PBKDF2 count: it ran 5 million without complaint, so a hostile file could set
/// <c>int.MaxValue</c> and hang the caller. It needs the key type first, which is inside the encryption, so it would
/// repeat the KDF per type. And it can't read Ed25519, which <c>ssh-keygen -m PKCS8</c> writes.
/// </remarks>
internal static class Pkcs8KeyFormat
{
    /// <summary>
    /// The largest PBKDF2 count accepted. The file sets the count, and this costs a hostile file about a second. The
    /// file <c>ssh-keygen -m PKCS8</c> writes is far below it.
    /// </summary>
    public const int MaxPbkdf2Iterations = 2_000_000;

    private const string RsaEncryption = "1.2.840.113549.1.1.1";
    private const string EcPublicKey = "1.2.840.10045.2.1";
    private const string Ed25519 = "1.3.101.112";
    private const string P256 = "1.2.840.10045.3.1.7";
    private const string P384 = "1.3.132.0.34";
    private const string P521 = "1.3.132.0.35";
    private const string Pbes2 = "1.2.840.113549.1.5.13";
    private const string Pbkdf2 = "1.2.840.113549.1.5.12";
    private const string HmacSha1 = "1.2.840.113549.2.7";
    private const string HmacSha256 = "1.2.840.113549.2.9";
    private const string HmacSha384 = "1.2.840.113549.2.10";
    private const string HmacSha512 = "1.2.840.113549.2.11";
    private const string Aes128Cbc = "2.16.840.1.101.3.4.1.2";
    private const string Aes192Cbc = "2.16.840.1.101.3.4.1.22";
    private const string Aes256Cbc = "2.16.840.1.101.3.4.1.42";

    private const string PrimeField = "1.2.840.10045.1.1";

    private const int Ed25519SeedLength = 32;

    private static readonly Asn1Tag CurveTag = new(TagClass.ContextSpecific, 0, isConstructed: true);
    private static readonly Asn1Tag PublicKeyTag = new(TagClass.ContextSpecific, 1, isConstructed: true);
    private const int AesBlock = 16;

    private const string UnsupportedEncryption = "The key file's encryption isn't supported: only PBES2 with PBKDF2 and AES-CBC is. Convert it to OpenSSH's format with: ssh-keygen -p -f <file>";

    /// <summary>Reads <c>BEGIN RSA PRIVATE KEY</c>.</summary>
    public static SshPrivateKey ParsePkcs1(ReadOnlyMemory<byte> der)
    {
        EnsureRsaValuesConsistent(der);
        RSA rsa = RSA.Create();
        try
        {
            rsa.ImportRSAPrivateKey(der.Span, out int read);
            EnsureAllRead(read, der);
        }
        catch
        {
            rsa.Dispose();
            throw;
        }

        return RsaPrivateKey.Adopt(rsa);
    }

    /// <summary>Reads <c>BEGIN EC PRIVATE KEY</c>.</summary>
    public static SshPrivateKey ParseSec1(ReadOnlyMemory<byte> der)
    {
        // ECPrivateKey: version, private key, [0] curve. Reading the curve first keeps explicit curve parameters,
        // which the file would control, away from the platform.
        AsnReader outer = new(der, AsnEncodingRules.BER);
        AsnReader key = outer.ReadSequence();
        outer.ThrowIfNotEmpty();
        _ = key.TryReadInt32(out _);
        _ = key.TryReadPrimitiveOctetString(out _);
        AsnReader parameters = key.ReadSequence(CurveTag);
        (NistCurve curve, bool named) = ReadCurve(parameters);
        parameters.ThrowIfNotEmpty();
        if (!named)
        {
            return ReadEcPrivateKey(der, curve);
        }

        ECDsa ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportECPrivateKey(der.Span, out int read);
            EnsureAllRead(read, der);
        }
        catch
        {
            ecdsa.Dispose();
            throw;
        }

        return EcdsaPrivateKey.Adopt(curve, ecdsa);
    }

    /// <summary>Reads <c>BEGIN PRIVATE KEY</c>, or the plaintext of an encrypted key.</summary>
    public static SshPrivateKey ParsePkcs8(ReadOnlyMemory<byte> der)
    {
        AsnReader outer = new(der, AsnEncodingRules.BER);
        AsnReader info = outer.ReadSequence();
        outer.ThrowIfNotEmpty();
        if (!info.TryReadInt32(out int version) || version is not (0 or 1))
        {
            throw new SshKeyFileException(SshKeyFile.Malformed);
        }

        AsnReader algorithm = info.ReadSequence();
        switch (algorithm.ReadObjectIdentifier())
        {
            case RsaEncryption:
                // The privateKey field is the PKCS#1 structure, so RSA has one path whichever way it arrives.
                return info.TryReadPrimitiveOctetString(out ReadOnlyMemory<byte> rsaKey)
                    ? ParsePkcs1(rsaKey)
                    : throw new SshKeyFileException(SshKeyFile.Malformed);
            case EcPublicKey:
                (NistCurve curve, bool named) = ReadCurve(algorithm);
                algorithm.ThrowIfNotEmpty();
                if (named)
                {
                    return ImportEc(der, curve);
                }

                // The privateKey field is the SEC 1 structure. Attributes or a separate public key aren't expected.
                if (!info.TryReadPrimitiveOctetString(out ReadOnlyMemory<byte> ecKey))
                {
                    throw new SshKeyFileException(SshKeyFile.Malformed);
                }

                info.ThrowIfNotEmpty();
                return ReadEcPrivateKey(ecKey, curve);
            case Ed25519:
                return ReadEd25519(info);
            default:
                throw new SshKeyFileException(SshKeyFile.UnsupportedKey);
        }
    }

    /// <summary>Reads <c>BEGIN ENCRYPTED PRIVATE KEY</c>.</summary>
    public static SshPrivateKey ParseEncryptedPkcs8(ReadOnlyMemory<byte> der, ReadOnlySpan<byte> passphrase)
    {
        AsnReader outer = new(der, AsnEncodingRules.BER);
        AsnReader info = outer.ReadSequence();
        outer.ThrowIfNotEmpty();
        Pbes2Parameters parameters = ReadParameters(info.ReadSequence());
        if (!info.TryReadPrimitiveOctetString(out ReadOnlyMemory<byte> ciphertext)
            || ciphertext.IsEmpty
            || ciphertext.Length % AesBlock != 0)
        {
            throw new SshKeyFileException(SshKeyFile.Malformed);
        }

        info.ThrowIfNotEmpty();
        if (passphrase.IsEmpty)
        {
            throw new SshKeyFileException(SshKeyFile.PassphraseRequired);
        }

        byte[] plaintext = new byte[ciphertext.Length];
        try
        {
            int length = Decrypt(parameters, passphrase, ciphertext.Span, plaintext);

            // There's no integrity check here. A wrong key shows up as bad padding or, rarely, as a bad structure.
            try
            {
                return ParsePkcs8(plaintext.AsMemory(0, length));
            }
            catch (Exception ex) when (SshKeyFile.IsBadKeyData(ex))
            {
                throw new SshKeyFileException(SshKeyFile.WrongPassphrase, ex);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private static int Decrypt(Pbes2Parameters parameters, ReadOnlySpan<byte> passphrase, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
    {
        Span<byte> key = stackalloc byte[parameters.KeyLength];
        try
        {
            Rfc2898DeriveBytes.Pbkdf2(passphrase, parameters.Salt.Span, key, parameters.Iterations, parameters.Hash);
            using Aes aes = Aes.Create();
            aes.SetKey(key);
            return aes.DecryptCbc(ciphertext, parameters.Iv.Span, plaintext, PaddingMode.PKCS7);
        }
        catch (CryptographicException ex)
        {
            throw new SshKeyFileException(SshKeyFile.WrongPassphrase, ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>Reads the AlgorithmIdentifier of an encrypted key, and refuses anything unknown or too costly.</summary>
    private static Pbes2Parameters ReadParameters(AsnReader algorithm)
    {
        if (algorithm.ReadObjectIdentifier() != Pbes2)
        {
            throw new SshKeyFileException(UnsupportedEncryption);
        }

        AsnReader parameters = algorithm.ReadSequence();
        AsnReader kdf = parameters.ReadSequence();
        AsnReader encryption = parameters.ReadSequence();
        if (kdf.ReadObjectIdentifier() != Pbkdf2)
        {
            throw new SshKeyFileException(UnsupportedEncryption);
        }

        int keyLength = encryption.ReadObjectIdentifier() switch
        {
            Aes128Cbc => 16,
            Aes192Cbc => 24,
            Aes256Cbc => 32,
            _ => throw new SshKeyFileException(UnsupportedEncryption),
        };

        if (!encryption.TryReadPrimitiveOctetString(out ReadOnlyMemory<byte> iv) || iv.Length != AesBlock)
        {
            throw new SshKeyFileException(SshKeyFile.Malformed);
        }

        AsnReader pbkdf2 = kdf.ReadSequence();
        if (!pbkdf2.TryReadPrimitiveOctetString(out ReadOnlyMemory<byte> salt) || salt.IsEmpty)
        {
            throw new SshKeyFileException(SshKeyFile.Malformed);
        }

        // A count too large for an int is too large for the limit, so both get the same refusal.
        if (!pbkdf2.TryReadInt32(out int iterations) || iterations > MaxPbkdf2Iterations)
        {
            throw new SshKeyFileException($"The key file asks for more than {MaxPbkdf2Iterations} PBKDF2 iterations, which isn't accepted. Convert it to OpenSSH's format with: ssh-keygen -p -f <file>");
        }

        if (iterations < 1)
        {
            throw new SshKeyFileException(SshKeyFile.Malformed);
        }

        // Optional fields: the key length if it's stated, then the PRF, which defaults to HMAC-SHA-1.
        if (pbkdf2.HasData && pbkdf2.PeekTag().HasSameClassAndValue(Asn1Tag.Integer)
            && (!pbkdf2.TryReadInt32(out int statedLength) || statedLength != keyLength))
        {
            throw new SshKeyFileException(SshKeyFile.Malformed);
        }

        HashAlgorithmName hash = HashAlgorithmName.SHA1;
        if (pbkdf2.HasData)
        {
            hash = pbkdf2.ReadSequence().ReadObjectIdentifier() switch
            {
                HmacSha1 => HashAlgorithmName.SHA1,
                HmacSha256 => HashAlgorithmName.SHA256,
                HmacSha384 => HashAlgorithmName.SHA384,
                HmacSha512 => HashAlgorithmName.SHA512,
                _ => throw new SshKeyFileException(UnsupportedEncryption),
            };
        }

        return new Pbes2Parameters(salt, iterations, hash, keyLength, iv);
    }

    /// <summary>
    /// Reads RSAPrivateKey: version, n, e, d, p, q, dp, dq, iqmp, and checks those values belong together. The reads
    /// point into the DER, so they make no copies of the private values. Version 1 is multi-prime, which SSH never uses.
    /// </summary>
    private static void EnsureRsaValuesConsistent(ReadOnlyMemory<byte> der)
    {
        AsnReader outer = new(der, AsnEncodingRules.BER);
        AsnReader key = outer.ReadSequence();
        outer.ThrowIfNotEmpty();
        if (!key.TryReadInt32(out int version) || version != 0)
        {
            throw new SshKeyFileException(SshKeyFile.UnsupportedKey);
        }

        ReadOnlySpan<byte> n = ReadPositive(key);
        ReadOnlySpan<byte> e = ReadPositive(key);
        ReadOnlySpan<byte> d = ReadPositive(key);
        ReadOnlySpan<byte> p = ReadPositive(key);
        ReadOnlySpan<byte> q = ReadPositive(key);
        ReadOnlySpan<byte> dp = ReadPositive(key);
        ReadOnlySpan<byte> dq = ReadPositive(key);
        ReadOnlySpan<byte> iqmp = ReadPositive(key);
        key.ThrowIfNotEmpty();
        RsaKeyValues.EnsureConsistent(n, e, d, p, q, dp, dq, iqmp);
    }

    private static ReadOnlySpan<byte> ReadPositive(AsnReader reader)
    {
        ReadOnlySpan<byte> value = reader.ReadIntegerBytes().Span;
        if ((value[0] & 0x80) != 0)
        {
            throw new SshKeyFileException(SshKeyFile.Malformed);
        }

        return value;
    }

    private static EcdsaPrivateKey ImportEc(ReadOnlyMemory<byte> der, NistCurve curve)
    {
        ECDsa ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportPkcs8PrivateKey(der.Span, out int read);
            EnsureAllRead(read, der);
        }
        catch
        {
            ecdsa.Dispose();
            throw;
        }

        return EcdsaPrivateKey.Adopt(curve, ecdsa);
    }

    /// <summary>RFC 8410: the privateKey field is an OCTET STRING that wraps another, the 32-byte seed.</summary>
    private static Ed25519PrivateKey ReadEd25519(AsnReader info)
    {
        if (!info.TryReadPrimitiveOctetString(out ReadOnlyMemory<byte> wrapped))
        {
            throw new SshKeyFileException(SshKeyFile.Malformed);
        }

        AsnReader inner = new(wrapped, AsnEncodingRules.BER);
        if (!inner.TryReadPrimitiveOctetString(out ReadOnlyMemory<byte> seed) || seed.Length != Ed25519SeedLength)
        {
            throw new SshKeyFileException(SshKeyFile.Malformed);
        }

        inner.ThrowIfNotEmpty();
        return Ed25519PrivateKey.FromSeed(seed.Span);
    }

    /// <summary>
    /// Reads ECParameters: a named curve's OID, or the curve spelled out (SpecifiedECDomain). ssh-keygen on macOS writes
    /// the second, and OpenSSH reads it when it is one of its curves. Spelled-out values are only compared with the
    /// known curves, never used, and the key is then imported on the named curve.
    /// </summary>
    private static (NistCurve Curve, bool Named) ReadCurve(AsnReader parameters)
    {
        Asn1Tag tag = parameters.PeekTag();
        if (tag.HasSameClassAndValue(Asn1Tag.ObjectIdentifier))
        {
            return (CurveFromOid(parameters.ReadObjectIdentifier()), true);
        }

        if (!tag.HasSameClassAndValue(Asn1Tag.Sequence))
        {
            // implicitCurve (NULL) names no curve at all.
            throw new SshKeyFileException(SshKeyFile.UnsupportedKey);
        }

        // SpecifiedECDomain: version, fieldID, curve, base, order, cofactor. A hash or anything later isn't accepted.
        AsnReader domain = parameters.ReadSequence();
        if (!domain.TryReadInt32(out int version) || version is < 1 or > 3)
        {
            throw new SshKeyFileException(SshKeyFile.UnsupportedKey);
        }

        AsnReader field = domain.ReadSequence();
        if (field.ReadObjectIdentifier() != PrimeField)
        {
            throw new SshKeyFileException(SshKeyFile.UnsupportedKey);
        }

        ReadOnlyMemory<byte> prime = field.ReadIntegerBytes();
        field.ThrowIfNotEmpty();

        // Curve: a, b and an optional seed. The seed only says how the curve was made.
        AsnReader coefficients = domain.ReadSequence();
        if (!coefficients.TryReadPrimitiveOctetString(out ReadOnlyMemory<byte> a)
            || !coefficients.TryReadPrimitiveOctetString(out ReadOnlyMemory<byte> b)
            || !domain.TryReadPrimitiveOctetString(out ReadOnlyMemory<byte> generator))
        {
            throw new SshKeyFileException(SshKeyFile.Malformed);
        }

        if (coefficients.HasData)
        {
            _ = coefficients.ReadBitString(out _);
        }

        coefficients.ThrowIfNotEmpty();
        ReadOnlyMemory<byte> order = domain.ReadIntegerBytes();
        if (domain.HasData && (!domain.TryReadInt32(out int cofactor) || cofactor != 1))
        {
            throw new SshKeyFileException(SshKeyFile.UnsupportedKey);
        }

        domain.ThrowIfNotEmpty();
        NistCurve curve = NistCurve.FromExplicitParameters(prime.Span, a.Span, b.Span, generator.Span, order.Span)
            ?? throw new SshKeyFileException(SshKeyFile.UnsupportedKey);
        return (curve, false);
    }

    /// <summary>
    /// Reads ECPrivateKey on a curve already known, and imports it on that named curve. The public key must be
    /// there, on the curve, and match the scalar; any curve the structure repeats must be the same one.
    /// </summary>
    private static EcdsaPrivateKey ReadEcPrivateKey(ReadOnlyMemory<byte> der, NistCurve curve)
    {
        AsnReader outer = new(der, AsnEncodingRules.BER);
        AsnReader key = outer.ReadSequence();
        outer.ThrowIfNotEmpty();
        if (!key.TryReadInt32(out int version) || version != 1
            || !key.TryReadPrimitiveOctetString(out ReadOnlyMemory<byte> scalar)
            || scalar.IsEmpty
            || scalar.Length > curve.CoordinateLength)
        {
            throw new SshKeyFileException(SshKeyFile.Malformed);
        }

        if (key.HasData && key.PeekTag() == CurveTag)
        {
            AsnReader parameters = key.ReadSequence(CurveTag);
            if (ReadCurve(parameters).Curve != curve)
            {
                throw new SshKeyFileException(SshKeyFile.Mismatch);
            }

            parameters.ThrowIfNotEmpty();
        }

        if (!key.HasData || key.PeekTag() != PublicKeyTag)
        {
            throw new SshKeyFileException(SshKeyFile.Malformed);
        }

        AsnReader publicKey = key.ReadSequence(PublicKeyTag);
        if (!publicKey.TryReadPrimitiveBitString(out int unusedBits, out ReadOnlyMemory<byte> encodedPoint)
            || unusedBits != 0
            || !curve.TryDecodePoint(encodedPoint.Span, out ECPoint point))
        {
            throw new SshKeyFileException(SshKeyFile.Malformed);
        }

        publicKey.ThrowIfNotEmpty();
        key.ThrowIfNotEmpty();

        // The platform refuses a scalar that isn't the point's, as it does for OpenSSH's own format.
        byte[] d = new byte[curve.CoordinateLength];
        scalar.Span.CopyTo(d.AsSpan(d.Length - scalar.Length));
        try
        {
            return EcdsaPrivateKey.Adopt(curve, ECDsa.Create(new ECParameters { Curve = curve.Curve, Q = point, D = d }));
        }
        catch (CryptographicException ex)
        {
            throw new SshKeyFileException(SshKeyFile.Malformed, ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(d);
        }
    }

    private static NistCurve CurveFromOid(string oid) => oid switch
    {
        P256 => NistCurve.P256,
        P384 => NistCurve.P384,
        P521 => NistCurve.P521,
        _ => throw new SshKeyFileException(SshKeyFile.UnsupportedKey),
    };

    private static void EnsureAllRead(int read, ReadOnlyMemory<byte> der)
    {
        if (read != der.Length)
        {
            throw new SshKeyFileException(SshKeyFile.Malformed);
        }
    }

    private readonly record struct Pbes2Parameters(ReadOnlyMemory<byte> Salt, int Iterations, HashAlgorithmName Hash, int KeyLength, ReadOnlyMemory<byte> Iv);
}

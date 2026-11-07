using System;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Crypto.Keys;

/// <summary>
/// An <c>ssh-rsa</c> public key, for <c>rsa-sha2-256</c> and <c>rsa-sha2-512</c> (RFC 8332). <see cref="SupportsSignatureAlgorithm"/>
/// and <see cref="Verify"/> never take SHA-1, so no generic path (certificates, the agent, a CA) can accept it. The legacy
/// <c>ssh-rsa</c> signature has its own method, <see cref="VerifyLegacySha1"/>, called only where it was negotiated.
/// </summary>
internal sealed class RsaPublicKey : SshPublicKey
{
    /// <summary>The key type.</summary>
    public const string Name = "ssh-rsa";

    /// <summary>The SHA-512 signature algorithm.</summary>
    public const string Sha512 = "rsa-sha2-512";

    /// <summary>The SHA-256 signature algorithm.</summary>
    public const string Sha256 = "rsa-sha2-256";

    /// <summary>The smallest modulus accepted, in bits.</summary>
    public const int MinimumModulusBits = 2048;

    private readonly byte[] _exponent;
    private readonly byte[] _modulus;
    private readonly byte[] _blob;

    private RsaPublicKey(byte[] exponent, byte[] modulus, byte[] blob)
    {
        _exponent = exponent;
        _modulus = modulus;
        _blob = blob;
    }

    /// <inheritdoc/>
    public override string KeyType => Name;

    /// <inheritdoc/>
    public override ReadOnlyMemory<byte> Blob => _blob;

    /// <summary>Makes a key from big-endian magnitudes, checking them as peer data.</summary>
    /// <param name="exponent">The public exponent.</param>
    /// <param name="modulus">The modulus.</param>
    /// <remarks>
    /// The blob is always rebuilt in canonical form, without redundant leading zeros (RFC 4251 section 5). OpenSSH accepts
    /// such zeros on the wire and compares keys by value, so this does too: one key has one <see cref="Blob"/>, and
    /// equality, known_hosts matching, <c>@revoked</c> and fingerprints can not be dodged by re-encoding. Code that needs
    /// the peer's exact bytes, as the exchange hash does, keeps what it received.
    /// </remarks>
    public static RsaPublicKey FromParameters(ReadOnlySpan<byte> exponent, ReadOnlySpan<byte> modulus)
    {
        exponent = TrimLeadingZeros(exponent);
        modulus = TrimLeadingZeros(modulus);
        long modulusBits = modulus.IsEmpty ? 0 : new BigInteger(modulus, isUnsigned: true, isBigEndian: true).GetBitLength();
        if (modulusBits < MinimumModulusBits)
        {
            throw new SshProtocolException("The peer's RSA key is smaller than 2048 bits, so it isn't accepted. Replace the key with a larger one.");
        }

        // An exponent of 1 would make every value a valid signature of itself, and RSA moduli and exponents are odd.
        // Real exponents are small, and a huge one would make each verification take a very long time.
        const int MaxExponentLength = 8;
        bool exponentTooSmall = exponent.IsEmpty || (exponent.Length == 1 && exponent[0] < 3);
        if (exponentTooSmall || (exponent[^1] & 1) == 0 || (modulus[^1] & 1) == 0 || exponent.Length > MaxExponentLength)
        {
            throw new SshProtocolException("The peer sent an invalid RSA public key.");
        }

        SshWriter writer = new(modulus.Length + exponent.Length + 32);
        try
        {
            writer.WriteUtf8String(Name);
            writer.WriteMPInt(exponent);
            writer.WriteMPInt(modulus);
            byte[] blob = writer.ToArray();
            RsaPublicKey key = new(exponent.ToArray(), modulus.ToArray(), blob);
            key.EnsurePlatformAccepts();
            return key;
        }
        finally
        {
            writer.Dispose();
        }
    }

    /// <summary>
    /// Gives the canonical form of an <c>ssh-rsa</c> blob, or the input if it isn't one or can't be read. No other check
    /// is made, so a weak or odd key still gets one spelling. known_hosts lines go through this, so that a line spelled
    /// with redundant zeros means the same key as the canonical blob.
    /// </summary>
    public static byte[] Canonicalize(ReadOnlySpan<byte> blob)
    {
        try
        {
            SshReader reader = new(blob);
            if (reader.ReadUtf8String() != Name)
            {
                return blob.ToArray();
            }

            ReadOnlySpan<byte> exponent = reader.ReadMPInt();
            ReadOnlySpan<byte> modulus = reader.ReadMPInt();
            reader.EnsureEnd();
            SshWriter writer = new(modulus.Length + exponent.Length + 32);
            try
            {
                writer.WriteUtf8String(Name);
                writer.WriteMPInt(exponent);
                writer.WriteMPInt(modulus);
                return writer.ToArray();
            }
            finally
            {
                writer.Dispose();
            }
        }
        catch (SshProtocolException)
        {
            return blob.ToArray();
        }
    }

    /// <summary>Reads the body of a blob, after the key type.</summary>
    public static RsaPublicKey ParseBody(ref SshReader reader)
    {
        ReadOnlySpan<byte> exponent = reader.ReadMPInt();
        ReadOnlySpan<byte> modulus = reader.ReadMPInt();
        reader.EnsureEnd();
        return FromParameters(exponent, modulus);
    }

    /// <inheritdoc/>
    public override bool SupportsSignatureAlgorithm(string signatureAlgorithm) => signatureAlgorithm is Sha512 or Sha256;

    /// <inheritdoc/>
    public override bool Verify(string signatureAlgorithm, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signatureBlob)
    {
        if (!SupportsSignatureAlgorithm(signatureAlgorithm))
        {
            return false;
        }

        HashAlgorithmName hash = signatureAlgorithm == Sha512 ? HashAlgorithmName.SHA512 : HashAlgorithmName.SHA256;
        try
        {
            return VerifyCore(signatureAlgorithm, hash, data, signatureBlob);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>
    /// Checks a legacy <c>ssh-rsa</c> signature: PKCS#1 v1.5 with SHA-1. Only for a host key or user signature whose algorithm
    /// was negotiated from a list that names <c>ssh-rsa</c>. Returns false for a bad signature. Platforms whose crypto
    /// policy forbids SHA-1 signatures (RHEL 9 and later, at the DEFAULT policy) make the check itself throw, which becomes
    /// <see cref="SshNegotiationException"/> saying so.
    /// </summary>
    public bool VerifyLegacySha1(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signatureBlob)
    {
        try
        {
#pragma warning disable CA5350 // Legacy ssh-rsa, opt-in through SshAlgorithms.LegacyUnsafe or an explicit list only.
            return VerifyCore(LegacyAlgorithms.RsaSha1, HashAlgorithmName.SHA1, data, signatureBlob);
#pragma warning restore CA5350
        }
        catch (CryptographicException ex)
        {
            // Only the platform's own refusal of SHA-1 gets this message. A key or signature from the peer never does.
            if (LegacyRsa.PlatformAllowsSha1)
            {
                return false;
            }

            throw LegacyRsa.PolicyRefusal(ex);
        }
    }

    private bool VerifyCore(string signatureAlgorithm, HashAlgorithmName hash, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signatureBlob)
    {
        if (!SignatureBlob.TryRead(signatureAlgorithm, signatureBlob, out ReadOnlySpan<byte> signature) || signature.Length > _modulus.Length)
        {
            return false;
        }

        // Some peers drop leading zero bytes from the signature, and OpenSSH accepts that. The BCL wants the full width.
        byte[] padded = new byte[_modulus.Length];
        signature.CopyTo(padded.AsSpan(padded.Length - signature.Length));
        using RSA? rsa = CreateOrNull();
        return rsa is not null && rsa.VerifyData(data, padded, hash, RSASignaturePadding.Pkcs1);
    }

    /// <summary>Loads the key into the platform, or gives null if it won't. That has nothing to do with SHA-1.</summary>
    private RSA? CreateOrNull()
    {
        try
        {
            return RSA.Create(Parameters());
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    private static ReadOnlySpan<byte> TrimLeadingZeros(ReadOnlySpan<byte> value)
    {
        int start = 0;
        while (start < value.Length && value[start] == 0)
        {
            start++;
        }

        return value[start..];
    }

    private RSAParameters Parameters() => new() { Exponent = _exponent, Modulus = _modulus };

    private void EnsurePlatformAccepts()
    {
        try
        {
            using RSA rsa = RSA.Create(Parameters());
        }
        catch (CryptographicException ex)
        {
            throw new SshProtocolException("The peer sent an RSA public key the platform rejected.", ex);
        }
    }
}

/// <summary>An RSA private key. The BCL object holds and clears the key.</summary>
internal sealed class RsaPrivateKey : SshPrivateKey
{
    private static readonly IReadOnlyList<string> Algorithms = Array.AsReadOnly([RsaPublicKey.Sha512, RsaPublicKey.Sha256]);

    private readonly RSA _key;

    private RsaPrivateKey(RSA key)
    {
        _key = key;
        RSAParameters parameters = key.ExportParameters(includePrivateParameters: false);
        PublicKey = RsaPublicKey.FromParameters(parameters.Exponent, parameters.Modulus);
    }

    /// <inheritdoc/>
    public override SshPublicKey PublicKey { get; }

    /// <inheritdoc/>
    public override IReadOnlyList<string> SignatureAlgorithms => Algorithms;

    /// <summary>Makes a new random key. Fewer than 2048 bits isn't allowed.</summary>
    public static RsaPrivateKey Generate(int bits)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(bits, RsaPublicKey.MinimumModulusBits);
        return new RsaPrivateKey(RSA.Create(bits));
    }

    /// <summary>Makes a key that owns a loaded BCL key. If this throws, the BCL key has been disposed.</summary>
    public static RsaPrivateKey Adopt(RSA key)
    {
        try
        {
            return new RsaPrivateKey(key);
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    /// <inheritdoc/>
    public override byte[] Sign(string signatureAlgorithm, ReadOnlySpan<byte> data)
    {
        HashAlgorithmName hash = signatureAlgorithm switch
        {
            RsaPublicKey.Sha512 => HashAlgorithmName.SHA512,
            RsaPublicKey.Sha256 => HashAlgorithmName.SHA256,
            _ => throw new ArgumentException("This key can't make that signature algorithm.", nameof(signatureAlgorithm)),
        };

        return SignatureBlob.Write(signatureAlgorithm, _key.SignData(data, hash, RSASignaturePadding.Pkcs1));
    }

    /// <summary>
    /// Makes a legacy <c>ssh-rsa</c> signature (PKCS#1 v1.5 with SHA-1), only where <c>ssh-rsa</c> was negotiated. A platform
    /// crypto policy that forbids SHA-1 signatures becomes <see cref="SshNegotiationException"/> saying so.
    /// </summary>
    public byte[] SignLegacySha1(ReadOnlySpan<byte> data)
    {
        try
        {
#pragma warning disable CA5350 // Legacy ssh-rsa, opt-in through SshAlgorithms.LegacyUnsafe or an explicit list only.
            return SignatureBlob.Write(LegacyAlgorithms.RsaSha1, _key.SignData(data, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1));
#pragma warning restore CA5350
        }
        catch (CryptographicException ex) when (!LegacyRsa.PlatformAllowsSha1)
        {
            throw LegacyRsa.PolicyRefusal(ex);
        }
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _key.Dispose();
        }

        base.Dispose(disposing);
    }
}

/// <summary>
/// The legacy <c>ssh-rsa</c> signature algorithm, RSA with SHA-1. Each caller checks that it was negotiated, or that its own
/// options allow it, before it gets here: the key classes' generic signature methods never accept SHA-1.
/// </summary>
internal static class LegacyRsa
{
    /// <summary>Gets whether this private key can make an <c>ssh-rsa</c> signature: a plain RSA key, not a certificate.</summary>
    public static bool CanSign(SshPrivateKey key) => key is RsaPrivateKey;

    /// <summary>Gets whether this public key can check an <c>ssh-rsa</c> signature: a plain RSA key, not a certificate.</summary>
    public static bool CanVerify(SshPublicKey key) => key is RsaPublicKey;

    /// <summary>Signs with SHA-1. The key must pass <see cref="CanSign"/>.</summary>
    public static byte[] Sign(SshPrivateKey key, ReadOnlySpan<byte> data) => ((RsaPrivateKey)key).SignLegacySha1(data);

    /// <summary>Checks a SHA-1 signature. Returns false for any key that isn't plain RSA.</summary>
    public static bool Verify(SshPublicKey key, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signatureBlob) =>
        key is RsaPublicKey rsa && rsa.VerifyLegacySha1(data, signatureBlob);

    private static readonly Lazy<bool> Probe = new(ProbeSha1, LazyThreadSafetyMode.ExecutionAndPublication);

    private static readonly AsyncLocal<bool?> ProbeOverride = new();

    /// <summary>
    /// Gets whether the platform signs and checks RSA with SHA-1. It's tried once, on a key made here, so nothing
    /// from a peer can decide the answer.
    /// </summary>
    public static bool PlatformAllowsSha1 => ProbeOverride.Value ?? Probe.Value;

    /// <summary>Sets the answer of <see cref="PlatformAllowsSha1"/> for the current async flow, so tests can pretend.</summary>
    internal static void SetPlatformAllowsSha1ForTests(bool? value) => ProbeOverride.Value = value;

    /// <summary>Runs the probe itself, whatever was set for tests.</summary>
    internal static bool ProbeSha1()
    {
        try
        {
            using RSA rsa = RSA.Create(RsaPublicKey.MinimumModulusBits);
            byte[] data = [1, 2, 3];
#pragma warning disable CA5350 // Legacy ssh-rsa, opt-in through SshAlgorithms.LegacyUnsafe or an explicit list only.
            byte[] signature = rsa.SignData(data, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
            return rsa.VerifyData(data, signature, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
#pragma warning restore CA5350
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>The failure when the platform refuses SHA-1 signatures. It carries no data, only what to do.</summary>
    public static SshNegotiationException PolicyRefusal(CryptographicException inner) => new(
        "The platform refused an ssh-rsa (RSA with SHA-1) signature. Its crypto policy probably forbids SHA-1 signatures, as RHEL 9 and later do by default. "
        + "Upgrade the peer to rsa-sha2-256 or rsa-sha2-512, or allow SHA-1 in the system policy (on RHEL: update-crypto-policies --set DEFAULT:SHA1).",
        inner);
}

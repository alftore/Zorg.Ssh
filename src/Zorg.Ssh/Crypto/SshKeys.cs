using System;
using System.Collections.Generic;
using Zorg.Ssh.Crypto.Keys;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Crypto;

/// <summary>A public key in SSH form. Instances are immutable, and made from wire blobs by <c>SshPublicKey.Parse</c>.</summary>
internal abstract class SshPublicKey
{
    /// <summary>Gets the key type in the blob, for example <c>ssh-ed25519</c> or <c>ssh-rsa</c>.</summary>
    public abstract string KeyType { get; }

    /// <summary>Gets the key in SSH wire form, the <c>K_S</c> or public key blob.</summary>
    public abstract ReadOnlyMemory<byte> Blob { get; }

    /// <summary>Gets whether this key can check signatures made with the given algorithm name.</summary>
    public abstract bool SupportsSignatureAlgorithm(string signatureAlgorithm);

    /// <summary>
    /// Checks a signature blob: <c>string algorithm</c>, <c>string signature</c>. Returns false for any bad
    /// signature, including a malformed one, or one whose algorithm isn't <paramref name="signatureAlgorithm"/>.
    /// It never throws because of the blob's contents.
    /// </summary>
    public abstract bool Verify(string signatureAlgorithm, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signatureBlob);

    /// <summary>
    /// Reads a public key blob. Anything malformed or unsupported, including trailing data and an RSA modulus
    /// below 2048 bits, throws <see cref="SshProtocolException"/>.
    /// </summary>
    public static SshPublicKey Parse(ReadOnlySpan<byte> blob)
    {
        SshReader reader = new(blob);
        string keyType = reader.ReadUtf8String();
        if (keyType == Ed25519PublicKey.Name)
        {
            return Ed25519PublicKey.ParseBody(ref reader);
        }

        if (keyType == RsaPublicKey.Name)
        {
            return RsaPublicKey.ParseBody(ref reader, blob);
        }

        // The peer's text stays out of the message: it's unchecked, and messages reach logs.
        NistCurve curve = NistCurve.FromKeyType(keyType)
            ?? throw new SshProtocolException("The peer sent a public key of an unsupported type.");
        return EcdsaPublicKey.ParseBody(curve, ref reader);
    }
}

/// <summary>A private key that can sign, as a server host key or for publickey auth. Dispose it to zero the key.</summary>
internal abstract class SshPrivateKey : IDisposable
{
    /// <summary>Gets the matching public key.</summary>
    public abstract SshPublicKey PublicKey { get; }

    /// <summary>Gets the signature algorithms this key can make, most preferred first.</summary>
    public abstract IReadOnlyList<string> SignatureAlgorithms { get; }

    /// <summary>Signs data, and returns the signature blob: <c>string algorithm</c>, <c>string signature</c>.</summary>
    public abstract byte[] Sign(string signatureAlgorithm, ReadOnlySpan<byte> data);

    /// <summary>Makes a new random Ed25519 key.</summary>
    public static SshPrivateKey GenerateEd25519() => Ed25519PrivateKey.Generate();

    /// <summary>Makes a new random ECDSA key.</summary>
    /// <param name="curveKeyType">The key type, for example <c>ecdsa-sha2-nistp256</c>.</param>
    public static SshPrivateKey GenerateEcdsa(string curveKeyType) => EcdsaPrivateKey.Generate(
        NistCurve.FromKeyType(curveKeyType) ?? throw new ArgumentException("That isn't a supported ECDSA key type.", nameof(curveKeyType)));

    /// <summary>Makes a new random RSA key.</summary>
    /// <param name="bits">The modulus size, at least 2048.</param>
    public static SshPrivateKey GenerateRsa(int bits) => RsaPrivateKey.Generate(bits);

    /// <summary>Zeroes the key.</summary>
    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    /// <summary>Zeroes the key.</summary>
    protected virtual void Dispose(bool disposing)
    {
    }
}

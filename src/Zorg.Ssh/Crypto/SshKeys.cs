using System;
using System.Collections.Generic;

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

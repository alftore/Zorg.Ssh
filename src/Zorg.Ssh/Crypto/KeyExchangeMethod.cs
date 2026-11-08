using System;
using System.Security.Cryptography;

namespace Zorg.Ssh.Crypto;

/// <summary>
/// One run of a key exchange that follows the client-public, server-public shape: curve25519, ECDH and the
/// post-quantum hybrids. Create a new instance per exchange, and dispose it when the exchange ends so that
/// ephemeral secrets are zeroed (libssh CVE-2025-8277).
/// </summary>
internal abstract class KeyExchangeMethod : IDisposable
{
    /// <summary>Gets the hash used for the exchange hash and for key derivation.</summary>
    public abstract HashAlgorithmName HashAlgorithm { get; }

    /// <summary>
    /// Gets whether answering a client costs enough CPU to bound before login: finite-field Diffie-Hellman does
    /// (tens of milliseconds), elliptic-curve and ML-KEM exchanges don't (microseconds).
    /// </summary>
    public virtual bool IsCostly => false;

    /// <summary>Client side: generates the ephemeral key, and returns the bytes of the <c>Q_C</c> string.</summary>
    public abstract byte[] CreateClientPublicValue();

    /// <summary>
    /// Client side: combines the server's <c>Q_S</c> with the ephemeral key, and returns the shared secret
    /// <c>K</c> already encoded for hashing: as an mpint, or as a string for the hybrids, with its length
    /// prefix. Invalid peer values throw <see cref="SshProtocolException"/>.
    /// </summary>
    public abstract byte[] ClientComputeSharedSecret(ReadOnlySpan<byte> serverPublicValue);

    /// <summary>
    /// Server side: answers the client's <c>Q_C</c>. Returns <c>Q_S</c>, and sets <paramref name="encodedSharedSecret"/>
    /// to <c>K</c>, encoded as in <see cref="ClientComputeSharedSecret"/>. Invalid peer values throw
    /// <see cref="SshProtocolException"/>.
    /// </summary>
    public abstract byte[] ServerRespond(ReadOnlySpan<byte> clientPublicValue, out byte[] encodedSharedSecret);

    /// <summary>Hashes data with <see cref="HashAlgorithm"/>.</summary>
    public byte[] Hash(ReadOnlySpan<byte> data) => CryptographicOperations.HashData(HashAlgorithm, data);

    /// <summary>Zeroes ephemeral secrets.</summary>
    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    /// <summary>Zeroes ephemeral secrets.</summary>
    protected virtual void Dispose(bool disposing)
    {
    }
}

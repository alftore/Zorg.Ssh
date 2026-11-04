using System;

namespace Zorg.Ssh.Crypto.KeyExchange;

/// <summary>
/// The post-quantum half of a hybrid exchange, for one run. Implementations check nothing the hybrid already
/// checks: the lengths passed in are exact. Bad content throws <see cref="SshProtocolException"/>.
/// </summary>
internal abstract class KeyEncapsulation : IDisposable
{
    /// <summary>Gets the length of a public key.</summary>
    public abstract int PublicKeyLength { get; }

    /// <summary>Gets the length of a ciphertext.</summary>
    public abstract int CiphertextLength { get; }

    /// <summary>Client side: makes a key pair, keeps the private half, and returns the public key.</summary>
    public abstract byte[] GenerateKeyPair();

    /// <summary>Client side: returns the shared secret for a ciphertext.</summary>
    public abstract byte[] Decapsulate(ReadOnlySpan<byte> ciphertext);

    /// <summary>Server side: returns a new shared secret, and its ciphertext for the given public key.</summary>
    public abstract byte[] Encapsulate(ReadOnlySpan<byte> publicKey, out byte[] ciphertext);

    /// <summary>Drops the private key.</summary>
    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    /// <summary>Drops the private key.</summary>
    protected virtual void Dispose(bool disposing)
    {
    }
}

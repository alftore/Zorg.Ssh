using System;
using System.Security.Cryptography;
using Org.BouncyCastle.Math.EC.Rfc7748;

namespace Zorg.Ssh.Crypto.KeyExchange;

/// <summary>One ephemeral X25519 key. BouncyCastle only ever sees arrays owned here, so disposing really zeroes the key.</summary>
internal sealed class X25519Ephemeral : IDisposable
{
    /// <summary>The length of a public value, a private key and a shared secret.</summary>
    public const int KeyLength = 32;

    private readonly byte[] _privateKey;

    private X25519Ephemeral(byte[] privateKey)
    {
        _privateKey = privateKey;
        PublicKey = new byte[KeyLength];
        X25519.ScalarMultBase(_privateKey, 0, PublicKey, 0);
    }

    /// <summary>Gets the public value.</summary>
    public byte[] PublicKey { get; }

    /// <summary>Makes a new random key. The scalar is clamped inside every BouncyCastle operation.</summary>
    public static X25519Ephemeral Generate() => new(RandomNumberGenerator.GetBytes(KeyLength));

    /// <summary>Makes a key from known bytes, for known-answer tests only.</summary>
    public static X25519Ephemeral FromPrivateKey(ReadOnlySpan<byte> privateKey) => new(privateKey.ToArray());

    /// <summary>
    /// Returns the 32 raw bytes of the agreement with a peer's public value. A value of the wrong length, or
    /// one that gives the all-zero secret (RFC 8731 section 3), throws <see cref="SshProtocolException"/>.
    /// </summary>
    public byte[] Agree(ReadOnlySpan<byte> peerPublicKey)
    {
        if (peerPublicKey.Length != KeyLength)
        {
            throw new SshProtocolException("The peer sent an X25519 public value of the wrong length, so the key exchange failed.");
        }

        byte[] shared = new byte[KeyLength];
        if (!X25519.CalculateAgreement(_privateKey, 0, peerPublicKey.ToArray(), 0, shared, 0))
        {
            throw new SshProtocolException("The peer sent a low-order X25519 public value, so the key exchange failed.");
        }

        return shared;
    }

    /// <summary>Zeroes the private key.</summary>
    public void Dispose() => CryptographicOperations.ZeroMemory(_privateKey);
}

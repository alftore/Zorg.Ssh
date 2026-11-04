using System;
using System.Security.Cryptography;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Crypto.KeyExchange;

/// <summary>Encodes the shared secret <c>K</c> as it is fed to the exchange hash and key derivation.</summary>
internal static class SharedSecretEncoding
{
    /// <summary>Encodes a big-endian unsigned magnitude as an mpint.</summary>
    public static byte[] EncodeMPInt(ReadOnlySpan<byte> magnitude)
    {
        SshWriter writer = new(magnitude.Length + 5);
        try
        {
            writer.WriteMPInt(magnitude);
            return writer.ToArray();
        }
        finally
        {
            writer.Dispose();
        }
    }

    /// <summary>
    /// Makes the hybrid <c>K</c>: the hash of the KEM secret followed by the X25519 secret, encoded as a
    /// string (RFC 10042 section 2.4, RFC 9941 section 3).
    /// </summary>
    public static byte[] EncodeHybrid(HashAlgorithmName hash, ReadOnlySpan<byte> kemSecret, ReadOnlySpan<byte> x25519Secret)
    {
        byte[] input = new byte[kemSecret.Length + x25519Secret.Length];
        byte[]? digest = null;
        SshWriter writer = new(72);
        try
        {
            kemSecret.CopyTo(input);
            x25519Secret.CopyTo(input.AsSpan(kemSecret.Length));
            digest = CryptographicOperations.HashData(hash, input);
            writer.WriteBinary(digest);
            return writer.ToArray();
        }
        finally
        {
            writer.Dispose();
            CryptographicOperations.ZeroMemory(input);
            CryptographicOperations.ZeroMemory(digest);
        }
    }
}

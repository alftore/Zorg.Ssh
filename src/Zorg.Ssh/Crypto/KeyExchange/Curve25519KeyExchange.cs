using System;
using System.Security.Cryptography;

namespace Zorg.Ssh.Crypto.KeyExchange;

/// <summary><c>curve25519-sha256</c> and its <c>@libssh.org</c> alias (RFC 8731).</summary>
internal sealed class Curve25519KeyExchange : KeyExchangeMethod
{
    private X25519Ephemeral? _key;
    private bool _started;

    /// <summary>Creates the exchange. A given key is for known-answer tests, and this instance then owns it.</summary>
    public Curve25519KeyExchange(X25519Ephemeral? key = null) => _key = key;

    /// <inheritdoc/>
    public override HashAlgorithmName HashAlgorithm => HashAlgorithmName.SHA256;

    /// <inheritdoc/>
    public override byte[] CreateClientPublicValue()
    {
        Start();
        _key ??= X25519Ephemeral.Generate();
        return (byte[])_key.PublicKey.Clone();
    }

    /// <inheritdoc/>
    public override byte[] ClientComputeSharedSecret(ReadOnlySpan<byte> serverPublicValue)
    {
        X25519Ephemeral key = _key is not null && _started
            ? _key
            : throw new InvalidOperationException("Create the client public value first.");

        byte[] encoded = Agree(key, serverPublicValue);
        ClearKey();
        return encoded;
    }

    /// <inheritdoc/>
    public override byte[] ServerRespond(ReadOnlySpan<byte> clientPublicValue, out byte[] encodedSharedSecret)
    {
        Start();
        _key ??= X25519Ephemeral.Generate();
        encodedSharedSecret = Agree(_key, clientPublicValue);
        byte[] publicValue = (byte[])_key.PublicKey.Clone();
        ClearKey();
        return publicValue;
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            ClearKey();
        }

        base.Dispose(disposing);
    }

    private static byte[] Agree(X25519Ephemeral key, ReadOnlySpan<byte> peerPublicValue)
    {
        byte[] secret = key.Agree(peerPublicValue);
        try
        {
            // RFC 8731 section 3.1: the output octets read as a big-endian integer, with no byte reversal.
            return SharedSecretEncoding.EncodeMPInt(secret);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    private void Start()
    {
        if (_started)
        {
            throw new InvalidOperationException("A key exchange instance runs one exchange only.");
        }

        _started = true;
    }

    private void ClearKey()
    {
        _key?.Dispose();
        _key = null;
    }
}

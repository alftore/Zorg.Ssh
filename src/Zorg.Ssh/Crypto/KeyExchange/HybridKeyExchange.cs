using System;
using System.Security.Cryptography;

namespace Zorg.Ssh.Crypto.KeyExchange;

/// <summary>
/// A post-quantum KEM combined with X25519: <c>mlkem768x25519-sha256</c> (RFC 10042) and
/// <c>sntrup761x25519-sha512</c> (RFC 9941). In both, the KEM part comes first on the wire and in the hash.
/// </summary>
internal sealed class HybridKeyExchange : KeyExchangeMethod
{
    private readonly KeyEncapsulation _kem;
    private readonly Func<byte[], bool>? _publicKeyCheck;
    private X25519Ephemeral? _key;
    private bool _started;

    /// <summary>Creates the exchange, which then owns <paramref name="kem"/>.</summary>
    /// <param name="kem">The post-quantum half.</param>
    /// <param name="hash">The exchange hash, which also combines the two secrets.</param>
    /// <param name="publicKeyCheck">An extra check of the client's KEM public key, for the server side.</param>
    public HybridKeyExchange(KeyEncapsulation kem, HashAlgorithmName hash, Func<byte[], bool>? publicKeyCheck = null)
    {
        _kem = kem;
        HashAlgorithm = hash;
        _publicKeyCheck = publicKeyCheck;
    }

    /// <inheritdoc/>
    public override HashAlgorithmName HashAlgorithm { get; }

    /// <inheritdoc/>
    public override byte[] CreateClientPublicValue()
    {
        Start();
        _key = X25519Ephemeral.Generate();
        byte[] kemPublicKey = _kem.GenerateKeyPair();
        return [.. kemPublicKey, .. _key.PublicKey];
    }

    /// <inheritdoc/>
    public override byte[] ClientComputeSharedSecret(ReadOnlySpan<byte> serverPublicValue)
    {
        X25519Ephemeral key = _key ?? throw new InvalidOperationException("Create the client public value first.");
        int ciphertextLength = _kem.CiphertextLength;
        if (serverPublicValue.Length != ciphertextLength + X25519Ephemeral.KeyLength)
        {
            throw new SshProtocolException("The peer sent a hybrid key exchange reply of the wrong length, so the key exchange failed.");
        }

        byte[] x25519Secret = key.Agree(serverPublicValue[ciphertextLength..]);
        byte[]? kemSecret = null;
        try
        {
            kemSecret = _kem.Decapsulate(serverPublicValue[..ciphertextLength]);
            byte[] encoded = SharedSecretEncoding.EncodeHybrid(HashAlgorithm, kemSecret, x25519Secret);
            ClearKeys();
            return encoded;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(x25519Secret);
            CryptographicOperations.ZeroMemory(kemSecret);
        }
    }

    /// <inheritdoc/>
    public override byte[] ServerRespond(ReadOnlySpan<byte> clientPublicValue, out byte[] encodedSharedSecret)
    {
        Start();
        int publicKeyLength = _kem.PublicKeyLength;
        if (clientPublicValue.Length != publicKeyLength + X25519Ephemeral.KeyLength)
        {
            throw new SshProtocolException("The peer sent a hybrid key exchange value of the wrong length, so the key exchange failed.");
        }

        ReadOnlySpan<byte> kemPublicKey = clientPublicValue[..publicKeyLength];
        if (_publicKeyCheck is not null && !_publicKeyCheck(kemPublicKey.ToArray()))
        {
            throw new SshProtocolException("The peer sent an invalid post-quantum public key, so the key exchange failed.");
        }

        _key = X25519Ephemeral.Generate();
        byte[] x25519Secret = _key.Agree(clientPublicValue[publicKeyLength..]);
        byte[]? kemSecret = null;
        try
        {
            kemSecret = _kem.Encapsulate(kemPublicKey, out byte[] ciphertext);
            encodedSharedSecret = SharedSecretEncoding.EncodeHybrid(HashAlgorithm, kemSecret, x25519Secret);
            byte[] reply = [.. ciphertext, .. _key.PublicKey];
            ClearKeys();
            return reply;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(x25519Secret);
            CryptographicOperations.ZeroMemory(kemSecret);
        }
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            ClearKeys();
        }

        base.Dispose(disposing);
    }

    private void Start()
    {
        if (_started)
        {
            throw new InvalidOperationException("A key exchange instance runs one exchange only.");
        }

        _started = true;
    }

    private void ClearKeys()
    {
        _key?.Dispose();
        _key = null;
        _kem.Dispose();
    }
}

using System;
using System.Security.Cryptography;
using Zorg.Ssh.Crypto.Keys;

namespace Zorg.Ssh.Crypto.KeyExchange;

/// <summary><c>ecdh-sha2-nistp256</c>, <c>-nistp384</c> and <c>-nistp521</c> (RFC 5656), on the BCL.</summary>
internal sealed class EcdhKeyExchange : KeyExchangeMethod
{
    private readonly NistCurve _curve;
    private ECDiffieHellman? _key;
    private bool _started;

    /// <summary>Creates the exchange. A given key is for known-answer tests, and this instance then owns it.</summary>
    public EcdhKeyExchange(NistCurve curve, ECDiffieHellman? key = null)
    {
        _curve = curve;
        _key = key;
    }

    /// <inheritdoc/>
    public override HashAlgorithmName HashAlgorithm => _curve.Hash;

    /// <inheritdoc/>
    public override byte[] CreateClientPublicValue()
    {
        Start();
        _key ??= ECDiffieHellman.Create(_curve.Curve);
        return _curve.EncodePoint(_key.ExportParameters(includePrivateParameters: false).Q);
    }

    /// <inheritdoc/>
    public override byte[] ClientComputeSharedSecret(ReadOnlySpan<byte> serverPublicValue)
    {
        ECDiffieHellman key = _key is not null && _started
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
        _key ??= ECDiffieHellman.Create(_curve.Curve);
        encodedSharedSecret = Agree(_key, clientPublicValue);
        byte[] publicValue = _curve.EncodePoint(_key.ExportParameters(includePrivateParameters: false).Q);
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

    private byte[] Agree(ECDiffieHellman key, ReadOnlySpan<byte> peerPublicValue)
    {
        if (!_curve.TryDecodePoint(peerPublicValue, out ECPoint point))
        {
            throw new SshProtocolException("The peer sent an invalid elliptic curve point, so the key exchange failed.");
        }

        byte[]? secret = null;
        try
        {
            using ECDiffieHellman peer = ECDiffieHellman.Create(new ECParameters { Curve = _curve.Curve, Q = point });
            using ECDiffieHellmanPublicKey peerKey = peer.PublicKey;
            secret = key.DeriveRawSecretAgreement(peerKey);
            return SharedSecretEncoding.EncodeMPInt(secret);
        }
        catch (CryptographicException ex)
        {
            throw new SshProtocolException("The peer sent an elliptic curve point the platform rejected, so the key exchange failed.", ex);
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

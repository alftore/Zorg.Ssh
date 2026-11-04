using System;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Security;

namespace Zorg.Ssh.Crypto.KeyExchange;

/// <summary>Picks the ML-KEM-768 implementation, and holds what both implementations share.</summary>
internal static class MlKem768
{
    /// <summary>The length of an encapsulation key.</summary>
    public const int PublicKeyLength = 1184;

    /// <summary>The length of a ciphertext.</summary>
    public const int CiphertextLength = 1088;

    private const int Modulus = 3329;
    private const int PolynomialBytes = 1152;

    /// <summary>The one place that chooses: BCL where the platform has it, otherwise BouncyCastle.</summary>
    public static KeyEncapsulation Create() => MLKem.IsSupported ? new BclMlKem768() : new BouncyCastleMlKem768();

    /// <summary>
    /// The FIPS 203 section 7.2 modulus check, which RFC 10042 requires of the server. Every 12-bit
    /// coefficient must be below q, which is the same as the decode and re-encode round trip in the standard.
    /// </summary>
    public static bool IsValidEncapsulationKey(ReadOnlySpan<byte> key)
    {
        if (key.Length != PublicKeyLength)
        {
            return false;
        }

        for (int i = 0; i < PolynomialBytes; i += 3)
        {
            int first = key[i] | ((key[i + 1] & 0x0F) << 8);
            int second = (key[i + 1] >> 4) | (key[i + 2] << 4);
            if (first >= Modulus || second >= Modulus)
            {
                return false;
            }
        }

        return true;
    }
}

/// <summary>ML-KEM-768 on BouncyCastle. Its private key object can't be zeroed from outside, only dropped.</summary>
internal sealed class BouncyCastleMlKem768 : KeyEncapsulation
{
    private readonly SecureRandom _random = new(new CryptoApiRandomGenerator());
    private AsymmetricKeyParameter? _privateKey;

    /// <inheritdoc/>
    public override int PublicKeyLength => MlKem768.PublicKeyLength;

    /// <inheritdoc/>
    public override int CiphertextLength => MlKem768.CiphertextLength;

    /// <inheritdoc/>
    public override byte[] GenerateKeyPair()
    {
        MLKemKeyPairGenerator generator = new();
        generator.Init(new MLKemKeyGenerationParameters(_random, MLKemParameters.ml_kem_768));
        AsymmetricCipherKeyPair pair = generator.GenerateKeyPair();
        _privateKey = pair.Private;
        return ((MLKemPublicKeyParameters)pair.Public).GetEncoded();
    }

    /// <inheritdoc/>
    public override byte[] Decapsulate(ReadOnlySpan<byte> ciphertext)
    {
        AsymmetricKeyParameter key = _privateKey ?? throw new InvalidOperationException("Generate the key pair first.");
        try
        {
            MLKemDecapsulator decapsulator = new(MLKemParameters.ml_kem_768);
            decapsulator.Init(key);
            byte[] secret = new byte[decapsulator.SecretLength];
            decapsulator.Decapsulate(ciphertext.ToArray(), 0, ciphertext.Length, secret, 0, secret.Length);
            return secret;
        }
#pragma warning disable CA1031 // BouncyCastle doesn't document what bad peer input throws, and a peer must only ever cause SshException.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            throw new SshProtocolException("The peer sent an ML-KEM ciphertext that couldn't be processed, so the key exchange failed.", ex);
        }
    }

    /// <inheritdoc/>
    public override byte[] Encapsulate(ReadOnlySpan<byte> publicKey, out byte[] ciphertext)
    {
        try
        {
            MLKemPublicKeyParameters key = MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, publicKey.ToArray());
            MLKemEncapsulator encapsulator = new(MLKemParameters.ml_kem_768);
            encapsulator.Init(new ParametersWithRandom(key, _random));
            ciphertext = new byte[encapsulator.EncapsulationLength];
            byte[] secret = new byte[encapsulator.SecretLength];
            encapsulator.Encapsulate(ciphertext, 0, ciphertext.Length, secret, 0, secret.Length);
            return secret;
        }
#pragma warning disable CA1031 // BouncyCastle doesn't document what bad peer input throws, and a peer must only ever cause SshException.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            throw new SshProtocolException("The peer sent an ML-KEM key that couldn't be processed, so the key exchange failed.", ex);
        }
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        _privateKey = null;
        base.Dispose(disposing);
    }
}

/// <summary>ML-KEM-768 on the BCL. Not run on the development machine, where <see cref="MLKem.IsSupported"/> is false.</summary>
internal sealed class BclMlKem768 : KeyEncapsulation
{
    private MLKem? _key;

    /// <inheritdoc/>
    public override int PublicKeyLength => MlKem768.PublicKeyLength;

    /// <inheritdoc/>
    public override int CiphertextLength => MlKem768.CiphertextLength;

    /// <inheritdoc/>
    public override byte[] GenerateKeyPair()
    {
        _key = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
        return _key.ExportEncapsulationKey();
    }

    /// <inheritdoc/>
    public override byte[] Decapsulate(ReadOnlySpan<byte> ciphertext)
    {
        MLKem key = _key ?? throw new InvalidOperationException("Generate the key pair first.");
        byte[] secret = new byte[MLKemAlgorithm.MLKem768.SharedSecretSizeInBytes];
        try
        {
            key.Decapsulate(ciphertext, secret);
            return secret;
        }
        catch (CryptographicException ex)
        {
            throw new SshProtocolException("The peer sent an ML-KEM ciphertext that couldn't be processed, so the key exchange failed.", ex);
        }
    }

    /// <inheritdoc/>
    public override byte[] Encapsulate(ReadOnlySpan<byte> publicKey, out byte[] ciphertext)
    {
        try
        {
            using MLKem key = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, publicKey);
            key.Encapsulate(out ciphertext, out byte[] secret);
            return secret;
        }
        catch (CryptographicException ex)
        {
            throw new SshProtocolException("The peer sent an ML-KEM key that couldn't be processed, so the key exchange failed.", ex);
        }
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _key?.Dispose();
            _key = null;
        }

        base.Dispose(disposing);
    }
}

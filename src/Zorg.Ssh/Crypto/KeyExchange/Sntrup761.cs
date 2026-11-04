using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Pqc.Crypto.NtruPrime;
using Org.BouncyCastle.Security;

namespace Zorg.Ssh.Crypto.KeyExchange;

/// <summary>Streamlined NTRU Prime sntrup761 on BouncyCastle. Its private key object can't be zeroed from outside, only dropped.</summary>
internal sealed class Sntrup761 : KeyEncapsulation
{
    private readonly SecureRandom _random = new(new CryptoApiRandomGenerator());
    private SNtruPrimePrivateKeyParameters? _privateKey;

    /// <inheritdoc/>
    public override int PublicKeyLength => 1158;

    /// <inheritdoc/>
    public override int CiphertextLength => 1039;

    /// <inheritdoc/>
    public override byte[] GenerateKeyPair()
    {
        SNtruPrimeKeyPairGenerator generator = new();
        generator.Init(new SNtruPrimeKeyGenerationParameters(_random, SNtruPrimeParameters.sntrup761));
        AsymmetricCipherKeyPair pair = generator.GenerateKeyPair();
        _privateKey = (SNtruPrimePrivateKeyParameters)pair.Private;
        return ((SNtruPrimePublicKeyParameters)pair.Public).GetEncoded();
    }

    /// <inheritdoc/>
    public override byte[] Decapsulate(ReadOnlySpan<byte> ciphertext)
    {
        SNtruPrimePrivateKeyParameters key = _privateKey ?? throw new InvalidOperationException("Generate the key pair first.");
        try
        {
            return new SNtruPrimeKemExtractor(key).ExtractSecret(ciphertext.ToArray());
        }
#pragma warning disable CA1031 // BouncyCastle doesn't document what bad peer input throws, and a peer must only ever cause SshException.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            throw new SshProtocolException("The peer sent an sntrup761 ciphertext that couldn't be processed, so the key exchange failed.", ex);
        }
    }

    /// <inheritdoc/>
    public override byte[] Encapsulate(ReadOnlySpan<byte> publicKey, out byte[] ciphertext)
    {
        try
        {
            SNtruPrimePublicKeyParameters key = new(SNtruPrimeParameters.sntrup761, publicKey.ToArray());
            using ISecretWithEncapsulation result = new SNtruPrimeKemGenerator(_random).GenerateEncapsulated(key);
            ciphertext = (byte[])result.GetEncapsulation().Clone();
            return (byte[])result.GetSecret().Clone();
        }
#pragma warning disable CA1031 // BouncyCastle doesn't document what bad peer input throws, and a peer must only ever cause SshException.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            throw new SshProtocolException("The peer sent an sntrup761 key that couldn't be processed, so the key exchange failed.", ex);
        }
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        _privateKey = null;
        base.Dispose(disposing);
    }
}

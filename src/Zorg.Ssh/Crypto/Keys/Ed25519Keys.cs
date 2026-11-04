using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Crypto.Keys;

/// <summary>An <c>ssh-ed25519</c> public key (RFC 8709).</summary>
internal sealed class Ed25519PublicKey : SshPublicKey
{
    /// <summary>The key type and signature algorithm name.</summary>
    public const string Name = "ssh-ed25519";

    private const int KeyLength = 32;
    private const int SignatureLength = 64;

    private readonly byte[] _key;
    private readonly byte[] _blob;

    private Ed25519PublicKey(byte[] key, byte[] blob)
    {
        _key = key;
        _blob = blob;
    }

    /// <inheritdoc/>
    public override string KeyType => Name;

    /// <inheritdoc/>
    public override ReadOnlyMemory<byte> Blob => _blob;

    /// <summary>Makes a key from its 32 raw bytes.</summary>
    public static Ed25519PublicKey FromRawKey(ReadOnlySpan<byte> key)
    {
        SshWriter writer = new(64);
        try
        {
            writer.WriteUtf8String(Name);
            writer.WriteBinary(key);
            return new Ed25519PublicKey(key.ToArray(), writer.ToArray());
        }
        finally
        {
            writer.Dispose();
        }
    }

    /// <summary>Reads the body of a blob, after the key type.</summary>
    public static Ed25519PublicKey ParseBody(ref SshReader reader)
    {
        ReadOnlySpan<byte> key = reader.ReadBinary();
        reader.EnsureEnd();

        // The full check also refuses small-order points, for which one signature can verify for many messages.
        if (key.Length != KeyLength || !Ed25519.ValidatePublicKeyFull(key.ToArray(), 0))
        {
            throw new SshProtocolException("The peer sent an invalid Ed25519 public key.");
        }

        return FromRawKey(key);
    }

    /// <inheritdoc/>
    public override bool SupportsSignatureAlgorithm(string signatureAlgorithm) => signatureAlgorithm == Name;

    /// <inheritdoc/>
    public override bool Verify(string signatureAlgorithm, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signatureBlob)
    {
        if (!SupportsSignatureAlgorithm(signatureAlgorithm)
            || !SignatureBlob.TryRead(Name, signatureBlob, out ReadOnlySpan<byte> signature)
            || signature.Length != SignatureLength)
        {
            return false;
        }

        byte[] message = data.ToArray();
        return Ed25519.Verify(signature.ToArray(), 0, _key, 0, message, 0, message.Length);
    }
}

/// <summary>An <c>ssh-ed25519</c> private key. BouncyCastle only sees the seed array owned here, so disposing zeroes it.</summary>
internal sealed class Ed25519PrivateKey : SshPrivateKey
{
    private const int SeedLength = 32;

    private static readonly IReadOnlyList<string> Algorithms = Array.AsReadOnly([Ed25519PublicKey.Name]);

    private readonly byte[] _seed;
    private bool _disposed;

    private Ed25519PrivateKey(byte[] seed)
    {
        _seed = seed;
        byte[] publicKey = new byte[SeedLength];
        Ed25519.GeneratePublicKey(_seed, 0, publicKey, 0);
        PublicKey = Ed25519PublicKey.FromRawKey(publicKey);
    }

    /// <inheritdoc/>
    public override SshPublicKey PublicKey { get; }

    /// <inheritdoc/>
    public override IReadOnlyList<string> SignatureAlgorithms => Algorithms;

    /// <summary>Makes a new random key.</summary>
    public static Ed25519PrivateKey Generate() => new(RandomNumberGenerator.GetBytes(SeedLength));

    /// <summary>Makes a key from a 32-byte seed.</summary>
    public static Ed25519PrivateKey FromSeed(ReadOnlySpan<byte> seed)
    {
        if (seed.Length != SeedLength)
        {
            throw new ArgumentException("An Ed25519 seed is 32 bytes.", nameof(seed));
        }

        return new Ed25519PrivateKey(seed.ToArray());
    }

    /// <inheritdoc/>
    public override byte[] Sign(string signatureAlgorithm, ReadOnlySpan<byte> data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (signatureAlgorithm != Ed25519PublicKey.Name)
        {
            throw new ArgumentException("This key can't make that signature algorithm.", nameof(signatureAlgorithm));
        }

        byte[] message = data.ToArray();
        byte[] signature = new byte[Ed25519.SignatureSize];
        Ed25519.Sign(_seed, 0, message, 0, message.Length, signature, 0);
        return SignatureBlob.Write(Ed25519PublicKey.Name, signature);
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        _disposed = true;
        CryptographicOperations.ZeroMemory(_seed);
        base.Dispose(disposing);
    }
}

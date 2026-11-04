using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Crypto.Keys;

/// <summary>An <c>ecdsa-sha2-nistp*</c> public key (RFC 5656).</summary>
internal sealed class EcdsaPublicKey : SshPublicKey
{
    private readonly NistCurve _curve;
    private readonly ECPoint _point;
    private readonly byte[] _blob;

    private EcdsaPublicKey(NistCurve curve, ECPoint point, byte[] blob)
    {
        _curve = curve;
        _point = point;
        _blob = blob;
    }

    /// <inheritdoc/>
    public override string KeyType => _curve.KeyType;

    /// <inheritdoc/>
    public override ReadOnlyMemory<byte> Blob => _blob;

    /// <summary>Makes a key from a point that has been checked, or that the BCL generated.</summary>
    public static EcdsaPublicKey FromPoint(NistCurve curve, ECPoint point)
    {
        SshWriter writer = new(256);
        try
        {
            writer.WriteUtf8String(curve.KeyType);
            writer.WriteUtf8String(curve.Identifier);
            writer.WriteBinary(curve.EncodePoint(point));
            return new EcdsaPublicKey(curve, point, writer.ToArray());
        }
        finally
        {
            writer.Dispose();
        }
    }

    /// <summary>Reads the body of a blob, after the key type.</summary>
    public static EcdsaPublicKey ParseBody(NistCurve curve, ref SshReader reader)
    {
        ReadOnlySpan<byte> identifier = reader.ReadBinary();
        ReadOnlySpan<byte> encodedPoint = reader.ReadBinary();
        reader.EnsureEnd();
        if (!Ascii.Equals(identifier, curve.Identifier))
        {
            throw new SshProtocolException("The peer sent an ECDSA public key whose curve doesn't match its type.");
        }

        if (!curve.TryDecodePoint(encodedPoint, out ECPoint point))
        {
            throw new SshProtocolException("The peer sent an invalid ECDSA public key.");
        }

        return FromPoint(curve, point);
    }

    /// <inheritdoc/>
    public override bool SupportsSignatureAlgorithm(string signatureAlgorithm) => signatureAlgorithm == _curve.KeyType;

    /// <inheritdoc/>
    public override bool Verify(string signatureAlgorithm, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signatureBlob)
    {
        if (!SupportsSignatureAlgorithm(signatureAlgorithm)
            || !SignatureBlob.TryRead(_curve.KeyType, signatureBlob, out ReadOnlySpan<byte> signature))
        {
            return false;
        }

        Span<byte> fixedSignature = stackalloc byte[2 * 66];
        fixedSignature = fixedSignature[..(2 * _curve.CoordinateLength)];
        if (!TryDecodeSignature(signature, fixedSignature))
        {
            return false;
        }

        try
        {
            using ECDsa ecdsa = ECDsa.Create(new ECParameters { Curve = _curve.Curve, Q = _point });
            return ecdsa.VerifyData(data, fixedSignature, _curve.Hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>Turns <c>mpint r, mpint s</c> into fixed-width <c>r || s</c>. Zero and oversized values fail.</summary>
    private bool TryDecodeSignature(ReadOnlySpan<byte> signature, Span<byte> destination)
    {
        try
        {
            SshReader reader = new(signature);
            ReadOnlySpan<byte> r = reader.ReadMPInt();
            ReadOnlySpan<byte> s = reader.ReadMPInt();
            reader.EnsureEnd();
            int size = _curve.CoordinateLength;
            if (r.IsEmpty || s.IsEmpty || r.Length > size || s.Length > size)
            {
                return false;
            }

            destination.Clear();
            r.CopyTo(destination[(size - r.Length)..]);
            s.CopyTo(destination[((2 * size) - s.Length)..]);
            return true;
        }
        catch (SshProtocolException)
        {
            return false;
        }
    }
}

/// <summary>An <c>ecdsa-sha2-nistp*</c> private key. The BCL object holds and clears the key.</summary>
internal sealed class EcdsaPrivateKey : SshPrivateKey
{
    private readonly NistCurve _curve;
    private readonly ECDsa _key;

    private EcdsaPrivateKey(NistCurve curve, ECDsa key)
    {
        _curve = curve;
        _key = key;
        SignatureAlgorithms = Array.AsReadOnly([curve.KeyType]);
        PublicKey = EcdsaPublicKey.FromPoint(curve, key.ExportParameters(includePrivateParameters: false).Q);
    }

    /// <inheritdoc/>
    public override SshPublicKey PublicKey { get; }

    /// <inheritdoc/>
    public override IReadOnlyList<string> SignatureAlgorithms { get; }

    /// <summary>Makes a new random key on a curve.</summary>
    public static EcdsaPrivateKey Generate(NistCurve curve) => new(curve, ECDsa.Create(curve.Curve));

    /// <inheritdoc/>
    public override byte[] Sign(string signatureAlgorithm, ReadOnlySpan<byte> data)
    {
        if (signatureAlgorithm != _curve.KeyType)
        {
            throw new ArgumentException("This key can't make that signature algorithm.", nameof(signatureAlgorithm));
        }

        byte[] signature = _key.SignData(data, _curve.Hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        int size = _curve.CoordinateLength;
        SshWriter writer = new(signature.Length + 16);
        try
        {
            writer.WriteMPInt(signature.AsSpan(0, size));
            writer.WriteMPInt(signature.AsSpan(size));
            return SignatureBlob.Write(_curve.KeyType, writer.Written);
        }
        finally
        {
            writer.Dispose();
        }
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _key.Dispose();
        }

        base.Dispose(disposing);
    }
}

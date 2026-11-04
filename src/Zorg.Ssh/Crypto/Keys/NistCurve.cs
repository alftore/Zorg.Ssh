using System;
using System.Numerics;
using System.Security.Cryptography;

namespace Zorg.Ssh.Crypto.Keys;

/// <summary>
/// One NIST curve, as ECDH and ECDSA both use it. Point validation is done here rather than left to the
/// platform, so that it's the same on every OS. Points are public, so this needn't run in constant time.
/// </summary>
internal sealed class NistCurve
{
    /// <summary>NIST P-256 with SHA-256.</summary>
    public static readonly NistCurve P256 = new(
        "nistp256",
        ECCurve.NamedCurves.nistP256,
        32,
        HashAlgorithmName.SHA256,
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");

    /// <summary>NIST P-384 with SHA-384.</summary>
    public static readonly NistCurve P384 = new(
        "nistp384",
        ECCurve.NamedCurves.nistP384,
        48,
        HashAlgorithmName.SHA384,
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
        "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef");

    /// <summary>NIST P-521 with SHA-512.</summary>
    public static readonly NistCurve P521 = new(
        "nistp521",
        ECCurve.NamedCurves.nistP521,
        66,
        HashAlgorithmName.SHA512,
        "01" + new string('f', 130), // 2^521 - 1
        "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00");

    private readonly BigInteger _prime;
    private readonly BigInteger _b;

    private NistCurve(string identifier, ECCurve curve, int coordinateLength, HashAlgorithmName hash, string primeHex, string bHex)
    {
        Identifier = identifier;
        KeyType = "ecdsa-sha2-" + identifier;
        Curve = curve;
        CoordinateLength = coordinateLength;
        Hash = hash;
        _prime = Unsigned(Convert.FromHexString(primeHex));
        _b = Unsigned(Convert.FromHexString(bHex));
    }

    /// <summary>Gets the curve name in key blobs, for example <c>nistp256</c>.</summary>
    public string Identifier { get; }

    /// <summary>Gets the key type, for example <c>ecdsa-sha2-nistp256</c>.</summary>
    public string KeyType { get; }

    /// <summary>Gets the curve for the BCL.</summary>
    public ECCurve Curve { get; }

    /// <summary>Gets the fixed length of one coordinate, in bytes.</summary>
    public int CoordinateLength { get; }

    /// <summary>Gets the hash SSH pairs with this curve.</summary>
    public HashAlgorithmName Hash { get; }

    /// <summary>Finds a curve by key type. Returns null if the name isn't known.</summary>
    public static NistCurve? FromKeyType(string keyType) => keyType switch
    {
        "ecdsa-sha2-nistp256" => P256,
        "ecdsa-sha2-nistp384" => P384,
        "ecdsa-sha2-nistp521" => P521,
        _ => null,
    };

    /// <summary>Encodes a point as <c>0x04 || X || Y</c>, with fixed-length coordinates.</summary>
    public byte[] EncodePoint(ECPoint point)
    {
        byte[] encoded = new byte[1 + (2 * CoordinateLength)];
        encoded[0] = 0x04;
        ReadOnlySpan<byte> x = point.X;
        ReadOnlySpan<byte> y = point.Y;
        x.CopyTo(encoded.AsSpan(1 + CoordinateLength - x.Length));
        y.CopyTo(encoded.AsSpan(encoded.Length - y.Length));
        return encoded;
    }

    /// <summary>
    /// Decodes an uncompressed point. Returns false unless the length is exact, both coordinates are below
    /// the prime, and the point is on the curve. These curves have cofactor 1 and the point at infinity has
    /// no uncompressed form, so this is the whole of the SEC 1 public key check that RFC 5656 asks for.
    /// </summary>
    public bool TryDecodePoint(ReadOnlySpan<byte> encoded, out ECPoint point)
    {
        point = default;
        if (encoded.Length != 1 + (2 * CoordinateLength) || encoded[0] != 0x04)
        {
            return false;
        }

        ReadOnlySpan<byte> xBytes = encoded.Slice(1, CoordinateLength);
        ReadOnlySpan<byte> yBytes = encoded[(1 + CoordinateLength)..];
        BigInteger x = Unsigned(xBytes);
        BigInteger y = Unsigned(yBytes);
        if (x >= _prime || y >= _prime)
        {
            return false;
        }

        // y^2 = x^3 - 3x + b (mod p). All three curves have a = -3.
        BigInteger left = y * y % _prime;
        BigInteger right = ((((x * x * x) - (3 * x) + _b) % _prime) + _prime) % _prime;
        if (left != right)
        {
            return false;
        }

        point = new ECPoint { X = xBytes.ToArray(), Y = yBytes.ToArray() };
        return true;
    }

    private static BigInteger Unsigned(ReadOnlySpan<byte> bigEndian) => new(bigEndian, isUnsigned: true, isBigEndian: true);
}

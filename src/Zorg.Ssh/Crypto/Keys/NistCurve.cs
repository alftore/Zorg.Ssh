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
        "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");

    /// <summary>NIST P-384 with SHA-384.</summary>
    public static readonly NistCurve P384 = new(
        "nistp384",
        ECCurve.NamedCurves.nistP384,
        48,
        HashAlgorithmName.SHA384,
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
        "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
        "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
        "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973");

    /// <summary>NIST P-521 with SHA-512.</summary>
    public static readonly NistCurve P521 = new(
        "nistp521",
        ECCurve.NamedCurves.nistP521,
        66,
        HashAlgorithmName.SHA512,
        "01" + new string('f', 130), // 2^521 - 1
        "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
        "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
        "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
        "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409");

    private readonly BigInteger _prime;
    private readonly BigInteger _b;
    private readonly BigInteger _order;
    private readonly byte[] _generator;

    // The generator and the order are SEC 2's. They are used only to recognise a curve a key file spells out in full.
    private NistCurve(string identifier, ECCurve curve, int coordinateLength, HashAlgorithmName hash, string primeHex, string bHex, string gxHex, string gyHex, string orderHex)
    {
        Identifier = identifier;
        KeyType = "ecdsa-sha2-" + identifier;
        Curve = curve;
        CoordinateLength = coordinateLength;
        Hash = hash;
        _prime = Unsigned(Convert.FromHexString(primeHex));
        _b = Unsigned(Convert.FromHexString(bHex));
        _order = Unsigned(Convert.FromHexString(orderHex));
        _generator = [0x04, .. Convert.FromHexString(gxHex), .. Convert.FromHexString(gyHex)];
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

    /// <summary>
    /// Finds the curve that explicit parameters describe: every value must be that curve's own. Returns null for any
    /// other curve, so the values from a file never become a curve themselves.
    /// </summary>
    /// <param name="prime">The field's prime, as a big-endian two's complement integer.</param>
    /// <param name="a">The coefficient a, as unsigned big-endian bytes.</param>
    /// <param name="b">The coefficient b, as unsigned big-endian bytes.</param>
    /// <param name="generator">The base point, encoded.</param>
    /// <param name="order">The base point's order, as a big-endian two's complement integer.</param>
    public static NistCurve? FromExplicitParameters(
        ReadOnlySpan<byte> prime, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> generator, ReadOnlySpan<byte> order)
    {
        BigInteger p = new(prime, isUnsigned: false, isBigEndian: true);
        BigInteger n = new(order, isUnsigned: false, isBigEndian: true);
        foreach (NistCurve curve in (ReadOnlySpan<NistCurve>)[P256, P384, P521])
        {
            if (p == curve._prime && Unsigned(a) == curve._prime - 3 && Unsigned(b) == curve._b && n == curve._order
                && generator.SequenceEqual(curve._generator))
            {
                return curve;
            }
        }

        return null;
    }

    /// <summary>Gets the prime, one coordinate long. For tests.</summary>
    internal byte[] Prime => Fixed(_prime);

    /// <summary>Gets the coefficient b, one coordinate long. For tests.</summary>
    internal byte[] B => Fixed(_b);

    /// <summary>Gets the base point as <c>0x04 || X || Y</c>. For tests.</summary>
    internal ReadOnlySpan<byte> Generator => _generator;

    /// <summary>Gets the order of the base point, as unsigned big-endian bytes. For tests.</summary>
    internal byte[] Order => _order.ToByteArray(isUnsigned: true, isBigEndian: true);

    private static BigInteger Unsigned(ReadOnlySpan<byte> bigEndian) => new(bigEndian, isUnsigned: true, isBigEndian: true);

    private byte[] Fixed(BigInteger value)
    {
        byte[] bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        byte[] padded = new byte[CoordinateLength];
        bytes.CopyTo(padded, CoordinateLength - bytes.Length);
        return padded;
    }
}

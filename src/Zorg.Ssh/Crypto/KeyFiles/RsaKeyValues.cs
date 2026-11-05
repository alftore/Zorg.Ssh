using System;
using System.Numerics;
using System.Security.Cryptography;
using Zorg.Ssh.Crypto.Keys;

namespace Zorg.Ssh.Crypto.KeyFiles;

/// <summary>
/// Arithmetic on the private values in an RSA key file, in buffers that can be zeroed. <c>BigInteger</c> would be
/// simpler, but its copies of the private exponent and primes couldn't be. Each value is a big-endian magnitude. This
/// runs a few times per load, so plain shift-and-subtract is fast enough, and its timing is only visible locally.
/// </summary>
internal static class RsaKeyValues
{
    /// <summary>
    /// Checks that the values in a file form one RSA key. A sign and verify can't stand in for this: Windows keeps only
    /// e, n, p and q and works out the rest, so it would pass a file whose d or CRT values are wrong, while OpenSSL
    /// uses them. And a signature made with a bad CRT value can give away a prime. So the check is made here, the same
    /// on every OS, before the platform sees the key.
    /// </summary>
    public static void EnsureConsistent(
        ReadOnlySpan<byte> n,
        ReadOnlySpan<byte> e,
        ReadOnlySpan<byte> d,
        ReadOnlySpan<byte> p,
        ReadOnlySpan<byte> q,
        ReadOnlySpan<byte> dp,
        ReadOnlySpan<byte> dq,
        ReadOnlySpan<byte> iqmp)
    {
        n = Trim(n);

        // First, because the cost of everything below grows with the square of these lengths.
        int modulusBits = n.IsEmpty ? 0 : ((n.Length - 1) * 8) + BitOperations.Log2(n[0]) + 1;
        if (modulusBits is < RsaPublicKey.MinimumModulusBits or > SshKeyFile.MaxRsaBits)
        {
            throw new SshKeyFileException(SshKeyFile.UnsupportedKey);
        }

        e = Trim(e);
        d = Trim(d);
        p = Trim(p);
        q = Trim(q);
        dp = Trim(dp);
        dq = Trim(dq);
        iqmp = Trim(iqmp);
        if (e.IsEmpty || d.IsEmpty || p.IsEmpty || q.IsEmpty || dp.IsEmpty || dq.IsEmpty || iqmp.IsEmpty
            || e.Length > n.Length || d.Length > n.Length || p.Length > n.Length || q.Length > n.Length
            || dp.Length > n.Length || dq.Length > n.Length || iqmp.Length > n.Length
            || (p[^1] & 1) == 0 || (q[^1] & 1) == 0)
        {
            throw new SshKeyFileException(SshKeyFile.Malformed);
        }

        if (!ProductEquals(p, q, n)
            || !IsInverse(iqmp, q, p)
            || !ExponentsAgree(e, d, dp, p)
            || !ExponentsAgree(e, d, dq, q))
        {
            throw new SshKeyFileException(SshKeyFile.Mismatch);
        }
    }

    /// <summary>Computes <paramref name="value"/> mod (<paramref name="oddPrime"/> - 1), as <paramref name="length"/> bytes.</summary>
    public static byte[] Residue(ReadOnlySpan<byte> value, ReadOnlySpan<byte> oddPrime, int length)
    {
        byte[] modulus = PredecessorOfOdd(oddPrime);
        byte[] reduced = Reduce(value, modulus);
        try
        {
            ReadOnlySpan<byte> trimmed = Trim(reduced);
            byte[] result = new byte[length];
            trimmed.CopyTo(result.AsSpan(length - trimmed.Length));
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(modulus);
            CryptographicOperations.ZeroMemory(reduced);
        }
    }

    private static bool ProductEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> expected)
    {
        byte[] product = Multiply(a, b);
        try
        {
            return Trim(product).SequenceEqual(expected);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(product);
        }
    }

    private static bool IsInverse(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> modulus)
    {
        byte[] product = Multiply(a, b);
        byte[] reduced = Reduce(product, modulus);
        try
        {
            return Trim(reduced) is [1];
        }
        finally
        {
            CryptographicOperations.ZeroMemory(product);
            CryptographicOperations.ZeroMemory(reduced);
        }
    }

    /// <summary>Checks that the CRT exponent is d mod (prime - 1), and that it inverts e there.</summary>
    private static bool ExponentsAgree(ReadOnlySpan<byte> e, ReadOnlySpan<byte> d, ReadOnlySpan<byte> crtExponent, ReadOnlySpan<byte> oddPrime)
    {
        byte[] modulus = PredecessorOfOdd(oddPrime);
        byte[] reduced = Reduce(d, modulus);
        try
        {
            return Trim(reduced).SequenceEqual(crtExponent) && IsInverse(e, crtExponent, modulus);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(modulus);
            CryptographicOperations.ZeroMemory(reduced);
        }
    }

    /// <summary>Subtracting one from an odd number only clears its low bit.</summary>
    private static byte[] PredecessorOfOdd(ReadOnlySpan<byte> oddValue)
    {
        byte[] result = oddValue.ToArray();
        result[^1] &= 0xFE;
        return result;
    }

    /// <summary>Schoolbook multiplication.</summary>
    private static byte[] Multiply(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        byte[] product = new byte[a.Length + b.Length];
        for (int i = a.Length - 1; i >= 0; i--)
        {
            int carry = 0;
            for (int j = b.Length - 1; j >= 0; j--)
            {
                int sum = product[i + j + 1] + (a[i] * b[j]) + carry;
                product[i + j + 1] = (byte)sum;
                carry = sum >> 8;
            }

            product[i] = (byte)carry;
        }

        return product;
    }

    /// <summary>Computes value mod modulus one bit at a time, as long division does. The result has a spare leading byte.</summary>
    private static byte[] Reduce(ReadOnlySpan<byte> value, ReadOnlySpan<byte> modulus)
    {
        // The spare byte holds the bit that doubling a remainder can carry out.
        byte[] wideModulus = new byte[modulus.Length + 1];
        modulus.CopyTo(wideModulus.AsSpan(1));
        byte[] remainder = new byte[wideModulus.Length];
        try
        {
            foreach (byte b in value)
            {
                for (int bit = 7; bit >= 0; bit--)
                {
                    int carry = (b >> bit) & 1;
                    for (int i = remainder.Length - 1; i >= 0; i--)
                    {
                        int doubled = (remainder[i] << 1) | carry;
                        remainder[i] = (byte)doubled;
                        carry = doubled >> 8;
                    }

                    if (remainder.AsSpan().SequenceCompareTo(wideModulus) >= 0)
                    {
                        Subtract(remainder, wideModulus);
                    }
                }
            }

            return remainder;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(remainder);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wideModulus);
        }
    }

    private static void Subtract(Span<byte> value, ReadOnlySpan<byte> amount)
    {
        int borrow = 0;
        for (int i = value.Length - 1; i >= 0; i--)
        {
            int difference = value[i] - amount[i] - borrow;
            value[i] = (byte)difference;
            borrow = difference < 0 ? 1 : 0;
        }
    }

    private static ReadOnlySpan<byte> Trim(ReadOnlySpan<byte> value)
    {
        int start = 0;
        while (start < value.Length && value[start] == 0)
        {
            start++;
        }

        return value[start..];
    }
}

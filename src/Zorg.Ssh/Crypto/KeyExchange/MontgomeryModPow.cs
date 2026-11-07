using System;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace Zorg.Ssh.Crypto.KeyExchange;

/// <summary>
/// Modular exponentiation for finite-field Diffie-Hellman, with a secret exponent. <see cref="BigInteger.ModPow"/> can't be
/// used for that: it isn't constant-time, and a <see cref="BigInteger"/> can't be zeroed.
/// </summary>
/// <remarks>
/// <para>
/// Numbers are little-endian arrays of 64-bit limbs, all as wide as the modulus. Multiplication is Montgomery's, in the
/// CIOS form (Koç, Acar and Kaliski, "Analyzing and comparing Montgomery multiplication algorithms", IEEE Micro 1996),
/// with a final subtraction that is always computed and then selected by mask. Exponentiation is a fixed 4-bit window,
/// left to right, over a fixed number of windows: four squarings and one multiplication per window, whatever its value.
/// The table entry for each window is read by scanning all 16 entries under a mask, so no memory address depends on the
/// exponent.
/// </para>
/// <para>
/// No branch or index depends on a secret: loop counts depend only on the modulus width and the public exponent length.
/// Carries and borrows are computed with bit operations rather than comparisons, so the JIT has nothing to branch on.
/// <see cref="Math.BigMul(ulong, ulong, out ulong)"/> is a single MUL or MULX on x64 and MUL plus UMULH on Arm64, which
/// take constant time on current cores. Every buffer that holds a secret is pinned, so the collector can't leave copies,
/// and is zeroed before the method returns.
/// </para>
/// <para>
/// The precomputation (R² mod p and −p⁻¹ mod 2⁶⁴) uses <see cref="BigInteger"/>, but only on the modulus, which is public.
/// </para>
/// </remarks>
internal sealed class MontgomeryModPow
{
    private const int WindowBits = 4;
    private const int TableSize = 1 << WindowBits;

    private readonly ulong[] _modulus;
    private readonly ulong[] _rSquared;
    private readonly ulong _inverse;

    /// <summary>Prepares a modulus, given as a big-endian magnitude. It must be odd and at least 128 bits.</summary>
    public MontgomeryModPow(ReadOnlySpan<byte> modulus)
    {
        BigInteger p = new(modulus, isUnsigned: true, isBigEndian: true);
        if (p.IsEven || p.GetBitLength() < 128)
        {
            throw new ArgumentException("The modulus must be odd and at least 128 bits.", nameof(modulus));
        }

        Limbs = (int)((p.GetBitLength() + 63) / 64);
        ByteLength = (int)((p.GetBitLength() + 7) / 8);
        _modulus = ToLimbs(p, Limbs);

        BigInteger r = BigInteger.One << (64 * Limbs);
        _rSquared = ToLimbs(r * r % p, Limbs);

        // −p⁻¹ mod 2⁶⁴, by Newton's iteration: each step doubles the correct low bits, and p₀ is its own inverse mod 8.
        ulong p0 = _modulus[0];
        ulong inverse = p0;
        for (int i = 0; i < 5; i++)
        {
            inverse *= 2 - (p0 * inverse);
        }

        _inverse = 0 - inverse;
    }

    /// <summary>Gets the width of every number, in 64-bit limbs.</summary>
    public int Limbs { get; }

    /// <summary>Gets the modulus length in bytes.</summary>
    public int ByteLength { get; }

    /// <summary>Gets the modulus, in limbs. Callers must not change it.</summary>
    public ReadOnlySpan<ulong> Modulus => _modulus;

    /// <summary>
    /// Computes <paramref name="value"/>^<paramref name="exponent"/> mod p into <paramref name="result"/>. The value must be
    /// below p, which the caller checks: it's public, either the generator or a peer's checked public value. The exponent is
    /// secret, has no bits set at or above <paramref name="exponentBits"/>, and <paramref name="exponentBits"/> is public.
    /// </summary>
    public void Pow(ReadOnlySpan<ulong> value, ReadOnlySpan<ulong> exponent, int exponentBits, Span<ulong> result)
    {
        int n = Limbs;
        if (value.Length != n || result.Length != n || exponentBits < 1 || exponent.Length * 64 < exponentBits)
        {
            throw new ArgumentException("The operands don't match the modulus.");
        }

        // One pinned workspace: the table, the accumulator, the selected entry, the value in Montgomery form, a raw one,
        // and the multiplication's n + 2 limbs.
        ulong[] work = GC.AllocateArray<ulong>(((TableSize + 4) * n) + n + 2, pinned: true);
        try
        {
            Span<ulong> table = work.AsSpan(0, TableSize * n);
            Span<ulong> accumulator = work.AsSpan(TableSize * n, n);
            Span<ulong> selected = work.AsSpan((TableSize + 1) * n, n);
            Span<ulong> montgomeryValue = work.AsSpan((TableSize + 2) * n, n);
            Span<ulong> rawOne = work.AsSpan((TableSize + 3) * n, n);
            Span<ulong> scratch = work.AsSpan((TableSize + 4) * n, n + 2);
            rawOne[0] = 1;

            // table[0] = R mod p (one, in Montgomery form), table[k] = value^k in Montgomery form.
            Multiply(rawOne, _rSquared, table[..n], scratch);
            Multiply(value, _rSquared, montgomeryValue, scratch);
            montgomeryValue.CopyTo(table.Slice(n, n));
            for (int k = 2; k < TableSize; k++)
            {
                Multiply(table.Slice((k - 1) * n, n), montgomeryValue, table.Slice(k * n, n), scratch);
            }

            table[..n].CopyTo(accumulator);
            int windows = (exponentBits + WindowBits - 1) / WindowBits;
            for (int w = windows - 1; w >= 0; w--)
            {
                for (int s = 0; s < WindowBits; s++)
                {
                    Multiply(accumulator, accumulator, accumulator, scratch);
                }

                // A window never straddles two limbs, because 64 is a multiple of 4. The position is public.
                int bit = w * WindowBits;
                ulong digit = (exponent[bit >> 6] >> (bit & 63)) & (TableSize - 1);
                Select(table, digit, selected, n);
                Multiply(accumulator, selected, accumulator, scratch);
            }

            // Out of Montgomery form: multiply by a raw one.
            Multiply(accumulator, rawOne, result, scratch);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(System.Runtime.InteropServices.MemoryMarshal.AsBytes(work.AsSpan()));
        }
    }

    /// <summary>Reads a public big-endian magnitude into limbs, as wide as the modulus. Returns false if it doesn't fit.</summary>
    public static bool TryReadLimbs(ReadOnlySpan<byte> bigEndian, Span<ulong> limbs)
    {
        limbs.Clear();
        int start = 0;
        while (start < bigEndian.Length && bigEndian[start] == 0)
        {
            start++;
        }

        // For public values only: the loop above stops at the first non-zero byte.
        ReadOnlySpan<byte> magnitude = bigEndian[start..];
        if (magnitude.Length > limbs.Length * 8)
        {
            return false;
        }

        for (int i = 0; i < magnitude.Length; i++)
        {
            int fromEnd = magnitude.Length - 1 - i;
            limbs[fromEnd >> 3] |= (ulong)magnitude[i] << (8 * (fromEnd & 7));
        }

        return true;
    }

    /// <summary>Writes limbs as a big-endian magnitude of exactly <paramref name="output"/>'s length, which must hold them all.</summary>
    public static void WriteBigEndian(ReadOnlySpan<ulong> limbs, Span<byte> output)
    {
        for (int i = 0; i < output.Length; i++)
        {
            int fromEnd = output.Length - 1 - i;
            int limb = fromEnd >> 3;
            output[i] = limb < limbs.Length ? (byte)(limbs[limb] >> (8 * (fromEnd & 7))) : (byte)0;
        }
    }

    /// <summary>Compares two numbers of equal width: -1, 0 or 1. For public values only: it returns at the first difference.</summary>
    public static int ComparePublic(ReadOnlySpan<ulong> left, ReadOnlySpan<ulong> right)
    {
        for (int i = left.Length - 1; i >= 0; i--)
        {
            if (left[i] != right[i])
            {
                return left[i] < right[i] ? -1 : 1;
            }
        }

        return 0;
    }

    /// <summary>Copies table entry <paramref name="digit"/> into <paramref name="selected"/>, reading every entry.</summary>
    private static void Select(ReadOnlySpan<ulong> table, ulong digit, Span<ulong> selected, int n)
    {
        selected.Clear();
        for (int k = 0; k < TableSize; k++)
        {
            ulong mask = EqualMask((ulong)k, digit);
            ReadOnlySpan<ulong> entry = table.Slice(k * n, n);
            for (int j = 0; j < n; j++)
            {
                selected[j] |= entry[j] & mask;
            }
        }
    }

    /// <summary>All ones if the two are equal, otherwise zero, with no branch.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong EqualMask(ulong a, ulong b)
    {
        ulong difference = a ^ b;

        // The top bit of d | -d is set exactly when d isn't zero.
        return ((difference | (0 - difference)) >> 63) - 1;
    }

    /// <summary>The carry out of a + b, given their sum, with no comparison.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong CarryOut(ulong a, ulong b, ulong sum) => ((a & b) | ((a | b) & ~sum)) >> 63;

    /// <summary>The borrow out of a − b − borrow, given the difference, with no comparison (Hacker's Delight, 2-13).</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong BorrowOut(ulong a, ulong b, ulong difference) => ((~a & b) | (~(a ^ b) & difference)) >> 63;

    /// <summary>Returns the high limb of a × b + c + d, and sets the low one. The sum always fits in 128 bits.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong MultiplyAdd(ulong a, ulong b, ulong c, ulong d, out ulong low)
    {
        ulong high = Math.BigMul(a, b, out ulong product);
        ulong first = product + c;
        high += CarryOut(product, c, first);
        low = first + d;
        high += CarryOut(first, d, low);
        return high;
    }

    /// <summary>
    /// result = a × b × R⁻¹ mod p, with a and b below p. The result may be the same span as a or b, because it's written
    /// only at the end. <paramref name="t"/> is n + 2 limbs of scratch.
    /// </summary>
    private void Multiply(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, Span<ulong> result, Span<ulong> t)
    {
        int n = Limbs;
        ReadOnlySpan<ulong> p = _modulus;
        t.Clear();
        for (int i = 0; i < n; i++)
        {
            // t += a × b[i]
            ulong bi = b[i];
            ulong carry = 0;
            for (int j = 0; j < n; j++)
            {
                carry = MultiplyAdd(a[j], bi, t[j], carry, out t[j]);
            }

            ulong top = t[n] + carry;
            t[n + 1] = CarryOut(t[n], carry, top);
            t[n] = top;

            // t = (t + m × p) / 2⁶⁴, where m makes the low limb zero.
            ulong m = t[0] * _inverse;
            carry = MultiplyAdd(m, p[0], t[0], 0, out _);
            for (int j = 1; j < n; j++)
            {
                carry = MultiplyAdd(m, p[j], t[j], carry, out t[j - 1]);
            }

            top = t[n] + carry;
            ulong overflow = CarryOut(t[n], carry, top);
            t[n - 1] = top;
            t[n] = t[n + 1] + overflow;
        }

        // t < 2p here. Compute t − p into result, then keep it if t ≥ p: when the top limb is set or nothing was borrowed.
        ulong borrow = 0;
        for (int j = 0; j < n; j++)
        {
            ulong difference = t[j] - p[j] - borrow;
            borrow = BorrowOut(t[j], p[j], difference);
            result[j] = difference;
        }

        ulong keepDifference = 0 - (t[n] | (borrow ^ 1));
        for (int j = 0; j < n; j++)
        {
            result[j] = (result[j] & keepDifference) | (t[j] & ~keepDifference);
        }
    }

    private static ulong[] ToLimbs(BigInteger value, int limbs)
    {
        byte[] bytes = value.ToByteArray(isUnsigned: true, isBigEndian: false);
        ulong[] result = new ulong[limbs];
        for (int i = 0; i < bytes.Length; i++)
        {
            result[i >> 3] |= (ulong)bytes[i] << (8 * (i & 7));
        }

        return result;
    }
}

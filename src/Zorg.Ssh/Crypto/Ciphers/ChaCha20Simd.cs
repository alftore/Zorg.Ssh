using System;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;

namespace Zorg.Ssh.Crypto.Ciphers;

/// <summary>
/// ChaCha20 (RFC 8439's block function, 20 rounds) in OpenSSH's layout: a 64-bit block counter in state words 12 and
/// 13, and a 64-bit nonce in words 14 and 15. With a counter under 2^32 and a nonce whose first four bytes are zero,
/// that is the same cipher as RFC 8439's 32-bit counter and 96-bit nonce.
/// </summary>
/// <remarks>
/// Every path does only additions, XORs, rotations and fixed shuffles on the key and the data, so none has a branch
/// or an index that depends on a secret. The lengths, the counter and the nonce are not secret. The paths differ in
/// how many blocks they make at once: 4 in 256-bit vectors (AVX2), 2 in 128-bit vectors (SSE2, SSSE3 or Arm
/// AdvSimd), and 1 in plain integers. The state in registers can't be zeroed from managed code. The caller holds the
/// key as words and wipes them.
/// </remarks>
internal static class ChaCha20Simd
{
    internal const int KeyWords = 8;
    internal const int BlockSize = 64;

    /// <summary>Which implementation to use. Tests name one; production code uses <see cref="Auto"/>.</summary>
    internal enum Path
    {
        Auto,
        Scalar,
        Vector128,
        Vector256,
    }

    internal static bool IsSupported(Path path) => path switch
    {
        Path.Auto or Path.Scalar => true,
        Path.Vector128 => Vector128.IsHardwareAccelerated,
        Path.Vector256 => Vector256.IsHardwareAccelerated,
        _ => false,
    };

    /// <summary>Reads a 32-byte key as eight little-endian words.</summary>
    internal static void LoadKey(ReadOnlySpan<byte> key, Span<uint> words)
    {
        if (key.Length != KeyWords * 4 || words.Length != KeyWords)
        {
            throw new ArgumentException("A ChaCha20 key is 32 bytes.", nameof(key));
        }

        for (int i = 0; i < KeyWords; i++)
        {
            words[i] = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(key[(i * 4)..]);
        }
    }

    /// <summary>
    /// XORs the keystream that starts at block <paramref name="counter"/> into <paramref name="input"/>. Input and
    /// output may be the same span, but may not overlap in any other way.
    /// </summary>
    /// <param name="key">The eight key words.</param>
    /// <param name="counter">The 64-bit block counter, state words 12 and 13.</param>
    /// <param name="nonce0">State word 14.</param>
    /// <param name="nonce1">State word 15.</param>
    /// <param name="input">The data.</param>
    /// <param name="output">The result, as long as the input.</param>
    /// <param name="path">The implementation.</param>
    internal static void Crypt(
        ReadOnlySpan<uint> key,
        ulong counter,
        uint nonce0,
        uint nonce1,
        ReadOnlySpan<byte> input,
        Span<byte> output,
        Path path = Path.Auto)
    {
        if (key.Length != KeyWords)
        {
            throw new ArgumentException("A ChaCha20 key is eight words.", nameof(key));
        }

        if (output.Length != input.Length)
        {
            throw new ArgumentException("The output must be as long as the input.", nameof(output));
        }

        if (path == Path.Auto)
        {
            path = Vector256.IsHardwareAccelerated
                ? Path.Vector256
                : Vector128.IsHardwareAccelerated ? Path.Vector128 : Path.Scalar;
        }
        else if (!IsSupported(path))
        {
            throw new PlatformNotSupportedException("That ChaCha20 path isn't hardware accelerated here.");
        }

        ref byte src = ref MemoryMarshal.GetReference(input);
        ref byte dst = ref MemoryMarshal.GetReference(output);
        int length = input.Length;
        int done = 0;

        if (path == Path.Vector256)
        {
            done = Wide(key, counter, nonce0, nonce1, ref src, ref dst, length);
            counter += (ulong)(done / BlockSize);
        }

        if (path == Path.Vector128)
        {
            done = Narrow(key, counter, nonce0, nonce1, ref src, ref dst, length);
            counter += (ulong)(done / BlockSize);
        }

        Span<byte> block = stackalloc byte[BlockSize];
        while (done < length)
        {
            if (path == Path.Scalar)
            {
                BlockScalar(key, counter, nonce0, nonce1, block);
            }
            else
            {
                Block128(key, counter, nonce0, nonce1, block);
            }

            int take = Math.Min(BlockSize, length - done);
            for (int i = 0; i < take; i++)
            {
                Unsafe.Add(ref dst, done + i) = (byte)(Unsafe.Add(ref src, done + i) ^ block[i]);
            }

            done += take;
            counter++;
        }

        block.Clear();
    }

    /// <summary>Writes block <paramref name="counter"/> of the keystream.</summary>
    internal static void Keystream(
        ReadOnlySpan<uint> key,
        ulong counter,
        uint nonce0,
        uint nonce1,
        Span<byte> block,
        Path path = Path.Auto)
    {
        if (block.Length != BlockSize)
        {
            throw new ArgumentException("A ChaCha20 block is 64 bytes.", nameof(block));
        }

        if (path == Path.Scalar || (path == Path.Auto && !Vector128.IsHardwareAccelerated))
        {
            BlockScalar(key, counter, nonce0, nonce1, block);
        }
        else
        {
            Block128(key, counter, nonce0, nonce1, block);
        }
    }

    private static void BlockScalar(ReadOnlySpan<uint> key, ulong counter, uint nonce0, uint nonce1, Span<byte> block)
    {
        const uint C0 = 0x61707865;
        const uint C1 = 0x3320646e;
        const uint C2 = 0x79622d32;
        const uint C3 = 0x6b206574;
        uint k0 = key[0], k1 = key[1], k2 = key[2], k3 = key[3], k4 = key[4], k5 = key[5], k6 = key[6], k7 = key[7];
        uint t0 = (uint)counter;
        uint t1 = (uint)(counter >> 32);
        uint x0 = C0, x1 = C1, x2 = C2, x3 = C3;
        uint x4 = k0, x5 = k1, x6 = k2, x7 = k3;
        uint x8 = k4, x9 = k5, x10 = k6, x11 = k7;
        uint x12 = t0, x13 = t1, x14 = nonce0, x15 = nonce1;

        for (int i = 0; i < 10; i++)
        {
            Quarter(ref x0, ref x4, ref x8, ref x12);
            Quarter(ref x1, ref x5, ref x9, ref x13);
            Quarter(ref x2, ref x6, ref x10, ref x14);
            Quarter(ref x3, ref x7, ref x11, ref x15);
            Quarter(ref x0, ref x5, ref x10, ref x15);
            Quarter(ref x1, ref x6, ref x11, ref x12);
            Quarter(ref x2, ref x7, ref x8, ref x13);
            Quarter(ref x3, ref x4, ref x9, ref x14);
        }

        Word(block, 0, x0 + C0);
        Word(block, 1, x1 + C1);
        Word(block, 2, x2 + C2);
        Word(block, 3, x3 + C3);
        Word(block, 4, x4 + k0);
        Word(block, 5, x5 + k1);
        Word(block, 6, x6 + k2);
        Word(block, 7, x7 + k3);
        Word(block, 8, x8 + k4);
        Word(block, 9, x9 + k5);
        Word(block, 10, x10 + k6);
        Word(block, 11, x11 + k7);
        Word(block, 12, x12 + t0);
        Word(block, 13, x13 + t1);
        Word(block, 14, x14 + nonce0);
        Word(block, 15, x15 + nonce1);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Word(Span<byte> block, int index, uint value)
        => System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(block[(index * 4)..], value);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Quarter(ref uint a, ref uint b, ref uint c, ref uint d)
    {
        a += b;
        d = BitOperations.RotateLeft(d ^ a, 16);
        c += d;
        b = BitOperations.RotateLeft(b ^ c, 12);
        a += b;
        d = BitOperations.RotateLeft(d ^ a, 8);
        c += d;
        b = BitOperations.RotateLeft(b ^ c, 7);
    }

    // ---- 128-bit vectors: one row of the 4x4 state per vector ----

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<uint> Rotl(Vector128<uint> x, [System.Diagnostics.CodeAnalysis.ConstantExpected] byte n)
        => Vector128.ShiftLeft(x, n) | Vector128.ShiftRightLogical(x, 32 - n);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Quarter(ref Vector128<uint> a, ref Vector128<uint> b, ref Vector128<uint> c, ref Vector128<uint> d)
    {
        a += b;
        d ^= a;
        d = Rotl(d, 16);
        c += d;
        b ^= c;
        b = Rotl(b, 12);
        a += b;
        d ^= a;
        d = Rotl(d, 8);
        c += d;
        b ^= c;
        b = Rotl(b, 7);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Quarter(
        ref Vector128<uint> a0,
        ref Vector128<uint> b0,
        ref Vector128<uint> c0,
        ref Vector128<uint> d0,
        ref Vector128<uint> a1,
        ref Vector128<uint> b1,
        ref Vector128<uint> c1,
        ref Vector128<uint> d1)
    {
        a0 += b0;
        a1 += b1;
        d0 ^= a0;
        d1 ^= a1;
        d0 = Rotl(d0, 16);
        d1 = Rotl(d1, 16);
        c0 += d0;
        c1 += d1;
        b0 ^= c0;
        b1 ^= c1;
        b0 = Rotl(b0, 12);
        b1 = Rotl(b1, 12);
        a0 += b0;
        a1 += b1;
        d0 ^= a0;
        d1 ^= a1;
        d0 = Rotl(d0, 8);
        d1 = Rotl(d1, 8);
        c0 += d0;
        c1 += d1;
        b0 ^= c0;
        b1 ^= c1;
        b0 = Rotl(b0, 7);
        b1 = Rotl(b1, 7);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Diagonal(ref Vector128<uint> b, ref Vector128<uint> c, ref Vector128<uint> d)
    {
        b = Vector128.Shuffle(b, Vector128.Create(1u, 2u, 3u, 0u));
        c = Vector128.Shuffle(c, Vector128.Create(2u, 3u, 0u, 1u));
        d = Vector128.Shuffle(d, Vector128.Create(3u, 0u, 1u, 2u));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Undiagonal(ref Vector128<uint> b, ref Vector128<uint> c, ref Vector128<uint> d)
    {
        b = Vector128.Shuffle(b, Vector128.Create(3u, 0u, 1u, 2u));
        c = Vector128.Shuffle(c, Vector128.Create(2u, 3u, 0u, 1u));
        d = Vector128.Shuffle(d, Vector128.Create(1u, 2u, 3u, 0u));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Diagonal(
        ref Vector128<uint> b0,
        ref Vector128<uint> c0,
        ref Vector128<uint> d0,
        ref Vector128<uint> b1,
        ref Vector128<uint> c1,
        ref Vector128<uint> d1)
    {
        Diagonal(ref b0, ref c0, ref d0);
        Diagonal(ref b1, ref c1, ref d1);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Undiagonal(
        ref Vector128<uint> b0,
        ref Vector128<uint> c0,
        ref Vector128<uint> d0,
        ref Vector128<uint> b1,
        ref Vector128<uint> c1,
        ref Vector128<uint> d1)
    {
        Undiagonal(ref b0, ref c0, ref d0);
        Undiagonal(ref b1, ref c1, ref d1);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Quarter(
        ref Vector256<uint> a0,
        ref Vector256<uint> b0,
        ref Vector256<uint> c0,
        ref Vector256<uint> d0,
        ref Vector256<uint> a1,
        ref Vector256<uint> b1,
        ref Vector256<uint> c1,
        ref Vector256<uint> d1)
    {
        a0 += b0;
        a1 += b1;
        d0 ^= a0;
        d1 ^= a1;
        d0 = Rotl(d0, 16);
        d1 = Rotl(d1, 16);
        c0 += d0;
        c1 += d1;
        b0 ^= c0;
        b1 ^= c1;
        b0 = Rotl(b0, 12);
        b1 = Rotl(b1, 12);
        a0 += b0;
        a1 += b1;
        d0 ^= a0;
        d1 ^= a1;
        d0 = Rotl(d0, 8);
        d1 = Rotl(d1, 8);
        c0 += d0;
        c1 += d1;
        b0 ^= c0;
        b1 ^= c1;
        b0 = Rotl(b0, 7);
        b1 = Rotl(b1, 7);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Diagonal(
        ref Vector256<uint> b0,
        ref Vector256<uint> c0,
        ref Vector256<uint> d0,
        ref Vector256<uint> b1,
        ref Vector256<uint> c1,
        ref Vector256<uint> d1)
    {
        b0 = Vector256.Shuffle(b0, Vector256.Create(1u, 2u, 3u, 0u, 5u, 6u, 7u, 4u));
        b1 = Vector256.Shuffle(b1, Vector256.Create(1u, 2u, 3u, 0u, 5u, 6u, 7u, 4u));
        c0 = Vector256.Shuffle(c0, Vector256.Create(2u, 3u, 0u, 1u, 6u, 7u, 4u, 5u));
        c1 = Vector256.Shuffle(c1, Vector256.Create(2u, 3u, 0u, 1u, 6u, 7u, 4u, 5u));
        d0 = Vector256.Shuffle(d0, Vector256.Create(3u, 0u, 1u, 2u, 7u, 4u, 5u, 6u));
        d1 = Vector256.Shuffle(d1, Vector256.Create(3u, 0u, 1u, 2u, 7u, 4u, 5u, 6u));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Undiagonal(
        ref Vector256<uint> b0,
        ref Vector256<uint> c0,
        ref Vector256<uint> d0,
        ref Vector256<uint> b1,
        ref Vector256<uint> c1,
        ref Vector256<uint> d1)
    {
        b0 = Vector256.Shuffle(b0, Vector256.Create(3u, 0u, 1u, 2u, 7u, 4u, 5u, 6u));
        b1 = Vector256.Shuffle(b1, Vector256.Create(3u, 0u, 1u, 2u, 7u, 4u, 5u, 6u));
        c0 = Vector256.Shuffle(c0, Vector256.Create(2u, 3u, 0u, 1u, 6u, 7u, 4u, 5u));
        c1 = Vector256.Shuffle(c1, Vector256.Create(2u, 3u, 0u, 1u, 6u, 7u, 4u, 5u));
        d0 = Vector256.Shuffle(d0, Vector256.Create(1u, 2u, 3u, 0u, 5u, 6u, 7u, 4u));
        d1 = Vector256.Shuffle(d1, Vector256.Create(1u, 2u, 3u, 0u, 5u, 6u, 7u, 4u));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<uint> Row0() => Vector128.Create(0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u);

    private static void Block128(ReadOnlySpan<uint> key, ulong counter, uint nonce0, uint nonce1, Span<byte> block)
    {
        Vector128<uint> a = Row0();
        Vector128<uint> b = Vector128.Create(key[0], key[1], key[2], key[3]);
        Vector128<uint> c = Vector128.Create(key[4], key[5], key[6], key[7]);
        Vector128<uint> d = Vector128.Create((uint)counter, (uint)(counter >> 32), nonce0, nonce1);
        Vector128<uint> a0 = a, b0 = b, c0 = c, d0 = d;

        for (int i = 0; i < 10; i++)
        {
            Quarter(ref a, ref b, ref c, ref d);
            Diagonal(ref b, ref c, ref d);
            Quarter(ref a, ref b, ref c, ref d);
            Undiagonal(ref b, ref c, ref d);
        }

        ref byte o = ref MemoryMarshal.GetReference(block);
        (a + a0).AsByte().StoreUnsafe(ref o, 0);
        (b + b0).AsByte().StoreUnsafe(ref o, 16);
        (c + c0).AsByte().StoreUnsafe(ref o, 32);
        (d + d0).AsByte().StoreUnsafe(ref o, 48);
    }

    /// <summary>Two blocks at a time in 128-bit vectors. Returns the bytes done, a multiple of 128.</summary>
    private static int Narrow(
        ReadOnlySpan<uint> key,
        ulong counter,
        uint nonce0,
        uint nonce1,
        ref byte src,
        ref byte dst,
        int length)
    {
        Vector128<uint> k0 = Row0();
        Vector128<uint> kb = Vector128.Create(key[0], key[1], key[2], key[3]);
        Vector128<uint> kc = Vector128.Create(key[4], key[5], key[6], key[7]);
        int done = 0;

        while (length - done >= 2 * BlockSize)
        {
            Vector128<uint> d0 = Vector128.Create((uint)counter, (uint)(counter >> 32), nonce0, nonce1);
            ulong next = counter + 1;
            Vector128<uint> d1 = Vector128.Create((uint)next, (uint)(next >> 32), nonce0, nonce1);

            Vector128<uint> a0 = k0, b0 = kb, c0 = kc, e0 = d0;
            Vector128<uint> a1 = k0, b1 = kb, c1 = kc, e1 = d1;

            for (int i = 0; i < 10; i++)
            {
                Quarter(ref a0, ref b0, ref c0, ref e0, ref a1, ref b1, ref c1, ref e1);
                Diagonal(ref b0, ref c0, ref e0, ref b1, ref c1, ref e1);
                Quarter(ref a0, ref b0, ref c0, ref e0, ref a1, ref b1, ref c1, ref e1);
                Undiagonal(ref b0, ref c0, ref e0, ref b1, ref c1, ref e1);
            }

            nuint o = (nuint)done;
            Xor(ref src, ref dst, o, a0 + k0);
            Xor(ref src, ref dst, o + 16, b0 + kb);
            Xor(ref src, ref dst, o + 32, c0 + kc);
            Xor(ref src, ref dst, o + 48, e0 + d0);
            Xor(ref src, ref dst, o + 64, a1 + k0);
            Xor(ref src, ref dst, o + 80, b1 + kb);
            Xor(ref src, ref dst, o + 96, c1 + kc);
            Xor(ref src, ref dst, o + 112, e1 + d1);

            done += 2 * BlockSize;
            counter += 2;
        }

        return done;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Xor(ref byte src, ref byte dst, nuint offset, Vector128<uint> keystream)
        => (Vector128.LoadUnsafe(ref src, offset) ^ keystream.AsByte()).StoreUnsafe(ref dst, offset);

    // ---- 256-bit vectors: two blocks per vector, two vectors per row, so four blocks at a time ----

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<uint> Rotl(Vector256<uint> x, [System.Diagnostics.CodeAnalysis.ConstantExpected] byte n)
        => Vector256.ShiftLeft(x, n) | Vector256.ShiftRightLogical(x, 32 - n);

    private static int Wide(
        ReadOnlySpan<uint> key,
        ulong counter,
        uint nonce0,
        uint nonce1,
        ref byte src,
        ref byte dst,
        int length)
    {
        Vector128<uint> r0 = Row0();
        Vector128<uint> rb = Vector128.Create(key[0], key[1], key[2], key[3]);
        Vector128<uint> rc = Vector128.Create(key[4], key[5], key[6], key[7]);
        Vector256<uint> ka = Vector256.Create(r0, r0);
        Vector256<uint> kb = Vector256.Create(rb, rb);
        Vector256<uint> kc = Vector256.Create(rc, rc);
        int done = 0;

        while (length - done >= 4 * BlockSize)
        {
            Vector256<uint> kd0 = Counters(counter, nonce0, nonce1);
            Vector256<uint> kd1 = Counters(counter + 2, nonce0, nonce1);

            Vector256<uint> a0 = ka, b0 = kb, c0 = kc, d0 = kd0;
            Vector256<uint> a1 = ka, b1 = kb, c1 = kc, d1 = kd1;

            for (int i = 0; i < 10; i++)
            {
                Quarter(ref a0, ref b0, ref c0, ref d0, ref a1, ref b1, ref c1, ref d1);
                Diagonal(ref b0, ref c0, ref d0, ref b1, ref c1, ref d1);
                Quarter(ref a0, ref b0, ref c0, ref d0, ref a1, ref b1, ref c1, ref d1);
                Undiagonal(ref b0, ref c0, ref d0, ref b1, ref c1, ref d1);
            }

            a0 += ka;
            b0 += kb;
            c0 += kc;
            d0 += kd0;
            a1 += ka;
            b1 += kb;
            c1 += kc;
            d1 += kd1;

            // Block 0 is the low halves, block 1 the high halves. Each 32-byte store takes two rows of one block.
            nuint o = (nuint)done;
            Xor(ref src, ref dst, o, Vector256.Create(a0.GetLower(), b0.GetLower()));
            Xor(ref src, ref dst, o + 32, Vector256.Create(c0.GetLower(), d0.GetLower()));
            Xor(ref src, ref dst, o + 64, Vector256.Create(a0.GetUpper(), b0.GetUpper()));
            Xor(ref src, ref dst, o + 96, Vector256.Create(c0.GetUpper(), d0.GetUpper()));
            Xor(ref src, ref dst, o + 128, Vector256.Create(a1.GetLower(), b1.GetLower()));
            Xor(ref src, ref dst, o + 160, Vector256.Create(c1.GetLower(), d1.GetLower()));
            Xor(ref src, ref dst, o + 192, Vector256.Create(a1.GetUpper(), b1.GetUpper()));
            Xor(ref src, ref dst, o + 224, Vector256.Create(c1.GetUpper(), d1.GetUpper()));

            done += 4 * BlockSize;
            counter += 4;
        }

        return done;
    }

    /// <summary>Row 3 for two blocks, counters <paramref name="counter"/> and the one after it.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<uint> Counters(ulong counter, uint nonce0, uint nonce1)
    {
        ulong next = counter + 1;
        return Vector256.Create((uint)counter, (uint)(counter >> 32), nonce0, nonce1, (uint)next, (uint)(next >> 32), nonce0, nonce1);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Xor(ref byte src, ref byte dst, nuint offset, Vector256<uint> keystream)
        => (Vector256.LoadUnsafe(ref src, offset) ^ keystream.AsByte()).StoreUnsafe(ref dst, offset);
}

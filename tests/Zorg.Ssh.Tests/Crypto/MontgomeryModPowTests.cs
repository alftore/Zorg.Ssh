using System;
using System.Collections.Generic;
using System.Numerics;
using Xunit;
using Zorg.Ssh.Crypto.KeyExchange;

namespace Zorg.Ssh.Tests.Crypto;

/// <summary>
/// The constant-time modular exponentiation, against <see cref="BigInteger.ModPow"/> on public values. Seeds are fixed, so a
/// failure names a case that can be rerun.
/// </summary>
public class MontgomeryModPowTests
{
    public static TheoryData<int> ModulusBits => [128, 129, 191, 192, 255, 256, 511, 1000, 1023, 1024, 2048, 3072, 4095, 4096];

    [Theory]
    [MemberData(nameof(ModulusBits))]
    public void Random_values_match_BigInteger(int bits)
    {
        Random random = new(bits);
        for (int round = 0; round < (bits > 2048 ? 3 : 12); round++)
        {
            BigInteger modulus = RandomOdd(random, bits);
            MontgomeryModPow arithmetic = new(BigEndian(modulus));
            BigInteger value = RandomBelow(random, modulus);
            int exponentBits = 1 + random.Next(bits + 64);
            BigInteger exponent = RandomBits(random, exponentBits);

            AssertMatches(arithmetic, modulus, value, exponent, exponentBits);
        }
    }

    [Fact]
    public void Edge_values_match_BigInteger()
    {
        foreach (BigInteger modulus in new[]
        {
            (BigInteger.One << 128) - 1 - 158, // 2^128 - 159 is prime, the low limb is all ones but a few bits
            (BigInteger.One << 128) + 1,
            (BigInteger.One << 255) - 19,
            (BigInteger.One << 2047) + 1,
            (BigInteger.One << 2048) - 1,
            new BigInteger(DiffieHellmanGroup.Group14.Prime, isUnsigned: true, isBigEndian: true),
        })
        {
            MontgomeryModPow arithmetic = new(BigEndian(modulus));
            int bits = (int)modulus.GetBitLength();
            foreach (BigInteger value in new[] { BigInteger.Zero, BigInteger.One, 2, modulus - 1, modulus - 2, modulus >> 1, (modulus >> 1) + 1 })
            {
                foreach ((BigInteger exponent, int exponentBits) in new (BigInteger, int)[]
                {
                    (0, 1), (1, 1), (2, 2), (3, 2), (15, 4), (16, 5), (17, 5),
                    ((BigInteger.One << 64) - 1, 64), (BigInteger.One << 64, 65),
                    ((BigInteger.One << bits) - 1, bits), (modulus - 1, bits), (modulus - 2, bits),
                })
                {
                    AssertMatches(arithmetic, modulus, value, exponent, exponentBits);
                }
            }
        }
    }

    [Fact]
    public void An_exponent_narrower_than_its_bit_count_still_gives_the_right_answer()
    {
        // The window count follows the public length, so leading zero windows must be harmless.
        BigInteger modulus = new(DiffieHellmanGroup.Group14.Prime, isUnsigned: true, isBigEndian: true);
        MontgomeryModPow arithmetic = new(BigEndian(modulus));
        AssertMatches(arithmetic, modulus, 2, 5, 2047);
        AssertMatches(arithmetic, modulus, 2, BigInteger.One << 1000, 2047);
    }

    [Fact]
    public void The_RFC_3526_groups_match_BigInteger_with_random_exponents()
    {
        Random random = new(3526);
        foreach (DiffieHellmanGroup group in new[] { DiffieHellmanGroup.Group14, DiffieHellmanGroup.Group16 })
        {
            BigInteger p = new(group.Prime, isUnsigned: true, isBigEndian: true);
            for (int round = 0; round < 3; round++)
            {
                int exponentBits = round == 0 ? group.Bits - 1 : 512 * (round + 1);
                AssertMatches(group.Arithmetic, p, 2, RandomBits(random, exponentBits), exponentBits);
                AssertMatches(group.Arithmetic, p, RandomBelow(random, p), RandomBits(random, exponentBits), exponentBits);
            }
        }
    }

    [Fact]
    public void Bad_operands_are_refused()
    {
        Assert.Throws<ArgumentException>(() => new MontgomeryModPow(BigEndian((BigInteger.One << 200) + 2)));
        Assert.Throws<ArgumentException>(() => new MontgomeryModPow(BigEndian(65537)));

        MontgomeryModPow arithmetic = DiffieHellmanGroup.Group14.Arithmetic;
        ulong[] value = new ulong[arithmetic.Limbs];
        ulong[] result = new ulong[arithmetic.Limbs];
        Assert.Throws<ArgumentException>(() => arithmetic.Pow(value.AsSpan(1), new ulong[4], 256, result));
        Assert.Throws<ArgumentException>(() => arithmetic.Pow(value, new ulong[4], 257, result));
        Assert.Throws<ArgumentException>(() => arithmetic.Pow(value, new ulong[4], 0, result));
    }

    [Fact]
    public void Limbs_round_trip_and_wide_values_are_refused()
    {
        ulong[] limbs = new ulong[4];
        Assert.True(MontgomeryModPow.TryReadLimbs([0, 0, 1, 2, 3], limbs));
        Assert.Equal(0x010203UL, limbs[0]);
        Assert.False(MontgomeryModPow.TryReadLimbs(new byte[33] { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, limbs));
        Assert.True(MontgomeryModPow.TryReadLimbs(new byte[40], limbs));

        byte[] bytes = new byte[32];
        limbs = [1, 2, 3, 0x8000_0000_0000_0000];
        MontgomeryModPow.WriteBigEndian(limbs, bytes);
        Assert.Equal(new BigInteger(bytes, isUnsigned: true, isBigEndian: true), ToBig(limbs));
    }

    [Fact]
    public void The_group_primes_follow_the_RFC_3526_formula()
    {
        // p = 2^n - 2^(n-64) - 1 + 2^64 * (floor(2^(n-130) * pi) + k), with pi from Machin's formula: no shared code, no table.
        foreach ((DiffieHellmanGroup group, int n, int k) in new[] { (DiffieHellmanGroup.Group14, 2048, 124476), (DiffieHellmanGroup.Group16, 4096, 240904) })
        {
            BigInteger expected = (BigInteger.One << n) - (BigInteger.One << (n - 64)) - 1 + ((BigInteger.One << 64) * (PiTimesPowerOfTwo(n - 130) + k));
            Assert.Equal(expected, new BigInteger(group.Prime, isUnsigned: true, isBigEndian: true));
            Assert.Equal(n, group.Bits);
        }
    }

    [Fact]
    public void The_group_primes_are_safe_primes()
    {
        foreach (DiffieHellmanGroup group in new[] { DiffieHellmanGroup.Group14, DiffieHellmanGroup.Group16 })
        {
            BigInteger p = new(group.Prime, isUnsigned: true, isBigEndian: true);
            Assert.True(ProbablyPrime(p, 4));
            Assert.True(ProbablyPrime((p - 1) / 2, 4));
        }
    }

    private static void AssertMatches(MontgomeryModPow arithmetic, BigInteger modulus, BigInteger value, BigInteger exponent, int exponentBits)
    {
        ulong[] valueLimbs = ToLimbs(value, arithmetic.Limbs);
        ulong[] exponentLimbs = ToLimbs(exponent, Math.Max(1, (exponentBits + 63) / 64));
        ulong[] result = new ulong[arithmetic.Limbs];

        arithmetic.Pow(valueLimbs, exponentLimbs, exponentBits, result);

        BigInteger expected = BigInteger.ModPow(value, exponent, modulus);
        Assert.True(expected == ToBig(result), $"{value:X} ^ {exponent:X} mod {modulus:X} ({exponentBits} bits)");
    }

    private static BigInteger PiTimesPowerOfTwo(int bits)
    {
        const int Guard = 64;
        int scale = bits + Guard;
        BigInteger pi = 4 * ((4 * ArctanInverse(5, scale)) - ArctanInverse(239, scale));
        return pi >> Guard;
    }

    private static BigInteger ArctanInverse(int x, int bits)
    {
        BigInteger term = (BigInteger.One << bits) / x;
        BigInteger total = term;
        BigInteger square = x * x;
        for (int n = 1, sign = -1; !term.IsZero; n++, sign = -sign)
        {
            term /= square;
            total += sign * (term / ((2 * n) + 1));
        }

        return total;
    }

    private static bool ProbablyPrime(BigInteger n, int rounds)
    {
        BigInteger d = n - 1;
        int r = 0;
        while (d.IsEven)
        {
            d >>= 1;
            r++;
        }

        Random random = new(7);
        for (int i = 0; i < rounds; i++)
        {
            BigInteger a = 2 + RandomBelow(random, n - 4);
            BigInteger x = BigInteger.ModPow(a, d, n);
            if (x.IsOne || x == n - 1)
            {
                continue;
            }

            bool composite = true;
            for (int j = 1; j < r && composite; j++)
            {
                x = BigInteger.ModPow(x, 2, n);
                composite = x != n - 1;
            }

            if (composite)
            {
                return false;
            }
        }

        return true;
    }

    private static BigInteger RandomBits(Random random, int bits)
    {
        byte[] bytes = new byte[(bits + 7) / 8 + 1];
        random.NextBytes(bytes);
        bytes[^1] = 0;
        BigInteger value = new(bytes, isUnsigned: true);
        return value & ((BigInteger.One << bits) - 1);
    }

    private static BigInteger RandomOdd(Random random, int bits) => RandomBits(random, bits) | (BigInteger.One << (bits - 1)) | 1;

    private static BigInteger RandomBelow(Random random, BigInteger bound)
    {
        BigInteger value;
        do
        {
            value = RandomBits(random, (int)bound.GetBitLength());
        }
        while (value >= bound);
        return value;
    }

    private static byte[] BigEndian(BigInteger value) => value.ToByteArray(isUnsigned: true, isBigEndian: true);

    private static ulong[] ToLimbs(BigInteger value, int count)
    {
        ulong[] limbs = new ulong[count];
        byte[] bytes = value.ToByteArray(isUnsigned: true);
        for (int i = 0; i < bytes.Length; i++)
        {
            limbs[i / 8] |= (ulong)bytes[i] << (8 * (i % 8));
        }

        return limbs;
    }

    private static BigInteger ToBig(IReadOnlyList<ulong> limbs)
    {
        BigInteger value = BigInteger.Zero;
        for (int i = limbs.Count - 1; i >= 0; i--)
        {
            value = (value << 64) | limbs[i];
        }

        return value;
    }
}

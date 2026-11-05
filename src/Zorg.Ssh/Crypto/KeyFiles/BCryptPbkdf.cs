using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Zorg.Ssh.Crypto.KeyFiles;

/// <summary>
/// <c>bcrypt_pbkdf</c>, the key derivation OpenSSH uses for encrypted key files. It's PBKDF2 in shape, but each round
/// is a Blowfish based hash in place of an HMAC, and the output bytes are spread across the blocks, so that no block
/// can be computed alone to test a passphrase.
/// </summary>
/// <remarks>
/// BouncyCastle has no use here: its <c>BCrypt</c> is the password hash, with another magic string and key schedule,
/// and its <c>BlowfishEngine</c> can't take the salted key schedule this needs.
/// </remarks>
internal static class BCryptPbkdf
{
    /// <summary>
    /// The most rounds accepted, because the count comes from a file. <c>ssh-keygen</c> writes 16 to 24 by default.
    /// A round costs about 7 ms in an optimized build, so a hostile file can hold a caller for about 8 seconds, and
    /// only if the caller supplies a passphrase.
    /// </summary>
    public const int MaxRounds = 1024;

    /// <summary>The most output one call can make: 32 blocks of 32 bytes, as OpenBSD defines it.</summary>
    public const int MaxOutputLength = HashLength * HashLength;

    private const int HashLength = 32;
    private const int Sha512Length = 64;
    private const int CounterLength = 4;
    private const int HashWords = HashLength / sizeof(uint);
    private const int ExpansionRounds = 64;
    private const int EncryptionRounds = 64;

    /// <summary>Fills <paramref name="output"/> with key material.</summary>
    /// <param name="password">The passphrase. It can't be empty.</param>
    /// <param name="salt">The salt. It can't be empty.</param>
    /// <param name="rounds">The round count, from 1 to <see cref="MaxRounds"/>.</param>
    /// <param name="output">Where the key goes. Up to <see cref="MaxOutputLength"/> bytes.</param>
    public static void DeriveKey(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int rounds, Span<byte> output)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(rounds, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(rounds, MaxRounds);
        if (password.IsEmpty || salt.IsEmpty || output.IsEmpty || output.Length > MaxOutputLength)
        {
            throw new ArgumentException("bcrypt_pbkdf needs a password, a salt, and from 1 to 1024 bytes of output.");
        }

        // Output byte i of block b lands at i * blockCount + b, which is the step that differs from PBKDF2.
        int blockCount = (output.Length + HashLength - 1) / HashLength;

        byte[] saltWithCounter = new byte[salt.Length + CounterLength];
        salt.CopyTo(saltWithCounter);
        Span<byte> counter = saltWithCounter.AsSpan(salt.Length);

        Span<byte> passwordHash = stackalloc byte[Sha512Length];
        Span<byte> saltHash = stackalloc byte[Sha512Length];
        Span<byte> roundOutput = stackalloc byte[HashLength];
        Span<byte> block = stackalloc byte[HashLength];
        Blowfish blowfish = new();
        try
        {
            SHA512.HashData(password, passwordHash);
            for (int blockIndex = 0; blockIndex < blockCount; blockIndex++)
            {
                BinaryPrimitives.WriteUInt32BigEndian(counter, (uint)blockIndex + 1);
                SHA512.HashData(saltWithCounter, saltHash);
                blowfish.Hash(passwordHash, saltHash, roundOutput);
                roundOutput.CopyTo(block);

                for (int round = 1; round < rounds; round++)
                {
                    SHA512.HashData(roundOutput, saltHash);
                    blowfish.Hash(passwordHash, saltHash, roundOutput);
                    for (int i = 0; i < HashLength; i++)
                    {
                        block[i] ^= roundOutput[i];
                    }
                }

                for (int i = 0; i < HashLength; i++)
                {
                    int destination = (i * blockCount) + blockIndex;
                    if (destination >= output.Length)
                    {
                        break;
                    }

                    output[destination] = block[i];
                }
            }
        }
        finally
        {
            blowfish.Clear();
            CryptographicOperations.ZeroMemory(passwordHash);
            CryptographicOperations.ZeroMemory(saltHash);
            CryptographicOperations.ZeroMemory(roundOutput);
            CryptographicOperations.ZeroMemory(block);
        }
    }

    /// <summary>Blowfish with the Eksblowfish key schedule. It only ever encrypts.</summary>
    internal sealed class Blowfish
    {
        private const int PWords = 18;
        private const int SWords = 1024;
        private const int InputWords = Sha512Length / sizeof(uint);

        private readonly uint[] _p = new uint[PWords];
        private readonly uint[] _s = new uint[SWords];
        private readonly uint[] _salt = new uint[InputWords];
        private readonly uint[] _key = new uint[InputWords];

        private static ReadOnlySpan<byte> Magic => "OxychromaticBlowfishSwatDynamite"u8;

        /// <summary>Sets the state to the digits of pi.</summary>
        public void Reset()
        {
            BlowfishTables.Pi[..PWords].CopyTo(_p);
            BlowfishTables.Pi[PWords..].CopyTo(_s);
        }

        /// <summary>The <c>bcrypt_hash</c> step: 32 bytes from two 64-byte inputs.</summary>
        public void Hash(ReadOnlySpan<byte> passwordHash, ReadOnlySpan<byte> saltHash, Span<byte> output)
        {
            LoadWords(passwordHash, _key);
            LoadWords(saltHash, _salt);

            Reset();
            ExpandKey(_key, _salt);
            for (int i = 0; i < ExpansionRounds; i++)
            {
                ExpandKey(_salt, salt: null);
                ExpandKey(_key, salt: null);
            }

            Span<uint> data = stackalloc uint[HashWords];
            for (int i = 0; i < HashWords; i++)
            {
                data[i] = BinaryPrimitives.ReadUInt32BigEndian(Magic[(i * sizeof(uint))..]);
            }

            for (int round = 0; round < EncryptionRounds; round++)
            {
                for (int i = 0; i < HashWords; i += 2)
                {
                    (data[i], data[i + 1]) = Encrypt(data[i], data[i + 1]);
                }
            }

            // Little-endian here, unlike the big-endian input. OpenBSD's output is defined this way.
            for (int i = 0; i < HashWords; i++)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(output[(i * sizeof(uint))..], data[i]);
            }

            data.Clear();
        }

        /// <summary>Encrypts one block, as two big-endian words.</summary>
        public (uint Left, uint Right) Encrypt(uint left, uint right)
        {
            uint[] p = _p;
            left ^= p[0];
            for (int i = 1; i < PWords - 1; i += 2)
            {
                right ^= Round(left) ^ p[i];
                left ^= Round(right) ^ p[i + 1];
            }

            return (right ^ p[PWords - 1], left);
        }

        /// <summary>The plain Blowfish key schedule, for a key of 16 words. Tests use it to compare with another Blowfish.</summary>
        internal void ExpandPlainKey(uint[] key) => ExpandKey(key, salt: null);

        /// <summary>Overwrites everything derived from the password.</summary>
        public void Clear()
        {
            Array.Clear(_p);
            Array.Clear(_s);
            Array.Clear(_salt);
            Array.Clear(_key);
        }

        private static void LoadWords(ReadOnlySpan<byte> bytes, uint[] words)
        {
            for (int i = 0; i < words.Length; i++)
            {
                words[i] = BinaryPrimitives.ReadUInt32BigEndian(bytes[(i * sizeof(uint))..]);
            }
        }

        /// <summary>
        /// The key schedule. The key is XORed into P, then P and the S-boxes are replaced by a running encryption,
        /// which mixes in the salt if there is one. Both inputs are 16 words, used as endless cycles.
        /// </summary>
        private void ExpandKey(uint[] key, uint[]? salt)
        {
            for (int i = 0; i < PWords; i++)
            {
                _p[i] ^= key[i % InputWords];
            }

            uint left = 0;
            uint right = 0;
            int position = 0;
            for (int i = 0; i < PWords; i += 2)
            {
                (left, right) = Next(left, right, salt, ref position);
                _p[i] = left;
                _p[i + 1] = right;
            }

            for (int i = 0; i < SWords; i += 2)
            {
                (left, right) = Next(left, right, salt, ref position);
                _s[i] = left;
                _s[i + 1] = right;
            }
        }

        private (uint Left, uint Right) Next(uint left, uint right, uint[]? salt, ref int position)
        {
            if (salt is not null)
            {
                left ^= salt[position];
                right ^= salt[position + 1];
                position = (position + 2) % InputWords;
            }

            return Encrypt(left, right);
        }

        private uint Round(uint x)
        {
            uint[] s = _s;
            return ((s[x >> 24] + s[256 + ((x >> 16) & 0xFF)]) ^ s[512 + ((x >> 8) & 0xFF)]) + s[768 + (x & 0xFF)];
        }
    }
}

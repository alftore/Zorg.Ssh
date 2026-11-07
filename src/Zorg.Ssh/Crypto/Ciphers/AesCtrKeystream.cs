using System;
using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;

namespace Zorg.Ssh.Crypto.Ciphers;

/// <summary>
/// The AES-CTR keystream of RFC 4344: a 128-bit big-endian counter that starts at the IV, runs on across packets, and
/// wraps. It works on whole blocks only. The caller checks every length that comes from a peer before it gets here.
/// </summary>
internal sealed class AesCtrKeystream : IDisposable
{
    /// <summary>The AES block size.</summary>
    public const int Block = 16;

    // Bytes of keystream per call into the BCL. A multiple of the block size.
    private const int ChunkSize = 4096;

    private readonly ICryptoTransform _ecb;

    // TransformBlock takes arrays. They're kept so a packet needn't rent any.
    private readonly byte[] _counterBlocks = new byte[ChunkSize];
    private readonly byte[] _keystream = new byte[ChunkSize];
    private ulong _counterHigh;
    private ulong _counterLow;
    private bool _disposed;

    public AesCtrKeystream(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        _counterHigh = BinaryPrimitives.ReadUInt64BigEndian(iv);
        _counterLow = BinaryPrimitives.ReadUInt64BigEndian(iv[8..]);

        // The transform keeps its own key, so the Aes object is finished with once it exists.
        using Aes aes = Aes.Create();
        aes.Padding = PaddingMode.None;
        aes.SetKey(key);
#pragma warning disable CA5358 // ECB here is the block function of CTR: it only ever encrypts unique counter blocks.
        aes.Mode = CipherMode.ECB;
#pragma warning restore CA5358
        _ecb = aes.CreateEncryptor();
    }

    /// <summary>XORs the keystream into <paramref name="data"/>, a whole number of blocks, and moves the counter past it.</summary>
    public void Crypt(Span<byte> data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (data.Length % Block != 0)
        {
            throw new ArgumentException("CTR works on whole blocks here.", nameof(data));
        }

        ulong high = _counterHigh;
        ulong low = _counterLow;
        while (!data.IsEmpty)
        {
            int count = Math.Min(data.Length, ChunkSize);
            FillCounterBlocks(count, ref high, ref low);
            Transform(count);
            Xor(data[..count], _keystream.AsSpan(0, count));
            data = data[count..];
        }

        _counterHigh = high;
        _counterLow = low;
    }

    /// <summary>
    /// Decrypts one block at the current counter into <paramref name="output"/>, without moving the counter, so that
    /// the same bytes can be decrypted again in place by <see cref="Crypt"/>. The keystream used is cleared.
    /// </summary>
    public void PeekBlock(ReadOnlySpan<byte> input, Span<byte> output)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (input.Length != Block || output.Length != Block)
        {
            throw new ArgumentException("A peek is exactly one block.", nameof(input));
        }

        ulong high = _counterHigh;
        ulong low = _counterLow;
        FillCounterBlocks(Block, ref high, ref low);
        Transform(Block);
        for (int i = 0; i < Block; i++)
        {
            output[i] = (byte)(input[i] ^ _keystream[i]);
        }

        CryptographicOperations.ZeroMemory(_keystream.AsSpan(0, Block));
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _disposed = true;
            _counterHigh = 0;
            _counterLow = 0;
            CryptographicOperations.ZeroMemory(_counterBlocks);
            CryptographicOperations.ZeroMemory(_keystream);
            _ecb.Dispose();
        }
    }

    private static void Xor(Span<byte> data, ReadOnlySpan<byte> keystream)
    {
        // Both lengths are whole AES blocks, but Vector<byte> needn't divide them.
        int width = Vector<byte>.Count;
        int i = 0;
        for (; i <= data.Length - width; i += width)
        {
            Span<byte> target = data[i..];
            (new Vector<byte>(target) ^ new Vector<byte>(keystream[i..])).CopyTo(target);
        }

        for (; i < data.Length; i++)
        {
            data[i] ^= keystream[i];
        }
    }

    private void Transform(int count)
    {
        // ECB has no chaining, and without padding the transform holds nothing back, so one object serves every call.
        int produced = _ecb.TransformBlock(_counterBlocks, 0, count, _keystream, 0);
        if (produced != count)
        {
            throw new InvalidOperationException("The AES transform returned less keystream than requested.");
        }
    }

    private void FillCounterBlocks(int count, ref ulong high, ref ulong low)
    {
        Span<byte> blocks = _counterBlocks.AsSpan(0, count);
        for (int offset = 0; offset < count; offset += Block)
        {
            BinaryPrimitives.WriteUInt64BigEndian(blocks[offset..], high);
            BinaryPrimitives.WriteUInt64BigEndian(blocks[(offset + 8)..], low);
            if (++low == 0)
            {
                high++;
            }
        }
    }
}

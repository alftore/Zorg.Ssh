using System;
using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;

namespace Zorg.Ssh.Crypto.Ciphers;

/// <summary>
/// <c>aes128-ctr</c> and <c>aes256-ctr</c> (RFC 4344) with <c>hmac-sha2-256-etm@openssh.com</c> or
/// <c>hmac-sha2-512-etm@openssh.com</c>. The length stays in clear. The MAC covers the uint32 sequence number, the
/// length field and the ciphertext. The 128-bit big-endian counter runs on across packets, and wraps.
/// </summary>
internal sealed class AesCtrEtmCipher : PacketCipher
{
    private const int Block = 16;
    private const int BodyOffset = 4;
    private const int SequenceSize = 4;
    private const int MaxTag = 64;

    // Bytes of keystream per call into the BCL. A multiple of the block size.
    private const int ChunkSize = 4096;

    private readonly ICryptoTransform _ecb;
    private readonly IncrementalHash _mac;
    private readonly int _tagLength;

    // TransformBlock takes arrays. They're kept so a packet needn't rent any.
    private readonly byte[] _counterBlocks = new byte[ChunkSize];
    private readonly byte[] _keystream = new byte[ChunkSize];
    private ulong _counterHigh;
    private ulong _counterLow;
    private bool _disposed;

    public AesCtrEtmCipher(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, HashAlgorithmName macAlgorithm, ReadOnlySpan<byte> macKey, int tagLength)
    {
        _counterHigh = BinaryPrimitives.ReadUInt64BigEndian(iv);
        _counterLow = BinaryPrimitives.ReadUInt64BigEndian(iv[8..]);
        _tagLength = tagLength;
        _mac = IncrementalHash.CreateHMAC(macAlgorithm, macKey);

        // The transform keeps its own key, so the Aes object is finished with once it exists.
        using Aes aes = Aes.Create();
        aes.Padding = PaddingMode.None;
        aes.SetKey(key);
#pragma warning disable CA5358 // ECB here is the block function of CTR: it only ever encrypts unique counter blocks.
        aes.Mode = CipherMode.ECB;
#pragma warning restore CA5358
        _ecb = aes.CreateEncryptor();
    }

    public override int BlockSize => Block;

    public override int TagLength => _tagLength;

    public override bool LengthExcludedFromPadding => true;

    public override uint ReadPacketLength(ReadOnlySpan<byte> header, uint sequenceNumber)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return PacketChecks.ReadLength(header);
    }

    public override void Open(Span<byte> packet, uint sequenceNumber)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        PacketChecks.CheckSize(packet.Length, Block, _tagLength);
        PacketChecks.CheckLength(PacketChecks.ReadLength(packet), packet.Length, _tagLength);

        Span<byte> expectedTag = stackalloc byte[MaxTag];
        expectedTag = expectedTag[.._tagLength];
        ComputeTag(packet[..^_tagLength], sequenceNumber, expectedTag);
        bool authentic = CryptographicOperations.FixedTimeEquals(expectedTag, packet[^_tagLength..]);
        CryptographicOperations.ZeroMemory(expectedTag);
        if (!authentic)
        {
            PacketChecks.ThrowAuthenticationFailed();
        }

        Span<byte> body = packet[BodyOffset..^_tagLength];
        Crypt(body);
        PacketChecks.CheckPadding(body);
    }

    public override void Seal(Span<byte> packet, uint sequenceNumber)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        PacketChecks.CheckOutgoing(packet, Block, _tagLength);

        Crypt(packet[BodyOffset..^_tagLength]);
        ComputeTag(packet[..^_tagLength], sequenceNumber, packet[^_tagLength..]);
    }

    protected override void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            _disposed = true;
            _counterHigh = 0;
            _counterLow = 0;
            if (disposing)
            {
                CryptographicOperations.ZeroMemory(_counterBlocks);
                CryptographicOperations.ZeroMemory(_keystream);
                _ecb.Dispose();
                _mac.Dispose();
            }
        }

        base.Dispose(disposing);
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

    private void ComputeTag(ReadOnlySpan<byte> lengthAndBody, uint sequenceNumber, Span<byte> tag)
    {
        Span<byte> sequence = stackalloc byte[SequenceSize];
        BinaryPrimitives.WriteUInt32BigEndian(sequence, sequenceNumber);
        _mac.AppendData(sequence);
        _mac.AppendData(lengthAndBody);
        _mac.GetHashAndReset(tag);
    }

    private void Crypt(Span<byte> body)
    {
        while (!body.IsEmpty)
        {
            int count = Math.Min(body.Length, ChunkSize);
            FillCounterBlocks(count);

            // ECB has no chaining, and without padding the transform holds nothing back, so one object serves every call.
            int produced = _ecb.TransformBlock(_counterBlocks, 0, count, _keystream, 0);
            if (produced != count)
            {
                throw new InvalidOperationException("The AES transform returned less keystream than requested.");
            }

            Xor(body[..count], _keystream.AsSpan(0, count));
            body = body[count..];
        }
    }

    private void FillCounterBlocks(int count)
    {
        Span<byte> blocks = _counterBlocks.AsSpan(0, count);
        for (int offset = 0; offset < count; offset += Block)
        {
            BinaryPrimitives.WriteUInt64BigEndian(blocks[offset..], _counterHigh);
            BinaryPrimitives.WriteUInt64BigEndian(blocks[(offset + 8)..], _counterLow);
            if (++_counterLow == 0)
            {
                _counterHigh++;
            }
        }
    }
}

using System;
using System.Buffers.Binary;
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

    private readonly AesCtrKeystream _keystream;
    private readonly IncrementalHash _mac;
    private readonly int _tagLength;
    private bool _disposed;

    public AesCtrEtmCipher(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, HashAlgorithmName macAlgorithm, ReadOnlySpan<byte> macKey, int tagLength)
    {
        _tagLength = tagLength;
        _mac = IncrementalHash.CreateHMAC(macAlgorithm, macKey);
        _keystream = new AesCtrKeystream(key, iv);
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
        _keystream.Crypt(body);
        PacketChecks.CheckPadding(body);
    }

    public override void Seal(Span<byte> packet, uint sequenceNumber)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        PacketChecks.CheckOutgoing(packet, Block, _tagLength);

        _keystream.Crypt(packet[BodyOffset..^_tagLength]);
        ComputeTag(packet[..^_tagLength], sequenceNumber, packet[^_tagLength..]);
    }

    protected override void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            _disposed = true;
            if (disposing)
            {
                _keystream.Dispose();
                _mac.Dispose();
            }
        }

        base.Dispose(disposing);
    }

    private void ComputeTag(ReadOnlySpan<byte> lengthAndBody, uint sequenceNumber, Span<byte> tag)
    {
        Span<byte> sequence = stackalloc byte[SequenceSize];
        BinaryPrimitives.WriteUInt32BigEndian(sequence, sequenceNumber);
        _mac.AppendData(sequence);
        _mac.AppendData(lengthAndBody);
        _mac.GetHashAndReset(tag);
    }
}

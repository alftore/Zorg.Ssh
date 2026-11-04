using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Zorg.Ssh.Crypto.Ciphers;

/// <summary>
/// <c>aes128-gcm@openssh.com</c> and <c>aes256-gcm@openssh.com</c>, per RFC 5647. The length stays in clear as the
/// associated data. The nonce is a 4-byte fixed field and an 8-byte invocation counter, which starts at the value
/// in the derived IV and wraps modulo 2^64. The sequence number plays no part: a lost or reordered packet shows up
/// as a tag failure, because the counters no longer match.
/// </summary>
internal sealed class AesGcmCipher : PacketCipher
{
    private const int Block = 16;
    private const int Tag = 16;
    private const int NonceSize = 12;
    private const int FixedFieldSize = 4;
    private const int BodyOffset = 4;

    private readonly AesGcm _aes;
    private uint _fixedField;
    private ulong _invocationCounter;
    private bool _disposed;

    public AesGcmCipher(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        _aes = new AesGcm(key, Tag);
        _fixedField = BinaryPrimitives.ReadUInt32BigEndian(iv);
        _invocationCounter = BinaryPrimitives.ReadUInt64BigEndian(iv[FixedFieldSize..]);
    }

    public override int BlockSize => Block;

    public override int TagLength => Tag;

    public override bool LengthExcludedFromPadding => true;

    public override uint ReadPacketLength(ReadOnlySpan<byte> header, uint sequenceNumber)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return PacketChecks.ReadLength(header);
    }

    public override void Open(Span<byte> packet, uint sequenceNumber)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        PacketChecks.CheckSize(packet.Length, Block, Tag);
        PacketChecks.CheckLength(PacketChecks.ReadLength(packet), packet.Length, Tag);

        Span<byte> nonce = stackalloc byte[NonceSize];
        WriteNonce(nonce);

        Span<byte> body = packet[BodyOffset..^Tag];
        try
        {
            _aes.Decrypt(nonce, body, packet[^Tag..], body, packet[..BodyOffset]);
        }
        catch (CryptographicException)
        {
            // AesGcm has already cleared the output, so nothing unauthenticated is left in the buffer.
            PacketChecks.ThrowAuthenticationFailed();
        }

        _invocationCounter++;
        PacketChecks.CheckPadding(body);
    }

    public override void Seal(Span<byte> packet, uint sequenceNumber)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        PacketChecks.CheckOutgoing(packet, Block, Tag);

        Span<byte> nonce = stackalloc byte[NonceSize];
        WriteNonce(nonce);

        Span<byte> body = packet[BodyOffset..^Tag];
        _aes.Encrypt(nonce, body, body, packet[^Tag..], packet[..BodyOffset]);
        _invocationCounter++;
    }

    protected override void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            _disposed = true;
            _fixedField = 0;
            _invocationCounter = 0;
            if (disposing)
            {
                _aes.Dispose();
            }
        }

        base.Dispose(disposing);
    }

    private void WriteNonce(Span<byte> nonce)
    {
        BinaryPrimitives.WriteUInt32BigEndian(nonce, _fixedField);
        BinaryPrimitives.WriteUInt64BigEndian(nonce[FixedFieldSize..], _invocationCounter);
    }
}

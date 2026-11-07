using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Zorg.Ssh.Crypto.Ciphers;

/// <summary>
/// <c>aes128-ctr</c> and <c>aes256-ctr</c> (RFC 4344) with an encrypt-and-MAC HMAC (RFC 4253 section 6.4, RFC 6668):
/// <c>hmac-sha2-256</c>, <c>hmac-sha2-512</c>, and <c>hmac-sha1</c> for legacy peers. The length field is padded and
/// encrypted with the body, and the MAC covers the uint32 sequence number and the whole <em>plaintext</em> packet.
/// </summary>
/// <remarks>
/// <para>
/// The length is encrypted, so the reader must decrypt the first block to learn how much to read (see
/// <see cref="LengthBlockSize"/>). That one value is the only plaintext used before the MAC is checked, and it's checked
/// against the reader's limits and the block shape before anything is read or allocated for it. CTR is seekable, so
/// <see cref="ReadPacketLength"/> decrypts into scratch without moving the counter, and <see cref="Open"/> decrypts the
/// same bytes again in place.
/// </para>
/// <para>
/// Terrapin: the paper (Bäumer, Brinkmann, Schwenk, USENIX Security 2024) finds CTR with encrypt-and-MAC not affected. The
/// MAC covers the sequence number and the keystream position is the counter, so dropped or added packets break both.
/// Strict KEX is still negotiated and enforced exactly as for every other cipher.
/// </para>
/// </remarks>
internal sealed class AesCtrEamCipher : PacketCipher
{
    private const int Block = AesCtrKeystream.Block;
    private const int LengthFieldSize = 4;
    private const int SequenceSize = 4;
    private const int MaxTag = 64;

    private readonly AesCtrKeystream _keystream;
    private readonly IncrementalHash _mac;
    private readonly int _tagLength;
    private bool _disposed;

    public AesCtrEamCipher(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, HashAlgorithmName macAlgorithm, ReadOnlySpan<byte> macKey, int tagLength)
    {
        if (tagLength is < 1 or > MaxTag)
        {
            throw new ArgumentOutOfRangeException(nameof(tagLength));
        }

        _tagLength = tagLength;
        _mac = IncrementalHash.CreateHMAC(macAlgorithm, macKey);
        _keystream = new AesCtrKeystream(key, iv);
    }

    public override int BlockSize => Block;

    public override int TagLength => _tagLength;

    public override bool LengthExcludedFromPadding => false;

    public override int LengthBlockSize => Block;

    public override uint ReadPacketLength(ReadOnlySpan<byte> header, uint sequenceNumber)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        PacketChecks.CheckHeader(header.Length, Block);

        // The first block holds the length, padding_length and 11 payload bytes. Only the length leaves this method.
        Span<byte> first = stackalloc byte[Block];
        _keystream.PeekBlock(header[..Block], first);
        uint packetLength = BinaryPrimitives.ReadUInt32BigEndian(first);
        CryptographicOperations.ZeroMemory(first);

        // Shape before size: a length that can't be whole blocks is refused here, before the reader waits for or
        // allocates anything on its account. The reader then applies its own minimum and maximum.
        PacketChecks.CheckCoveredSize((long)packetLength + LengthFieldSize, Block);
        return packetLength;
    }

    public override void Open(Span<byte> packet, uint sequenceNumber)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        // Checked before decryption, which works on whole blocks: anything else from a peer is a protocol error.
        PacketChecks.CheckCoveredSize((long)packet.Length - _tagLength, Block);
        Span<byte> covered = packet[..^_tagLength];
        _keystream.Crypt(covered);

        // The buffer holds plaintext that isn't authenticated yet. Nothing reads it before the tag check.
        Span<byte> expectedTag = stackalloc byte[MaxTag];
        expectedTag = expectedTag[.._tagLength];
        ComputeTag(covered, sequenceNumber, expectedTag);
        bool authentic = CryptographicOperations.FixedTimeEquals(expectedTag, packet[^_tagLength..]);
        CryptographicOperations.ZeroMemory(expectedTag);
        if (!authentic)
        {
            // Unauthenticated plaintext is never left behind, or released.
            CryptographicOperations.ZeroMemory(covered);
            PacketChecks.ThrowAuthenticationFailed();
        }

        PacketChecks.CheckLength(BinaryPrimitives.ReadUInt32BigEndian(packet), packet.Length, _tagLength);
        PacketChecks.CheckPadding(packet[LengthFieldSize..^_tagLength]);
    }

    public override void Seal(Span<byte> packet, uint sequenceNumber)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        long covered = (long)packet.Length - _tagLength;
        if (covered < Block || covered % Block != 0 || BinaryPrimitives.ReadUInt32BigEndian(packet) != covered - LengthFieldSize)
        {
            throw new ArgumentException("The packet must hold its length field and padded body in whole blocks, and room for the tag.", nameof(packet));
        }

        ComputeTag(packet[..^_tagLength], sequenceNumber, packet[^_tagLength..]);
        _keystream.Crypt(packet[..^_tagLength]);
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

    private void ComputeTag(ReadOnlySpan<byte> plaintextPacket, uint sequenceNumber, Span<byte> tag)
    {
        Span<byte> sequence = stackalloc byte[SequenceSize];
        BinaryPrimitives.WriteUInt32BigEndian(sequence, sequenceNumber);
        _mac.AppendData(sequence);
        _mac.AppendData(plaintextPacket);

        // GetHashAndReset writes the full digest. Every MAC here has a tag as long as its digest.
        _mac.GetHashAndReset(tag);
    }
}

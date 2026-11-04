using System;
using System.Buffers.Binary;

namespace Zorg.Ssh.Crypto;

/// <summary>The state before the first NEWKEYS: no encryption and no tag. It can't be negotiated.</summary>
internal sealed class NoneCipher : PacketCipher
{
    public static readonly NoneCipher Instance = new();

    private NoneCipher()
    {
    }

    public override int BlockSize => 8;

    public override int TagLength => 0;

    public override bool LengthExcludedFromPadding => false;

    public override uint ReadPacketLength(ReadOnlySpan<byte> header, uint sequenceNumber) =>
        BinaryPrimitives.ReadUInt32BigEndian(header);

    public override void Open(Span<byte> packet, uint sequenceNumber)
    {
    }

    public override void Seal(Span<byte> packet, uint sequenceNumber)
    {
    }
}

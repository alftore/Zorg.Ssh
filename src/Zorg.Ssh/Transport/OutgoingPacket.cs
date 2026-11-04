using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using Zorg.Ssh.Crypto;

namespace Zorg.Ssh.Transport;

/// <summary>
/// A payload waiting to be sent, in a rented buffer with room for framing in front and for padding and a
/// tag behind. Exactly one of <see cref="Release"/> or sending must happen to each packet.
/// </summary>
internal readonly struct OutgoingPacket
{
    private const int FrontRoom = 5;
    private const int BackRoom = 128;
    private const int MinPadding = 4;

    private OutgoingPacket(byte[] buffer, int payloadLength, PacketCipher? nextCipher, bool resetSequence, bool isTerminal, int parkGeneration)
    {
        Buffer = buffer;
        PayloadLength = payloadLength;
        NextCipher = nextCipher;
        ResetSequence = resetSequence;
        IsTerminal = isTerminal;
        ParkGeneration = parkGeneration;
    }

    public byte[] Buffer { get; }

    public int PayloadLength { get; }

    /// <summary>Gets the cipher that takes over after this packet, which makes it a NEWKEYS.</summary>
    public PacketCipher? NextCipher { get; }

    /// <summary>Gets whether strict KEX resets the sequence number after this packet.</summary>
    public bool ResetSequence { get; }

    /// <summary>Gets whether the send loop ends after this packet: it's a DISCONNECT.</summary>
    public bool IsTerminal { get; }

    /// <summary>Gets the key exchange a NEWKEYS belongs to. A stale one must not unpark the next exchange.</summary>
    public int ParkGeneration { get; }

    public static OutgoingPacket Create(
        scoped ReadOnlySpan<byte> payload,
        PacketCipher? nextCipher = null,
        bool resetSequence = false,
        bool isTerminal = false,
        int parkGeneration = 0)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(FrontRoom + payload.Length + BackRoom);
        payload.CopyTo(buffer.AsSpan(FrontRoom));
        return new OutgoingPacket(buffer, payload.Length, nextCipher, resetSequence, isTerminal, parkGeneration);
    }

    /// <summary>Writes the length, padding length and random padding. Returns the packet length before the tag.</summary>
    public int Frame(PacketCipher cipher)
    {
        int block = Math.Max(8, cipher.BlockSize);
        int covered = 1 + PayloadLength + (cipher.LengthExcludedFromPadding ? 0 : 4);
        int padding = block - (covered % block);
        if (padding < MinPadding)
        {
            padding += block;
        }

        int packetLength = 1 + PayloadLength + padding;
        BinaryPrimitives.WriteUInt32BigEndian(Buffer, (uint)packetLength);
        Buffer[4] = (byte)padding;
        RandomNumberGenerator.Fill(Buffer.AsSpan(FrontRoom + PayloadLength, padding));
        return 4 + packetLength;
    }

    /// <summary>Clears the buffer, which can hold secrets, and returns it to the pool.</summary>
    public void Release()
    {
        ArrayPool<byte>.Shared.Return(Buffer, clearArray: true);
    }

    /// <summary>Drops a packet that never reached the wire, with any cipher it was carrying.</summary>
    public void Discard()
    {
        NextCipher?.Dispose();
        Release();
    }
}

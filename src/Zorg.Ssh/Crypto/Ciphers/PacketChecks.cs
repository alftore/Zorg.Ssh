using System;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;

namespace Zorg.Ssh.Crypto.Ciphers;

/// <summary>
/// The packet shape rules every cipher here shares. Each cipher leaves the length out of the padding, so the body
/// alone is a multiple of the block size. Messages hold no peer data.
/// </summary>
internal static class PacketChecks
{
    private const int LengthFieldSize = 4;

    // RFC 4253 section 6: at least four bytes of padding.
    private const int MinPadding = 4;

    /// <summary>Reads a length field, rejecting a header too short to hold one.</summary>
    public static uint ReadLength(ReadOnlySpan<byte> header)
    {
        if (header.Length < LengthFieldSize)
        {
            ThrowMalformed();
        }

        return BinaryPrimitives.ReadUInt32BigEndian(header);
    }

    /// <summary>Checks an incoming packet's size alone: room for the length, a body of whole blocks, and the tag.</summary>
    public static void CheckSize(int packetSize, int blockSize, int tagLength)
    {
        if (!IsValidBodySize((long)packetSize - LengthFieldSize - tagLength, blockSize))
        {
            ThrowMalformed();
        }
    }

    /// <summary>Checks that a decoded length field describes exactly the packet that was received.</summary>
    public static void CheckLength(uint packetLength, int packetSize, int tagLength)
    {
        // In long, because a hostile length near 2^32 would wrap in 32 bits.
        if (packetLength != (long)packetSize - LengthFieldSize - tagLength)
        {
            ThrowMalformed();
        }
    }

    /// <summary>
    /// Checks <c>padding_length</c> in a decrypted body, leaving at least one payload byte. It's a byte from the
    /// peer, so the sum is done as an int: Go CVE-2026-46597 did it in a byte, and 255 + 1 wrapped to 0.
    /// </summary>
    public static void CheckPadding(ReadOnlySpan<byte> body)
    {
        int padding = body[0];
        if (padding < MinPadding || padding + 1 >= body.Length)
        {
            ThrowMalformed();
        }
    }

    /// <summary>
    /// Checks an outgoing packet. A bad shape here is a bug in this library rather than peer behaviour, so it isn't a
    /// protocol failure.
    /// </summary>
    public static void CheckOutgoing(ReadOnlySpan<byte> packet, int blockSize, int tagLength)
    {
        long bodyLength = (long)packet.Length - LengthFieldSize - tagLength;
        if (!IsValidBodySize(bodyLength, blockSize) || BinaryPrimitives.ReadUInt32BigEndian(packet) != bodyLength)
        {
            throw new ArgumentException("The packet must hold its length field, a padded body and room for the tag.", nameof(packet));
        }
    }

    [DoesNotReturn]
    public static void ThrowAuthenticationFailed() =>
        throw new SshProtocolException("A packet failed authentication, so it was corrupted or tampered with. Reconnect, and check the network path if this repeats.");

    private static bool IsValidBodySize(long bodyLength, int blockSize) =>
        bodyLength >= blockSize && bodyLength % blockSize == 0;

    [DoesNotReturn]
    private static void ThrowMalformed() =>
        throw new SshProtocolException("The peer sent a malformed packet. Check that it is a real SSH implementation, then reconnect.");
}

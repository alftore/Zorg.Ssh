using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;

namespace Zorg.Ssh.Protocol;

/// <summary>
/// Reads RFC 4251 section 5 data types from peer-supplied bytes. Every read checks its bounds and
/// throws <see cref="SshProtocolException"/> on malformed input, never an index or argument exception.
/// </summary>
internal ref struct SshReader
{
    /// <summary>The largest mpint accepted, in bytes. Matches OpenSSH: a 16384-bit value plus a sign byte.</summary>
    public const int MaxMPIntLength = 2049;

    /// <summary>The most names accepted in one name-list. Real lists hold a few dozen.</summary>
    public const int MaxNameListCount = 256;

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    private ReadOnlySpan<byte> _remaining;

    /// <summary>Creates a reader over the given bytes.</summary>
    public SshReader(ReadOnlySpan<byte> data) => _remaining = data;

    /// <summary>Gets the number of unread bytes.</summary>
    public readonly int Remaining => _remaining.Length;

    /// <summary>Gets the unread bytes.</summary>
    public readonly ReadOnlySpan<byte> RemainingSpan => _remaining;

    /// <summary>Reads one byte.</summary>
    public byte ReadByte()
    {
        ReadOnlySpan<byte> bytes = ReadRaw(1);
        return bytes[0];
    }

    /// <summary>Reads a boolean. Any nonzero byte is true (RFC 4251).</summary>
    public bool ReadBoolean() => ReadByte() != 0;

    /// <summary>Reads a big-endian uint32.</summary>
    public uint ReadUInt32() => BinaryPrimitives.ReadUInt32BigEndian(ReadRaw(4));

    /// <summary>Reads a big-endian uint64.</summary>
    public ulong ReadUInt64() => BinaryPrimitives.ReadUInt64BigEndian(ReadRaw(8));

    /// <summary>Reads exactly <paramref name="length"/> bytes with no length prefix.</summary>
    public ReadOnlySpan<byte> ReadRaw(int length)
    {
        if (length < 0 || length > _remaining.Length)
        {
            throw Malformed("the message ended early");
        }

        ReadOnlySpan<byte> bytes = _remaining[..length];
        _remaining = _remaining[length..];
        return bytes;
    }

    /// <summary>Reads a length-prefixed binary string. The result points into the source bytes.</summary>
    public ReadOnlySpan<byte> ReadBinary()
    {
        uint length = ReadUInt32();
        if (length > (uint)_remaining.Length)
        {
            throw Malformed("a string length exceeds the message");
        }

        return ReadRaw((int)length);
    }

    /// <summary>Reads a length-prefixed string that must be valid UTF-8.</summary>
    public string ReadUtf8String()
    {
        ReadOnlySpan<byte> bytes = ReadBinary();
        try
        {
            return StrictUtf8.GetString(bytes);
        }
        catch (ArgumentException ex)
        {
            throw new SshProtocolException("The peer sent a malformed message: a string isn't valid UTF-8.", ex);
        }
    }

    /// <summary>Reads a name-list. Names must be non-empty printable US-ASCII, as RFC 4251 requires.</summary>
    public string[] ReadNameList()
    {
        ReadOnlySpan<byte> bytes = ReadBinary();
        if (bytes.IsEmpty)
        {
            return [];
        }

        List<string> names = [];
        while (true)
        {
            int comma = bytes.IndexOf((byte)',');
            ReadOnlySpan<byte> name = comma < 0 ? bytes : bytes[..comma];
            if (name.IsEmpty)
            {
                throw Malformed("a name-list holds an empty name");
            }

            foreach (byte b in name)
            {
                if (b is <= 0x20 or >= 0x7F)
                {
                    throw Malformed("a name-list holds a non-ASCII or control character");
                }
            }

            if (names.Count == MaxNameListCount)
            {
                throw Malformed("a name-list holds too many names");
            }

            names.Add(Encoding.ASCII.GetString(name));
            if (comma < 0)
            {
                return [.. names];
            }

            bytes = bytes[(comma + 1)..];
        }
    }

    /// <summary>
    /// Reads a non-negative mpint and returns its big-endian magnitude with leading zeros removed.
    /// Zero returns an empty span. Negative values and oversized values are rejected, as OpenSSH does.
    /// Redundant leading zeros are tolerated because real peers have sent them.
    /// </summary>
    public ReadOnlySpan<byte> ReadMPInt()
    {
        ReadOnlySpan<byte> bytes = ReadBinary();
        if (bytes.Length > MaxMPIntLength)
        {
            throw Malformed("an mpint is too large");
        }

        if (!bytes.IsEmpty && (bytes[0] & 0x80) != 0)
        {
            throw Malformed("an mpint is negative");
        }

        int start = 0;
        while (start < bytes.Length && bytes[start] == 0)
        {
            start++;
        }

        return bytes[start..];
    }

    /// <summary>Throws unless every byte has been read. Trailing data means a message is not what it claims to be.</summary>
    public readonly void EnsureEnd()
    {
        if (!_remaining.IsEmpty)
        {
            throw Malformed("the message has trailing data");
        }
    }

    private static SshProtocolException Malformed(string detail) => new($"The peer sent a malformed message: {detail}.");
}

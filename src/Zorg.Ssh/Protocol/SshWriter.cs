using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;

namespace Zorg.Ssh.Protocol;

/// <summary>
/// Writes RFC 4251 section 5 data types into a pooled, growing buffer. The buffer is cleared when it
/// goes back to the pool, because written data can hold secrets. Dispose exactly once.
/// </summary>
internal ref struct SshWriter
{
    private byte[] _buffer;
    private int _position;

    /// <summary>Creates a writer with a default capacity. Without this, <c>new()</c> would leave the buffer null.</summary>
    public SshWriter()
        : this(256)
    {
    }

    /// <summary>Creates a writer. <paramref name="reserve"/> bytes at the start stay free for framing.</summary>
    public SshWriter(int capacity, int reserve = 0)
    {
        _buffer = ArrayPool<byte>.Shared.Rent(Math.Max(capacity, reserve));
        _position = reserve;
    }

    /// <summary>Gets everything written, including any reserved bytes.</summary>
    public readonly ReadOnlySpan<byte> Written => _buffer.AsSpan(0, _position);

    /// <summary>Gets the number of bytes written, including any reserved bytes.</summary>
    public readonly int Length => _position;

    /// <summary>Writes one byte.</summary>
    public void WriteByte(byte value) => GetSpan(1)[0] = value;

    /// <summary>Writes a boolean as 0 or 1.</summary>
    public void WriteBoolean(bool value) => WriteByte(value ? (byte)1 : (byte)0);

    /// <summary>Writes a big-endian uint32.</summary>
    public void WriteUInt32(uint value) => BinaryPrimitives.WriteUInt32BigEndian(GetSpan(4), value);

    /// <summary>Writes a big-endian uint64.</summary>
    public void WriteUInt64(ulong value) => BinaryPrimitives.WriteUInt64BigEndian(GetSpan(8), value);

    /// <summary>Writes bytes with no length prefix.</summary>
    public void WriteRaw(scoped ReadOnlySpan<byte> value) => value.CopyTo(GetSpan(value.Length));

    /// <summary>Writes a length-prefixed binary string.</summary>
    public void WriteBinary(scoped ReadOnlySpan<byte> value)
    {
        WriteUInt32((uint)value.Length);
        WriteRaw(value);
    }

    /// <summary>Writes a length-prefixed UTF-8 string.</summary>
    public void WriteUtf8String(string value)
    {
        int length = Encoding.UTF8.GetByteCount(value);
        WriteUInt32((uint)length);
        Encoding.UTF8.GetBytes(value, GetSpan(length));
    }

    /// <summary>Writes a name-list.</summary>
    public void WriteNameList(IReadOnlyList<string> names)
    {
        int start = _position;
        WriteUInt32(0);
        for (int i = 0; i < names.Count; i++)
        {
            if (i > 0)
            {
                WriteByte((byte)',');
            }

            string name = names[i];
            Encoding.ASCII.GetBytes(name, GetSpan(name.Length));
        }

        BinaryPrimitives.WriteUInt32BigEndian(_buffer.AsSpan(start), (uint)(_position - start - 4));
    }

    /// <summary>
    /// Writes a non-negative mpint from a big-endian unsigned magnitude. Leading zeros are removed, and a
    /// zero byte is added when the top bit is set, so the encoding is the canonical one RFC 4251 requires.
    /// </summary>
    public void WriteMPInt(scoped ReadOnlySpan<byte> magnitude)
    {
        int start = 0;
        while (start < magnitude.Length && magnitude[start] == 0)
        {
            start++;
        }

        ReadOnlySpan<byte> trimmed = magnitude[start..];
        bool pad = !trimmed.IsEmpty && (trimmed[0] & 0x80) != 0;
        WriteUInt32((uint)(trimmed.Length + (pad ? 1 : 0)));
        if (pad)
        {
            WriteByte(0);
        }

        WriteRaw(trimmed);
    }

    /// <summary>Copies what was written into a new array.</summary>
    public readonly byte[] ToArray() => Written.ToArray();

    /// <summary>Clears the buffer and returns it to the pool.</summary>
    public void Dispose()
    {
        byte[] buffer = _buffer;
        _buffer = [];
        _position = 0;
        if (buffer.Length != 0)
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    private Span<byte> GetSpan(int length)
    {
        int needed = checked(_position + length);
        if (needed > _buffer.Length)
        {
            byte[] larger = ArrayPool<byte>.Shared.Rent(Math.Max(needed, _buffer.Length * 2));
            _buffer.AsSpan(0, _position).CopyTo(larger);
            ArrayPool<byte>.Shared.Return(_buffer, clearArray: true);
            _buffer = larger;
        }

        Span<byte> span = _buffer.AsSpan(_position, length);
        _position = needed;
        return span;
    }
}

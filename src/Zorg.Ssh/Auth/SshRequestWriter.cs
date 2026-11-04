using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Zorg.Ssh.Auth;

/// <summary>
/// A heap-based message builder for auth messages, which are rare and built inside closures, where the
/// span-based <see cref="Protocol.SshWriter"/> can't go. <see cref="Clear"/> zeroes what it held, because
/// these messages carry passwords.
/// </summary>
internal sealed class SshRequestWriter
{
    private readonly List<byte[]> _parts = [];

    public void Byte(byte value) => _parts.Add([value]);

    public void Bool(bool value) => _parts.Add([value ? (byte)1 : (byte)0]);

    public void UInt32(uint value)
    {
        byte[] bytes = new byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        _parts.Add(bytes);
    }

    public void String(string value) => Bytes(Encoding.UTF8.GetBytes(value));

    public void Bytes(byte[] value)
    {
        UInt32((uint)value.Length);
        _parts.Add((byte[])value.Clone()); // A copy, because Clear zeroes what this holds.
    }

    public byte[] ToArray()
    {
        int length = 0;
        foreach (byte[] part in _parts)
        {
            length += part.Length;
        }

        byte[] result = new byte[length];
        int position = 0;
        foreach (byte[] part in _parts)
        {
            part.CopyTo(result, position);
            position += part.Length;
        }

        return result;
    }

    public void Clear()
    {
        foreach (byte[] part in _parts)
        {
            CryptographicOperations.ZeroMemory(part);
        }

        _parts.Clear();
    }
}

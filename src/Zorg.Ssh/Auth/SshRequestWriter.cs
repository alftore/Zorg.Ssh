using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

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

    // A1: encode straight into the stored part, so no second copy of a password is left on the heap unzeroed.
    public void String(string value)
    {
        byte[] part = new byte[Encoding.UTF8.GetByteCount(value)];
        Encoding.UTF8.GetBytes(value, part);
        UInt32((uint)part.Length);
        _parts.Add(part);
    }

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

    /// <summary>Builds the message, hands it to <paramref name="send"/>, and zeroes every copy afterwards, also when sending fails.</summary>
    /// <remarks>A1: the array passed to <paramref name="send"/> must not be kept, because it is zeroed when the call returns.</remarks>
    public async ValueTask BuildSendAndClearAsync(Func<byte[], CancellationToken, ValueTask> send, CancellationToken cancellationToken)
    {
        byte[] wire = ToArray();
        try
        {
            await send(wire, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wire);
            Clear();
        }
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

using System;
using System.Buffers;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Zorg.Ssh.Crypto;

namespace Zorg.Ssh.Transport;

/// <summary>
/// Reads the identification line and then packets from the stream, through one contiguous pooled buffer
/// (decision D6). Everything the peer sends is bounded here, before any allocation depends on it.
/// </summary>
internal sealed class PacketReader : IDisposable
{
    /// <summary>The start size of the buffer. Covers an RFC-sized packet with room to spare.</summary>
    public const int InitialBufferSize = 36 * 1024;

    /// <summary>The largest SSH identification line, including its line ending (RFC 4253 section 4.2).</summary>
    public const int MaxIdentificationLine = 255;

    /// <summary>The most lines a server may send before its identification line.</summary>
    public const int MaxPreambleLines = 1024;

    /// <summary>The most bytes of identification and preamble together.</summary>
    public const int MaxPreambleBytes = 8192;

    private const int MinPacketLength = 5;
    private const int MinPadding = 4;

#pragma warning disable CA2213 // The transport owns the stream and closes it.
    private readonly Stream _stream;
#pragma warning restore CA2213
    private readonly int _maxPacketLength;
    private byte[] _buffer;
    private int _start;
    private int _end;
    private int _lastPacketLength;

    public PacketReader(Stream stream, int maxPacketLength)
    {
        _stream = stream;
        _maxPacketLength = maxPacketLength;
        _buffer = ArrayPool<byte>.Shared.Rent(InitialBufferSize);
    }

    /// <summary>
    /// Reads the peer's identification line and returns it without its line ending, as the exchange hash
    /// needs. A client skips any lines before it, as RFC 4253 allows servers to send them. LF alone is
    /// accepted as a line ending, because some servers use it.
    /// </summary>
    public async ValueTask<byte[]> ReadIdentificationAsync(bool allowPreamble, CancellationToken cancellationToken)
    {
        int lines = 0;
        int total = 0;
        while (true)
        {
            int lineFeed = _buffer.AsSpan(_start, _end - _start).IndexOf((byte)'\n');
            if (lineFeed < 0)
            {
                if (_end - _start >= MaxPreambleBytes || total + (_end - _start) > MaxPreambleBytes)
                {
                    throw new SshProtocolException("The peer's identification is too long. Check that the port runs SSH.");
                }

                await FillAsync(_end - _start + 1, cancellationToken).ConfigureAwait(false);
                continue;
            }

            ReadOnlySpan<byte> line = _buffer.AsSpan(_start, lineFeed);
            if (line.EndsWith("\r"u8))
            {
                line = line[..^1];
            }

            total += lineFeed + 1;
            _start += lineFeed + 1;
            if (line.StartsWith("SSH-"u8))
            {
                return ValidateIdentification(line, lineFeed + 1);
            }

            if (!allowPreamble)
            {
                throw new SshProtocolException("The peer didn't start with an SSH identification line. Check that it's an SSH client.");
            }

            if (++lines > MaxPreambleLines || total > MaxPreambleBytes)
            {
                throw new SshProtocolException("The peer sent too many lines before its identification. Check that the port runs SSH.");
            }
        }
    }

    /// <summary>
    /// Reads and opens one packet, and returns its payload. The result is valid until the next call.
    /// </summary>
    public async ValueTask<ReadOnlyMemory<byte>> ReadPacketAsync(PacketCipher cipher, uint sequenceNumber, CancellationToken cancellationToken)
    {
        // The caller has finished with the last packet, and its plaintext can hold passwords.
        _buffer.AsSpan(_start - _lastPacketLength, _lastPacketLength).Clear();
        _lastPacketLength = 0;

        // Encrypt-and-MAC needs a whole cipher block to decrypt the length. Every valid packet is at least that long,
        // so waiting for it never waits for more than the peer must send anyway.
        int lengthBlock = cipher.LengthBlockSize;
        if (_end - _start < lengthBlock)
        {
            await FillAsync(lengthBlock, cancellationToken).ConfigureAwait(false);
        }

        // Every check on the length comes before the read or the buffer growth it would cause.
        uint packetLength = cipher.ReadPacketLength(_buffer.AsSpan(_start, lengthBlock), sequenceNumber);
        if (packetLength < MinPacketLength || packetLength > (uint)_maxPacketLength)
        {
            throw new SshProtocolException("The peer sent a packet with an invalid length.");
        }

        int total = 4 + (int)packetLength + cipher.TagLength;
        if (_end - _start < total)
        {
            await FillAsync(total, cancellationToken).ConfigureAwait(false);
        }

        Span<byte> packet = _buffer.AsSpan(_start, total);
        cipher.Open(packet, sequenceNumber);
        int padding = packet[4];
        int payloadLength = (int)packetLength - 1 - padding;
        if (padding < MinPadding || payloadLength < 1)
        {
            throw new SshProtocolException("The peer sent a packet with invalid padding.");
        }

        ReadOnlyMemory<byte> payload = _buffer.AsMemory(_start + 5, payloadLength);
        _start += total;
        _lastPacketLength = total;
        return payload;
    }

    public void Dispose()
    {
        byte[] buffer = _buffer;
        _buffer = [];
        _start = 0;
        _end = 0;
        if (buffer.Length != 0)
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    private static byte[] ValidateIdentification(ReadOnlySpan<byte> line, int rawLength)
    {
        if (rawLength > MaxIdentificationLine)
        {
            throw new SshProtocolException("The peer's identification line is too long.");
        }

        foreach (byte b in line)
        {
            if (b is < 0x20 or >= 0x7F)
            {
                throw new SshProtocolException("The peer's identification line holds invalid characters.");
            }
        }

        if (!line.StartsWith("SSH-2.0-"u8) && !line.StartsWith("SSH-1.99-"u8))
        {
            throw new SshProtocolException("The peer doesn't speak SSH version 2.");
        }

        return line.ToArray();
    }

    /// <summary>Reads until at least <paramref name="needed"/> bytes are available from the current position.</summary>
    private async ValueTask FillAsync(int needed, CancellationToken cancellationToken)
    {
        if (_start + needed > _buffer.Length)
        {
            MakeRoom(needed);
        }

        while (_end - _start < needed)
        {
            int read = await _stream.ReadAsync(_buffer.AsMemory(_end), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new SshConnectionException("The peer closed the connection. Connect again to continue.");
            }

            _end += read;
        }
    }

    private void MakeRoom(int needed)
    {
        int count = _end - _start;
        if (needed <= _buffer.Length)
        {
            _buffer.AsSpan(_start, count).CopyTo(_buffer);
            _buffer.AsSpan(count, _end - count).Clear();
        }
        else
        {
            byte[] larger = ArrayPool<byte>.Shared.Rent(needed);
            _buffer.AsSpan(_start, count).CopyTo(larger);
            ArrayPool<byte>.Shared.Return(_buffer, clearArray: true);
            _buffer = larger;
        }

        _start = 0;
        _end = count;
    }
}

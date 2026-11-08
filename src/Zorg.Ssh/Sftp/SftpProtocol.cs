using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Text;
using System.Text.Unicode;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Sftp;

/// <summary>Packet types from draft-ietf-secsh-filexfer-02.</summary>
internal static class SftpMessage
{
    public const byte Init = 1;
    public const byte Version = 2;
    public const byte Open = 3;
    public const byte Close = 4;
    public const byte Read = 5;
    public const byte Write = 6;
    public const byte Lstat = 7;
    public const byte Fstat = 8;
    public const byte SetStat = 9;
    public const byte FSetStat = 10;
    public const byte OpenDir = 11;
    public const byte ReadDir = 12;
    public const byte Remove = 13;
    public const byte MkDir = 14;
    public const byte RmDir = 15;
    public const byte RealPath = 16;
    public const byte Stat = 17;
    public const byte Rename = 18;
    public const byte ReadLink = 19;
    public const byte SymLink = 20;
    public const byte Status = 101;
    public const byte Handle = 102;
    public const byte Data = 103;
    public const byte Name = 104;
    public const byte Attrs = 105;
    public const byte Extended = 200;
    public const byte ExtendedReply = 201;
}

/// <summary>Open flags from the draft.</summary>
[Flags]
internal enum SftpOpenFlags : uint
{
    Read = 0x01,
    Write = 0x02,
    Append = 0x04,
    Create = 0x08,
    Truncate = 0x10,
    Exclusive = 0x20,
}

/// <summary>Every limit a session applies. Tests shrink them; everything else uses <see cref="Default"/>.</summary>
internal sealed record SftpLimits
{
    public const int MaxDataLength = 256 * 1024;

    public static SftpLimits Default { get; } = new();

    /// <summary>Gets the largest packet accepted, excluding its length field. Checked before anything is allocated.</summary>
    public int MaxPacketLength { get; init; } = MaxDataLength + 64;

    /// <summary>Gets the most requests on the wire. With the packet limit, this bounds what a session can hold.</summary>
    public int MaxOutstandingRequests { get; init; } = 128;

    /// <summary>Gets the most names accepted in one NAME packet. OpenSSH sends up to 100.</summary>
    public int MaxNamesPerBatch { get; init; } = 4096;

    /// <summary>Gets the most extensions accepted in VERSION. OpenSSH sends about a dozen.</summary>
    public int MaxExtensions { get; init; } = 256;

    /// <summary>Gets how many reads or writes one transfer keeps in flight.</summary>
    public int TransferDepth { get; init; } = 64;

    /// <summary>
    /// Gets the size of one READ. Servers are only required to serve 32 KiB, and older OpenSSH stops at 64 KiB.
    /// </summary>
    public int ReadChunk { get; init; } = 32 * 1024;

    /// <summary>Gets the size of one WRITE.</summary>
    public int WriteChunk { get; init; } = 32 * 1024;

    /// <summary>Gets how many empty answers in a row are tolerated before a server counts as stalling on purpose.</summary>
    public int MaxEmptyResponses { get; init; } = 16;
}

/// <summary>A request ready to send. The session returns <see cref="Buffer"/> to the pool.</summary>
internal readonly record struct SftpFrame(byte[] Buffer, int Length);

/// <summary>Builds request packets. The first 9 bytes stay free for the length, type and id.</summary>
internal static class SftpFrames
{
    public const int HeaderLength = 9;

    public static SftpFrame Path(string path)
    {
        SshWriter writer = NewWriter();
        writer.WriteUtf8String(path);
        return Detach(ref writer);
    }

    public static SftpFrame TwoPaths(string first, string second)
    {
        SshWriter writer = NewWriter();
        writer.WriteUtf8String(first);
        writer.WriteUtf8String(second);
        return Detach(ref writer);
    }

    public static SftpFrame PathAndAttributes(string path, SftpAttributes attributes)
    {
        SshWriter writer = NewWriter();
        writer.WriteUtf8String(path);
        attributes.Write(ref writer);
        return Detach(ref writer);
    }

    public static SftpFrame HandleAndAttributes(byte[] handle, SftpAttributes attributes)
    {
        SshWriter writer = NewWriter();
        writer.WriteBinary(handle);
        attributes.Write(ref writer);
        return Detach(ref writer);
    }

    public static SftpFrame Handle(byte[] handle)
    {
        SshWriter writer = NewWriter();
        writer.WriteBinary(handle);
        return Detach(ref writer);
    }

    public static SftpFrame Open(string path, SftpOpenFlags flags)
    {
        SshWriter writer = NewWriter();
        writer.WriteUtf8String(path);
        writer.WriteUInt32((uint)flags);
        writer.WriteUInt32(0);
        return Detach(ref writer);
    }

    public static SftpFrame Read(byte[] handle, long offset, int length)
    {
        SshWriter writer = NewWriter();
        writer.WriteBinary(handle);
        writer.WriteUInt64((ulong)offset);
        writer.WriteUInt32((uint)length);
        return Detach(ref writer);
    }

    /// <summary>Builds a WRITE directly in a pooled buffer, because this is the one large request.</summary>
    public static SftpFrame Write(byte[] handle, long offset, ReadOnlySpan<byte> data)
    {
        int length = HeaderLength + 4 + handle.Length + 8 + 4 + data.Length;
        byte[] buffer = ArrayPool<byte>.Shared.Rent(length);
        Span<byte> span = buffer.AsSpan(HeaderLength);
        BinaryPrimitives.WriteUInt32BigEndian(span, (uint)handle.Length);
        handle.CopyTo(span[4..]);
        span = span[(4 + handle.Length)..];
        BinaryPrimitives.WriteUInt64BigEndian(span, (ulong)offset);
        BinaryPrimitives.WriteUInt32BigEndian(span[8..], (uint)data.Length);
        data.CopyTo(span[12..]);
        return new SftpFrame(buffer, length);
    }

    public static SftpFrame Extended(string name)
    {
        SshWriter writer = NewWriter();
        writer.WriteUtf8String(name);
        return Detach(ref writer);
    }

    public static SftpFrame ExtendedPath(string name, string path)
    {
        SshWriter writer = NewWriter();
        writer.WriteUtf8String(name);
        writer.WriteUtf8String(path);
        return Detach(ref writer);
    }

    public static SftpFrame ExtendedTwoPaths(string name, string first, string second)
    {
        SshWriter writer = NewWriter();
        writer.WriteUtf8String(name);
        writer.WriteUtf8String(first);
        writer.WriteUtf8String(second);
        return Detach(ref writer);
    }

    public static SftpFrame ExtendedHandle(string name, byte[] handle)
    {
        SshWriter writer = NewWriter();
        writer.WriteUtf8String(name);
        writer.WriteBinary(handle);
        return Detach(ref writer);
    }

    /// <summary>Builds copy-data: the whole of one handle, to the start of another.</summary>
    public static SftpFrame CopyData(byte[] source, byte[] destination)
    {
        SshWriter writer = NewWriter();
        writer.WriteUtf8String("copy-data");
        writer.WriteBinary(source);
        writer.WriteUInt64(0);
        writer.WriteUInt64(0);
        writer.WriteBinary(destination);
        writer.WriteUInt64(0);
        return Detach(ref writer);
    }

    private static SshWriter NewWriter() => new(256, HeaderLength);

    private static SftpFrame Detach(ref SshWriter writer)
    {
        try
        {
            byte[] buffer = ArrayPool<byte>.Shared.Rent(writer.Length);
            writer.Written.CopyTo(buffer);
            return new SftpFrame(buffer, writer.Length);
        }
        finally
        {
            writer.Dispose();
        }
    }
}

/// <summary>One packet from the server, in a pooled buffer. Dispose returns it, cleared, because it can hold file contents.</summary>
internal sealed class SftpResponse(byte type, byte[] buffer, int length) : IDisposable
{
    private byte[]? _buffer = buffer;

    /// <summary>Gets the packet type.</summary>
    public byte Type { get; } = type;

    /// <summary>Gets the bytes after the request id.</summary>
    public ReadOnlySpan<byte> Body => _buffer.AsSpan(0, length);

    /// <summary>Gets part of the body, to hand to a stream.</summary>
    public ReadOnlyMemory<byte> Slice(int offset, int count) => _buffer.AsMemory(offset, count);

    public void Dispose()
    {
        byte[]? buffer = _buffer;
        _buffer = null;
        if (buffer is not null)
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }
}

/// <summary>Reads response bodies. Everything goes through <see cref="SshReader"/>, so malformed input is an <see cref="SshProtocolException"/>.</summary>
internal static class SftpParser
{
    /// <summary>The longest handle the draft allows.</summary>
    public const int MaxHandleLength = 256;

    private const int MinNameEntryLength = 12;
    private const int MaxServerMessageLength = 256;

    /// <summary>
    /// Decodes a name, or other text the server chose. Version 3 names are bytes, so bad UTF-8 is legal here: it
    /// becomes U+FFFD. A caller that keeps a name checks <see cref="Utf8.IsValid"/> first.
    /// </summary>
    public static string DecodeString(ReadOnlySpan<byte> bytes) => Encoding.UTF8.GetString(bytes);

    /// <summary>Reads a status as code and message. Servers older than the draft stop after the code.</summary>
    public static (SftpStatusCode Code, string Message) ReadStatus(SftpResponse response)
    {
        SshReader reader = new(response.Body);
        SftpStatusCode code = (SftpStatusCode)reader.ReadUInt32();
        string message = reader.Remaining == 0 ? string.Empty : Sanitise(DecodeString(reader.ReadBinary()));
        return (code, message);
    }

    /// <summary>
    /// Reads only the code of a status, with the same checks on its shape as <see cref="ReadStatus"/>, for the callers
    /// that have no use for the text: OK and EOF. Decoding and cleaning the text would cost a few allocations a reply.
    /// </summary>
    public static SftpStatusCode ReadStatusCode(SftpResponse response)
    {
        SshReader reader = new(response.Body);
        SftpStatusCode code = (SftpStatusCode)reader.ReadUInt32();
        if (reader.Remaining != 0)
        {
            reader.ReadBinary();
        }

        return code;
    }

    public static byte[] ReadHandle(SftpResponse response)
    {
        SshReader reader = new(response.Body);
        ReadOnlySpan<byte> handle = reader.ReadBinary();
        if (handle.IsEmpty || handle.Length > MaxHandleLength)
        {
            throw new SshProtocolException($"The SFTP server sent a handle of {handle.Length} bytes. The limit is {MaxHandleLength}, and it can't be empty.");
        }

        return handle.ToArray();
    }

    /// <summary>Reads DATA, as a position in the body so no copy is made.</summary>
    public static (int Offset, int Length) ReadData(SftpResponse response, int requested)
    {
        SshReader reader = new(response.Body);
        int length = reader.ReadBinary().Length;
        if (length > requested)
        {
            throw new SshProtocolException($"The SFTP server answered a read of {requested} bytes with {length} bytes.");
        }

        return (response.Body.Length - reader.Remaining - length, length);
    }

    public static SftpEntry[] ReadNames(SftpResponse response, int maxNames)
    {
        SshReader reader = new(response.Body);
        uint count = reader.ReadUInt32();
        if (count > (uint)maxNames)
        {
            throw new SshProtocolException($"The SFTP server sent {count} names in one packet. The limit is {maxNames}.");
        }

        // Checked before the array is made, so a count can't cost more memory than the packet itself did.
        if ((long)count * MinNameEntryLength > reader.Remaining)
        {
            throw new SshProtocolException("The SFTP server sent a malformed message: the name count exceeds the packet.");
        }

        SftpEntry[] entries = new SftpEntry[count];
        for (int i = 0; i < entries.Length; i++)
        {
            ReadOnlySpan<byte> nameBytes = reader.ReadBinary();
            bool validName = Utf8.IsValid(nameBytes);
            string name = DecodeString(nameBytes);
            reader.ReadBinary();
            entries[i] = new SftpEntry { Name = name, HasValidName = validName, Attributes = SftpAttributes.Read(ref reader) };
        }

        return entries;
    }

    public static SftpAttributes ReadAttributes(SftpResponse response)
    {
        SshReader reader = new(response.Body);
        return SftpAttributes.Read(ref reader);
    }

    public static SftpFileSystemInfo ReadFileSystemInfo(SftpResponse response)
    {
        const ulong ReadOnlyFlag = 1;
        SshReader reader = new(response.Body);
        ulong blockSize = reader.ReadUInt64();
        ulong fragmentSize = reader.ReadUInt64();
        ulong blocks = reader.ReadUInt64();
        ulong freeBlocks = reader.ReadUInt64();
        ulong availableBlocks = reader.ReadUInt64();
        ulong files = reader.ReadUInt64();
        ulong freeFiles = reader.ReadUInt64();
        ulong availableFiles = reader.ReadUInt64();
        ulong id = reader.ReadUInt64();
        ulong flags = reader.ReadUInt64();
        ulong maxName = reader.ReadUInt64();
        return new SftpFileSystemInfo
        {
            BlockSize = blockSize,
            FragmentSize = fragmentSize,
            Blocks = blocks,
            FreeBlocks = freeBlocks,
            AvailableBlocks = availableBlocks,
            Files = files,
            FreeFiles = freeFiles,
            AvailableFiles = availableFiles,
            FileSystemId = id,
            IsReadOnly = (flags & ReadOnlyFlag) != 0,
            MaxNameLength = maxName,
        };
    }

    /// <summary>Removes control characters and caps the length: this text is server-controlled and goes into exception messages.</summary>
    public static string Sanitise(string text)
    {
        ReadOnlySpan<char> span = text.AsSpan(0, Math.Min(text.Length, MaxServerMessageLength));
        StringBuilder clean = new(span.Length);
        foreach (char c in span)
        {
            if (!char.IsControl(c))
            {
                clean.Append(c);
            }
        }

        return clean.ToString();
    }

    /// <summary>The exception for a status that isn't what the caller wanted.</summary>
    public static SftpException ToException(SftpStatusCode code, string message, string? path)
    {
        string where = path is null ? string.Empty : $" on '{Sanitise(path)}'";
        string said = message.Length == 0 ? string.Empty : $" The server said: {message}";
        return code switch
        {
            SftpStatusCode.NoSuchFile => new SftpFileNotFoundException($"The file or directory doesn't exist{where}. Check the path, or create it first.{said}", path),
            SftpStatusCode.PermissionDenied => new SftpPermissionDeniedException($"Permission denied{where}. Check the account's rights on the server.{said}", path),
            SftpStatusCode.EndOfFile => new SftpException($"The server reported end of file{where} where it wasn't expected.{said}", code, path),
            SftpStatusCode.OperationUnsupported => new SftpException($"The server doesn't support this operation{where}. Use another way to do it.{said}", code, path),
            SftpStatusCode.BadMessage => new SftpException($"The server didn't understand the request{where}. It may not fully support SFTP version 3.{said}", code, path),
            _ => new SftpException($"The server refused the request{where} with status {(uint)code}. The target may already exist, or the file may be in use.{said}", code, path),
        };
    }
}

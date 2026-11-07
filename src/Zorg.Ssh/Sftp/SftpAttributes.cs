using System;
using System.IO;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Sftp;

/// <summary>
/// File attributes. From a server, a property is null if the server didn't send it. For
/// <see cref="SftpClient.SetAttributesAsync"/>, only the properties you set are changed.
/// </summary>
/// <example>
/// <code>
/// SftpAttributes attributes = await sftp.GetAttributesAsync("/var/log/app.log", cancellationToken);
/// Console.WriteLine($"{attributes.Size} bytes, changed {attributes.ModifiedTime}");
///
/// await sftp.SetAttributesAsync(
///     "/srv/secret.key",
///     new SftpAttributes { Permissions = UnixFileMode.UserRead | UnixFileMode.UserWrite },
///     cancellationToken);
/// </code>
/// </example>
public sealed record SftpAttributes
{
    internal const uint TypeDirectory = 0x4000;
    internal const uint TypeRegular = 0x8000;
    internal const uint TypeSymbolicLink = 0xA000;

    private const uint FlagSize = 0x00000001;
    private const uint FlagUidGid = 0x00000002;
    private const uint FlagPermissions = 0x00000004;
    private const uint FlagTimes = 0x00000008;
    private const uint FlagExtended = 0x80000000;

    private const uint TypeMask = 0xF000;
    private const uint PermissionMask = 0xFFF;

    private readonly uint? _fileType;

    /// <summary>Gets the size in bytes. Setting it truncates or extends the file.</summary>
    /// <example>
    /// <code>
    /// await sftp.SetAttributesAsync(path, new SftpAttributes { Size = 0 }, cancellationToken);
    /// </code>
    /// </example>
    public long? Size { get; init; }

    /// <summary>Gets the numeric owner. Set <see cref="Gid"/> with it, because the protocol sends them together.</summary>
    /// <example>
    /// <code>
    /// await sftp.SetAttributesAsync(path, new SftpAttributes { Uid = 1000, Gid = 1000 }, cancellationToken);
    /// </code>
    /// </example>
    public uint? Uid { get; init; }

    /// <summary>Gets the numeric group. Set <see cref="Uid"/> with it, because the protocol sends them together.</summary>
    /// <example>
    /// <code>
    /// Console.WriteLine(attributes.Gid);
    /// </code>
    /// </example>
    public uint? Gid { get; init; }

    /// <summary>Gets the permission bits, including setuid, setgid and sticky. The file type isn't part of this.</summary>
    /// <example>
    /// <code>
    /// bool groupCanWrite = attributes.Permissions?.HasFlag(UnixFileMode.GroupWrite) == true;
    /// </code>
    /// </example>
    public UnixFileMode? Permissions { get; init; }

    /// <summary>Gets the time of the last change, to the second. Set <see cref="AccessTime"/> with it, because the protocol sends them together.</summary>
    /// <example>
    /// <code>
    /// await sftp.SetAttributesAsync(
    ///     path,
    ///     new SftpAttributes { ModifiedTime = DateTimeOffset.UtcNow, AccessTime = DateTimeOffset.UtcNow },
    ///     cancellationToken);
    /// </code>
    /// </example>
    public DateTimeOffset? ModifiedTime { get; init; }

    /// <summary>Gets the time of the last access, to the second. Set <see cref="ModifiedTime"/> with it, because the protocol sends them together.</summary>
    /// <example>
    /// <code>
    /// Console.WriteLine(attributes.AccessTime);
    /// </code>
    /// </example>
    public DateTimeOffset? AccessTime { get; init; }

    /// <summary>Gets a value saying whether this is a directory. It's false if the server sent no permissions.</summary>
    /// <example>
    /// <code>
    /// if (entry.Attributes.IsDirectory)
    /// {
    ///     Console.WriteLine($"{entry.Name}/");
    /// }
    /// </code>
    /// </example>
    public bool IsDirectory => _fileType == TypeDirectory;

    /// <summary>Gets a value saying whether this is a regular file. It's false if the server sent no permissions.</summary>
    /// <example>
    /// <code>
    /// long total = entry.Attributes.IsRegularFile ? entry.Attributes.Size ?? 0 : 0;
    /// </code>
    /// </example>
    public bool IsRegularFile => _fileType == TypeRegular;

    /// <summary>Gets a value saying whether this is a symbolic link. Only a listing or <c>followSymbolicLinks: false</c> can report one.</summary>
    /// <example>
    /// <code>
    /// if (entry.Attributes.IsSymbolicLink)
    /// {
    ///     string target = await sftp.ReadLinkAsync($"{directory}/{entry.Name}", cancellationToken);
    /// }
    /// </code>
    /// </example>
    public bool IsSymbolicLink => _fileType == TypeSymbolicLink;

    /// <summary>Gets a value saying whether the server sent the file type at all.</summary>
    internal bool HasFileType => _fileType is not null;

    private uint? FileType
    {
        get => _fileType;
        init => _fileType = value;
    }

    /// <summary>Reads an attribute block. Extended pairs are skipped, and each costs at least 8 bytes of a bounded packet.</summary>
    internal static SftpAttributes Read(ref SshReader reader)
    {
        uint flags = reader.ReadUInt32();
        long? size = null;
        if ((flags & FlagSize) != 0)
        {
            ulong value = reader.ReadUInt64();
            if (value > long.MaxValue)
            {
                throw new SshProtocolException("The SFTP server sent a malformed message: a file size is out of range.");
            }

            size = (long)value;
        }

        uint? uid = null;
        uint? gid = null;
        if ((flags & FlagUidGid) != 0)
        {
            uid = reader.ReadUInt32();
            gid = reader.ReadUInt32();
        }

        UnixFileMode? permissions = null;
        uint? fileType = null;
        if ((flags & FlagPermissions) != 0)
        {
            uint mode = reader.ReadUInt32();
            permissions = (UnixFileMode)(mode & PermissionMask);
            fileType = mode & TypeMask;
        }

        DateTimeOffset? accessTime = null;
        DateTimeOffset? modifiedTime = null;
        if ((flags & FlagTimes) != 0)
        {
            accessTime = DateTimeOffset.FromUnixTimeSeconds(reader.ReadUInt32());
            modifiedTime = DateTimeOffset.FromUnixTimeSeconds(reader.ReadUInt32());
        }

        if ((flags & FlagExtended) != 0)
        {
            uint count = reader.ReadUInt32();
            for (uint i = 0; i < count; i++)
            {
                reader.ReadBinary();
                reader.ReadBinary();
            }
        }

        return new SftpAttributes
        {
            Size = size,
            Uid = uid,
            Gid = gid,
            Permissions = permissions,
            FileType = fileType,
            AccessTime = accessTime,
            ModifiedTime = modifiedTime,
        };
    }

    /// <summary>Checks what can't be sent. Call before building a packet.</summary>
    internal void Validate(string parameterName)
    {
        if (Size < 0)
        {
            throw new ArgumentException("Size can't be negative.", parameterName);
        }

        if (Uid.HasValue != Gid.HasValue)
        {
            throw new ArgumentException("Set Uid and Gid together: the protocol sends them as a pair. Read the current values with GetAttributesAsync.", parameterName);
        }

        if (ModifiedTime.HasValue != AccessTime.HasValue)
        {
            throw new ArgumentException("Set ModifiedTime and AccessTime together: the protocol sends them as a pair. Read the current values with GetAttributesAsync.", parameterName);
        }

        if (ModifiedTime is { } modified && AccessTime is { } access && (!Fits(modified) || !Fits(access)))
        {
            throw new ArgumentException("SFTP version 3 can only send times from 1970 to 2106.", parameterName);
        }
    }

    /// <summary>Builds what a server reports. Times outside what version 3 can send are clamped.</summary>
    internal static SftpAttributes ForServer(long size, UnixFileMode permissions, uint fileType, DateTimeOffset accessTime, DateTimeOffset modifiedTime) => new()
    {
        Size = size,
        Permissions = permissions,
        FileType = fileType,
        AccessTime = Clamp(accessTime),
        ModifiedTime = Clamp(modifiedTime),
    };

    /// <summary>Writes an attribute block with what's set.</summary>
    internal void Write(ref SshWriter writer) => Write(ref writer, 0);

    /// <summary>Writes a block for a client to read, which needs the file type beside the permission bits.</summary>
    internal void WriteWithFileType(ref SshWriter writer) => Write(ref writer, _fileType ?? 0);

    private static DateTimeOffset Clamp(DateTimeOffset time) => DateTimeOffset.FromUnixTimeSeconds(Math.Clamp(time.ToUnixTimeSeconds(), 0, uint.MaxValue));

    private void Write(ref SshWriter writer, uint fileType)
    {
        uint flags = (Size.HasValue ? FlagSize : 0)
            | (Uid.HasValue ? FlagUidGid : 0)
            | (Permissions.HasValue ? FlagPermissions : 0)
            | (ModifiedTime.HasValue ? FlagTimes : 0);
        writer.WriteUInt32(flags);
        if (Size is { } size)
        {
            writer.WriteUInt64((ulong)size);
        }

        if (Uid is { } uid && Gid is { } gid)
        {
            writer.WriteUInt32(uid);
            writer.WriteUInt32(gid);
        }

        if (Permissions is { } permissions)
        {
            writer.WriteUInt32(((uint)permissions & PermissionMask) | fileType);
        }

        if (AccessTime is { } access && ModifiedTime is { } modified)
        {
            writer.WriteUInt32((uint)access.ToUnixTimeSeconds());
            writer.WriteUInt32((uint)modified.ToUnixTimeSeconds());
        }
    }

    private static bool Fits(DateTimeOffset time) => time.ToUnixTimeSeconds() is >= 0 and <= uint.MaxValue;
}

/// <summary>One directory entry from <see cref="SftpClient.ListDirectoryAsync"/>.</summary>
/// <example>
/// <code>
/// await foreach (SftpEntry entry in sftp.ListDirectoryAsync("/var/log", cancellationToken))
/// {
///     if (entry.IsSafeName)
///     {
///         Console.WriteLine($"{entry.Name}: {entry.Attributes.Size}");
///     }
/// }
/// </code>
/// </example>
public sealed record SftpEntry
{
    /// <summary>
    /// Gets the name exactly as the server sent it, so it's untrusted: it can hold <c>../</c>, a slash or a control
    /// character. Check <see cref="IsSafeName"/> before using it in a local path. Bytes that aren't valid UTF-8
    /// become U+FFFD, so such a name can't be used to reach the file.
    /// </summary>
    public required string Name { get; init; }

    /// <summary>Gets what the server said about the entry, without following symbolic links.</summary>
    public required SftpAttributes Attributes { get; init; }

    /// <summary>
    /// Gets a value saying whether <see cref="Name"/> is a plain file name on this machine: it isn't <c>.</c> or
    /// <c>..</c>, and has no slash, backslash, NUL or anything else this operating system would treat specially.
    /// </summary>
    /// <example>
    /// <code>
    /// if (entry.IsSafeName)
    /// {
    ///     string local = Path.Join(destination, entry.Name);
    /// }
    /// </code>
    /// </example>
    public bool IsSafeName => SftpLocalPath.IsSafeName(Name);
}

/// <summary>What <see cref="SftpClient.GetFileSystemInfoAsync"/> reports, in the terms of POSIX <c>statvfs</c>. Every value is the server's.</summary>
/// <example>
/// <code>
/// SftpFileSystemInfo info = await sftp.GetFileSystemInfoAsync("/srv", cancellationToken);
/// Console.WriteLine($"{info.AvailableBytes} bytes free");
/// </code>
/// </example>
public sealed record SftpFileSystemInfo
{
    internal SftpFileSystemInfo()
    {
    }

    /// <summary>Gets the preferred block size.</summary>
    public ulong BlockSize { get; init; }

    /// <summary>Gets the unit the block counts use.</summary>
    public ulong FragmentSize { get; init; }

    /// <summary>Gets the size of the file system, in fragments.</summary>
    public ulong Blocks { get; init; }

    /// <summary>Gets the free fragments.</summary>
    public ulong FreeBlocks { get; init; }

    /// <summary>Gets the fragments free for an unprivileged user.</summary>
    public ulong AvailableBlocks { get; init; }

    /// <summary>Gets the number of file nodes.</summary>
    public ulong Files { get; init; }

    /// <summary>Gets the free file nodes.</summary>
    public ulong FreeFiles { get; init; }

    /// <summary>Gets the file nodes free for an unprivileged user.</summary>
    public ulong AvailableFiles { get; init; }

    /// <summary>Gets the file system's id.</summary>
    public ulong FileSystemId { get; init; }

    /// <summary>Gets whether it's mounted read-only.</summary>
    public bool IsReadOnly { get; init; }

    /// <summary>Gets the longest allowed file name.</summary>
    public ulong MaxNameLength { get; init; }

    /// <summary>Gets the bytes free for an unprivileged user. It's computed from values the server chose.</summary>
    /// <example>
    /// <code>
    /// if (info.AvailableBytes &lt; requiredBytes)
    /// {
    ///     throw new IOException("Not enough space on the server.");
    /// }
    /// </code>
    /// </example>
    public ulong AvailableBytes => unchecked(AvailableBlocks * (FragmentSize == 0 ? BlockSize : FragmentSize));
}

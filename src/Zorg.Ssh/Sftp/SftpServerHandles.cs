using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace Zorg.Ssh.Sftp;

/// <summary>An open file. The stream is only there to own the handle: reads and writes are positional.</summary>
internal sealed class SftpServerFile(FileStream stream, bool canRead, bool canWrite, bool append) : IDisposable
{
    public FileStream Stream { get; } = stream;

    public SafeFileHandle Handle => Stream.SafeFileHandle;

    public bool CanRead { get; } = canRead;

    public bool CanWrite { get; } = canWrite;

    public bool Append { get; } = append;

    public void Dispose() => Stream.Dispose();
}

/// <summary>An entry of a listing. <paramref name="RawName"/> holds the name's bytes when they aren't UTF-8, and is null otherwise.</summary>
internal readonly record struct SftpServerListedEntry(string Name, byte[]? RawName, SftpAttributes Attributes);

/// <summary>
/// Reads a directory an entry at a time, without <c>.</c> and <c>..</c>. An entry that can't be looked at is left out.
/// A directory that can't be opened is not an empty one: opening it throws <see cref="UnauthorizedAccessException"/>,
/// which the session answers with permission denied, as OpenSSH does.
/// </summary>
internal abstract class SftpServerListing : IDisposable
{
    private static readonly EnumerationOptions ListingOptions = new()
    {
        AttributesToSkip = 0,
        IgnoreInaccessible = false,
        RecurseSubdirectories = false,
        ReturnSpecialDirectories = false,
    };

    /// <summary>
    /// Opens a directory to list it. On Linux it's read as bytes (<see cref="SftpServerLinux"/>), so a name that isn't
    /// UTF-8 is listed as it is, with its own attributes. Elsewhere .NET reads it.
    /// </summary>
    public static SftpServerListing Open(string path) =>
        SftpServerLinux.IsSupported ? SftpServerLinux.OpenListing(path) : OpenWithDotNet(path);

    /// <summary>Opens a directory through .NET, which decodes each name with U+FFFD in place of bytes that aren't UTF-8.</summary>
    internal static SftpServerListing OpenWithDotNet(string path)
    {
        // .NET opens the directory on the first MoveNext, so do that now: a directory that can't be opened has to fail
        // here, not turn into a listing with nothing in it.
        IEnumerator<FileSystemInfo> entries = new DirectoryInfo(path).EnumerateFileSystemInfos("*", ListingOptions).GetEnumerator();
        try
        {
            bool any = entries.MoveNext();
            SftpServerListing listing = new DotNetListing(entries, any);
            entries = null!;
            return listing;
        }
        finally
        {
            entries?.Dispose();
        }
    }

    public abstract bool TryNext(out SftpServerListedEntry entry);

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected abstract void Dispose(bool disposing);

    private sealed class DotNetListing(IEnumerator<FileSystemInfo> entries, bool hasCurrent) : SftpServerListing
    {
        private bool _hasCurrent = hasCurrent;

        public override bool TryNext(out SftpServerListedEntry entry)
        {
            while (_hasCurrent)
            {
                FileSystemInfo info = entries.Current;
                _hasCurrent = Advance();
                try
                {
                    entry = new SftpServerListedEntry(info.Name, null, SftpServerAttributes.FromInfo(info));
                    return true;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    // It went away, or can't be read. Neither stops the rest of the listing.
                }
            }

            entry = default;
            return false;
        }

        protected override void Dispose(bool disposing) => entries.Dispose();

        private bool Advance()
        {
            try
            {
                return entries.MoveNext();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // The directory went away, or became unreadable, in the middle of the listing: what was read stands.
                return false;
            }
        }
    }
}

/// <summary>A listing in progress. The operating system is read as batches are asked for, so nothing grows with the directory.</summary>
internal sealed class SftpServerDirectory(SftpServerListing entries, SftpAttributes self) : IDisposable
{
    public SftpServerListing Entries { get; } = entries;

    /// <summary>Gets what <c>.</c> and <c>..</c> report. Using the directory itself for both means the root's real parent is never looked at.</summary>
    public SftpAttributes Self { get; } = self;

    public bool SpecialsSent { get; set; }

    public void Dispose() => Entries.Dispose();
}

/// <summary>
/// The handles of one session. A handle is 128 random bits and the only thing behind it is this table, so it says
/// nothing about the file and can't be guessed or carried to another session.
/// </summary>
internal sealed class SftpServerHandles(int limit) : IDisposable
{
    private const int HandleLength = 16;

    private readonly Dictionary<UInt128, IDisposable> _open = [];

    public bool IsFull => _open.Count >= limit;

    public byte[] Add(IDisposable entry)
    {
        byte[] handle = new byte[HandleLength];
        do
        {
            RandomNumberGenerator.Fill(handle);
        }
        while (!_open.TryAdd(BinaryPrimitives.ReadUInt128BigEndian(handle), entry));

        return handle;
    }

    public T Get<T>(ReadOnlySpan<byte> handle)
        where T : class, IDisposable =>
        Find(handle) as T ?? throw new SftpServerRefusedException(SftpStatusCode.Failure);

    /// <summary>Forgets a handle and closes what's behind it.</summary>
    public void Close(ReadOnlySpan<byte> handle)
    {
        IDisposable entry = Find(handle) ?? throw new SftpServerRefusedException(SftpStatusCode.Failure);
        _open.Remove(BinaryPrimitives.ReadUInt128BigEndian(handle));
        entry.Dispose();
    }

    /// <summary>Closes everything left open. A failure closing one must not leave the others open.</summary>
    public void Dispose()
    {
        foreach (IDisposable entry in _open.Values)
        {
            try
            {
                entry.Dispose();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // The session is over, and there's nobody to tell.
            }
        }

        _open.Clear();
    }

    private IDisposable? Find(ReadOnlySpan<byte> handle) =>
        handle.Length == HandleLength && _open.TryGetValue(BinaryPrimitives.ReadUInt128BigEndian(handle), out IDisposable? entry) ? entry : null;
}

/// <summary>Turns what the file system says into what the protocol says.</summary>
internal static class SftpServerAttributes
{
    /// <summary>The bits a client may set: never setuid, setgid or sticky, which on a client's own upload could hand it the server's account.</summary>
    public const UnixFileMode ClientMode = (UnixFileMode)0x1FF;

    private const UnixFileMode DirectoryMode = (UnixFileMode)0x1ED;
    private const UnixFileMode FileMode = (UnixFileMode)0x1A4;
    private const UnixFileMode ReadOnlyFileMode = (UnixFileMode)0x124;
    private const UnixFileMode LinkMode = (UnixFileMode)0x1FF;

    /// <summary>
    /// Describes an entry without following it. On Windows the permission bits are made up from the attributes. .NET
    /// calls a FIFO, socket or device a file, so on Linux and macOS its real type is read: a client that checks
    /// <see cref="SftpAttributes.IsRegularFile"/> before opening must not be told a FIFO is one. Only those four types
    /// replace what .NET said. Elsewhere on Unix there's no way to tell, and such an entry is reported as a regular file.
    /// </summary>
    public static SftpAttributes FromInfo(FileSystemInfo info)
    {
        FileAttributes attributes = info.Attributes;
        bool link = SftpServerPaths.ReadLinkTarget(info, attributes) is not null;
        bool directory = !link && attributes.HasFlag(FileAttributes.Directory);
        // .NET gives a link its target's permission bits (or -1 when there's no target), which would describe a file
        // that can be outside the root. A link's own bits mean nothing on Unix and are 0777 on Linux, as OpenSSH sends.
        UnixFileMode mode = OperatingSystem.IsWindows() ? WindowsMode(attributes) : link ? LinkMode : info.UnixFileMode;
        uint type = link ? SftpAttributes.TypeSymbolicLink : directory ? SftpAttributes.TypeDirectory : SftpAttributes.TypeRegular;
        if (type == SftpAttributes.TypeRegular && LocalFile.GetFileType(info.FullName, mode) is { } real && IsSpecialFileType(real))
        {
            type = real;
        }

        long size = type == SftpAttributes.TypeRegular && info is FileInfo file ? file.Length : 0;
        return SftpAttributes.ForServer(size, mode, type, info.LastAccessTimeUtc, info.LastWriteTimeUtc);
    }

    /// <summary>A FIFO, character device, block device or socket: the types .NET reports as a regular file.</summary>
    internal static bool IsSpecialFileType(uint type) => type is 0x1000 or 0x2000 or 0x6000 or 0xC000;

    public static SftpAttributes FromHandle(SafeFileHandle handle)
    {
        UnixFileMode mode = OperatingSystem.IsWindows() ? WindowsMode(File.GetAttributes(handle)) : File.GetUnixFileMode(handle);
        return SftpAttributes.ForServer(
            RandomAccess.GetLength(handle),
            mode,
            SftpAttributes.TypeRegular,
            File.GetLastAccessTimeUtc(handle),
            File.GetLastWriteTimeUtc(handle));
    }

    /// <summary>Applies a client's changes through the open file, so they land on what was checked.</summary>
    public static void Apply(SafeFileHandle handle, SftpAttributes attributes)
    {
        if (attributes.Size is { } size)
        {
            RandomAccess.SetLength(handle, size);
        }

        if (attributes.Permissions is { } permissions && !OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(handle, permissions & ClientMode);
        }

        if (attributes.ModifiedTime is { } modified && attributes.AccessTime is { } access)
        {
            File.SetLastAccessTimeUtc(handle, access.UtcDateTime);
            File.SetLastWriteTimeUtc(handle, modified.UtcDateTime);
        }
    }

    /// <summary>Applies a client's changes to a directory, which .NET can't hold open.</summary>
    public static void ApplyToDirectory(string path, SftpAttributes attributes)
    {
        if (attributes.Size is not null)
        {
            throw new SftpServerRefusedException(SftpStatusCode.Failure);
        }

        if (attributes.Permissions is { } permissions && !OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, permissions & ClientMode);
        }

        if (attributes.ModifiedTime is { } modified && attributes.AccessTime is { } access)
        {
            Directory.SetLastAccessTimeUtc(path, access.UtcDateTime);
            Directory.SetLastWriteTimeUtc(path, modified.UtcDateTime);
        }
    }

    /// <summary>The line <c>ls -l</c> shows. Owner and group would be the server's business, and .NET can't read them anyway.</summary>
    public static string LongName(string name, SftpAttributes attributes)
    {
        uint mode = (uint)(attributes.Permissions ?? 0);
        Span<char> flags = stackalloc char[10];
        flags[0] = attributes.IsSymbolicLink ? 'l' : attributes.IsDirectory ? 'd' : '-';
        for (int i = 0; i < 9; i++)
        {
            flags[i + 1] = (mode & (0x100u >> i)) == 0 ? '-' : "rwx"[i % 3];
        }

        string time = (attributes.ModifiedTime ?? DateTimeOffset.UnixEpoch).ToString("MMM dd yyyy", CultureInfo.InvariantCulture);
        return string.Create(CultureInfo.InvariantCulture, $"{flags} 1 - - {attributes.Size,10} {time} {name}");
    }

    private static UnixFileMode WindowsMode(FileAttributes attributes)
    {
        if (attributes.HasFlag(FileAttributes.Directory))
        {
            return DirectoryMode;
        }

        return attributes.HasFlag(FileAttributes.ReadOnly) ? ReadOnlyFileMode : FileMode;
    }
}

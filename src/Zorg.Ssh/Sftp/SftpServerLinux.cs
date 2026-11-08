using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Unicode;

namespace Zorg.Ssh.Sftp;

/// <summary>A file descriptor from <c>openat</c>, closed when disposed. A negative value is the invalid one, as 0 is a real descriptor.</summary>
internal sealed class SftpServerLinuxFd : SafeHandle
{
    public SftpServerLinuxFd()
        : base(-1, ownsHandle: true)
    {
    }

    public override bool IsInvalid => handle < 0;

    protected override bool ReleaseHandle() => SftpServerLinux.Close((int)handle) == 0;
}

/// <summary>
/// Reads directories below .NET on Linux, as the bytes the kernel holds. .NET decodes a name that isn't UTF-8 with
/// U+FFFD in place of the bad bytes, and then looks the entry up by that string, so it gets another entry's attributes
/// or none, and the entry can't be found again. Here a directory is opened once, its names are read with
/// <c>getdents64</c>, and each entry is looked at relative to that open directory with <c>statx</c> and
/// <c>readlinkat</c>, so the attributes are that entry's own whatever its name is.
/// </summary>
/// <remarks>
/// <para>
/// <c>getdents64</c> fills a buffer with the kernel's <c>linux_dirent64</c> records, whose layout is the same on every
/// architecture and both libcs: <c>d_ino</c> (8 bytes), <c>d_off</c> (8), <c>d_reclen</c> (2), <c>d_type</c> (1),
/// then the name and a NUL. <c>readdir</c> would hand back libc's <c>struct dirent</c>, whose layout differs on 32-bit
/// glibc, and its buffer would be libc's. glibc has exported <c>getdents64</c> since 2.30. musl's <c>getdents</c> is
/// the same call (it uses <c>SYS_getdents64</c> and the same record) and some versions export no <c>getdents64</c>,
/// so that's the fallback. <c>statx</c> has one layout everywhere too, unlike <c>struct stat</c>. glibc has it since
/// 2.28 and musl since 1.2.5. If any of these is missing, <see cref="IsSupported"/> is false and the caller uses .NET.
/// </para>
/// <para>
/// The <c>open</c> flags differ by architecture, so only the architectures whose values are known here are served this
/// way, and the directory is checked to be one after it's opened.
/// </para>
/// </remarks>
internal static partial class SftpServerLinux
{
    /// <summary>The getdents buffer of a listing. A record is at most 19 + 256 bytes, padded to 8, so this holds dozens.</summary>
    internal const int BufferLength = 8192;

    private const int AtFdCwd = -100;
    private const int AtSymlinkNoFollow = 0x100;
    private const int AtEmptyPath = 0x1000;
    private const int OCloexec = 0x80000;

    // STATX_TYPE | STATX_MODE | STATX_ATIME | STATX_MTIME | STATX_SIZE.
    private const uint StatxMask = 0x1 | 0x2 | 0x20 | 0x40 | 0x200;
    private const int StatxLength = 256;
    private const int StatxModeOffset = 28;
    private const int StatxSizeOffset = 40;
    private const int StatxAtimeOffset = 64;
    private const int StatxMtimeOffset = 112;

    private const int DirentReclenOffset = 16;
    private const int DirentTypeOffset = 18;
    private const int DirentNameOffset = 19;
    private const byte DirentUnknown = 0;
    private const byte DirentDirectory = 4;
    private const byte DirentLink = 10;

    private const uint TypeMask = 0xF000;
    private const uint TypeDirectory = 0x4000;
    private const uint TypeLink = 0xA000;

    private const int MaxLinkLength = 4096;

    private const int ENoEnt = 2;
    private const int EPerm = 1;
    private const int EAcces = 13;
    private const int ENotDir = 20;
    private const int ELoop = 40;

    private static readonly int OpenDirectoryFlags = DirectoryFlags();
    private static readonly Lazy<bool> Supported = new(Probe);
    private static bool _useGetdents;

    /// <summary>Gets a value saying whether directories are read here, rather than by .NET.</summary>
    public static bool IsSupported => OperatingSystem.IsLinux() && OpenDirectoryFlags != 0 && Supported.Value;

    /// <summary>
    /// Opens a directory to list it, never through a final link. Throws what .NET would for one that's
    /// gone, and <see cref="UnauthorizedAccessException"/> for one that can't be opened: that's not an empty directory.
    /// </summary>
    public static SftpServerListing OpenListing(string path)
    {
        SftpServerLinuxFd fd = OpenAt(AtFdCwd, ToNullTerminated(path), out int errno);
        if (fd.IsInvalid)
        {
            fd.Dispose();
            throw Error(errno);
        }

        try
        {
            // The flags are per architecture, so check what was opened is a directory, before a getdents on it.
            byte[] status = new byte[StatxLength];
            if (StatX(fd, [0], AtEmptyPath, StatxMask, status) != 0 || (Mode(status) & TypeMask) != TypeDirectory)
            {
                throw new IOException("What was opened to be listed isn't a directory.");
            }

            SftpServerListing listing = new LinuxListing(fd);
            fd = null!;
            return listing;
        }
        finally
        {
            fd?.Dispose();
        }
    }

    /// <summary>
    /// Looks at every entry below <paramref name="directory"/> without following a link, and calls
    /// <paramref name="climbsOut"/> with each link's target and its depth. A target that isn't UTF-8 is decoded with
    /// U+FFFD in place of bad bytes, which keeps every <c>/</c> and <c>.</c> where it was: those are ASCII, and no
    /// UTF-8 sequence, valid or not, takes one as a continuation byte. A bad byte inside a component makes it a plain
    /// name, which is what the kernel takes it for too. Each directory is read to the end before any below it is
    /// opened, so one buffer serves them all, and the open directories are those on the way down from the top.
    /// </summary>
    public static void ScanForClimbs(string directory, int depth, ref int budget, Func<string, int, bool> climbsOut)
    {
        byte[] buffer = new byte[BufferLength];
        byte[] status = new byte[StatxLength];
        byte[] target = new byte[MaxLinkLength + 1];
        List<ScanFrame> stack = [];
        try
        {
#pragma warning disable CA2000 // Each descriptor goes on the stack, and the finally below closes everything there.
            SftpServerLinuxFd top = OpenAt(AtFdCwd, ToNullTerminated(directory), out int errno);
            if (top.IsInvalid)
            {
                top.Dispose();
                throw Error(errno);
            }

            stack.Add(new ScanFrame(top, depth));
            while (stack.Count != 0)
            {
                ScanFrame frame = stack[^1];
                if (!frame.Read)
                {
                    ReadForScan(frame, buffer, status, target, ref budget, climbsOut);
                }

                if (frame.Next == frame.Directories.Count)
                {
                    frame.Fd.Dispose();
                    stack.RemoveAt(stack.Count - 1);
                    continue;
                }

                byte[] name = frame.Directories[frame.Next++];
                SftpServerLinuxFd child = OpenAt(frame.Fd, name, out errno);
#pragma warning restore CA2000
                if (child.IsInvalid)
                {
                    child.Dispose();
                    if (errno == ENoEnt)
                    {
                        // Gone since it was listed: there's nothing below it to move.
                        continue;
                    }

                    throw Error(errno);
                }

                stack.Add(new ScanFrame(child, frame.Depth + 1));
            }
        }
        finally
        {
            foreach (ScanFrame frame in stack)
            {
                frame.Fd.Dispose();
            }
        }
    }

    internal static int Close(int fd) => CloseFd(fd);

    private static void ReadForScan(ScanFrame frame, byte[] buffer, byte[] status, byte[] target, ref int budget, Func<string, int, bool> climbsOut)
    {
        frame.Read = true;
        while (true)
        {
            int length = GetDents(frame.Fd, buffer);
            if (length == 0)
            {
                return;
            }

            for (int at = 0; at < length;)
            {
                ReadOnlySpan<byte> name = NextRecord(buffer, length, ref at, out byte type);
                if (IsDotOrDotDot(name))
                {
                    continue;
                }

                if (--budget < 0)
                {
                    throw new SftpServerRefusedException(SftpStatusCode.Failure);
                }

                byte[] nameZ = [.. name, 0];
                if (type == DirentUnknown)
                {
                    if (StatX(frame.Fd, nameZ, AtSymlinkNoFollow, StatxMask, status) != 0)
                    {
                        int errno = Marshal.GetLastPInvokeError();
                        if (errno == ENoEnt)
                        {
                            continue;
                        }

                        throw Error(errno);
                    }

                    type = (Mode(status) & TypeMask) switch
                    {
                        TypeLink => DirentLink,
                        TypeDirectory => DirentDirectory,
                        _ => DirentUnknown,
                    };
                }

                if (type == DirentLink)
                {
                    nint read = ReadLinkAt(frame.Fd, nameZ, target, (nuint)target.Length);
                    if (read < 0)
                    {
                        int errno = Marshal.GetLastPInvokeError();
                        if (errno == ENoEnt)
                        {
                            continue;
                        }

                        throw Error(errno);
                    }

                    if (read > MaxLinkLength)
                    {
                        throw new SftpServerRefusedException(SftpStatusCode.Failure);
                    }

                    if (climbsOut(Encoding.UTF8.GetString(target, 0, (int)read), frame.Depth))
                    {
                        throw new SftpServerRefusedException(SftpStatusCode.PermissionDenied);
                    }
                }
                else if (type == DirentDirectory)
                {
                    frame.Directories.Add(nameZ);
                }
            }
        }
    }

    /// <summary>Reads the next batch of records into <paramref name="buffer"/>, and returns its length, 0 at the end.</summary>
    private static int GetDents(SftpServerLinuxFd fd, byte[] buffer)
    {
        nint read = _useGetdents ? GetDentsMusl(fd, buffer, (nuint)buffer.Length) : GetDents64(fd, buffer, (nuint)buffer.Length);
        if (read < 0)
        {
            throw Error(Marshal.GetLastPInvokeError());
        }

        if (read > buffer.Length)
        {
            throw new IOException("The directory listing came back longer than its buffer.");
        }

        return (int)read;
    }

    /// <summary>Takes one record apart, checking it lies inside what was read, and moves past it.</summary>
    private static ReadOnlySpan<byte> NextRecord(byte[] buffer, int length, ref int at, out byte type)
    {
        if (length - at < DirentNameOffset + 1)
        {
            throw new IOException("The directory listing ended inside a record.");
        }

        int recordLength = BinaryPrimitives.ReadUInt16LittleEndian(buffer.AsSpan(at + DirentReclenOffset));

        if (recordLength < DirentNameOffset + 1 || recordLength > length - at)
        {
            throw new IOException("The directory listing held a record of a bad length.");
        }

        type = buffer[at + DirentTypeOffset];
        ReadOnlySpan<byte> field = buffer.AsSpan(at + DirentNameOffset, recordLength - DirentNameOffset);
        int end = field.IndexOf((byte)0);
        if (end <= 0)
        {
            throw new IOException("The directory listing held a name with no end, or an empty one.");
        }

        at += recordLength;
        return field[..end];
    }

    private static bool IsDotOrDotDot(ReadOnlySpan<byte> name) => name is [(byte)'.'] or [(byte)'.', (byte)'.'];

    private static uint Mode(byte[] status) => BinaryPrimitives.ReadUInt16LittleEndian(status.AsSpan(StatxModeOffset));

    private static long Int64At(byte[] status, int offset) => BinaryPrimitives.ReadInt64LittleEndian(status.AsSpan(offset));

    private static DateTimeOffset Time(byte[] status, int offset) =>
        DateTimeOffset.FromUnixTimeSeconds(Math.Clamp(Int64At(status, offset), 0, uint.MaxValue));

    /// <summary>
    /// What <see cref="SftpServerAttributes.FromInfo"/> reports for the same entry: the entry itself, never what a link
    /// leads to (its type and permission bits are its own, 0777 for a link on Linux, as OpenSSH sends), and a size only
    /// for a regular file. A link is never followed, so a listing doesn't look outside the root.
    /// </summary>
    private static SftpAttributes ToAttributes(byte[] status)
    {
        uint mode = Mode(status);
        uint type = mode & TypeMask;
        if (type == 0)
        {
            type = SftpAttributes.TypeRegular;
        }

        uint permissions = mode & 0xFFF;
        long size = type == SftpAttributes.TypeRegular ? Int64At(status, StatxSizeOffset) : 0;
        return SftpAttributes.ForServer(size, (UnixFileMode)permissions, type, Time(status, StatxAtimeOffset), Time(status, StatxMtimeOffset));
    }

    private static byte[] ToNullTerminated(string path)
    {
        if (path.Contains('\0', StringComparison.Ordinal))
        {
            throw new ArgumentException("A path can't hold a NUL.", nameof(path));
        }

        byte[] bytes = new byte[Encoding.UTF8.GetByteCount(path) + 1];
        Encoding.UTF8.GetBytes(path, bytes);
        return bytes;
    }

    private static SftpServerLinuxFd OpenAt(int directory, byte[] nameZ, out int errno)
    {
        SftpServerLinuxFd fd = OpenAtCwd(directory, nameZ, OpenDirectoryFlags, 0);
        errno = fd.IsInvalid ? Marshal.GetLastPInvokeError() : 0;
        return fd;
    }

    private static SftpServerLinuxFd OpenAt(SftpServerLinuxFd directory, byte[] nameZ, out int errno)
    {
        SftpServerLinuxFd fd = OpenAtFd(directory, nameZ, OpenDirectoryFlags, 0);
        errno = fd.IsInvalid ? Marshal.GetLastPInvokeError() : 0;
        return fd;
    }

    private static Exception Error(int errno) => errno switch
    {
        ENoEnt or ENotDir => new DirectoryNotFoundException("The directory isn't there any more."),
        EAcces or EPerm => new UnauthorizedAccessException("The directory can't be read."),

        // A final link where a directory was: something changed it since the path was checked.
        ELoop => new SftpServerRefusedException(SftpStatusCode.PermissionDenied),
        _ => new IOException($"Reading the directory failed (errno {errno})."),
    };

    /// <summary>
    /// O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, or 0 where the values aren't known. Every architecture named
    /// here is little-endian, which is how the records and <c>statx</c> fields are read.
    /// </summary>
    private static int DirectoryFlags() => RuntimeInformation.ProcessArchitecture switch
    {
        // asm-generic/fcntl.h: O_DIRECTORY 0200000, O_NOFOLLOW 0400000.
        Architecture.X64 or Architecture.X86 or Architecture.RiscV64 or Architecture.LoongArch64 => 0x10000 | 0x20000 | OCloexec,

        // arch/arm*/include/uapi/asm/fcntl.h: O_DIRECTORY 040000, O_NOFOLLOW 0100000.
        Architecture.Arm64 or Architecture.Arm => 0x4000 | 0x8000 | OCloexec,
        _ => 0,
    };

    /// <summary>Calls each function once, so a libc without one is found out before a listing depends on it.</summary>
    private static bool Probe()
    {
        try
        {
            using SftpServerLinuxFd fd = OpenAtCwd(AtFdCwd, "/\0"u8.ToArray(), OpenDirectoryFlags, 0);
            if (fd.IsInvalid)
            {
                return false;
            }

            byte[] status = new byte[StatxLength];
            if (StatX(fd, [0], AtEmptyPath, StatxMask, status) != 0 || (Mode(status) & TypeMask) != TypeDirectory)
            {
                return false;
            }

            byte[] buffer = new byte[BufferLength];
            try
            {
                if (GetDents64(fd, buffer, (nuint)buffer.Length) < 0)
                {
                    return false;
                }
            }
            catch (EntryPointNotFoundException)
            {
                _useGetdents = true;
                if (GetDentsMusl(fd, buffer, (nuint)buffer.Length) < 0)
                {
                    return false;
                }
            }

            // "/" isn't a link, so this fails with EINVAL, which shows the function is there.
            _ = ReadLinkAt(fd, [0], buffer, (nuint)buffer.Length);
            return true;
        }
        catch (Exception ex) when (ex is EntryPointNotFoundException or DllNotFoundException)
        {
            return false;
        }
    }

    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [LibraryImport("libc", EntryPoint = "openat", SetLastError = true)]
    private static partial SftpServerLinuxFd OpenAtCwd(int directory, byte[] path, int flags, int mode);

    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [LibraryImport("libc", EntryPoint = "openat", SetLastError = true)]
    private static partial SftpServerLinuxFd OpenAtFd(SftpServerLinuxFd directory, byte[] path, int flags, int mode);

    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [LibraryImport("libc", EntryPoint = "close", SetLastError = true)]
    private static partial int CloseFd(int fd);

    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [LibraryImport("libc", EntryPoint = "getdents64", SetLastError = true)]
    private static partial nint GetDents64(SftpServerLinuxFd fd, [Out] byte[] buffer, nuint length);

    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [LibraryImport("libc", EntryPoint = "getdents", SetLastError = true)]
    private static partial int GetDentsMusl(SftpServerLinuxFd fd, [Out] byte[] buffer, nuint length);

    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [LibraryImport("libc", EntryPoint = "statx", SetLastError = true)]
    private static partial int StatX(SftpServerLinuxFd directory, byte[] path, int flags, uint mask, [Out] byte[] buffer);

    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [LibraryImport("libc", EntryPoint = "readlinkat", SetLastError = true)]
    private static partial nint ReadLinkAt(SftpServerLinuxFd directory, byte[] path, [Out] byte[] buffer, nuint length);

    /// <summary>A directory being scanned: its descriptor, its depth below the new place, and the directories found in it.</summary>
    private sealed class ScanFrame(SftpServerLinuxFd fd, int depth)
    {
        public SftpServerLinuxFd Fd { get; } = fd;

        public int Depth { get; } = depth;

        public List<byte[]> Directories { get; } = [];

        public int Next { get; set; }

        public bool Read { get; set; }
    }

    /// <summary>A listing in progress: the open directory, and what's left of the last batch the kernel gave.</summary>
    private sealed class LinuxListing(SftpServerLinuxFd fd) : SftpServerListing
    {
        private readonly byte[] _buffer = new byte[BufferLength];
        private readonly byte[] _status = new byte[StatxLength];
        private int _at;
        private int _length;
        private bool _ended;

        public override bool TryNext(out SftpServerListedEntry entry)
        {
            while (!_ended)
            {
                if (_at == _length)
                {
                    _at = 0;
                    _length = GetDents(fd, _buffer);
                    if (_length == 0)
                    {
                        _ended = true;
                        break;
                    }
                }

                ReadOnlySpan<byte> name = NextRecord(_buffer, _length, ref _at, out _);
                if (IsDotOrDotDot(name))
                {
                    continue;
                }

                byte[] nameZ = [.. name, 0];
                if (StatX(fd, nameZ, AtSymlinkNoFollow, StatxMask, _status) != 0)
                {
                    // It went away, or can't be read. Neither stops the rest of the listing.
                    continue;
                }

                SftpAttributes attributes = ToAttributes(_status);
                ReadOnlySpan<byte> raw = nameZ.AsSpan(0, nameZ.Length - 1);
                entry = Utf8.IsValid(raw)
                    ? new SftpServerListedEntry(Encoding.UTF8.GetString(raw), null, attributes)
                    : new SftpServerListedEntry(Encoding.UTF8.GetString(raw), raw.ToArray(), attributes);
                return true;
            }

            entry = default;
            return false;
        }

        protected override void Dispose(bool disposing) => fd.Dispose();
    }
}

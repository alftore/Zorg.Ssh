using System;
using System.IO;
using System.Runtime.InteropServices;

namespace Zorg.Ssh;

/// <summary>What a path names, as far as reading or recording into it is concerned.</summary>
internal enum LocalFileKind
{
    /// <summary>Nothing is there.</summary>
    Missing,

    /// <summary>An ordinary file, which is the only kind these files may be.</summary>
    Regular,

    /// <summary>A directory, device, pipe, socket or anything else. Reading it could block for ever or never end.</summary>
    Other,
}

/// <summary>
/// Reads the local files that decide trust or hold secrets: known_hosts, config, Include and key files. They must be
/// regular files, and they're read with a limit, so that <c>/dev/zero</c> can't use up memory and a FIFO can't hang the
/// caller. A file the user names is the user's choice, but a config file can name another one.
/// </summary>
internal static partial class LocalFile
{
    private const int AtFdCwd = -100;
    private const int AtSymlinkNoFollow = 0x100;
    private const uint StatxType = 0x1;
    private const int StatxModeOffset = 28;
    private const int StatxSize = 256;
    private const uint FileTypeMask = 0xF000;
    private const uint RegularFile = 0x8000;
    private const uint DirectoryFile = 0x4000;

    /// <summary>Tells what a path names. Symbolic links are followed. Unreadable information counts as <see cref="LocalFileKind.Other"/>.</summary>
    public static LocalFileKind GetKind(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        try
        {
            if (OperatingSystem.IsWindows())
            {
                return WindowsKind(path);
            }

            if (OperatingSystem.IsLinux() && TryLinuxIsRegular(path, out bool regular, out bool missing))
            {
                return missing ? LocalFileKind.Missing : regular ? LocalFileKind.Regular : LocalFileKind.Other;
            }

            if (OperatingSystem.IsMacOS() && TryMacIsRegular(path, out regular, out missing))
            {
                return missing ? LocalFileKind.Missing : regular ? LocalFileKind.Regular : LocalFileKind.Other;
            }

            // Another Unix, or the call wasn't there. Without a file type, directories are all that can be told apart,
            // and every read below is limited and checked for seeking, so the rest fails closed where it can.
            FileInfo info = new(path);
            if (Directory.Exists(path))
            {
                return LocalFileKind.Other;
            }

            return info.Exists ? (path.StartsWith("/dev/", StringComparison.Ordinal) ? LocalFileKind.Other : LocalFileKind.Regular) : LocalFileKind.Missing;
        }
        catch (SshException)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException
            or EntryPointNotFoundException or DllNotFoundException)
        {
            return LocalFileKind.Other;
        }
    }

    /// <summary>
    /// Reads a whole regular file, at most <paramref name="maxLength"/> bytes. The caller owns the buffer and can zero it.
    /// A missing file throws <see cref="FileNotFoundException"/>. A file of another kind, or one that's too long, throws
    /// <see cref="IOException"/> with a message that says what to do. The length is checked while reading, not taken from
    /// the file, because a device reports none.
    /// </summary>
    public static byte[] ReadAllBytes(string path, int maxLength)
    {
        switch (GetKind(path))
        {
            case LocalFileKind.Missing:
                throw new FileNotFoundException("The file doesn't exist.", path);
            case LocalFileKind.Other:
                throw new IOException($"{path} isn't a regular file (it's a directory, device, pipe or similar), so it wasn't read. Name an ordinary file.");
        }

        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        if (!stream.CanSeek)
        {
            throw new IOException($"{path} isn't a regular file (it can't be seeked, like a pipe or device), so it wasn't read. Name an ordinary file.");
        }

        // One byte more than the limit, so that a file over it is seen to be over it.
        byte[] buffer = new byte[(int)Math.Min(Math.Max(stream.Length, 0) + 1, maxLength + 1L)];
        int used = 0;
        while (true)
        {
            if (used == buffer.Length)
            {
                if (buffer.Length > maxLength)
                {
                    break;
                }

                byte[] bigger = new byte[(int)Math.Min(buffer.Length * 2L, maxLength + 1L)];
                buffer.AsSpan().CopyTo(bigger);
                Array.Clear(buffer);
                buffer = bigger;
            }

            int read = stream.Read(buffer, used, buffer.Length - used);
            if (read == 0)
            {
                break;
            }

            used += read;
        }

        if (used > maxLength)
        {
            Array.Clear(buffer);
            throw new IOException($"{path} is over the limit of {maxLength} bytes, so it wasn't read. Check that this is the right file.");
        }

        byte[] result = buffer.AsSpan(0, used).ToArray();
        Array.Clear(buffer);
        return result;
    }

    /// <summary>
    /// Reads the file type bits of a path (<c>st_mode &amp; S_IFMT</c>) without following a final link, on Linux and
    /// macOS. Null on any other system, or if they can't be read or can't be trusted. .NET reports a FIFO, a socket or a
    /// device as an ordinary file, and this is what tells them apart. <paramref name="permissions"/> is what .NET reports
    /// for the same entry: on macOS, whose <c>struct stat</c> layout hasn't been run here, the type is believed only if
    /// the permission bits read beside it match, so a wrong layout gives null, not a wrong type.
    /// </summary>
    public static uint? GetFileType(string path, UnixFileMode permissions)
    {
        if (OperatingSystem.IsMacOS())
        {
            return GetMacFileType(path, permissions);
        }

        if (!OperatingSystem.IsLinux())
        {
            return null;
        }

        byte[] buffer = new byte[StatxSize];
        try
        {
            if (StatX(AtFdCwd, path, AtSymlinkNoFollow, StatxType, buffer) != 0)
            {
                return null;
            }
        }
        catch (Exception ex) when (ex is EntryPointNotFoundException or DllNotFoundException or ArgumentException)
        {
            return null;
        }

        return BitConverter.ToUInt16(buffer, StatxModeOffset) & FileTypeMask;
    }

    /// <summary>
    /// Takes the file type out of a macOS <c>struct stat</c> (64-bit inode layout, <c>st_mode</c> at offset 4), if the
    /// permission bits beside it are <paramref name="permissions"/> and the type is one <c>S_IFMT</c> can hold. Null
    /// otherwise: the layout was misread, or the entry changed between the two looks.
    /// </summary>
    internal static uint? ParseMacFileType(ReadOnlySpan<byte> status, UnixFileMode permissions)
    {
        if (status.Length < 6)
        {
            return null;
        }

        uint mode = System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(status[4..]);
        uint type = mode & FileTypeMask;
        bool knownType = type is 0x1000 or 0x2000 or 0x4000 or 0x6000 or 0x8000 or 0xA000 or 0xC000;
        return knownType && (mode & 0xFFF) == (uint)permissions ? type : null;
    }

    private static uint? GetMacFileType(string path, UnixFileMode permissions)
    {
        byte[] buffer = new byte[256];
        try
        {
            // As in TryMacIsRegular: x64 has the 64-bit-inode layout under lstat$INODE64, arm64 under plain lstat.
            int result = RuntimeInformation.ProcessArchitecture switch
            {
                Architecture.Arm64 => LStat(path, buffer),
                Architecture.X64 => LStatInode64(path, buffer),
                _ => -1,
            };
            return result == 0 ? ParseMacFileType(buffer, permissions) : null;
        }
        catch (Exception ex) when (ex is EntryPointNotFoundException or DllNotFoundException or ArgumentException)
        {
            return null;
        }
    }

    private static LocalFileKind WindowsKind(string path)
    {
        // A device name such as NUL, CON or COM1 turns into \\.\NUL, and so does a path that starts that way.
        string full = Path.GetFullPath(path);
        if (full.StartsWith(@"\\.\", StringComparison.Ordinal) || full.StartsWith(@"\\?\GLOBALROOT", StringComparison.OrdinalIgnoreCase))
        {
            return LocalFileKind.Other;
        }

        if (Directory.Exists(full))
        {
            return LocalFileKind.Other;
        }

        return File.Exists(full) ? LocalFileKind.Regular : LocalFileKind.Missing;
    }

    private static bool TryLinuxIsRegular(string path, out bool regular, out bool missing)
    {
        regular = false;
        missing = false;
        byte[] buffer = new byte[StatxSize];
        int result;
        try
        {
            result = StatX(AtFdCwd, path, 0, StatxType, buffer);
        }
        catch (Exception ex) when (ex is EntryPointNotFoundException or DllNotFoundException)
        {
            return false;
        }

        if (result != 0)
        {
            int errno = Marshal.GetLastPInvokeError();
            missing = errno is 2 or 20; // ENOENT, ENOTDIR
            return missing || errno != 0;
        }

        uint mode = BitConverter.ToUInt16(buffer, StatxModeOffset);
        regular = (mode & FileTypeMask) == RegularFile;
        return true;
    }

    private static bool TryMacIsRegular(string path, out bool regular, out bool missing)
    {
        regular = false;
        missing = false;
        byte[] buffer = new byte[256];
        int result;
        try
        {
            // x64 macOS exports the 64-bit-inode struct as stat$INODE64 and keeps a legacy 32-bit-inode layout under plain stat.
            result = RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? Stat(path, buffer) : StatInode64(path, buffer);
        }
        catch (Exception ex) when (ex is EntryPointNotFoundException or DllNotFoundException)
        {
            return false;
        }

        if (result != 0)
        {
            int errno = Marshal.GetLastPInvokeError();
            missing = errno is 2 or 20;
            return missing || errno != 0;
        }

        // The 64-bit-inode struct stat (Darwin sys/stat.h, __DARWIN_STRUCT_STAT64) begins with st_dev (dev_t, int32_t) and
        // then st_mode (mode_t, uint16_t), so the mode is at offset 4. That is the layout of plain stat on arm64, and of
        // stat$INODE64 on x64. The legacy struct behind plain stat on x64 has st_ino before st_mode, which is why it isn't used.
        uint mode = BitConverter.ToUInt16(buffer, 4);
        regular = (mode & FileTypeMask) == RegularFile;
        bool directory = (mode & FileTypeMask) == DirectoryFile;

        // This platform has never been run here, so the answer is checked against the runtime's own: a wrong layout would
        // read some other field as the mode, and that must not be trusted.
        if ((regular && !File.Exists(path)) || (directory && !Directory.Exists(path)))
        {
            throw new SshException("The file type of " + path + " could not be read reliably on this platform, so the file isn't used. Report this to the Zorg.Ssh maintainers, with your macOS version and architecture.");
        }

        return true;
    }

    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [LibraryImport("libc", EntryPoint = "statx", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int StatX(int directory, string path, int flags, uint mask, [Out] byte[] buffer);

    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [LibraryImport("libc", EntryPoint = "stat", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int Stat(string path, [Out] byte[] buffer);

    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [LibraryImport("libc", EntryPoint = "stat$INODE64", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int StatInode64(string path, [Out] byte[] buffer);

    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [LibraryImport("libc", EntryPoint = "lstat", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int LStat(string path, [Out] byte[] buffer);

    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [LibraryImport("libc", EntryPoint = "lstat$INODE64", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int LStatInode64(string path, [Out] byte[] buffer);
}

using System;
using System.IO;

namespace Zorg.Ssh.Sftp;

/// <summary>
/// Decides whether a name from a server can become a local path. Names are untrusted (SSH.NET 2026 advisory on
/// hostile server file names), so this checks what the name is and also what the local OS would make of it.
/// </summary>
internal static class SftpLocalPath
{
    private const int MaxNameLength = 255;

    private static readonly string[] WindowsDevices =
    [
        "CON", "PRN", "AUX", "NUL",
        "CONIN$", "CONOUT$",
        "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "COM¹", "COM²", "COM³",
        "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "LPT¹", "LPT²", "LPT³",
    ];

    /// <summary>Returns true if <paramref name="name"/> is one plain file name on this machine.</summary>
    public static bool IsSafeName(string name)
    {
        if (name.Length is 0 or > MaxNameLength || name is "." or "..")
        {
            return false;
        }

        if (name.AsSpan().IndexOfAny('/', '\\', '\0') >= 0 || name.AsSpan().IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
        {
            return false;
        }

        return !OperatingSystem.IsWindows() || IsSafeOnWindows(name);
    }

    /// <summary>
    /// Joins a safe name onto a full directory path, and proves the result is a direct child of it.
    /// Returns null if the OS would resolve the name to anything else.
    /// </summary>
    public static string? Resolve(string directory, string name)
    {
        if (!IsSafeName(name))
        {
            return null;
        }

        string target = Path.GetFullPath(Path.Join(directory, name));
        bool direct = string.Equals(Path.GetDirectoryName(target), Path.TrimEndingDirectorySeparator(directory), StringComparison.Ordinal)
            && string.Equals(Path.GetFileName(target), name, StringComparison.Ordinal);
        return direct ? target : null;
    }

    private static bool IsSafeOnWindows(string name)
    {
        // A colon names a drive or an alternate data stream. Trailing dots and spaces are stripped by Win32,
        // so "a." is "a" and ".. " can reach the parent.
        if (name.Contains(':', StringComparison.Ordinal) || name[^1] is '.' or ' ')
        {
            return false;
        }

        int dot = name.IndexOf('.', StringComparison.Ordinal);
        ReadOnlySpan<char> stem = (dot < 0 ? name.AsSpan() : name.AsSpan(0, dot)).TrimEnd(' ');
        foreach (string device in WindowsDevices)
        {
            if (stem.Equals(device, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        return true;
    }
}

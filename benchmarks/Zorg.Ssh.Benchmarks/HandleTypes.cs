using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Zorg.Ssh.Benchmarks;

/// <summary>
/// Counts this process's open handles by object type (Event, File, Key, Thread, ...) on Windows, through the system handle table. The soak uses it
/// to say which kind of handle grows. Returns null anywhere else, or when the query fails.
/// </summary>
internal static partial class HandleTypes
{
    private const int SystemExtendedHandleInformation = 64;
    private const int ObjectTypesInformation = 3;
    private const uint StatusInfoLengthMismatch = 0xC0000004;

    // x64 layouts: SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX is 40 bytes, OBJECT_TYPE_INFORMATION 104 with TypeIndex at 90.
    private const int HandleEntrySize = 40;
    private const int HandleEntriesOffset = 16;
    private const int TypeInfoSize = 104;
    private const int TypeIndexOffset = 90;

    private static Dictionary<int, string>? _names;

    public static Dictionary<string, int>? Count()
    {
        if (!OperatingSystem.IsWindows() || IntPtr.Size != 8)
        {
            return null;
        }

        _names ??= TypeNames();
        if (_names is null)
        {
            return null;
        }

        IntPtr buffer = Query(size => NtQuerySystemInformation(SystemExtendedHandleInformation, size.Buffer, size.Length, out size.Returned));
        if (buffer == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            long pid = Environment.ProcessId;
            long count = Marshal.ReadInt64(buffer);
            Dictionary<string, int> counts = new(StringComparer.Ordinal);
            for (long i = 0; i < count; i++)
            {
                IntPtr entry = buffer + HandleEntriesOffset + (int)(i * HandleEntrySize);
                if (Marshal.ReadInt64(entry, 8) != pid)
                {
                    continue;
                }

                int type = (ushort)Marshal.ReadInt16(entry, 30);
                string name = _names.TryGetValue(type, out string? n) ? n : "type " + type;
                counts[name] = counts.GetValueOrDefault(name) + 1;
            }

            return counts;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static Dictionary<int, string>? TypeNames()
    {
        IntPtr buffer = Query(size => NtQueryObject(IntPtr.Zero, ObjectTypesInformation, size.Buffer, size.Length, out size.Returned));
        if (buffer == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            Dictionary<int, string> names = [];
            int types = Marshal.ReadInt32(buffer);
            IntPtr entry = buffer + 8;
            for (int i = 0; i < types; i++)
            {
                int length = (ushort)Marshal.ReadInt16(entry);
                int maxLength = (ushort)Marshal.ReadInt16(entry, 2);
                IntPtr text = Marshal.ReadIntPtr(entry, 8);
                names[Marshal.ReadByte(entry, TypeIndexOffset)] = Marshal.PtrToStringUni(text, length / 2);
                long next = entry + TypeInfoSize + maxLength;
                entry = checked((IntPtr)((next + 7) & ~7L));
            }

            return names;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static IntPtr Query(Func<Size, uint> query)
    {
        int length = 1 << 20;
        for (int attempt = 0; attempt < 8; attempt++)
        {
            Size size = new() { Buffer = Marshal.AllocHGlobal(length), Length = length };
            uint status = query(size);
            if (status == 0)
            {
                return size.Buffer;
            }

            Marshal.FreeHGlobal(size.Buffer);
            if (status != StatusInfoLengthMismatch)
            {
                return IntPtr.Zero;
            }

            length = Math.Max(length * 2, size.Returned + (1 << 16));
        }

        return IntPtr.Zero;
    }

    private sealed class Size
    {
        public IntPtr Buffer;
        public int Length;
        public int Returned;
    }

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport("ntdll.dll")]
    private static partial uint NtQuerySystemInformation(int informationClass, IntPtr information, int length, out int returnLength);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport("ntdll.dll")]
    private static partial uint NtQueryObject(IntPtr handle, int informationClass, IntPtr information, int length, out int returnLength);
}

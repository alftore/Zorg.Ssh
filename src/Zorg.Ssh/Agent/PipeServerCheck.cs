using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Zorg.Ssh.Agent;

/// <summary>
/// Checks who serves a Windows named pipe before an agent request is sent to it. Pipe names are machine-wide, and the
/// OpenSSH agent service is off by default, so any local user can create <c>\\.\pipe\openssh-ssh-agent</c> first. A rogue
/// agent can't forge a login, because each signature is checked against the key it listed, but it learns who signs in
/// where. The server must run as the current user, or as LocalSystem, which is the account of the OpenSSH agent service.
/// </summary>
[SupportedOSPlatform("windows")]
internal static partial class PipeServerCheck
{
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint TokenQuery = 0x8;
    private const int TokenUser = 1;
    private const uint ScManagerConnect = 0x1;
    private const uint ServiceQueryStatus = 0x4;
    private const int ScStatusProcessInfo = 0;
    private const int ServiceStatusProcessSize = 36;
    private const int ServiceStatusProcessIdOffset = 28;
    private const string AgentServiceName = "ssh-agent";

    /// <summary>Throws <see cref="SshAgentException"/> unless the process serving the pipe is the current user's or LocalSystem's.</summary>
    public static void Ensure(SafePipeHandle pipe, string where)
    {
        if (!GetNamedPipeServerProcessId(pipe, out uint pid))
        {
            throw new SshAgentException($"Couldn't tell which process serves the agent pipe {where}, so it isn't used. Check that the OpenSSH Authentication Agent service is running.");
        }

        EnsureTrustedProcess(pid, where);
    }

    /// <summary>
    /// Decides on a process by its token's user. If that can't be read, which is normal for a LocalSystem service seen from an
    /// ordinary account, the process is accepted only if it is the process of the <c>ssh-agent</c> service, which the service
    /// manager reports to any user. A process that can't be identified either way is refused.
    /// </summary>
    internal static void EnsureTrustedProcess(uint pid, string where)
    {
        SecurityIdentifier? owner = TryGetProcessUser(pid);
        if (owner is not null)
        {
            using WindowsIdentity current = WindowsIdentity.GetCurrent();
            if (IsAcceptableOwner(owner, current.User))
            {
                return;
            }

            throw new SshAgentException($"The agent pipe {where} is served by a process that runs as {owner.Value}, which is neither you nor the system, so it isn't used. Another user may have created the pipe first. Stop that process, or start the OpenSSH Authentication Agent service.");
        }

        if (IsAgentServiceProcess(pid))
        {
            return;
        }

        throw new SshAgentException($"Couldn't tell who runs the process (id {pid}) that serves the agent pipe {where}, and it isn't the OpenSSH Authentication Agent service, so it isn't used. Start that service, or run the agent as yourself.");
    }

    /// <summary>Gets whether a pipe server's user may be trusted: LocalSystem, or the same user as this process.</summary>
    internal static bool IsAcceptableOwner(SecurityIdentifier owner, SecurityIdentifier? current) =>
        owner.IsWellKnown(WellKnownSidType.LocalSystemSid) || (current is not null && owner.Equals(current));

    private static SecurityIdentifier? TryGetProcessUser(uint pid)
    {
        using SafeProcessHandle process = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (process.IsInvalid || !OpenProcessToken(process, TokenQuery, out SafeAccessTokenHandle token))
        {
            return null;
        }

        using (token)
        {
            GetTokenInformation(token, TokenUser, IntPtr.Zero, 0, out uint needed);
            if (needed is 0 or > 4096)
            {
                return null;
            }

            IntPtr buffer = Marshal.AllocHGlobal((int)needed);
            try
            {
                if (!GetTokenInformation(token, TokenUser, buffer, needed, out _))
                {
                    return null;
                }

                // TOKEN_USER starts with a pointer to the SID, which lives in the same buffer.
                return new SecurityIdentifier(Marshal.ReadIntPtr(buffer));
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }

    private static bool IsAgentServiceProcess(uint pid)
    {
        IntPtr manager = OpenSCManagerW(null, null, ScManagerConnect);
        if (manager == IntPtr.Zero)
        {
            return false;
        }

        try
        {
            IntPtr service = OpenServiceW(manager, AgentServiceName, ServiceQueryStatus);
            if (service == IntPtr.Zero)
            {
                return false;
            }

            try
            {
                IntPtr status = Marshal.AllocHGlobal(ServiceStatusProcessSize);
                try
                {
                    return QueryServiceStatusEx(service, ScStatusProcessInfo, status, ServiceStatusProcessSize, out _)
                        && (uint)Marshal.ReadInt32(status, ServiceStatusProcessIdOffset) == pid
                        && pid != 0;
                }
                finally
                {
                    Marshal.FreeHGlobal(status);
                }
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(manager);
        }
    }

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint serverProcessId);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial SafeProcessHandle OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint processId);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool OpenProcessToken(SafeProcessHandle process, uint desiredAccess, out SafeAccessTokenHandle token);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetTokenInformation(SafeAccessTokenHandle token, int informationClass, IntPtr information, uint length, out uint returnLength);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport("advapi32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial IntPtr OpenSCManagerW(string? machine, string? database, uint desiredAccess);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport("advapi32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial IntPtr OpenServiceW(IntPtr manager, string name, uint desiredAccess);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool QueryServiceStatusEx(IntPtr service, int infoLevel, IntPtr buffer, uint bufferSize, out uint bytesNeeded);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseServiceHandle(IntPtr handle);
}

using System;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Net.Sockets;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;

namespace Zorg.Ssh.Agent;

/// <summary>Finds and opens the agent: a Unix socket named by <c>SSH_AUTH_SOCK</c>, or a Windows named pipe.</summary>
internal static class SshAgentEndpoint
{
    /// <summary>The environment variable that names the agent.</summary>
    public const string Variable = "SSH_AUTH_SOCK";

    private const string PipePrefix = @"\\.\pipe\";
    private const string WindowsDefault = PipePrefix + "openssh-ssh-agent";

    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(3);

    /// <summary>Gets where the agent is. Returns null if nothing says, which on Windows can't happen.</summary>
    public static string? Resolve(string? path)
    {
        if (!string.IsNullOrEmpty(path))
        {
            return path;
        }

        string? variable = Environment.GetEnvironmentVariable(Variable);
        if (!string.IsNullOrEmpty(variable))
        {
            return variable;
        }

        return OperatingSystem.IsWindows() ? WindowsDefault : null;
    }

    /// <summary>Opens the agent. A failure is a <see cref="SshAgentException"/> that says what was tried.</summary>
    public static async ValueTask<Stream> ConnectAsync(string? path, CancellationToken cancellationToken)
    {
        string where = Resolve(path)
            ?? throw new SshAgentException($"No ssh-agent is available: {Variable} isn't set. Start one with: eval \"$(ssh-agent)\"");
        try
        {
            // A bad pipe name throws SshAgentException here, which the catch below doesn't wrap.
            if (OperatingSystem.IsWindows() && PipeNameOf(where) is { } pipeName)
            {
                return await ConnectPipeAsync(pipeName, where, cancellationToken).ConfigureAwait(false);
            }

            return await ConnectSocketAsync(where, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or SocketException or TimeoutException or UnauthorizedAccessException or ArgumentException)
        {
            throw new SshAgentException(ConnectFailure(where), ex);
        }
    }

    private static string ConnectFailure(string where)
    {
        string message = $"Couldn't reach the ssh-agent at {where}. Check that it's running.";
        return OperatingSystem.IsWindows() && !where.Contains("pipe", StringComparison.OrdinalIgnoreCase)
            ? message + $" Agents from Git for Windows and MSYS use a socket format that only their own programs can reach: use the Windows OpenSSH agent at {WindowsDefault} instead."
            : message;
    }

    /// <summary>
    /// Gets the pipe name if <paramref name="where"/> is a path under <c>\\.\pipe\</c>, or null if it isn't one. The name must be
    /// a plain one: after the prefix, a <c>\</c>, <c>/</c> or a name that is <c>.</c> or <c>..</c> would let the path be
    /// normalised out of <c>\\.\pipe\</c>, for example to <c>\\.\UNC\host\pipe\x</c>, a pipe on another machine. That throws
    /// <see cref="SshAgentException"/>.
    /// </summary>
    internal static string? PipeNameOf(string where)
    {
        string normalized = where.Replace('/', '\\');
        if (!normalized.StartsWith(PipePrefix, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        string name = normalized[PipePrefix.Length..];
        if (name.Length == 0 || name is "." or ".." || name.Contains('\\', StringComparison.Ordinal) || name.Any(char.IsControl))
        {
            throw new SshAgentException($"The agent path {where} isn't a plain named pipe under {PipePrefix}: after the prefix it needs one name with no slashes, backslashes or dot segments. Name the pipe directly, for example {WindowsDefault}.");
        }

        return name;
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static async ValueTask<Stream> ConnectPipeAsync(string name, string where, CancellationToken cancellationToken)
    {
        // The OpenSSH service identifies its caller from the pipe, so it needs this level. It runs as SYSTEM, so
        // PipeOptions.CurrentUserOnly would refuse it.
        NamedPipeClientStream pipe = new(".", name, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
        try
        {
            await pipe.ConnectAsync((int)ConnectTimeout.TotalMilliseconds, cancellationToken).ConfigureAwait(false);

            // Pipe names are machine-wide and anyone can create the default one while the service is off.
            PipeServerCheck.Ensure(pipe.SafePipeHandle, where);
            return pipe;
        }
        catch
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private static async ValueTask<Stream> ConnectSocketAsync(string path, CancellationToken cancellationToken)
    {
#pragma warning disable CA2000 // The stream returned below owns it, and the catch block releases it otherwise.
        Socket socket = new(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
#pragma warning restore CA2000
        try
        {
            using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            limit.CancelAfter(ConnectTimeout);
            try
            {
                await socket.ConnectAsync(new UnixDomainSocketEndPoint(path), limit.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
            {
                throw new TimeoutException("The agent socket didn't accept the connection.", ex);
            }

            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}

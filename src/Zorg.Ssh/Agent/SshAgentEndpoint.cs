using System;
using System.IO;
using System.IO.Pipes;
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
            string normalized = where.Replace('/', '\\');
            return OperatingSystem.IsWindows() && normalized.StartsWith(PipePrefix, StringComparison.OrdinalIgnoreCase)
                ? await ConnectPipeAsync(normalized[PipePrefix.Length..], cancellationToken).ConfigureAwait(false)
                : await ConnectSocketAsync(where, cancellationToken).ConfigureAwait(false);
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

    private static async ValueTask<Stream> ConnectPipeAsync(string name, CancellationToken cancellationToken)
    {
        // The OpenSSH service identifies its caller from the pipe, so it needs this level. It runs as SYSTEM, so
        // PipeOptions.CurrentUserOnly would refuse it.
        NamedPipeClientStream pipe = new(".", name, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
        try
        {
            await pipe.ConnectAsync((int)ConnectTimeout.TotalMilliseconds, cancellationToken).ConfigureAwait(false);
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

using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Zorg.Ssh.Sftp;

/// <summary>
/// Serves SFTP version 3 from a directory, as a subsystem of <see cref="SshServer"/>. The client is authenticated
/// but treated as hostile: it can't reach anything outside <see cref="SftpServerOptions.RootDirectory"/>, and
/// nothing about the server's own paths appears in what it's sent.
/// </summary>
/// <remarks>
/// <para>
/// A path is checked one component at a time from the root, reading each symbolic link and following it only while
/// it stays inside. A link that leads out is refused, and nothing outside the root is ever looked at. Requests that
/// use a path run one at a time across the whole process, so two sessions can't race each other through that check.
/// </para>
/// <para>
/// .NET can't open a file relative to a directory handle, so another process changing the root while a request runs
/// can still win a race. On Linux an opened file is checked against <c>/proc</c> afterwards, which catches that for
/// opens. Don't let untrusted local users change the root.
/// </para>
/// <para>
/// Hard links can't be told from ordinary files, and a mount inside the root isn't noticed. On Windows, a reparse
/// point that isn't a link, such as a OneDrive placeholder or a deduplicated file, is refused. SFTP version 3 can't
/// change owners, and on Windows permission bits are accepted and ignored. Setuid, setgid and sticky bits are always
/// dropped. Disk space isn't limited here: use a quota.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// await using SshServer server = await SshServer.StartAsync(new SshServerOptions
/// {
///     HostKeys = [hostKey],
///     PublicKeyHandler = (request, ct) => users.CheckAsync(request, ct),
///     SessionHandler = (session, ct) =>
///     {
///         if (session.Kind == SshSessionKind.Subsystem &amp;&amp; session.Command == "sftp")
///         {
///             return SftpServer.ServeAsync(
///                 session,
///                 new SftpServerOptions { RootDirectory = Path.Combine("/srv/sftp", session.Principal.UserName) },
///                 ct);
///         }
///
///         return Task.FromResult(1);
///     },
/// }, cancellationToken);
/// </code>
/// </example>
public static class SftpServer
{
    /// <summary>Serves one session until the client closes it. Everything the client opened is closed when this ends.</summary>
    /// <param name="session">The session, whose <see cref="SshServerSession.Kind"/> is subsystem and command is <c>sftp</c>.</param>
    /// <param name="options">The root and limits. One instance can serve any number of sessions.</param>
    /// <param name="cancellationToken">Ends the session.</param>
    /// <returns>The exit code: 0 if the client closed the session cleanly, 1 if it broke the protocol or the connection failed.</returns>
    /// <exception cref="ArgumentException">An option is invalid.</exception>
    /// <exception cref="DirectoryNotFoundException">The root doesn't exist.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    /// <example>
    /// <code>
    /// SessionHandler = (session, ct) => session is { Kind: SshSessionKind.Subsystem, Command: "sftp" }
    ///     ? SftpServer.ServeAsync(session, new SftpServerOptions { RootDirectory = root }, ct)
    ///     : Task.FromResult(1),
    /// </code>
    /// </example>
    public static Task<int> ServeAsync(SshServerSession session, SftpServerOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        return ServeStreamsAsync(session.Input, session.Output, options, cancellationToken);
    }

    /// <summary>Serves over any pair of streams, so hostile clients can be tested in memory. The streams stay open.</summary>
    internal static async Task<int> ServeStreamsAsync(Stream input, Stream output, SftpServerOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        SftpServerSession session = new(input, output, options);
        await using (session.ConfigureAwait(false))
        {
            return await session.RunAsync(cancellationToken).ConfigureAwait(false);
        }
    }
}

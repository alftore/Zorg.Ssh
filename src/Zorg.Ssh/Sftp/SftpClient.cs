using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Zorg.Ssh.Connection;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Sftp;

/// <summary>
/// An SFTP version 3 session over one SSH channel. Open one with <see cref="SshClient.OpenSftpAsync(SftpClientOptions, System.Threading.CancellationToken)"/>. Calls may
/// run at the same time, and they share the session's requests in flight. Disposing it leaves the
/// <see cref="SshClient"/> connected.
/// </summary>
/// <remarks>
/// Servers are untrusted. A response that doesn't match an outstanding request, or a malformed one, ends the session
/// with <see cref="SshProtocolException"/>, and later calls fail with <see cref="SshConnectionException"/>.
/// A refusal from the server is an <see cref="SftpException"/> and leaves the session usable.
/// </remarks>
/// <example>
/// <code>
/// await using SshClient client = await SshClient.ConnectAsync(options, cancellationToken);
/// await using SftpClient sftp = await client.OpenSftpAsync(cancellationToken);
///
/// await using FileStream local = File.OpenRead("report.pdf");
/// await sftp.UploadFileAsync(local, "/srv/reports/report.pdf", cancellationToken);
///
/// await foreach (SftpEntry entry in sftp.ListDirectoryAsync("/srv/reports", cancellationToken))
/// {
///     Console.WriteLine(entry.Name);
/// }
/// </code>
/// </example>
public sealed class SftpClient : IAsyncDisposable
{
    private const string PosixRename = "posix-rename@openssh.com";
    private const string StatVfs = "statvfs@openssh.com";
    private const string FSync = "fsync@openssh.com";
    private const string HardLink = "hardlink@openssh.com";
    private const string LimitsExtension = "limits@openssh.com";
    private const string CopyData = "copy-data";
    private const string OpenSshSuffix = "@openssh.com";
    private const int MaxDownloadDepth = 64;
    private const int MaxEmptyBatches = 16;
    private const int MinServerPacketLength = 1024;

    private static readonly TimeSpan CloseLimit = TimeSpan.FromSeconds(5);

    private readonly SftpSession _session;
    private readonly bool _symlinkArgumentsReversed;
    private int _readChunk;
    private int _writeChunk;

    private SftpClient(SftpSession session, string? serverIdentification)
    {
        _session = session;
        _readChunk = session.Limits.ReadChunk;
        _writeChunk = session.Limits.WriteChunk;
        _symlinkArgumentsReversed = IsOpenSsh(session.Extensions, serverIdentification);
    }

    /// <summary>Gets the extensions the server advertised, by name, with their version strings. The server chose these.</summary>
    /// <example>
    /// <code>
    /// bool canSync = sftp.ServerExtensions.ContainsKey("fsync@openssh.com");
    /// </code>
    /// </example>
    public IReadOnlyDictionary<string, string> ServerExtensions => _session.Extensions;

    /// <summary>Gets the limits the session was opened with. Tests change them after the start.</summary>
    internal SftpClientOptions Options { get; set; } = SftpClientOptions.Default;

    private long MaxReadAllBytes => Options.MaxReadAllBytes;

    private long MaxDirectoryEntries => Options.MaxDirectoryEntries;

    /// <summary>Reads a whole file into memory. For large files use <see cref="DownloadFileAsync"/>.</summary>
    /// <param name="path">The remote path.</param>
    /// <param name="cancellationToken">Stops the transfer.</param>
    /// <returns>The file's contents.</returns>
    /// <exception cref="SftpFileNotFoundException">The file doesn't exist.</exception>
    /// <exception cref="SftpPermissionDeniedException">The account can't read it.</exception>
    /// <exception cref="SftpException">The server refused, or the file is larger than <see cref="SftpClientOptions.MaxReadAllBytes"/>.</exception>
    /// <example>
    /// <code>
    /// byte[] config = await sftp.ReadAllBytesAsync("/etc/app.conf", cancellationToken);
    /// </code>
    /// </example>
    public async Task<byte[]> ReadAllBytesAsync(string path, CancellationToken cancellationToken = default)
    {
        using MemoryStream contents = new();
        await UseHandleAsync(path, SftpOpenFlags.Read, handle => CopyFromHandleAsync(handle, path, 0, contents, Math.Min(MaxReadAllBytes, Array.MaxLength), "SftpClientOptions.MaxReadAllBytes", cancellationToken), cancellationToken).ConfigureAwait(false);
        return contents.ToArray();
    }

    /// <summary>Writes a whole file, creating it or replacing what it holds.</summary>
    /// <param name="path">The remote path.</param>
    /// <param name="contents">What to write.</param>
    /// <param name="cancellationToken">Stops the transfer. The file may be left incomplete.</param>
    /// <returns>A task that completes when the server has confirmed every write and closed the file.</returns>
    /// <exception cref="SftpException">The server refused.</exception>
    /// <example>
    /// <code>
    /// await sftp.WriteAllBytesAsync("/srv/data.bin", data, cancellationToken);
    /// </code>
    /// </example>
    public Task WriteAllBytesAsync(string path, ReadOnlyMemory<byte> contents, CancellationToken cancellationToken = default) =>
        UseHandleAsync(path, SftpOpenFlags.Write | SftpOpenFlags.Create | SftpOpenFlags.Truncate, handle => WriteAtAsync(handle, path, 0, contents, cancellationToken), cancellationToken);

    /// <summary>Copies a remote file into a stream, with many reads in flight.</summary>
    /// <param name="remotePath">The remote path.</param>
    /// <param name="destination">Where the bytes go, in order. It's left open.</param>
    /// <param name="cancellationToken">Stops the transfer. There's no size limit, so use this to bound a transfer from a server you don't trust.</param>
    /// <returns>A task that completes when the file has been copied.</returns>
    /// <exception cref="SftpFileNotFoundException">The file doesn't exist.</exception>
    /// <exception cref="SftpException">The server refused.</exception>
    /// <example>
    /// <code>
    /// await using FileStream local = File.Create("backup.tar");
    /// await sftp.DownloadFileAsync("/srv/backup.tar", local, cancellationToken);
    /// </code>
    /// </example>
    public Task DownloadFileAsync(string remotePath, Stream destination, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(destination);
        return UseHandleAsync(remotePath, SftpOpenFlags.Read, handle => CopyFromHandleAsync(handle, remotePath, 0, destination, long.MaxValue, null, cancellationToken), cancellationToken);
    }

    /// <summary>Copies a stream to a remote file, with many writes in flight. The file is created, or replaced if it exists.</summary>
    /// <param name="source">What to send, read to its end. It's left open.</param>
    /// <param name="remotePath">The remote path.</param>
    /// <param name="cancellationToken">Stops the transfer. The file may be left incomplete.</param>
    /// <returns>A task that completes when the server has confirmed every write and closed the file.</returns>
    /// <exception cref="SftpException">The server refused.</exception>
    /// <example>
    /// <code>
    /// await using FileStream local = File.OpenRead("backup.tar");
    /// await sftp.UploadFileAsync(local, "/srv/backup.tar", cancellationToken);
    /// </code>
    /// </example>
    public Task UploadFileAsync(Stream source, string remotePath, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(source);
        return UseHandleAsync(remotePath, SftpOpenFlags.Write | SftpOpenFlags.Create | SftpOpenFlags.Truncate, handle => CopyToHandleAsync(source, handle, remotePath, cancellationToken), cancellationToken);
    }

    /// <summary>
    /// Copies a remote directory tree to a local directory. Regular files and directories are copied. Symbolic links
    /// and special files are skipped, so a link can't lead the walk outside the tree.
    /// </summary>
    /// <remarks>
    /// Names from the server are untrusted. <c>.</c> and <c>..</c> are never used. A name holding a slash, a backslash
    /// or NUL, or anything this machine would resolve to something other than a direct child, stops the download with
    /// <see cref="SftpUnsafeNameException"/> before that name touches the disk. Existing files are never overwritten
    /// and existing links are never followed, so nothing is written outside <paramref name="localDirectory"/>.
    /// </remarks>
    /// <param name="remotePath">The remote directory.</param>
    /// <param name="localDirectory">The local directory. It's created if needed.</param>
    /// <param name="maxTotalBytes">The most bytes to accept across all files, which stops a server filling the disk.</param>
    /// <param name="cancellationToken">Stops the transfer. Files already written stay.</param>
    /// <returns>A task that completes when the tree has been copied.</returns>
    /// <exception cref="SftpUnsafeNameException">The server sent a name that's unsafe, or that collides with something already there.</exception>
    /// <exception cref="SftpException">The server refused, or a limit was reached.</exception>
    /// <example>
    /// <code>
    /// await sftp.DownloadDirectoryAsync("/srv/site", @"C:\backup\site", 10L * 1024 * 1024 * 1024, cancellationToken);
    /// </code>
    /// </example>
    public async Task DownloadDirectoryAsync(string remotePath, string localDirectory, long maxTotalBytes = long.MaxValue, CancellationToken cancellationToken = default)
    {
        ValidatePath(remotePath);
        ArgumentException.ThrowIfNullOrEmpty(localDirectory);
        ArgumentOutOfRangeException.ThrowIfNegative(maxTotalBytes);

        string root = Path.GetFullPath(localDirectory);
        Directory.CreateDirectory(root);
        DownloadBudget budget = new(MaxDirectoryEntries, maxTotalBytes);
        await DownloadTreeAsync(remotePath, root, 0, budget, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Opens a remote file as a <see cref="Stream"/>, with the same meanings as <see cref="FileStream"/>.</summary>
    /// <param name="path">The remote path.</param>
    /// <param name="mode">How to open it. <see cref="FileMode.Append"/> needs <see cref="FileAccess.Write"/>.</param>
    /// <param name="access">What the stream may do.</param>
    /// <param name="cancellationToken">Cancels the open.</param>
    /// <returns>The open file. Dispose it to close the handle.</returns>
    /// <exception cref="SftpFileNotFoundException">The file doesn't exist.</exception>
    /// <exception cref="SftpException">The server refused, or the file exists and <paramref name="mode"/> is <see cref="FileMode.CreateNew"/>.</exception>
    /// <example>
    /// <code>
    /// await using SftpFile file = await sftp.OpenAsync("/var/log/app.log", FileMode.Open, FileAccess.Read, cancellationToken);
    /// file.Seek(-4096, SeekOrigin.End);
    /// byte[] tail = new byte[4096];
    /// int read = await file.ReadAsync(tail, cancellationToken);
    /// </code>
    /// </example>
    public async Task<SftpFile> OpenAsync(string path, FileMode mode = FileMode.Open, FileAccess access = FileAccess.Read, CancellationToken cancellationToken = default)
    {
        byte[] handle = await OpenHandleAsync(path, ToOpenFlags(mode, access), cancellationToken).ConfigureAwait(false);
        long position = 0;
        if (mode == FileMode.Append)
        {
            try
            {
                position = (await GetHandleAttributesAsync(handle, path, cancellationToken).ConfigureAwait(false)).Size ?? 0;
            }
            catch
            {
                CloseHandleInBackground(handle);
                throw;
            }
        }

        return new SftpFile(this, handle, path, access, position);
    }

    /// <summary>
    /// Lists a directory, reading it as you enumerate. Names are returned exactly as the server sent them, including
    /// <c>.</c> and <c>..</c>, and can be hostile: check <see cref="SftpEntry.IsSafeName"/> before using one locally.
    /// </summary>
    /// <param name="path">The remote directory.</param>
    /// <param name="cancellationToken">Stops the listing.</param>
    /// <returns>The entries, in the server's order.</returns>
    /// <exception cref="SftpFileNotFoundException">The directory doesn't exist.</exception>
    /// <exception cref="SftpException">The server refused, or sent more than <see cref="SftpClientOptions.MaxDirectoryEntries"/> entries.</exception>
    /// <example>
    /// <code>
    /// await foreach (SftpEntry entry in sftp.ListDirectoryAsync("/var/log", cancellationToken))
    /// {
    ///     Console.WriteLine($"{entry.Name} {entry.Attributes.Size}");
    /// }
    /// </code>
    /// </example>
    public async IAsyncEnumerable<SftpEntry> ListDirectoryAsync(string path, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ValidatePath(path);
        long limit = MaxDirectoryEntries;
        long total = 0;
        int empty = 0;
        byte[] handle = await OpenDirectoryAsync(path, cancellationToken).ConfigureAwait(false);
        try
        {
            while (true)
            {
                SftpEntry[]? batch = await ReadDirectoryBatchAsync(handle, path, cancellationToken).ConfigureAwait(false);
                if (batch is null)
                {
                    yield break;
                }

                empty = batch.Length == 0 ? empty + 1 : 0;
                if (empty > MaxEmptyBatches)
                {
                    throw Fail(new SshProtocolException("The SFTP server keeps sending empty directory listings without ending them."));
                }

                total += batch.Length;
                if (total > limit)
                {
                    throw new SftpException($"The server listed more than {limit} entries in '{SftpParser.Sanitise(path)}'. Raise SftpClientOptions.MaxDirectoryEntries if that's expected.", SftpStatusCode.Failure, path);
                }

                foreach (SftpEntry entry in batch)
                {
                    yield return entry;
                }
            }
        }
        finally
        {
            await CloseHandleQuietlyAsync(handle).ConfigureAwait(false);
        }
    }

    /// <summary>Gets a file's attributes.</summary>
    /// <param name="path">The remote path.</param>
    /// <param name="followSymbolicLinks">False reports on a link itself, not on what it points to.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>What the server reported.</returns>
    /// <exception cref="SftpFileNotFoundException">Nothing exists at the path.</exception>
    /// <example>
    /// <code>
    /// SftpAttributes attributes = await sftp.GetAttributesAsync("/srv/data.bin", cancellationToken: cancellationToken);
    /// Console.WriteLine(attributes.Size);
    /// </code>
    /// </example>
    public Task<SftpAttributes> GetAttributesAsync(string path, bool followSymbolicLinks = true, CancellationToken cancellationToken = default)
    {
        ValidatePath(path);
        return RequestAsync(SftpFrames.Path(path), followSymbolicLinks ? SftpMessage.Stat : SftpMessage.Lstat, SftpMessage.Attrs, SftpParser.ReadAttributes, path, cancellationToken);
    }

    /// <summary>Changes a file's attributes. Only the properties you set are sent.</summary>
    /// <param name="path">The remote path.</param>
    /// <param name="attributes">What to change.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>A task that completes when the server has answered.</returns>
    /// <exception cref="SftpException">The server refused.</exception>
    /// <example>
    /// <code>
    /// await sftp.SetAttributesAsync(
    ///     "/srv/secret.key",
    ///     new SftpAttributes { Permissions = UnixFileMode.UserRead | UnixFileMode.UserWrite },
    ///     cancellationToken);
    /// </code>
    /// </example>
    public Task SetAttributesAsync(string path, SftpAttributes attributes, CancellationToken cancellationToken = default)
    {
        ValidatePath(path);
        ArgumentNullException.ThrowIfNull(attributes);
        attributes.Validate(nameof(attributes));
        return StatusRequestAsync(SftpFrames.PathAndAttributes(path, attributes), SftpMessage.SetStat, path, cancellationToken);
    }

    /// <summary>Creates a directory. Its parent must exist.</summary>
    /// <param name="path">The remote path.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>A task that completes when the server has answered.</returns>
    /// <exception cref="SftpException">The server refused. Most servers report an existing directory as <see cref="SftpStatusCode.Failure"/>.</exception>
    /// <example>
    /// <code>
    /// await sftp.CreateDirectoryAsync("/srv/uploads", cancellationToken);
    /// </code>
    /// </example>
    public Task CreateDirectoryAsync(string path, CancellationToken cancellationToken = default)
    {
        ValidatePath(path);
        return StatusRequestAsync(SftpFrames.PathAndAttributes(path, new SftpAttributes()), SftpMessage.MkDir, path, cancellationToken);
    }

    /// <summary>Deletes a file or a symbolic link.</summary>
    /// <param name="path">The remote path.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>A task that completes when the server has answered.</returns>
    /// <exception cref="SftpFileNotFoundException">Nothing exists at the path.</exception>
    /// <example>
    /// <code>
    /// await sftp.DeleteFileAsync("/srv/old.bin", cancellationToken);
    /// </code>
    /// </example>
    public Task DeleteFileAsync(string path, CancellationToken cancellationToken = default)
    {
        ValidatePath(path);
        return StatusRequestAsync(SftpFrames.Path(path), SftpMessage.Remove, path, cancellationToken);
    }

    /// <summary>Deletes an empty directory.</summary>
    /// <param name="path">The remote path.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>A task that completes when the server has answered.</returns>
    /// <exception cref="SftpException">The server refused, perhaps because the directory isn't empty.</exception>
    /// <example>
    /// <code>
    /// await sftp.DeleteDirectoryAsync("/srv/empty", cancellationToken);
    /// </code>
    /// </example>
    public Task DeleteDirectoryAsync(string path, CancellationToken cancellationToken = default)
    {
        ValidatePath(path);
        return StatusRequestAsync(SftpFrames.Path(path), SftpMessage.RmDir, path, cancellationToken);
    }

    /// <summary>
    /// Renames a file or directory. With <paramref name="overwrite"/>, an existing target is replaced atomically
    /// through <c>posix-rename@openssh.com</c>. A server without that extension can only rename to a free name.
    /// </summary>
    /// <param name="oldPath">The current remote path.</param>
    /// <param name="newPath">The new remote path.</param>
    /// <param name="overwrite">Whether an existing target may be replaced.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>A task that completes when the server has answered.</returns>
    /// <exception cref="SftpException">The server refused, perhaps because the target exists.</exception>
    /// <example>
    /// <code>
    /// await sftp.UploadFileAsync(local, "/srv/site.conf.tmp", cancellationToken);
    /// await sftp.RenameAsync("/srv/site.conf.tmp", "/srv/site.conf", overwrite: true, cancellationToken);
    /// </code>
    /// </example>
    public async Task RenameAsync(string oldPath, string newPath, bool overwrite = false, CancellationToken cancellationToken = default)
    {
        ValidatePath(oldPath);
        ValidatePath(newPath);
        if (overwrite && HasExtension(PosixRename, "1"))
        {
            await StatusRequestAsync(SftpFrames.ExtendedTwoPaths(PosixRename, oldPath, newPath), SftpMessage.Extended, oldPath, cancellationToken).ConfigureAwait(false);
            return;
        }

        try
        {
            await StatusRequestAsync(SftpFrames.TwoPaths(oldPath, newPath), SftpMessage.Rename, oldPath, cancellationToken).ConfigureAwait(false);
        }
        catch (SftpException ex) when (overwrite && ex.StatusCode == SftpStatusCode.Failure)
        {
            throw new SftpException($"{ex.Message} This server has no {PosixRename}, so it can't replace an existing target. Delete the target first.", ex.StatusCode, oldPath);
        }
    }

    /// <summary>Creates a symbolic link. The argument order is handled for you: OpenSSH reverses it against the draft.</summary>
    /// <param name="linkPath">Where the link goes.</param>
    /// <param name="targetPath">What it points to. The server stores this as given, and doesn't check it.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>A task that completes when the server has answered.</returns>
    /// <exception cref="SftpException">The server refused.</exception>
    /// <example>
    /// <code>
    /// await sftp.CreateSymbolicLinkAsync("/srv/current", "/srv/release-42", cancellationToken);
    /// </code>
    /// </example>
    public Task CreateSymbolicLinkAsync(string linkPath, string targetPath, CancellationToken cancellationToken = default)
    {
        ValidatePath(linkPath);
        ValidatePath(targetPath);
        SftpFrame frame = _symlinkArgumentsReversed ? SftpFrames.TwoPaths(targetPath, linkPath) : SftpFrames.TwoPaths(linkPath, targetPath);
        return StatusRequestAsync(frame, SftpMessage.SymLink, linkPath, cancellationToken);
    }

    /// <summary>Reads where a symbolic link points.</summary>
    /// <param name="path">The link's remote path.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The target as stored. It may be relative, and the server chose it.</returns>
    /// <exception cref="SftpFileNotFoundException">Nothing exists at the path.</exception>
    /// <exception cref="SftpException">The path isn't a link.</exception>
    /// <example>
    /// <code>
    /// string target = await sftp.ReadLinkAsync("/srv/current", cancellationToken);
    /// </code>
    /// </example>
    public Task<string> ReadLinkAsync(string path, CancellationToken cancellationToken = default)
    {
        ValidatePath(path);
        return RequestAsync(SftpFrames.Path(path), SftpMessage.ReadLink, SftpMessage.Name, ReadSingleName, path, cancellationToken);
    }

    /// <summary>Asks the server for the absolute, normalised form of a path. <c>.</c> gives the home directory.</summary>
    /// <param name="path">The remote path.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The absolute path. The server chose it.</returns>
    /// <exception cref="SftpFileNotFoundException">The path doesn't exist, on servers that require it to.</exception>
    /// <example>
    /// <code>
    /// string home = await sftp.GetFullPathAsync(".", cancellationToken);
    /// </code>
    /// </example>
    public Task<string> GetFullPathAsync(string path, CancellationToken cancellationToken = default)
    {
        ValidatePath(path);
        return RequestAsync(SftpFrames.Path(path), SftpMessage.RealPath, SftpMessage.Name, ReadSingleName, path, cancellationToken);
    }

    /// <summary>Checks whether anything exists at a path. A symbolic link counts, even if its target is missing.</summary>
    /// <param name="path">The remote path.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>True if the server found something there.</returns>
    /// <exception cref="SftpPermissionDeniedException">The account can't look there, so the answer is unknown.</exception>
    /// <example>
    /// <code>
    /// if (!await sftp.ExistsAsync("/srv/uploads", cancellationToken))
    /// {
    ///     await sftp.CreateDirectoryAsync("/srv/uploads", cancellationToken);
    /// }
    /// </code>
    /// </example>
    public async Task<bool> ExistsAsync(string path, CancellationToken cancellationToken = default)
    {
        try
        {
            await GetAttributesAsync(path, followSymbolicLinks: false, cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (SftpFileNotFoundException)
        {
            return false;
        }
    }

    /// <summary>Gets file system statistics, through <c>statvfs@openssh.com</c>.</summary>
    /// <param name="path">Any path on the file system.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>What the server reported.</returns>
    /// <exception cref="SftpException">The server refused, or doesn't have the extension (<see cref="SftpStatusCode.OperationUnsupported"/>).</exception>
    /// <example>
    /// <code>
    /// SftpFileSystemInfo info = await sftp.GetFileSystemInfoAsync("/srv", cancellationToken);
    /// Console.WriteLine($"{info.AvailableBytes} bytes free");
    /// </code>
    /// </example>
    public Task<SftpFileSystemInfo> GetFileSystemInfoAsync(string path, CancellationToken cancellationToken = default)
    {
        ValidatePath(path);
        RequireExtension(StatVfs, "2");
        return RequestAsync(SftpFrames.ExtendedPath(StatVfs, path), SftpMessage.Extended, SftpMessage.ExtendedReply, SftpParser.ReadFileSystemInfo, path, cancellationToken);
    }

    /// <summary>Creates a hard link, through <c>hardlink@openssh.com</c>.</summary>
    /// <param name="linkPath">The new name.</param>
    /// <param name="targetPath">The existing file.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>A task that completes when the server has answered.</returns>
    /// <exception cref="SftpException">The server refused, or doesn't have the extension (<see cref="SftpStatusCode.OperationUnsupported"/>).</exception>
    /// <example>
    /// <code>
    /// await sftp.CreateHardLinkAsync("/srv/data.bak", "/srv/data", cancellationToken);
    /// </code>
    /// </example>
    public Task CreateHardLinkAsync(string linkPath, string targetPath, CancellationToken cancellationToken = default)
    {
        ValidatePath(linkPath);
        ValidatePath(targetPath);
        RequireExtension(HardLink, "1");
        return StatusRequestAsync(SftpFrames.ExtendedTwoPaths(HardLink, targetPath, linkPath), SftpMessage.Extended, linkPath, cancellationToken);
    }

    /// <summary>Copies a file on the server, through <c>copy-data</c>, so the bytes never cross the network.</summary>
    /// <param name="sourcePath">The file to copy.</param>
    /// <param name="destinationPath">The new file.</param>
    /// <param name="overwrite">Whether an existing destination may be replaced.</param>
    /// <param name="cancellationToken">Stops waiting. The server may finish the copy anyway.</param>
    /// <returns>A task that completes when the copy is done.</returns>
    /// <exception cref="SftpException">The server refused, or doesn't have the extension (<see cref="SftpStatusCode.OperationUnsupported"/>).</exception>
    /// <example>
    /// <code>
    /// if (sftp.ServerExtensions.ContainsKey("copy-data"))
    /// {
    ///     await sftp.CopyFileAsync("/srv/a.bin", "/srv/b.bin", overwrite: false, cancellationToken);
    /// }
    /// </code>
    /// </example>
    public async Task CopyFileAsync(string sourcePath, string destinationPath, bool overwrite = false, CancellationToken cancellationToken = default)
    {
        ValidatePath(sourcePath);
        ValidatePath(destinationPath);
        RequireExtension(CopyData, "1");

        SftpOpenFlags writeFlags = SftpOpenFlags.Write | SftpOpenFlags.Create | (overwrite ? SftpOpenFlags.Truncate : SftpOpenFlags.Exclusive);
        await UseHandleAsync(
            sourcePath,
            SftpOpenFlags.Read,
            source => UseHandleAsync(
                destinationPath,
                writeFlags,
                destination => StatusRequestAsync(SftpFrames.CopyData(source, destination), SftpMessage.Extended, destinationPath, cancellationToken),
                cancellationToken),
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Closes the session and its channel. Open files stop working.</summary>
    /// <returns>A task that completes when the channel is released.</returns>
    /// <example>
    /// <code>
    /// await sftp.DisposeAsync();
    /// </code>
    /// </example>
    public ValueTask DisposeAsync() => _session.DisposeAsync();

    /// <summary>Starts a session over an open <c>sftp</c> subsystem channel. The client owns the channel from here on.</summary>
    internal static async Task<SftpClient> OpenOverChannelAsync(SshChannel channel, string serverIdentification, SftpClientOptions options, CancellationToken cancellationToken)
    {
        try
        {
            // Nothing reads stderr, so close it: what arrives there is then credited back to the window at once,
            // and a chatty server can't stall the shared window.
            await channel.ErrorOutput.DisposeAsync().ConfigureAwait(false);
            SftpClient client = await StartAsync(channel.Output, channel.Input, channel, serverIdentification, SftpLimits.Default, cancellationToken).ConfigureAwait(false);
            client.Options = options;
            return client;
        }
        catch
        {
            await channel.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>Starts a session over plain streams, which is how the protocol core is tested.</summary>
    internal static async Task<SftpClient> StartAsync(Stream input, Stream output, IAsyncDisposable? owner, string? serverIdentification, SftpLimits limits, CancellationToken cancellationToken)
    {
#pragma warning disable CA2000 // The client owns the session once this returns, and the catch releases it otherwise.
        SftpSession session = await SftpSession.StartAsync(input, output, owner, limits, cancellationToken).ConfigureAwait(false);
#pragma warning restore CA2000
        try
        {
            SftpClient client = new(session, serverIdentification);
            await client.ApplyServerLimitsAsync(cancellationToken).ConfigureAwait(false);
            return client;
        }
        catch
        {
            await session.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>Reads once at an offset. Short answers are legal, so the result can be below the buffer's length. Zero means end of file.</summary>
    internal async ValueTask<int> ReadAtAsync(byte[] handle, string path, long offset, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        int wanted = Math.Min(buffer.Length, _readChunk);
        for (int attempt = 0; attempt <= _session.Limits.MaxEmptyResponses; attempt++)
        {
            SftpPendingRequest request = await SendReadAsync(handle, offset, wanted, cancellationToken).ConfigureAwait(false);
            using SftpResponse response = await request.WaitAsync(cancellationToken).ConfigureAwait(false);
            if (IsEndOfFile(response, path))
            {
                return 0;
            }

            (int start, int length) = _session.Parse(response, r => SftpParser.ReadData(r, wanted));
            if (length != 0)
            {
                response.Slice(start, length).CopyTo(buffer);
                return length;
            }
        }

        throw Fail(EndlessEmptyReads());
    }

    /// <summary>Writes at an offset, with many writes in flight, and returns when all are confirmed.</summary>
    internal async Task WriteAtAsync(byte[] handle, string path, long offset, ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        Queue<SftpPendingRequest> inFlight = new();
        try
        {
            while (!data.IsEmpty)
            {
                int count = Math.Min(data.Length, _writeChunk);
                await EnqueueWriteAsync(inFlight, handle, path, offset, data[..count], cancellationToken).ConfigureAwait(false);
                offset += count;
                data = data[count..];
            }

            await DrainWritesAsync(inFlight, path, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            AbandonAll(inFlight);
        }
    }

    /// <summary>
    /// Copies from a handle to a stream, in order, with many reads in flight. The window grows from 2, so a small
    /// file doesn't cost a full window of requests. Only EOF ends the copy: a short answer just means the rest of
    /// that range is asked for again, before anything later is written.
    /// </summary>
    internal async Task<long> CopyFromHandleAsync(byte[] handle, string path, long offset, Stream destination, long maxBytes, string? limitName, CancellationToken cancellationToken)
    {
        Queue<InFlightRead> inFlight = new();
        InFlightRead? head = null;
        long next = offset;
        long written = 0;
        int window = 2;
        int chunk = _readChunk;
        int empty = 0;
        try
        {
            while (true)
            {
                while (inFlight.Count + (head is null ? 0 : 1) < window)
                {
                    inFlight.Enqueue(new InFlightRead(await SendReadAsync(handle, next, chunk, cancellationToken).ConfigureAwait(false), next, chunk));
                    next += chunk;
                }

                InFlightRead current = head ?? inFlight.Dequeue();
                head = null;
                using SftpResponse response = await current.Request.WaitAsync(cancellationToken).ConfigureAwait(false);
                if (IsEndOfFile(response, path))
                {
                    return written;
                }

                (int start, int length) = _session.Parse(response, r => SftpParser.ReadData(r, current.Length));
                empty = length == 0 ? empty + 1 : 0;
                if (empty > _session.Limits.MaxEmptyResponses)
                {
                    throw Fail(EndlessEmptyReads());
                }

                if (length > maxBytes - written)
                {
                    throw new SftpException($"'{SftpParser.Sanitise(path)}' is larger than the limit of {maxBytes} bytes.{(limitName is null ? string.Empty : $" Raise {limitName}, or stream it with DownloadFileAsync.")}", SftpStatusCode.Failure, path);
                }

                await destination.WriteAsync(response.Slice(start, length), cancellationToken).ConfigureAwait(false);
                written += length;
                window = Math.Min(window * 2, _session.Limits.TransferDepth);
                if (length < current.Length)
                {
                    long rest = current.Offset + length;
                    int count = current.Length - length;
                    head = new InFlightRead(await SendReadAsync(handle, rest, count, cancellationToken).ConfigureAwait(false), rest, count);

                    // A server that caps its reads would otherwise cost a second request for every chunk.
                    if (length != 0)
                    {
                        chunk = Math.Min(chunk, Math.Max(length, 4096));
                    }
                }
            }
        }
        finally
        {
            head?.Request.Abandon();
            foreach (InFlightRead read in inFlight)
            {
                read.Request.Abandon();
            }
        }
    }

    internal async Task<SftpAttributes> GetHandleAttributesAsync(byte[] handle, string path, CancellationToken cancellationToken) =>
        await RequestAsync(SftpFrames.Handle(handle), SftpMessage.Fstat, SftpMessage.Attrs, SftpParser.ReadAttributes, path, cancellationToken).ConfigureAwait(false);

    internal Task SetHandleAttributesAsync(byte[] handle, SftpAttributes attributes, string path, CancellationToken cancellationToken) =>
        StatusRequestAsync(SftpFrames.HandleAndAttributes(handle, attributes), SftpMessage.FSetStat, path, cancellationToken);

    internal Task SyncHandleAsync(byte[] handle, string path, CancellationToken cancellationToken)
    {
        RequireExtension(FSync, "1");
        return StatusRequestAsync(SftpFrames.ExtendedHandle(FSync, handle), SftpMessage.Extended, path, cancellationToken);
    }

    internal Task CloseHandleAsync(byte[] handle, string path, CancellationToken cancellationToken) =>
        StatusRequestAsync(SftpFrames.Handle(handle), SftpMessage.Close, path, cancellationToken);

    /// <summary>Closes a handle without waiting, for paths that are already failing or cancelled.</summary>
    internal void CloseHandleInBackground(byte[] handle) => _ = CloseHandleQuietlyAsync(handle);

    /// <summary>Closes a handle, ignoring failures, with a limit so a silent server can't hold up cleanup.</summary>
    internal async Task CloseHandleQuietlyAsync(byte[] handle)
    {
        using CancellationTokenSource limit = new(CloseLimit);
        try
        {
            await CloseHandleAsync(handle, string.Empty, limit.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SshException or OperationCanceledException)
        {
            // The handle goes away with the session at worst.
        }
    }

    private static SshProtocolException EndlessEmptyReads() =>
        new("The SFTP server keeps answering reads with no data and no end of file.");

    private static void ValidatePath(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        if (path.Contains('\0', StringComparison.Ordinal))
        {
            throw new ArgumentException("A path can't contain a NUL character.", nameof(path));
        }
    }

    /// <summary>
    /// OpenSSH reverses SYMLINK's arguments, and every sftp-server of the last 15 years advertises @openssh.com
    /// extensions, including under other SSH servers such as Dropbear. The identification string covers the rest.
    /// </summary>
    private static bool IsOpenSsh(IReadOnlyDictionary<string, string> extensions, string? serverIdentification)
    {
        foreach (string name in extensions.Keys)
        {
            if (name.EndsWith(OpenSshSuffix, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return serverIdentification?.Contains("OpenSSH", StringComparison.Ordinal) == true;
    }

    private static SftpOpenFlags ToOpenFlags(FileMode mode, FileAccess access)
    {
        SftpOpenFlags flags = access switch
        {
            FileAccess.Read => SftpOpenFlags.Read,
            FileAccess.Write => SftpOpenFlags.Write,
            FileAccess.ReadWrite => SftpOpenFlags.Read | SftpOpenFlags.Write,
            _ => throw new ArgumentOutOfRangeException(nameof(access)),
        };

        if (mode != FileMode.Open && mode != FileMode.OpenOrCreate && access == FileAccess.Read)
        {
            throw new ArgumentException($"FileMode.{mode} needs write access.", nameof(access));
        }

        if (mode == FileMode.Append && access != FileAccess.Write)
        {
            throw new ArgumentException("FileMode.Append needs FileAccess.Write.", nameof(access));
        }

        return flags | mode switch
        {
            FileMode.Open => 0,
            FileMode.OpenOrCreate => SftpOpenFlags.Create,
            FileMode.Create => SftpOpenFlags.Create | SftpOpenFlags.Truncate,
            FileMode.CreateNew => SftpOpenFlags.Create | SftpOpenFlags.Exclusive,
            FileMode.Truncate => SftpOpenFlags.Truncate,
            FileMode.Append => SftpOpenFlags.Create | SftpOpenFlags.Append,
            _ => throw new ArgumentOutOfRangeException(nameof(mode)),
        };
    }

    private static string ReadSingleName(SftpResponse response)
    {
        SftpEntry[] names = SftpParser.ReadNames(response, 1);
        return names.Length == 1
            ? names[0].Name
            : throw new SshProtocolException("The SFTP server answered with no name where one was required.");
    }

    private static void AbandonAll(Queue<SftpPendingRequest> requests)
    {
        foreach (SftpPendingRequest request in requests)
        {
            request.Abandon();
        }
    }

    private bool HasExtension(string name, string version) =>
        _session.Extensions.TryGetValue(name, out string? value) && value == version;

    private void RequireExtension(string name, string version)
    {
        if (!HasExtension(name, version))
        {
            throw new SftpException($"This server doesn't offer {name} version {version}. Check ServerExtensions before calling this.", SftpStatusCode.OperationUnsupported, null);
        }
    }

    private SshProtocolException Fail(SshProtocolException failure)
    {
        _session.Fail(failure);
        return failure;
    }

    private async Task ApplyServerLimitsAsync(CancellationToken cancellationToken)
    {
        if (!HasExtension(LimitsExtension, "1"))
        {
            return;
        }

        SftpPendingRequest request = await _session.SendAsync(SftpFrames.Extended(LimitsExtension), SftpMessage.Extended, SftpMessage.ExtendedReply, cancellationToken).ConfigureAwait(false);
        using SftpResponse response = await request.WaitAsync(cancellationToken).ConfigureAwait(false);
        if (response.Type == SftpMessage.Status)
        {
            return;
        }

        (ulong maxPacket, ulong maxRead, ulong maxWrite) = _session.Parse(response, ReadLimits);

        // Zero means the server states no limit. A limit can only lower what we'd use anyway.
        if (maxRead != 0)
        {
            _readChunk = (int)Math.Min((ulong)_readChunk, maxRead);
        }

        if (maxWrite != 0)
        {
            _writeChunk = (int)Math.Min((ulong)_writeChunk, maxWrite);
        }

        if (maxPacket > MinServerPacketLength)
        {
            _writeChunk = (int)Math.Min((ulong)_writeChunk, maxPacket - MinServerPacketLength);
        }
    }

    private static (ulong MaxPacket, ulong MaxRead, ulong MaxWrite) ReadLimits(SftpResponse response)
    {
        SshReader reader = new(response.Body);
        ulong maxPacket = reader.ReadUInt64();
        ulong maxRead = reader.ReadUInt64();
        ulong maxWrite = reader.ReadUInt64();
        reader.ReadUInt64();
        return (maxPacket, maxRead, maxWrite);
    }

    private async Task<T> RequestAsync<T>(SftpFrame frame, byte type, byte expected, Func<SftpResponse, T> parse, string? path, CancellationToken cancellationToken)
    {
        SftpPendingRequest request = await _session.SendAsync(frame, type, expected, cancellationToken).ConfigureAwait(false);
        using SftpResponse response = await request.WaitAsync(cancellationToken).ConfigureAwait(false);
        if (response.Type == SftpMessage.Status)
        {
            throw StatusFailure(response, path);
        }

        return _session.Parse(response, parse);
    }

    private async Task StatusRequestAsync(SftpFrame frame, byte type, string? path, CancellationToken cancellationToken)
    {
        SftpPendingRequest request = await _session.SendAsync(frame, type, 0, cancellationToken).ConfigureAwait(false);
        using SftpResponse response = await request.WaitAsync(cancellationToken).ConfigureAwait(false);
        EnsureOk(response, path);
    }

    private void EnsureOk(SftpResponse response, string? path)
    {
        (SftpStatusCode code, string message) = _session.Parse(response, SftpParser.ReadStatus);
        if (code != SftpStatusCode.Ok)
        {
            throw SftpParser.ToException(code, message, path);
        }
    }

    /// <summary>The exception for a STATUS answering a request that wanted data. OK makes no sense there.</summary>
    private SshException StatusFailure(SftpResponse response, string? path)
    {
        (SftpStatusCode code, string message) = _session.Parse(response, SftpParser.ReadStatus);
        return code == SftpStatusCode.Ok
            ? Fail(new SshProtocolException("The SFTP server answered OK to a request that needs data."))
            : SftpParser.ToException(code, message, path);
    }

    /// <summary>Returns true for EOF, false for DATA, and throws for any other status.</summary>
    private bool IsEndOfFile(SftpResponse response, string path)
    {
        if (response.Type != SftpMessage.Status)
        {
            return false;
        }

        (SftpStatusCode code, _) = _session.Parse(response, SftpParser.ReadStatus);
        return code == SftpStatusCode.EndOfFile ? true : throw StatusFailure(response, path);
    }

    private ValueTask<SftpPendingRequest> SendReadAsync(byte[] handle, long offset, int length, CancellationToken cancellationToken) =>
        _session.SendAsync(SftpFrames.Read(handle, offset, length), SftpMessage.Read, SftpMessage.Data, cancellationToken);

    private async ValueTask EnqueueWriteAsync(Queue<SftpPendingRequest> inFlight, byte[] handle, string path, long offset, ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        if (inFlight.Count >= _session.Limits.TransferDepth)
        {
            await AwaitWriteAsync(inFlight.Dequeue(), path, cancellationToken).ConfigureAwait(false);
        }

        inFlight.Enqueue(await _session.SendAsync(SftpFrames.Write(handle, offset, data.Span), SftpMessage.Write, 0, cancellationToken).ConfigureAwait(false));
    }

    private async ValueTask AwaitWriteAsync(SftpPendingRequest request, string path, CancellationToken cancellationToken)
    {
        using SftpResponse response = await request.WaitAsync(cancellationToken).ConfigureAwait(false);
        EnsureOk(response, path);
    }

    private async ValueTask DrainWritesAsync(Queue<SftpPendingRequest> inFlight, string path, CancellationToken cancellationToken)
    {
        while (inFlight.TryDequeue(out SftpPendingRequest? request))
        {
            await AwaitWriteAsync(request, path, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task CopyToHandleAsync(Stream source, byte[] handle, string path, CancellationToken cancellationToken)
    {
        Queue<SftpPendingRequest> inFlight = new();
        int chunk = _writeChunk;
        byte[] buffer = ArrayPool<byte>.Shared.Rent(chunk);
        try
        {
            long offset = 0;
            while (true)
            {
                int read = await source.ReadAtLeastAsync(buffer.AsMemory(0, chunk), chunk, throwOnEndOfStream: false, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                await EnqueueWriteAsync(inFlight, handle, path, offset, buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                offset += read;
            }

            await DrainWritesAsync(inFlight, path, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            AbandonAll(inFlight);
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    private async Task<byte[]> OpenHandleAsync(string path, SftpOpenFlags flags, CancellationToken cancellationToken)
    {
        ValidatePath(path);
        return await RequestHandleAsync(SftpFrames.Open(path, flags), SftpMessage.Open, path, cancellationToken).ConfigureAwait(false);
    }

    private Task<byte[]> OpenDirectoryAsync(string path, CancellationToken cancellationToken) =>
        RequestHandleAsync(SftpFrames.Path(path), SftpMessage.OpenDir, path, cancellationToken);

    /// <summary>Opens a handle. If the caller gives up first, the handle is closed when it arrives, so it doesn't leak.</summary>
    private async Task<byte[]> RequestHandleAsync(SftpFrame frame, byte type, string path, CancellationToken cancellationToken)
    {
        SftpPendingRequest request = await _session.SendAsync(frame, type, SftpMessage.Handle, cancellationToken).ConfigureAwait(false);
        SftpResponse response;
        try
        {
            response = await request.Response.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            _ = CloseLateHandleAsync(request);
            throw;
        }

        using (response)
        {
            if (response.Type == SftpMessage.Status)
            {
                throw StatusFailure(response, path);
            }

            return _session.Parse(response, SftpParser.ReadHandle);
        }
    }

    private async Task CloseLateHandleAsync(SftpPendingRequest request)
    {
        try
        {
            using SftpResponse response = await request.Response.ConfigureAwait(false);
            if (response.Type == SftpMessage.Handle)
            {
                await CloseHandleQuietlyAsync(_session.Parse(response, SftpParser.ReadHandle)).ConfigureAwait(false);
            }
        }
        catch (SshException)
        {
            // The session ended, and the handle went with it.
        }
    }

    private async Task UseHandleAsync(string path, SftpOpenFlags flags, Func<byte[], Task> use, CancellationToken cancellationToken)
    {
        byte[] handle = await OpenHandleAsync(path, flags, cancellationToken).ConfigureAwait(false);
        try
        {
            await use(handle).ConfigureAwait(false);
        }
        catch
        {
            CloseHandleInBackground(handle);
            throw;
        }

        // The status of CLOSE is part of the result: some file systems only report failure here.
        await CloseHandleAsync(handle, path, cancellationToken).ConfigureAwait(false);
    }

    private async Task<SftpEntry[]?> ReadDirectoryBatchAsync(byte[] handle, string path, CancellationToken cancellationToken)
    {
        SftpPendingRequest request = await _session.SendAsync(SftpFrames.Handle(handle), SftpMessage.ReadDir, SftpMessage.Name, cancellationToken).ConfigureAwait(false);
        using SftpResponse response = await request.WaitAsync(cancellationToken).ConfigureAwait(false);
        return IsEndOfFile(response, path) ? null : _session.Parse(response, r => SftpParser.ReadNames(r, _session.Limits.MaxNamesPerBatch));
    }

    private async Task DownloadTreeAsync(string remoteDirectory, string localDirectory, int depth, DownloadBudget budget, CancellationToken cancellationToken)
    {
        if (depth >= MaxDownloadDepth)
        {
            throw new SftpException($"'{SftpParser.Sanitise(remoteDirectory)}' is nested more than {MaxDownloadDepth} levels deep. A hostile server can fake this; copy the subtree you need instead.", SftpStatusCode.Failure, remoteDirectory);
        }

        // The whole directory is checked before any of it is written.
        List<(SftpEntry Entry, string Local)> entries = [];
        await foreach (SftpEntry entry in ListDirectoryAsync(remoteDirectory, cancellationToken).ConfigureAwait(false))
        {
            if (entry.Name is "." or "..")
            {
                continue;
            }

            string local = SftpLocalPath.Resolve(localDirectory, entry.Name) ?? throw UnsafeName(entry.Name, remoteDirectory);
            budget.TakeEntry(remoteDirectory);
            entries.Add((entry, local));
        }

        string remotePrefix = remoteDirectory.EndsWith('/') ? remoteDirectory : remoteDirectory + "/";
        foreach ((SftpEntry entry, string local) in entries)
        {
            string remote = remotePrefix + entry.Name;
            SftpAttributes attributes = entry.Attributes.HasFileType
                ? entry.Attributes
                : await GetAttributesAsync(remote, followSymbolicLinks: false, cancellationToken).ConfigureAwait(false);
            if (attributes.IsDirectory)
            {
                CreateLocalDirectory(local, entry.Name, remoteDirectory);
                await DownloadTreeAsync(remote, local, depth + 1, budget, cancellationToken).ConfigureAwait(false);
            }
            else if (attributes.IsRegularFile)
            {
                await DownloadTreeFileAsync(remote, local, entry.Name, remoteDirectory, budget, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private async Task DownloadTreeFileAsync(string remote, string local, string name, string remoteDirectory, DownloadBudget budget, CancellationToken cancellationToken)
    {
#pragma warning disable CA2000 // Disposed below, once the using can't be skipped by the catch.
        FileStream file;
        try
        {
            // CreateNew never follows a link or replaces a file, whatever appeared at this path.
            file = new FileStream(local, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1, useAsync: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new SftpUnsafeNameException($"Couldn't create a local file for the server's name '{SftpParser.Sanitise(name)}': {ex.Message} A server can send the same name twice, or collide with what's already there, so clear the destination before trusting it.", name, remoteDirectory);
        }
#pragma warning restore CA2000

        await using (file.ConfigureAwait(false))
        {
            try
            {
                await UseHandleAsync(
                    remote,
                    SftpOpenFlags.Read,
                    async handle => budget.TakeBytes(await CopyFromHandleAsync(handle, remote, 0, file, budget.RemainingBytes, null, cancellationToken).ConfigureAwait(false)),
                    cancellationToken).ConfigureAwait(false);
            }
            catch (IOException ex)
            {
                // A server decides how much is written, so even a full disk counts as something it can cause.
                throw new SftpException($"Couldn't write '{local}': {ex.Message} Free some space, or pass a lower maxTotalBytes.", ex);
            }
        }
    }

    private static void CreateLocalDirectory(string local, string name, string remoteDirectory)
    {
        try
        {
            // Only a directory that isn't a link may be entered: a link here could lead outside the destination.
            if (new DirectoryInfo(local).LinkTarget is not null || File.Exists(local))
            {
                throw UnsafeName(name, remoteDirectory);
            }

            Directory.CreateDirectory(local);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new SftpUnsafeNameException($"Couldn't create a local directory for the server's name '{SftpParser.Sanitise(name)}': {ex.Message}", name, remoteDirectory);
        }
    }

    private static SftpUnsafeNameException UnsafeName(string name, string remoteDirectory) =>
        new($"The server listed the unsafe name '{SftpParser.Sanitise(name)}' in '{SftpParser.Sanitise(remoteDirectory)}'. It can't become a local path inside the destination, so the download stopped. Don't trust this server.", name, remoteDirectory);

    private readonly record struct InFlightRead(SftpPendingRequest Request, long Offset, int Length);

    /// <summary>What's left of a recursive download's limits.</summary>
    private sealed class DownloadBudget(long entries, long bytes)
    {
        // A cap on names as well as entries: a hostile server can make each one long, and the tree is held in memory.
        private const long MaxPathCharacters = 32 * 1024 * 1024;

        private long _taken;
        private long _pathCharacters;

        public long RemainingBytes { get; private set; } = bytes;

        public void TakeEntry(string path)
        {
            _pathCharacters += path.Length;
            if (++_taken > entries || _pathCharacters > MaxPathCharacters)
            {
                throw new SftpException($"The tree has more than {entries} entries, reached at '{SftpParser.Sanitise(path)}'. Raise SftpClientOptions.MaxDirectoryEntries if that's expected.", SftpStatusCode.Failure, path);
            }
        }

        public void TakeBytes(long count) => RemainingBytes -= count;
    }
}

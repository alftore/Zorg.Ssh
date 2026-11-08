using System;
using System.IO;
using Microsoft.Extensions.Logging;

namespace Zorg.Ssh.Sftp;

/// <summary>What <see cref="SftpServer.ServeAsync"/> serves, and the limits on one session.</summary>
/// <example>
/// <code>
/// SftpServerOptions options = new()
/// {
///     RootDirectory = "/srv/sftp/alice",
///     ReadOnly = true,
/// };
/// </code>
/// </example>
public sealed class SftpServerOptions
{
    /// <summary>The largest <see cref="MaxReadSize"/>. Real clients refuse packets over 256 KiB.</summary>
    private const int ReadSizeCeiling = 255 * 1024;

    private const int MinReadSize = 1024;
    private const int MinBatch = 2;
    private const int MaxBatchCeiling = 1024;

    /// <summary>
    /// Gets the directory the client sees as <c>/</c>. It must exist. The client can't reach anything outside it,
    /// so give each user their own root if users mustn't see each other's files. Symbolic links in this path are
    /// resolved once, when the session starts.
    /// </summary>
    /// <example>
    /// <code>
    /// SftpServerOptions options = new() { RootDirectory = Path.Combine(dataDirectory, session.Principal.UserName) };
    /// </code>
    /// </example>
    public required string RootDirectory { get; init; }

    /// <summary>Gets a value saying whether every request that would change something is refused.</summary>
    /// <example>
    /// <code>
    /// SftpServerOptions options = new() { RootDirectory = "/srv/public", ReadOnly = true };
    /// </code>
    /// </example>
    public bool ReadOnly { get; init; }

    /// <summary>Gets the most files and directories one session can hold open. The default is 100. Past this, an open gets a failure status.</summary>
    /// <example>
    /// <code>
    /// SftpServerOptions options = new() { RootDirectory = root, MaxOpenHandles = 16 };
    /// </code>
    /// </example>
    public int MaxOpenHandles { get; init; } = 100;

    /// <summary>
    /// Gets the most bytes one READ returns. A client that asks for more gets this much, which the protocol allows.
    /// The default is 64 KiB, and it can be from 1 KiB to 255 KiB.
    /// </summary>
    /// <example>
    /// <code>
    /// SftpServerOptions options = new() { RootDirectory = root, MaxReadSize = 32 * 1024 };
    /// </code>
    /// </example>
    public int MaxReadSize { get; init; } = 64 * 1024;

    /// <summary>
    /// Gets the most names one READDIR returns. The default is 100, and it can be from 2 to 1024, because the first batch holds <c>.</c> and <c>..</c>. A directory is read
    /// as it's listed, so its size doesn't change what a session holds in memory.
    /// </summary>
    /// <example>
    /// <code>
    /// SftpServerOptions options = new() { RootDirectory = root, MaxListingBatch = 500 };
    /// </code>
    /// </example>
    public int MaxListingBatch { get; init; } = 100;

    /// <summary>Gets the logger factory. Paths the client sent aren't logged.</summary>
    /// <example>
    /// <code>
    /// SftpServerOptions options = new() { RootDirectory = root, LoggerFactory = loggerFactory };
    /// </code>
    /// </example>
    public ILoggerFactory? LoggerFactory { get; init; }

    /// <summary>
    /// Gets how long an open may take where the operating system could block it forever, as it does for a FIFO
    /// nobody is writing to. A session that hits this ends. Tests shorten it.
    /// </summary>
    internal TimeSpan OpenTimeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Gets a value saying whether OPEN and SETSTAT read a file's type and refuse a FIFO or device before opening it
    /// (finding S1). Only tests turn it off, to reach the open that blocks, as a FIFO swapped in after the look would.
    /// </summary>
    internal bool CheckTypeBeforeOpen { get; init; } = true;

    /// <summary>Checks everything a session depends on, before a byte of it is read.</summary>
    internal void Validate()
    {
        if (string.IsNullOrEmpty(RootDirectory))
        {
            throw new ArgumentException("Set RootDirectory to the directory clients should see as /.", nameof(RootDirectory));
        }

        if (!Directory.Exists(RootDirectory))
        {
            throw new DirectoryNotFoundException($"RootDirectory '{RootDirectory}' doesn't exist. Create it before serving SFTP.");
        }

        if (MaxOpenHandles < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxOpenHandles), MaxOpenHandles, "A session needs at least one handle.");
        }

        if (MaxReadSize is < MinReadSize or > ReadSizeCeiling)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxReadSize), MaxReadSize, $"Use a value from {MinReadSize} to {ReadSizeCeiling}.");
        }

        if (MaxListingBatch is < MinBatch or > MaxBatchCeiling)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxListingBatch), MaxListingBatch, $"Use a value from {MinBatch} to {MaxBatchCeiling}.");
        }
    }
}

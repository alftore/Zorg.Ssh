using System;

namespace Zorg.Ssh.Sftp;

/// <summary>Limits for an SFTP session, for <see cref="SshClient.OpenSftpAsync(SftpClientOptions, System.Threading.CancellationToken)"/>. The defaults suit most uses.</summary>
/// <example>
/// <code>
/// await using SftpClient sftp = await client.OpenSftpAsync(new SftpClientOptions { MaxReadAllBytes = 1024L * 1024 * 1024 }, cancellationToken);
/// </code>
/// </example>
public sealed class SftpClientOptions
{
    private readonly long _maxReadAllBytes = 256 * 1024 * 1024;
    private readonly long _maxDirectoryEntries = 1_000_000;

    /// <summary>Gets the defaults.</summary>
    internal static SftpClientOptions Default { get; } = new();

    /// <summary>Gets the most bytes <see cref="SftpClient.ReadAllBytesAsync"/> will hold, which stops a server filling memory. The default is 256 MiB.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is negative.</exception>
    /// <example>
    /// <code>
    /// SftpClientOptions options = new() { MaxReadAllBytes = 1024L * 1024 * 1024 };
    /// </code>
    /// </example>
    public long MaxReadAllBytes
    {
        get => _maxReadAllBytes;
        init
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value);
            _maxReadAllBytes = value;
        }
    }

    /// <summary>
    /// Gets the most entries one <see cref="SftpClient.ListDirectoryAsync"/> or <see cref="SftpClient.DownloadDirectoryAsync(string, string, long, SftpTransferOptions, System.Threading.CancellationToken)"/>
    /// will take, which stops a server listing for ever. The default is 1,000,000.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is negative.</exception>
    /// <example>
    /// <code>
    /// SftpClientOptions options = new() { MaxDirectoryEntries = 10_000_000 };
    /// </code>
    /// </example>
    public long MaxDirectoryEntries
    {
        get => _maxDirectoryEntries;
        init
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value);
            _maxDirectoryEntries = value;
        }
    }
}

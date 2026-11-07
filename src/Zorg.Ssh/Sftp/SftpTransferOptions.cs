using System;

namespace Zorg.Ssh.Sftp;

/// <summary>
/// Settings for one transfer: <see cref="SftpClient.UploadFileAsync(System.IO.Stream, string, SftpTransferOptions, System.Threading.CancellationToken)"/>,
/// <see cref="SftpClient.DownloadFileAsync(string, System.IO.Stream, SftpTransferOptions, System.Threading.CancellationToken)"/> and
/// <see cref="SftpClient.DownloadDirectoryAsync(string, string, long, SftpTransferOptions, System.Threading.CancellationToken)"/>.
/// The defaults are what the overloads without options do. Use <c>with</c> to change a copy.
/// </summary>
/// <example>
/// <code>
/// SftpTransferOptions options = new() { Progress = new Progress&lt;SftpTransferProgress&gt;(p => Console.WriteLine($"{p.BytesTransferred} of {p.TotalBytes}")) };
/// await sftp.UploadFileAsync(source, "backup.tar", options, cancellationToken);
/// </code>
/// </example>
public sealed record SftpTransferOptions
{
    /// <summary>
    /// Gets where progress goes, or null for none. <see cref="IProgress{T}.Report"/> is called on the transfer's own
    /// flow, at the start, at most about every 100 ms while bytes move, and once at the end with the final counts.
    /// Nothing is reported after the method has returned, but <see cref="Progress{T}"/> posts each report to the
    /// context it was made on, so its handler can run later.
    /// </summary>
    /// <remarks>
    /// The transfer waits while <see cref="IProgress{T}.Report"/> runs, so keep it quick. If it throws, the transfer
    /// stops, the remote file is closed, and your exception comes out of the transfer method unchanged: a failing
    /// callback is a bug in the caller, not something the server did. The SFTP session stays usable.
    /// </remarks>
    /// <example>
    /// <code>
    /// SftpTransferOptions options = new() { Progress = new Progress&lt;SftpTransferProgress&gt;(ShowProgress) };
    /// </code>
    /// </example>
    public IProgress<SftpTransferProgress>? Progress { get; init; }

    /// <summary>Gets the clock that spaces the reports out. Tests replace it.</summary>
    internal TimeProvider TimeProvider { get; init; } = TimeProvider.System;
}

/// <summary>
/// How far a transfer has got, as <see cref="SftpTransferOptions.Progress"/> reports it. Each report is a new object, so
/// it can be kept or passed to another thread.
/// </summary>
/// <example>
/// <code>
/// void ShowProgress(SftpTransferProgress p)
/// {
///     string percent = p.TotalBytes is long total and total > 0 ? $"{100 * p.BytesTransferred / total}%" : $"{p.BytesTransferred} bytes";
///     Console.WriteLine($"{p.RemotePath}: {percent}, {p.FilesCompleted} files done");
/// }
/// </code>
/// </example>
public sealed record SftpTransferProgress
{
    /// <summary>Gets the remote file being transferred.</summary>
    public required string RemotePath { get; init; }

    /// <summary>
    /// Gets the local file being written, for <see cref="SftpClient.DownloadDirectoryAsync(string, string, long, SftpTransferOptions, System.Threading.CancellationToken)"/>.
    /// It's null for the calls that take a stream.
    /// </summary>
    public string? LocalPath { get; init; }

    /// <summary>
    /// Gets the bytes of <see cref="RemotePath"/> transferred so far. A download counts what has been written to your
    /// stream or file. An upload counts what has been sent, and its last report comes after the server has confirmed
    /// every write and closed the file.
    /// </summary>
    public required long BytesTransferred { get; init; }

    /// <summary>
    /// Gets the size of <see cref="RemotePath"/>, or null if it isn't known. An upload knows it from a stream that can
    /// seek. A download asks the server, or takes it from the directory listing. The server's size is a claim, not a
    /// limit: the file can change during the transfer, so <see cref="BytesTransferred"/> can end above or below it.
    /// </summary>
    public long? TotalBytes { get; init; }

    /// <summary>Gets how many files this call has finished. A single file reports 1 in its last report.</summary>
    public required long FilesCompleted { get; init; }

    /// <summary>
    /// Gets the bytes transferred by this call so far, across every file. For a single file it equals
    /// <see cref="BytesTransferred"/>. A directory download has no total in advance, because the tree is listed as it
    /// is copied.
    /// </summary>
    public required long OverallBytesTransferred { get; init; }
}

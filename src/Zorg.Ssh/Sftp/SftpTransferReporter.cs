using System;

namespace Zorg.Ssh.Sftp;

/// <summary>
/// Turns a transfer's byte counts into throttled <see cref="SftpTransferProgress"/> reports. One per call, used on the
/// call's own flow, so it needs no locking. The first report always goes out, then at most one per
/// <see cref="Interval"/>, and <see cref="Complete"/> sends the final state if a later one was held back.
/// </summary>
internal sealed class SftpTransferReporter(IProgress<SftpTransferProgress> progress, TimeProvider time)
{
    /// <summary>The least time between two reports, apart from the first and the last.</summary>
    internal static readonly TimeSpan Interval = TimeSpan.FromMilliseconds(100);

    private string _remotePath = string.Empty;
    private string? _localPath;
    private long _bytes;
    private long? _total;
    private long _files;
    private long _overall;
    private bool _reported;
    private bool _dirty;
    private long _lastReport;

    /// <summary>Gets whether the callback threw, so a caller can tell its exception from one of its own.</summary>
    public bool CallbackFailed { get; private set; }

    /// <summary>Makes a reporter for these options, or null when nobody listens.</summary>
    public static SftpTransferReporter? For(SftpTransferOptions? options) =>
        options?.Progress is { } progress ? new SftpTransferReporter(progress, options.TimeProvider) : null;

    /// <summary>Starts a file. The first file of a call is reported at once.</summary>
    public void StartFile(string remotePath, string? localPath, long? totalBytes)
    {
        _remotePath = remotePath;
        _localPath = localPath;
        _total = totalBytes;
        _bytes = 0;
        _dirty = true;
        Report(force: !_reported);
    }

    /// <summary>Counts bytes of the current file.</summary>
    public void Advance(long count)
    {
        _bytes += count;
        _overall += count;
        _dirty = true;
        Report(force: false);
    }

    /// <summary>Ends the current file.</summary>
    public void EndFile()
    {
        _files++;
        _dirty = true;
        Report(force: false);
    }

    /// <summary>Sends the final state, if the last report didn't already carry it. Called only on success.</summary>
    public void Complete()
    {
        if (_dirty && _reported)
        {
            Report(force: true);
        }
    }

    private void Report(bool force)
    {
        long now = time.GetTimestamp();
        if (!force && time.GetElapsedTime(_lastReport, now) < Interval)
        {
            return;
        }

        _lastReport = now;
        _reported = true;
        _dirty = false;
        try
        {
            progress.Report(new SftpTransferProgress
            {
                RemotePath = _remotePath,
                LocalPath = _localPath,
                BytesTransferred = _bytes,
                TotalBytes = _total,
                FilesCompleted = _files,
                OverallBytesTransferred = _overall,
            });
        }
        catch
        {
            CallbackFailed = true;
            throw;
        }
    }
}

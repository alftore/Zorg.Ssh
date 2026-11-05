using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Zorg.Ssh.Sftp;

/// <summary>
/// An open remote file. Use the async methods: the sync ones block a thread on the network. Like other streams, one
/// instance isn't safe for use by several tasks at once. Each read asks the server once and can return less than
/// you asked for. <see cref="CopyToAsync(Stream, int, CancellationToken)"/> keeps many reads in flight, so it's the
/// fast way to read a lot. Writes are confirmed by the server before they return.
/// </summary>
/// <example>
/// <code>
/// await using SftpFile file = await sftp.OpenAsync("/srv/data.bin", FileMode.Open, FileAccess.ReadWrite, cancellationToken);
/// file.Position = 1024;
/// await file.WriteAsync(patch, cancellationToken);
/// await file.SyncAsync(cancellationToken);
/// </code>
/// </example>
#pragma warning disable CA1710 // The name mirrors SftpClient and SftpEntry, and says what it is better than SftpFileStream would.
public sealed class SftpFile : Stream
#pragma warning restore CA1710
{
    private readonly SftpClient _client;
    private readonly byte[] _handle;
    private readonly string _path;
    private readonly FileAccess _access;
    private long _position;
    private bool _closed;

    internal SftpFile(SftpClient client, byte[] handle, string path, FileAccess access, long position)
    {
        _client = client;
        _handle = handle;
        _path = path;
        _access = access;
        _position = position;
    }

    /// <summary>Gets the remote path this file was opened with.</summary>
    /// <example>
    /// <code>
    /// Console.WriteLine(file.Path);
    /// </code>
    /// </example>
    public string Path => _path;

    /// <summary>Gets a value saying whether the file is open for reading.</summary>
    /// <example>
    /// <code>
    /// if (file.CanRead)
    /// {
    ///     await file.CopyToAsync(destination, cancellationToken);
    /// }
    /// </code>
    /// </example>
    public override bool CanRead => !_closed && (_access & FileAccess.Read) != 0;

    /// <summary>Gets a value saying whether the file is open for writing.</summary>
    /// <example>
    /// <code>
    /// if (file.CanWrite)
    /// {
    ///     await file.WriteAsync(data, cancellationToken);
    /// }
    /// </code>
    /// </example>
    public override bool CanWrite => !_closed && (_access & FileAccess.Write) != 0;

    /// <summary>Gets a value saying whether the position can move. It's true until the file is closed.</summary>
    /// <example>
    /// <code>
    /// if (file.CanSeek)
    /// {
    ///     file.Position = 0;
    /// }
    /// </code>
    /// </example>
    public override bool CanSeek => !_closed;

    /// <summary>Gets the file's size. This blocks on the network: prefer <see cref="GetLengthAsync"/>.</summary>
    /// <example>
    /// <code>
    /// long length = file.Length;
    /// </code>
    /// </example>
    public override long Length => GetLengthAsync(CancellationToken.None).GetAwaiter().GetResult();

    /// <summary>Gets or sets where the next read or write happens. This only changes a local value, so it costs no round trip.</summary>
    /// <example>
    /// <code>
    /// file.Position = 1024;
    /// </code>
    /// </example>
    public override long Position
    {
        get => _position;
        set
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value);
            _position = value;
        }
    }

    /// <summary>Gets the file's current size from the server.</summary>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The size in bytes.</returns>
    /// <exception cref="SftpException">The server refused, or didn't report a size.</exception>
    /// <example>
    /// <code>
    /// long length = await file.GetLengthAsync(cancellationToken);
    /// </code>
    /// </example>
    public async Task<long> GetLengthAsync(CancellationToken cancellationToken = default)
    {
        SftpAttributes attributes = await GetAttributesAsync(cancellationToken).ConfigureAwait(false);
        return attributes.Size ?? throw new SftpException($"The server didn't report the size of '{SftpParser.Sanitise(_path)}'.", SftpStatusCode.OperationUnsupported, _path);
    }

    /// <summary>Gets the open file's attributes.</summary>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>What the server reported.</returns>
    /// <example>
    /// <code>
    /// SftpAttributes attributes = await file.GetAttributesAsync(cancellationToken);
    /// </code>
    /// </example>
    public Task<SftpAttributes> GetAttributesAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_closed, this);
        return _client.GetHandleAttributesAsync(_handle, _path, cancellationToken);
    }

    /// <summary>Truncates or extends the file.</summary>
    /// <param name="value">The new size.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>A task that completes when the server has answered.</returns>
    /// <example>
    /// <code>
    /// await file.SetLengthAsync(0, cancellationToken);
    /// </code>
    /// </example>
    public Task SetLengthAsync(long value, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_closed, this);
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        return _client.SetHandleAttributesAsync(_handle, new SftpAttributes { Size = value }, _path, cancellationToken);
    }

    /// <summary>Asks the server to commit the file to disk, through <c>fsync@openssh.com</c>.</summary>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>A task that completes when the server has answered.</returns>
    /// <exception cref="SftpException">The server refused, or doesn't have the extension (<see cref="SftpStatusCode.OperationUnsupported"/>).</exception>
    /// <example>
    /// <code>
    /// await file.WriteAsync(data, cancellationToken);
    /// await file.SyncAsync(cancellationToken);
    /// </code>
    /// </example>
    public Task SyncAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_closed, this);
        return _client.SyncHandleAsync(_handle, _path, cancellationToken);
    }

    /// <summary>Closes the handle and reports any failure, which disposing doesn't. Some file systems only fail here.</summary>
    /// <param name="cancellationToken">Cancels the wait.</param>
    /// <returns>A task that completes when the server has answered.</returns>
    /// <exception cref="SftpException">The server refused.</exception>
    /// <example>
    /// <code>
    /// await file.WriteAsync(data, cancellationToken);
    /// await file.CloseAsync(cancellationToken);
    /// </code>
    /// </example>
    public async Task CloseAsync(CancellationToken cancellationToken = default)
    {
        if (!_closed)
        {
            _closed = true;
            await _client.CloseHandleAsync(_handle, _path, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Reads with one request to the server. It can return less than the buffer holds, and zero means end of file.</summary>
    /// <param name="buffer">Where the bytes go.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The number of bytes read.</returns>
    /// <example>
    /// <code>
    /// int read = await file.ReadAsync(buffer, cancellationToken);
    /// </code>
    /// </example>
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        ThrowIfCant(CanRead, "read");
        if (buffer.IsEmpty)
        {
            return 0;
        }

        int read = await _client.ReadAtAsync(_handle, _path, _position, buffer, cancellationToken).ConfigureAwait(false);
        _position += read;
        return read;
    }

    /// <summary>Reads with one request to the server. It can return less than asked, and zero means end of file.</summary>
    /// <param name="buffer">Where the bytes go.</param>
    /// <param name="offset">Where in the buffer to start.</param>
    /// <param name="count">The most bytes to read.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The number of bytes read.</returns>
    /// <example>
    /// <code>
    /// int read = await file.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
    /// </code>
    /// </example>
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    /// <summary>Reads, blocking a thread on the network. Prefer <see cref="ReadAsync(Memory{byte}, CancellationToken)"/>.</summary>
    /// <param name="buffer">Where the bytes go.</param>
    /// <param name="offset">Where in the buffer to start.</param>
    /// <param name="count">The most bytes to read.</param>
    /// <returns>The number of bytes read. Zero means end of file.</returns>
    /// <example>
    /// <code>
    /// int read = file.Read(buffer, 0, buffer.Length);
    /// </code>
    /// </example>
    public override int Read(byte[] buffer, int offset, int count) =>
        ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    /// <summary>Writes at the position, with many requests in flight for a large buffer, and returns when the server has confirmed them all.</summary>
    /// <param name="buffer">The bytes to write.</param>
    /// <param name="cancellationToken">Stops waiting. Some of the bytes may have been written.</param>
    /// <returns>A task that completes when every write is confirmed.</returns>
    /// <example>
    /// <code>
    /// await file.WriteAsync(data, cancellationToken);
    /// </code>
    /// </example>
    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
    {
        ThrowIfCant(CanWrite, "write");
        await _client.WriteAtAsync(_handle, _path, _position, buffer, cancellationToken).ConfigureAwait(false);
        _position += buffer.Length;
    }

    /// <summary>Writes at the position, and returns when the server has confirmed it.</summary>
    /// <param name="buffer">The bytes to write.</param>
    /// <param name="offset">Where in the buffer to start.</param>
    /// <param name="count">How many bytes to write.</param>
    /// <param name="cancellationToken">Stops waiting. Some of the bytes may have been written.</param>
    /// <returns>A task that completes when every write is confirmed.</returns>
    /// <example>
    /// <code>
    /// await file.WriteAsync(buffer, 0, buffer.Length, cancellationToken);
    /// </code>
    /// </example>
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    /// <summary>Writes, blocking a thread on the network. Prefer <see cref="WriteAsync(ReadOnlyMemory{byte}, CancellationToken)"/>.</summary>
    /// <param name="buffer">The bytes to write.</param>
    /// <param name="offset">Where in the buffer to start.</param>
    /// <param name="count">How many bytes to write.</param>
    /// <example>
    /// <code>
    /// file.Write(data, 0, data.Length);
    /// </code>
    /// </example>
    public override void Write(byte[] buffer, int offset, int count) =>
        WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    /// <summary>Copies from the current position to the end, with many reads in flight.</summary>
    /// <param name="destination">Where the bytes go.</param>
    /// <param name="bufferSize">Ignored: the transfer sizes its own requests.</param>
    /// <param name="cancellationToken">Stops the copy.</param>
    /// <returns>A task that completes when the end of the file is reached.</returns>
    /// <example>
    /// <code>
    /// await file.CopyToAsync(destination, cancellationToken);
    /// </code>
    /// </example>
    public override async Task CopyToAsync(Stream destination, int bufferSize, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ThrowIfCant(CanRead, "read");
        _position += await _client.CopyFromHandleAsync(_handle, _path, _position, destination, long.MaxValue, null, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Does nothing: every write is already confirmed. To commit to disk, use <see cref="SyncAsync"/>.</summary>
    /// <example>
    /// <code>
    /// file.Flush();
    /// </code>
    /// </example>
    public override void Flush()
    {
    }

    /// <summary>Does nothing: every write is already confirmed. To commit to disk, use <see cref="SyncAsync"/>.</summary>
    /// <param name="cancellationToken">Unused.</param>
    /// <returns>A completed task.</returns>
    /// <example>
    /// <code>
    /// await file.FlushAsync(cancellationToken);
    /// </code>
    /// </example>
    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <summary>Moves the position. <see cref="SeekOrigin.End"/> asks the server for the size, so it blocks on the network.</summary>
    /// <param name="offset">The offset from <paramref name="origin"/>.</param>
    /// <param name="origin">Where to count from.</param>
    /// <returns>The new position.</returns>
    /// <example>
    /// <code>
    /// long position = file.Seek(-4096, SeekOrigin.End);
    /// </code>
    /// </example>
    public override long Seek(long offset, SeekOrigin origin)
    {
        ObjectDisposedException.ThrowIf(_closed, this);
        long target = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => _position + offset,
            SeekOrigin.End => Length + offset,
            _ => throw new ArgumentOutOfRangeException(nameof(origin)),
        };

        if (target < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(offset), "The position can't be before the start of the file.");
        }

        _position = target;
        return target;
    }

    /// <summary>Truncates or extends the file, blocking on the network. Prefer <see cref="SetLengthAsync"/>.</summary>
    /// <param name="value">The new size.</param>
    /// <example>
    /// <code>
    /// file.SetLength(0);
    /// </code>
    /// </example>
    public override void SetLength(long value) => SetLengthAsync(value, CancellationToken.None).GetAwaiter().GetResult();

    /// <summary>Closes the handle. Failures are ignored; use <see cref="CloseAsync"/> to see them.</summary>
    /// <returns>A task that completes when the handle is closed, or a few seconds have passed.</returns>
    /// <example>
    /// <code>
    /// await file.DisposeAsync();
    /// </code>
    /// </example>
    public override async ValueTask DisposeAsync()
    {
        if (!_closed)
        {
            _closed = true;
            await _client.CloseHandleQuietlyAsync(_handle).ConfigureAwait(false);
        }

        await base.DisposeAsync().ConfigureAwait(false);
    }

    /// <summary>Closes the handle, blocking on the network. Prefer <see cref="DisposeAsync"/>.</summary>
    /// <param name="disposing">True when called from <see cref="Stream.Dispose()"/>.</param>
    /// <example>
    /// <code>
    /// using SftpFile file = await sftp.OpenAsync(path);
    /// </code>
    /// </example>
    protected override void Dispose(bool disposing)
    {
        if (disposing && !_closed)
        {
            _closed = true;
            _client.CloseHandleQuietlyAsync(_handle).GetAwaiter().GetResult();
        }

        base.Dispose(disposing);
    }

    private void ThrowIfCant(bool allowed, string action)
    {
        ObjectDisposedException.ThrowIf(_closed, this);
        if (!allowed)
        {
            throw new NotSupportedException($"This file wasn't opened to {action}.");
        }
    }
}

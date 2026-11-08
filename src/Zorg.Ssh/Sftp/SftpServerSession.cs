using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Sftp;

/// <summary>
/// One client. Requests are served strictly in order, one at a time, so a session holds one request buffer and one
/// reply buffer however much the client pipelines. Every request gets exactly one reply, built in <c>_reply</c>.
/// </summary>
/// <remarks>
/// Replies carry fixed text per status. Exception messages name real paths, so they never go near the wire.
/// </remarks>
internal sealed partial class SftpServerSession : IAsyncDisposable
{
    private const uint ProtocolVersion = 3;
    private const int LengthField = 4;
    private const int MinPacketLength = 5;
    private const int ReplyHeaderLength = 9;
    private const int DataHeaderLength = ReplyHeaderLength + 4;
    private const int ListingMargin = 8192;
    private const ulong StatvfsReadOnly = 1;
    private const ulong StatvfsBlockSize = 4096;
    private const ulong StatvfsMaxName = 255;

    private const string PosixRename = "posix-rename@openssh.com";
    private const string Fsync = "fsync@openssh.com";
    private const string Limits = "limits@openssh.com";
    private const string Statvfs = "statvfs@openssh.com";

    /// <summary>
    /// Serialises everything that goes from a path to a change or an open, across every session in this process,
    /// whatever its root, as roots can nest. .NET has no openat, so between checking a path and using it another
    /// session could rename a link into place. Two sessions of one client are the cheapest way to get such a race,
    /// and this takes it away. File contents don't pass through here: only metadata work waits.
    /// </summary>
    internal static readonly SemaphoreSlim NamespaceGate = new(1, 1);

#pragma warning disable CA2213 // The streams belong to the caller.
    private readonly Stream _input;
    private readonly Stream _output;
#pragma warning restore CA2213
    private readonly SftpServerOptions _options;
    private readonly ILogger _logger;
    private readonly SftpServerPaths _paths;
    private readonly SftpServerHandles _handles;
    private readonly int _maxPacketLength = SftpLimits.Default.MaxPacketLength;
    private readonly byte[] _lengthField = new byte[LengthField];
    private byte[]? _request;
    private byte[]? _reply;
    private int _replyLength;

    public SftpServerSession(Stream input, Stream output, SftpServerOptions options)
    {
        _input = input;
        _output = output;
        _options = options;
        _logger = options.LoggerFactory?.CreateLogger<SftpServerSession>() ?? NullLogger<SftpServerSession>.Instance;
        _paths = new SftpServerPaths(options.RootDirectory);
        _handles = new SftpServerHandles(options.MaxOpenHandles);
        _request = ArrayPool<byte>.Shared.Rent(_maxPacketLength);
        _reply = ArrayPool<byte>.Shared.Rent(_maxPacketLength + LengthField);
    }

    private byte[] ReplyBuffer => _reply!;

    /// <summary>Gets the reply built for the last request, length field included. Only the fuzz tests read it.</summary>
    internal ReadOnlyMemory<byte> LastReply => _reply.AsMemory(0, _replyLength);

    public async Task<int> RunAsync(CancellationToken cancellationToken)
    {
        try
        {
            int length = await ReadPacketAsync(cancellationToken).ConfigureAwait(false);
            if (length < 0 || _request![0] != SftpMessage.Init)
            {
                return 1;
            }

            BuildVersion();
            await SendReplyAsync(cancellationToken).ConfigureAwait(false);
            while (true)
            {
                length = await ReadPacketAsync(cancellationToken).ConfigureAwait(false);
                if (length < 0)
                {
                    return 0;
                }

                await ServeAsync(length, cancellationToken).ConfigureAwait(false);
                await SendReplyAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (IsSessionEnd(ex, cancellationToken))
        {
            LogSessionEnded(_logger, ex);
            return 1;
        }
    }

    public ValueTask DisposeAsync()
    {
        _handles.Dispose();
        Return(ref _request);
        Return(ref _reply);
        return ValueTask.CompletedTask;
    }

    [LoggerMessage(Level = LogLevel.Debug, Message = "SFTP session ended")]
    private static partial void LogSessionEnded(ILogger logger, Exception exception);

    [LoggerMessage(Level = LogLevel.Debug, Message = "SFTP request type {RequestType} refused with status {Status}")]
    private static partial void LogRefused(ILogger logger, byte requestType, SftpStatusCode status);

    [LoggerMessage(Level = LogLevel.Error, Message = "SFTP request type {RequestType} failed unexpectedly")]
    private static partial void LogUnexpected(ILogger logger, byte requestType, Exception exception);

    private static void Return(ref byte[]? buffer)
    {
        byte[]? taken = buffer;
        buffer = null;
        if (taken is not null)
        {
            // Both can hold file contents.
            ArrayPool<byte>.Shared.Return(taken, clearArray: true);
        }
    }

    private static bool IsSessionEnd(Exception ex, CancellationToken cancellationToken) =>
        ex is SshException or IOException or ObjectDisposedException or TimeoutException
        || (ex is OperationCanceledException && !cancellationToken.IsCancellationRequested);

    private static SftpStatusCode ToStatus(Exception ex) => ex switch
    {
        SftpServerRefusedException refused => refused.Status,
        FileNotFoundException or DirectoryNotFoundException => SftpStatusCode.NoSuchFile,
        UnauthorizedAccessException or SecurityException => SftpStatusCode.PermissionDenied,
        _ => SftpStatusCode.Failure,
    };

    private static string StatusText(SftpStatusCode status) => status switch
    {
        SftpStatusCode.Ok => "Success",
        SftpStatusCode.EndOfFile => "End of file",
        SftpStatusCode.NoSuchFile => "No such file",
        SftpStatusCode.PermissionDenied => "Permission denied",
        SftpStatusCode.OperationUnsupported => "Operation unsupported",
        _ => "Failure",
    };

    private static SftpServerRefusedException Refuse(SftpStatusCode status) => new(status);

    private static SftpAttributes Stat(SftpServerResolved resolved)
    {
        if (!resolved.Exists)
        {
            throw Refuse(SftpStatusCode.NoSuchFile);
        }

        // The resolve's own look at the entry, made a moment ago in this request, so it isn't read a second time.
        return SftpServerAttributes.FromInfo(resolved.Info);
    }

    private static void Move(SftpServerResolved source, SftpServerResolved target, bool overwrite)
    {
        if (source.IsDirectory)
        {
            Directory.Move(source.RealPath, target.RealPath);
        }
        else
        {
            File.Move(source.RealPath, target.RealPath, overwrite);
        }
    }

    private async ValueTask<int> ReadPacketAsync(CancellationToken cancellationToken)
    {
        int read = await _input.ReadAtLeastAsync(_lengthField, LengthField, throwOnEndOfStream: false, cancellationToken).ConfigureAwait(false);
        if (read == 0)
        {
            return -1;
        }

        if (read < LengthField)
        {
            throw new SshProtocolException("The SFTP client ended in the middle of a packet.");
        }

        // Checked before anything is read, and the buffer was sized for the limit, so the claim costs nothing.
        uint length = BinaryPrimitives.ReadUInt32BigEndian(_lengthField);
        if (length < MinPacketLength || length > (uint)_maxPacketLength)
        {
            throw new SshProtocolException("The SFTP client sent a packet length outside the limits.");
        }

        Memory<byte> body = _request.AsMemory(0, (int)length);
        if (await _input.ReadAtLeastAsync(body, body.Length, throwOnEndOfStream: false, cancellationToken).ConfigureAwait(false) < body.Length)
        {
            throw new SshProtocolException("The SFTP client ended in the middle of a packet.");
        }

        return (int)length;
    }

    private ValueTask SendReplyAsync(CancellationToken cancellationToken) =>
        _output.WriteAsync(_reply.AsMemory(0, _replyLength), cancellationToken);

    /// <summary>Runs one request. Whatever goes wrong becomes a status, except what ends the session.</summary>
    private async ValueTask ServeAsync(int length, CancellationToken cancellationToken)
    {
        byte type = _request![0];
        uint id = BinaryPrimitives.ReadUInt32BigEndian(_request.AsSpan(1));
        ReadOnlyMemory<byte> body = _request.AsMemory(MinPacketLength, length - MinPacketLength);
        try
        {
            await DispatchAsync(type, id, body, cancellationToken).ConfigureAwait(false);
        }
        catch (SshProtocolException)
        {
            // Packets are framed, so a malformed one doesn't lose the next.
            BuildStatus(id, SftpStatusCode.Failure);
        }
        catch (Exception ex) when (ex is SftpServerRefusedException or IOException or UnauthorizedAccessException or SecurityException or ArgumentException or NotSupportedException)
        {
            SftpStatusCode status = ToStatus(ex);
            LogRefused(_logger, type, status);
            BuildStatus(id, status);
        }
#pragma warning disable CA1031 // Guarantee 3: whatever this was, the client gets a plain failure and the server carries on.
        catch (Exception ex) when (ex is not (OperationCanceledException or TimeoutException))
#pragma warning restore CA1031
        {
            LogUnexpected(_logger, type, ex);
            BuildStatus(id, SftpStatusCode.Failure);
        }
    }

    /// <summary>Runs one request body. Internal so the fuzz tests can see which exception escapes, which <see cref="ServeAsync"/> would turn into a plain failure.</summary>
    internal async ValueTask DispatchAsync(byte type, uint id, ReadOnlyMemory<byte> body, CancellationToken cancellationToken)
    {
        switch (type)
        {
            case SftpMessage.Read:
                await ReadAsync(id, body, cancellationToken).ConfigureAwait(false);
                break;
            case SftpMessage.Write:
                await WriteAsync(id, body, cancellationToken).ConfigureAwait(false);
                break;
            case SftpMessage.Close:
                Close(id, body.Span);
                break;
            case SftpMessage.Fstat:
                Fstat(id, body.Span);
                break;
            case SftpMessage.FSetStat:
                FSetStat(id, body.Span);
                break;
            case SftpMessage.ReadDir:
                ReadDirectory(id, body.Span);
                break;
            case SftpMessage.Open or SftpMessage.SetStat:
            case SftpMessage.Lstat or SftpMessage.Stat or SftpMessage.OpenDir or SftpMessage.Remove or SftpMessage.MkDir or SftpMessage.RmDir:
            case SftpMessage.RealPath or SftpMessage.Rename or SftpMessage.ReadLink or SftpMessage.SymLink:
                await ServeLockedAsync(type, id, body, cancellationToken).ConfigureAwait(false);
                break;
            case SftpMessage.Extended:
                await ExtendedAsync(id, body, cancellationToken).ConfigureAwait(false);
                break;
            default:
                BuildStatus(id, SftpStatusCode.OperationUnsupported);
                break;
        }
    }

    /// <summary>Runs a request that uses a path, under <see cref="NamespaceGate"/>.</summary>
    private async ValueTask ServeLockedAsync(byte type, uint id, ReadOnlyMemory<byte> body, CancellationToken cancellationToken)
    {
        await NamespaceGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            switch (type)
            {
                case SftpMessage.Open:
                    await OpenAsync(id, body, cancellationToken).ConfigureAwait(false);
                    break;
                case SftpMessage.SetStat:
                    await SetStatAsync(id, body, cancellationToken).ConfigureAwait(false);
                    break;
                case SftpMessage.Lstat:
                    StatPath(id, body.Span, SftpServerFinalLink.Keep);
                    break;
                case SftpMessage.Stat:
                    StatPath(id, body.Span, SftpServerFinalLink.Follow);
                    break;
                case SftpMessage.OpenDir:
                    OpenDirectory(id, body.Span);
                    break;
                case SftpMessage.Remove:
                    Remove(id, body.Span);
                    break;
                case SftpMessage.MkDir:
                    MakeDirectory(id, body.Span);
                    break;
                case SftpMessage.RmDir:
                    RemoveDirectory(id, body.Span);
                    break;
                case SftpMessage.RealPath:
                    RealPath(id, body.Span);
                    break;
                case SftpMessage.Rename:
                    Rename(id, body.Span, overwrite: false);
                    break;
                case SftpMessage.ReadLink:
                    ReadLink(id, body.Span);
                    break;
                default:
                    SymLink(id, body.Span);
                    break;
            }
        }
        finally
        {
            NamespaceGate.Release();
        }
    }

    private async ValueTask ExtendedAsync(uint id, ReadOnlyMemory<byte> body, CancellationToken cancellationToken)
    {
        (string name, int consumed) = ReadExtensionName(body.Span);
        ReadOnlyMemory<byte> arguments = body[consumed..];
        switch (name)
        {
            case Limits:
                BuildLimits(id);
                break;
            case Fsync:
                Sync(id, arguments.Span);
                break;
            case PosixRename:
                await NamespaceGate.WaitAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    Rename(id, arguments.Span, overwrite: true);
                }
                finally
                {
                    NamespaceGate.Release();
                }

                break;
            case Statvfs:
                await NamespaceGate.WaitAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    FileSystemInfo(id, arguments.Span);
                }
                finally
                {
                    NamespaceGate.Release();
                }

                break;
            default:
                BuildStatus(id, SftpStatusCode.OperationUnsupported);
                break;
        }
    }

    private static (string Name, int Consumed) ReadExtensionName(ReadOnlySpan<byte> body)
    {
        SshReader reader = new(body);
        string name = reader.ReadUtf8String();
        return (name, body.Length - reader.Remaining);
    }

    private void RefuseIfReadOnly()
    {
        if (_options.ReadOnly)
        {
            throw Refuse(SftpStatusCode.PermissionDenied);
        }
    }

    private async ValueTask OpenAsync(uint id, ReadOnlyMemory<byte> body, CancellationToken cancellationToken)
    {
        (string path, SftpOpenFlags flags, SftpAttributes attributes) = ReadOpen(body.Span);
        const SftpOpenFlags Mutating = SftpOpenFlags.Write | SftpOpenFlags.Append | SftpOpenFlags.Create | SftpOpenFlags.Truncate | SftpOpenFlags.Exclusive;
        bool mutating = (flags & Mutating) != 0;
        if (mutating)
        {
            RefuseIfReadOnly();
        }

        if (_handles.IsFull)
        {
            throw Refuse(SftpStatusCode.Failure);
        }

        bool create = flags.HasFlag(SftpOpenFlags.Create);
        bool exclusive = create && flags.HasFlag(SftpOpenFlags.Exclusive);
        SftpServerFinalLink finalLink = exclusive ? SftpServerFinalLink.Keep : SftpServerFinalLink.Follow;
        SftpServerResolved resolved = _paths.Resolve(path, finalLink);
        if (resolved.IsDirectory || (resolved.Exists && exclusive))
        {
            throw Refuse(SftpStatusCode.Failure);
        }

        if (!resolved.Exists && !create)
        {
            throw Refuse(SftpStatusCode.NoSuchFile);
        }

        // O_CREAT without O_EXCL would follow a link planted after the check, so a new file is always CreateNew.
        // Truncating waits until the file has been verified, because it can't be undone.
        FileStreamOptions open = new()
        {
            Mode = resolved.Exists ? FileMode.Open : FileMode.CreateNew,
            Access = !mutating ? FileAccess.Read : flags.HasFlag(SftpOpenFlags.Read) ? FileAccess.ReadWrite : FileAccess.Write,
            Share = FileShare.ReadWrite | FileShare.Delete,
            Options = FileOptions.Asynchronous,
            BufferSize = 0,
        };
        if (!resolved.Exists && !OperatingSystem.IsWindows())
        {
            open.UnixCreateMode = (attributes.Permissions ?? (UnixFileMode)0x1B6) & SftpServerAttributes.ClientMode;
        }

        FileStream stream = await OpenStreamAsync(resolved.RealPath, open, cancellationToken).ConfigureAwait(false);
        try
        {
            Verify(stream, path, resolved, finalLink);
            if (flags.HasFlag(SftpOpenFlags.Truncate) && resolved.Exists)
            {
                stream.SetLength(0);
            }

            bool append = flags.HasFlag(SftpOpenFlags.Append);
#pragma warning disable CA2000 // The handle table owns it from here.
            BuildHandle(id, _handles.Add(new SftpServerFile(
                stream,
                canRead: !mutating || flags.HasFlag(SftpOpenFlags.Read),
                canWrite: flags.HasFlag(SftpOpenFlags.Write) || append,
                append)));
#pragma warning restore CA2000
        }
        catch
        {
            await stream.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private static (string Path, SftpOpenFlags Flags, SftpAttributes Attributes) ReadOpen(ReadOnlySpan<byte> body)
    {
        SshReader reader = new(body);
        string path = reader.ReadUtf8String();
        SftpOpenFlags flags = (SftpOpenFlags)reader.ReadUInt32();
        return (path, flags, SftpAttributes.Read(ref reader));
    }

    /// <summary>
    /// Opens a file. On Unix an open can block for good, on a FIFO with no writer, and .NET has neither O_NONBLOCK nor
    /// a way to tell a FIFO from a file first. So it runs on the side, and a session that hits the limit ends:
    /// the thread stays stuck until a writer turns up, and one per session is the most a client can tie up at a time.
    /// </summary>
    private async ValueTask<FileStream> OpenStreamAsync(string realPath, FileStreamOptions open, CancellationToken cancellationToken)
    {
        if (OperatingSystem.IsWindows())
        {
            return new FileStream(realPath, open);
        }

        Task<FileStream> opening = Task.Run(() => new FileStream(realPath, open), CancellationToken.None);
        try
        {
            return await opening.WaitAsync(_options.OpenTimeout, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is TimeoutException or OperationCanceledException)
        {
            _ = opening.ContinueWith(
                static task =>
                {
                    if (task.IsCompletedSuccessfully)
                    {
                        task.Result.Dispose();
                    }
                    else
                    {
                        _ = task.Exception;
                    }
                },
                CancellationToken.None,
                TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
            throw;
        }
    }

    /// <summary>
    /// Checks what was really opened. The walk ran before the open, so something outside this process could have
    /// swapped a directory for a link in between. Walking again sees any swap that's still there. On Linux, the
    /// kernel can say which file the descriptor is, which also sees one that was swapped back.
    /// </summary>
    private void Verify(FileStream stream, string path, SftpServerResolved resolved, SftpServerFinalLink finalLink)
    {
        if (!stream.CanSeek)
        {
            // A FIFO or a device: not a file, whatever it's called.
            throw Refuse(SftpStatusCode.Failure);
        }

        if (_paths.Resolve(path, finalLink).RealPath != resolved.RealPath)
        {
            throw Refuse(SftpStatusCode.PermissionDenied);
        }

        if (OperatingSystem.IsLinux()
            && new FileInfo($"/proc/self/fd/{stream.SafeFileHandle.DangerousGetHandle()}").LinkTarget is { } opened
            && opened != resolved.RealPath)
        {
            throw Refuse(SftpStatusCode.PermissionDenied);
        }
    }

    private void Close(uint id, ReadOnlySpan<byte> body)
    {
        SshReader reader = new(body);
        _handles.Close(reader.ReadBinary());
        BuildStatus(id, SftpStatusCode.Ok);
    }

    private async ValueTask ReadAsync(uint id, ReadOnlyMemory<byte> body, CancellationToken cancellationToken)
    {
        (SftpServerFile file, ulong offset, uint requested) = ReadReadArguments(body.Span);
        if (!file.CanRead)
        {
            throw Refuse(SftpStatusCode.PermissionDenied);
        }

        // Asking for more than the cap gets the cap, which is a short read the protocol allows.
        int length = (int)Math.Min(requested, (uint)_options.MaxReadSize);
        if (offset > long.MaxValue || length == 0)
        {
            throw Refuse(SftpStatusCode.EndOfFile);
        }

        Memory<byte> destination = _reply.AsMemory(DataHeaderLength, length);
        int read = await RandomAccess.ReadAsync(file.Handle, destination, (long)offset, cancellationToken).ConfigureAwait(false);
        if (read == 0)
        {
            throw Refuse(SftpStatusCode.EndOfFile);
        }

        BinaryPrimitives.WriteUInt32BigEndian(ReplyBuffer.AsSpan(ReplyHeaderLength), (uint)read);
        FinishReply(SftpMessage.Data, id, DataHeaderLength + read);
    }

    private (SftpServerFile File, ulong Offset, uint Length) ReadReadArguments(ReadOnlySpan<byte> body)
    {
        SshReader reader = new(body);
        SftpServerFile file = _handles.Get<SftpServerFile>(reader.ReadBinary());
        ulong offset = reader.ReadUInt64();
        return (file, offset, reader.ReadUInt32());
    }

    private async ValueTask WriteAsync(uint id, ReadOnlyMemory<byte> body, CancellationToken cancellationToken)
    {
        (SftpServerFile file, ulong offset, int dataStart, int dataLength) = ReadWriteArguments(body.Span);
        if (!file.CanWrite)
        {
            throw Refuse(SftpStatusCode.PermissionDenied);
        }

        if (offset > (ulong)(long.MaxValue - dataLength))
        {
            throw Refuse(SftpStatusCode.Failure);
        }

        long position = file.Append ? RandomAccess.GetLength(file.Handle) : (long)offset;
        await RandomAccess.WriteAsync(file.Handle, body.Slice(dataStart, dataLength), position, cancellationToken).ConfigureAwait(false);
        BuildStatus(id, SftpStatusCode.Ok);
    }

    private (SftpServerFile File, ulong Offset, int DataStart, int DataLength) ReadWriteArguments(ReadOnlySpan<byte> body)
    {
        SshReader reader = new(body);
        SftpServerFile file = _handles.Get<SftpServerFile>(reader.ReadBinary());
        ulong offset = reader.ReadUInt64();
        int dataLength = reader.ReadBinary().Length;
        return (file, offset, body.Length - reader.Remaining - dataLength, dataLength);
    }

    private void Fstat(uint id, ReadOnlySpan<byte> body)
    {
        SshReader reader = new(body);
        SftpServerFile file = _handles.Get<SftpServerFile>(reader.ReadBinary());
        BuildAttributes(id, SftpServerAttributes.FromHandle(file.Handle));
    }

    private void FSetStat(uint id, ReadOnlySpan<byte> body)
    {
        RefuseIfReadOnly();
        SshReader reader = new(body);
        SftpServerFile file = _handles.Get<SftpServerFile>(reader.ReadBinary());
        SftpAttributes attributes = ReadChanges(ref reader);
        SftpServerAttributes.Apply(file.Handle, attributes);
        BuildStatus(id, SftpStatusCode.Ok);
    }

    private static SftpAttributes ReadChanges(ref SshReader reader)
    {
        SftpAttributes attributes = SftpAttributes.Read(ref reader);
        if (attributes.Uid is not null)
        {
            // .NET can't change owners, and saying yes would be a lie.
            throw Refuse(SftpStatusCode.OperationUnsupported);
        }

        return attributes;
    }

    private async ValueTask SetStatAsync(uint id, ReadOnlyMemory<byte> body, CancellationToken cancellationToken)
    {
        RefuseIfReadOnly();
        (string path, SftpAttributes attributes) = ReadSetStat(body.Span);
        SftpServerResolved resolved = _paths.Resolve(path, SftpServerFinalLink.Follow);
        if (!resolved.Exists)
        {
            throw Refuse(SftpStatusCode.NoSuchFile);
        }

        if (resolved.IsDirectory)
        {
            SftpServerAttributes.ApplyToDirectory(resolved.RealPath, attributes);
            BuildStatus(id, SftpStatusCode.Ok);
            return;
        }

        // Through a handle, so the check below covers the file that's changed. Windows needs write access for times.
        FileStreamOptions open = new()
        {
            Mode = FileMode.Open,
            Access = attributes.Size is not null || OperatingSystem.IsWindows() ? FileAccess.Write : FileAccess.Read,
            Share = FileShare.ReadWrite | FileShare.Delete,
            BufferSize = 0,
        };
        FileStream stream = await OpenStreamAsync(resolved.RealPath, open, cancellationToken).ConfigureAwait(false);
        await using (stream.ConfigureAwait(false))
        {
            Verify(stream, path, resolved, SftpServerFinalLink.Follow);
            SftpServerAttributes.Apply(stream.SafeFileHandle, attributes);
        }

        BuildStatus(id, SftpStatusCode.Ok);
    }

    private static (string Path, SftpAttributes Attributes) ReadSetStat(ReadOnlySpan<byte> body)
    {
        SshReader reader = new(body);
        string path = reader.ReadUtf8String();
        return (path, ReadChanges(ref reader));
    }

    private void StatPath(uint id, ReadOnlySpan<byte> body, SftpServerFinalLink finalLink)
    {
        SshReader reader = new(body);
        SftpServerResolved resolved = _paths.Resolve(reader.ReadUtf8String(), finalLink);
        BuildAttributes(id, Stat(resolved));
    }

    private void OpenDirectory(uint id, ReadOnlySpan<byte> body)
    {
        if (_handles.IsFull)
        {
            throw Refuse(SftpStatusCode.Failure);
        }

        SshReader reader = new(body);
        string path = reader.ReadUtf8String();
        SftpServerResolved resolved = _paths.Resolve(path, SftpServerFinalLink.Follow);
        SftpAttributes self = Stat(resolved);
        if (!resolved.IsDirectory)
        {
            throw Refuse(SftpStatusCode.Failure);
        }

        SftpServerListing entries = SftpServerListing.Open(resolved.RealPath);
        try
        {
            if (_paths.Resolve(path, SftpServerFinalLink.Follow).RealPath != resolved.RealPath)
            {
                throw Refuse(SftpStatusCode.PermissionDenied);
            }

#pragma warning disable CA2000 // The handle table owns it from here.
            BuildHandle(id, _handles.Add(new SftpServerDirectory(entries, self)));
#pragma warning restore CA2000
            entries = null!;
        }
        finally
        {
            entries?.Dispose();
        }
    }

    private void ReadDirectory(uint id, ReadOnlySpan<byte> body)
    {
        SshReader reader = new(body);
        SftpServerDirectory directory = _handles.Get<SftpServerDirectory>(reader.ReadBinary());

        SshWriter writer = new(4096, ReplyHeaderLength + 4);
        try
        {
            uint count = 0;
            if (!directory.SpecialsSent)
            {
                directory.SpecialsSent = true;
                WriteName(ref writer, ".", directory.Self);
                WriteName(ref writer, "..", directory.Self);
                count = 2;
            }

            int limit = _maxPacketLength - ListingMargin;
            while (count < (uint)_options.MaxListingBatch && writer.Length < limit && directory.Entries.TryNext(out SftpServerListedEntry entry))
            {
                if (entry.RawName is { } raw)
                {
                    WriteRawName(ref writer, raw, entry.Attributes);
                }
                else
                {
                    WriteName(ref writer, entry.Name, entry.Attributes);
                }

                count++;
            }

            if (count == 0)
            {
                throw Refuse(SftpStatusCode.EndOfFile);
            }

            writer.Written.CopyTo(ReplyBuffer);
            BinaryPrimitives.WriteUInt32BigEndian(ReplyBuffer.AsSpan(ReplyHeaderLength), count);
            FinishReply(SftpMessage.Name, id, writer.Length);
        }
        finally
        {
            writer.Dispose();
        }
    }

    private static void WriteName(ref SshWriter writer, string name, SftpAttributes attributes)
    {
        WriteFileName(ref writer, name);
        WriteFileName(ref writer, SftpServerAttributes.LongName(name, attributes));
        attributes.WriteWithFileType(ref writer);
    }

    /// <summary>
    /// Writes a name that isn't UTF-8 as the bytes the file system holds, in the name and the long name, as OpenSSH's
    /// <c>sftp-server</c> does. A client can't use it as a path, and our client reports it with
    /// <see cref="SftpEntry.HasValidName"/> false, but it isn't mistaken for another entry.
    /// </summary>
    private static void WriteRawName(ref SshWriter writer, byte[] name, SftpAttributes attributes)
    {
        writer.WriteBinary(name);
        string prefix = SftpServerAttributes.LongName(string.Empty, attributes);
        byte[] longName = ArrayPool<byte>.Shared.Rent(Encoding.UTF8.GetByteCount(prefix) + name.Length);
        try
        {
            int length = Encoding.UTF8.GetBytes(prefix, longName);
            name.CopyTo(longName.AsSpan(length));
            writer.WriteBinary(longName.AsSpan(0, length + name.Length));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(longName);
        }

        attributes.WriteWithFileType(ref writer);
    }

    /// <summary>
    /// Writes a name from the file system. A Windows name can hold an unpaired surrogate, which isn't Unicode, so UTF-8
    /// can't say it, and <see cref="SshWriter.WriteUtf8String"/> would send U+FFFD: a client would then see a valid name
    /// that leads nowhere, or to another file whose name really has U+FFFD in it. Such a name goes as the generalised
    /// UTF-8 of the surrogate instead (three bytes, as WTF-8 has it). No strict decoder accepts those bytes, so a client
    /// sees a name it can't use, as it does for the bytes of a name that isn't UTF-8 on a Unix server. Our client
    /// reports it with <see cref="SftpEntry.HasValidName"/> false, and a path naming it can't reach the server either.
    /// </summary>
    internal static void WriteFileName(ref SshWriter writer, string name)
    {
        if (!HasUnpairedSurrogate(name))
        {
            writer.WriteUtf8String(name);
            return;
        }

        byte[] bytes = ArrayPool<byte>.Shared.Rent(name.Length * 3);
        try
        {
            int length = 0;
            for (int i = 0; i < name.Length; i++)
            {
                char c = name[i];
                if (char.IsHighSurrogate(c) && i + 1 < name.Length && char.IsLowSurrogate(name[i + 1]))
                {
                    length += new Rune(c, name[++i]).EncodeToUtf8(bytes.AsSpan(length));
                }
                else if (char.IsSurrogate(c))
                {
                    bytes[length++] = (byte)(0xE0 | (c >> 12));
                    bytes[length++] = (byte)(0x80 | ((c >> 6) & 0x3F));
                    bytes[length++] = (byte)(0x80 | (c & 0x3F));
                }
                else
                {
                    length += new Rune(c).EncodeToUtf8(bytes.AsSpan(length));
                }
            }

            writer.WriteBinary(bytes.AsSpan(0, length));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(bytes);
        }
    }

    private static bool HasUnpairedSurrogate(string name)
    {
        for (int i = 0; i < name.Length; i++)
        {
            if (char.IsHighSurrogate(name[i]) && i + 1 < name.Length && char.IsLowSurrogate(name[i + 1]))
            {
                i++;
            }
            else if (char.IsSurrogate(name[i]))
            {
                return true;
            }
        }

        return false;
    }

    private void Remove(uint id, ReadOnlySpan<byte> body)
    {
        RefuseIfReadOnly();
        SshReader reader = new(body);
        SftpServerResolved resolved = _paths.Resolve(reader.ReadUtf8String(), SftpServerFinalLink.Keep);
        if (!resolved.Exists)
        {
            throw Refuse(SftpStatusCode.NoSuchFile);
        }

        if (resolved.IsDirectory && !resolved.IsLink)
        {
            throw Refuse(SftpStatusCode.Failure);
        }

        if (resolved.IsDirectory && OperatingSystem.IsWindows())
        {
            // A link to a directory is a directory to Win32. Only the link goes.
            Directory.Delete(resolved.RealPath, recursive: false);
        }
        else
        {
            File.Delete(resolved.RealPath);
        }

        BuildStatus(id, SftpStatusCode.Ok);
    }

    private void MakeDirectory(uint id, ReadOnlySpan<byte> body)
    {
        RefuseIfReadOnly();
        SshReader reader = new(body);
        string path = reader.ReadUtf8String();
        SftpAttributes attributes = SftpAttributes.Read(ref reader);
        SftpServerResolved resolved = _paths.Resolve(path, SftpServerFinalLink.Keep);
        if (resolved.Exists)
        {
            throw Refuse(SftpStatusCode.Failure);
        }

        // CreateDirectory would quietly create parents too.
        if (resolved.ParentMissing)
        {
            throw Refuse(SftpStatusCode.NoSuchFile);
        }

        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(resolved.RealPath);
        }
        else
        {
            Directory.CreateDirectory(resolved.RealPath, (attributes.Permissions ?? (UnixFileMode)0x1FF) & SftpServerAttributes.ClientMode);
        }

        BuildStatus(id, SftpStatusCode.Ok);
    }

    private void RemoveDirectory(uint id, ReadOnlySpan<byte> body)
    {
        RefuseIfReadOnly();
        SshReader reader = new(body);
        SftpServerResolved resolved = _paths.Resolve(reader.ReadUtf8String(), SftpServerFinalLink.Keep);
        if (!resolved.Exists)
        {
            throw Refuse(SftpStatusCode.NoSuchFile);
        }

        if (resolved.IsRoot)
        {
            throw Refuse(SftpStatusCode.PermissionDenied);
        }

        if (!resolved.IsDirectory || resolved.IsLink)
        {
            throw Refuse(SftpStatusCode.Failure);
        }

        Directory.Delete(resolved.RealPath, recursive: false);
        BuildStatus(id, SftpStatusCode.Ok);
    }

    private void RealPath(uint id, ReadOnlySpan<byte> body)
    {
        SshReader reader = new(body);
        SftpServerResolved resolved = _paths.Resolve(reader.ReadUtf8String(), SftpServerFinalLink.Follow);
        BuildSingleName(id, resolved.VirtualPath);
    }

    private void Rename(uint id, ReadOnlySpan<byte> body, bool overwrite)
    {
        RefuseIfReadOnly();
        SshReader reader = new(body);
        SftpServerResolved source = _paths.Resolve(reader.ReadUtf8String(), SftpServerFinalLink.Keep);
        SftpServerResolved target = _paths.Resolve(reader.ReadUtf8String(), SftpServerFinalLink.Keep);
        if (source.IsRoot || target.IsRoot)
        {
            throw Refuse(SftpStatusCode.PermissionDenied);
        }

        if (!source.Exists)
        {
            throw Refuse(SftpStatusCode.NoSuchFile);
        }

        if (target.Exists && !overwrite)
        {
            throw Refuse(SftpStatusCode.Failure);
        }

        SftpServerPaths.CheckMove(source, target);
        Move(source, target, overwrite);
        BuildStatus(id, SftpStatusCode.Ok);
    }

    private void ReadLink(uint id, ReadOnlySpan<byte> body)
    {
        SshReader reader = new(body);
        SftpServerResolved resolved = _paths.Resolve(reader.ReadUtf8String(), SftpServerFinalLink.Keep);
        if (!resolved.Exists)
        {
            throw Refuse(SftpStatusCode.NoSuchFile);
        }

        string target = new FileInfo(resolved.RealPath).LinkTarget ?? throw Refuse(SftpStatusCode.Failure);
        BuildSingleName(id, _paths.PresentLinkTarget(target, resolved));
    }

    /// <summary>The arguments come target first, as in OpenSSH, not as the draft has them: every real client follows OpenSSH.</summary>
    private void SymLink(uint id, ReadOnlySpan<byte> body)
    {
        RefuseIfReadOnly();
        SshReader reader = new(body);
        string target = reader.ReadUtf8String();
        SftpServerResolved link = _paths.Resolve(reader.ReadUtf8String(), SftpServerFinalLink.Keep);
        if (link.Exists || link.IsRoot)
        {
            throw Refuse(SftpStatusCode.Failure);
        }

        if (link.ParentMissing)
        {
            throw Refuse(SftpStatusCode.NoSuchFile);
        }

        string stored = _paths.PrepareLinkTarget(target, link);

        // Windows has two kinds of link, and the wrong kind can't be walked through.
        if (OperatingSystem.IsWindows() && Directory.Exists(Path.Join(Path.GetDirectoryName(link.RealPath), stored)))
        {
            Directory.CreateSymbolicLink(link.RealPath, stored);
        }
        else
        {
            File.CreateSymbolicLink(link.RealPath, stored);
        }

        BuildStatus(id, SftpStatusCode.Ok);
    }

    private void Sync(uint id, ReadOnlySpan<byte> body)
    {
        RefuseIfReadOnly();
        SshReader reader = new(body);
        SftpServerFile file = _handles.Get<SftpServerFile>(reader.ReadBinary());
        if (!file.CanWrite)
        {
            throw Refuse(SftpStatusCode.PermissionDenied);
        }

        file.Stream.Flush(flushToDisk: true);
        BuildStatus(id, SftpStatusCode.Ok);
    }

    /// <summary>Reports the volume the root is on. .NET offers only sizes, so the file counts are zero.</summary>
    private void FileSystemInfo(uint id, ReadOnlySpan<byte> body)
    {
        SshReader reader = new(body);
        _paths.Resolve(reader.ReadUtf8String(), SftpServerFinalLink.Follow);
        DriveInfo drive = new(_paths.Root);
        SshWriter writer = new(128, ReplyHeaderLength);
        try
        {
            writer.WriteUInt64(StatvfsBlockSize);
            writer.WriteUInt64(StatvfsBlockSize);
            writer.WriteUInt64((ulong)drive.TotalSize / StatvfsBlockSize);
            writer.WriteUInt64((ulong)drive.TotalFreeSpace / StatvfsBlockSize);
            writer.WriteUInt64((ulong)drive.AvailableFreeSpace / StatvfsBlockSize);
            writer.WriteUInt64(0);
            writer.WriteUInt64(0);
            writer.WriteUInt64(0);
            writer.WriteUInt64(0);
            writer.WriteUInt64(_options.ReadOnly ? StatvfsReadOnly : 0);
            writer.WriteUInt64(StatvfsMaxName);
            Finish(ref writer, SftpMessage.ExtendedReply, id);
        }
        finally
        {
            writer.Dispose();
        }
    }

    private void BuildVersion()
    {
        SshWriter writer = new(256, MinPacketLength);
        try
        {
            writer.WriteUInt32(ProtocolVersion);
            foreach ((string name, string version) in new[] { (PosixRename, "1"), (Fsync, "1"), (Limits, "1"), (Statvfs, "2") })
            {
                writer.WriteUtf8String(name);
                writer.WriteUtf8String(version);
            }

            writer.Written.CopyTo(ReplyBuffer);
            BinaryPrimitives.WriteUInt32BigEndian(ReplyBuffer, (uint)(writer.Length - LengthField));
            ReplyBuffer[LengthField] = SftpMessage.Version;
            _replyLength = writer.Length;
        }
        finally
        {
            writer.Dispose();
        }
    }

    private void BuildLimits(uint id)
    {
        const int WriteOverhead = 1024;
        SshWriter writer = new(64, ReplyHeaderLength);
        try
        {
            writer.WriteUInt64((ulong)_maxPacketLength);
            writer.WriteUInt64((ulong)_options.MaxReadSize);
            writer.WriteUInt64((ulong)(_maxPacketLength - WriteOverhead));
            writer.WriteUInt64((ulong)_options.MaxOpenHandles);
            Finish(ref writer, SftpMessage.ExtendedReply, id);
        }
        finally
        {
            writer.Dispose();
        }
    }

    private void BuildStatus(uint id, SftpStatusCode status)
    {
        SshWriter writer = new(64, ReplyHeaderLength);
        try
        {
            writer.WriteUInt32((uint)status);
            writer.WriteUtf8String(StatusText(status));
            writer.WriteUtf8String("en");
            Finish(ref writer, SftpMessage.Status, id);
        }
        finally
        {
            writer.Dispose();
        }
    }

    private void BuildHandle(uint id, byte[] handle)
    {
        SshWriter writer = new(32, ReplyHeaderLength);
        try
        {
            writer.WriteBinary(handle);
            Finish(ref writer, SftpMessage.Handle, id);
        }
        finally
        {
            writer.Dispose();
        }
    }

    private void BuildAttributes(uint id, SftpAttributes attributes)
    {
        SshWriter writer = new(64, ReplyHeaderLength);
        try
        {
            attributes.WriteWithFileType(ref writer);
            Finish(ref writer, SftpMessage.Attrs, id);
        }
        finally
        {
            writer.Dispose();
        }
    }

    /// <summary>A NAME of one entry with no attributes, as REALPATH and READLINK answer.</summary>
    private void BuildSingleName(uint id, string name)
    {
        SshWriter writer = new(256, ReplyHeaderLength);
        try
        {
            writer.WriteUInt32(1);
            WriteFileName(ref writer, name);
            WriteFileName(ref writer, name);
            writer.WriteUInt32(0);
            Finish(ref writer, SftpMessage.Name, id);
        }
        finally
        {
            writer.Dispose();
        }
    }

    private void Finish(ref SshWriter writer, byte type, uint id)
    {
        writer.Written.CopyTo(ReplyBuffer);
        FinishReply(type, id, writer.Length);
    }

    private void FinishReply(byte type, uint id, int length)
    {
        Span<byte> header = ReplyBuffer.AsSpan(0, ReplyHeaderLength);
        BinaryPrimitives.WriteUInt32BigEndian(header, (uint)(length - LengthField));
        header[LengthField] = type;
        BinaryPrimitives.WriteUInt32BigEndian(header[MinPacketLength..], id);
        _replyLength = length;
    }
}

using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Sftp;

/// <summary>A request on the wire, waiting for its response.</summary>
internal sealed class SftpPendingRequest(uint id, byte requestType, byte expectedType)
{
    private readonly TaskCompletionSource<SftpResponse> _response = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public uint Id { get; } = id;

    public byte RequestType { get; } = requestType;

    /// <summary>Gets the one type allowed besides STATUS. Zero means STATUS only.</summary>
    public byte ExpectedType { get; } = expectedType;

    public Task<SftpResponse> Response => _response.Task;

    public void Complete(SftpResponse response) => _response.TrySetResult(response);

    public void Fail(Exception failure) => _response.TrySetException(failure);

    /// <summary>Waits for the response. If the wait is cancelled, the response is discarded when it comes.</summary>
    public ValueTask<SftpResponse> WaitAsync(CancellationToken cancellationToken)
    {
        // With requests pipelined, the answer is often here already, and needs no state machine or extra task.
        Task<SftpResponse> response = Response;
        return response.IsCompletedSuccessfully && !cancellationToken.IsCancellationRequested
            ? new ValueTask<SftpResponse>(response)
            : WaitSlowAsync(cancellationToken);
    }

    // Runs once per packet or reply, so its state machine comes from a pool instead of a new allocation each time.
    [AsyncMethodBuilder(typeof(PoolingAsyncValueTaskMethodBuilder<>))]
    private async ValueTask<SftpResponse> WaitSlowAsync(CancellationToken cancellationToken)
    {
        try
        {
            return await Response.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            Abandon();
            throw;
        }
    }

    /// <summary>Stops caring about the response. The id stays outstanding, so the response is still valid when it arrives.</summary>
    public void Abandon() => Response.ContinueWith(
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
}

/// <summary>
/// The protocol core: framing, request ids and the one reader, over a plain pair of streams so hostile servers
/// can be tested in memory. A response must match an outstanding id and the type that request allows, or the
/// session ends (libssh CVE-2026-59848). Requests in flight and packet sizes are capped, so what a server can
/// make the session hold is bounded. Caller cancellation never tears a packet: a started write always finishes.
/// </summary>
internal sealed class SftpSession : IAsyncDisposable
{
    private const uint ProtocolVersion = 3;
    private const int ResponseHeaderLength = 9;
    private const int MinPacketLength = 5;

    private static readonly TimeSpan ReaderStopLimit = TimeSpan.FromSeconds(5);

#pragma warning disable CA2213 // The streams belong to the owner. The rest hold nothing that needs releasing, and a late write or Fail may still use them.
    private readonly Stream _input;
    private readonly Stream _output;
    private readonly SemaphoreSlim _slots;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly CancellationTokenSource _shutdown = new();
#pragma warning restore CA2213
    private readonly IAsyncDisposable? _owner;
    private readonly Lock _gate = new();
    private readonly Dictionary<uint, SftpPendingRequest> _pending = [];
    private readonly CancellationToken _shutdownToken;
    private Dictionary<string, string> _extensions = [];
    private Task? _reader;
    private uint _nextId;
    private Exception? _failure;
    private int _transportClosed;
    private int _disposed;

    private SftpSession(Stream input, Stream output, IAsyncDisposable? owner, SftpLimits limits)
    {
        _input = input;
        _output = output;
        _owner = owner;
        Limits = limits;
        _slots = new SemaphoreSlim(limits.MaxOutstandingRequests, limits.MaxOutstandingRequests);
        _shutdownToken = _shutdown.Token;
    }

    public SftpLimits Limits { get; }

    /// <summary>Gets the extensions from VERSION, by name, with their version strings.</summary>
    public IReadOnlyDictionary<string, string> Extensions => _extensions;

    /// <summary>Exchanges versions and starts the reader. <paramref name="owner"/> is closed with the session, but not if this throws.</summary>
    public static async Task<SftpSession> StartAsync(Stream input, Stream output, IAsyncDisposable? owner, SftpLimits limits, CancellationToken cancellationToken)
    {
        SftpSession session = new(input, output, owner, limits);
        try
        {
            await session.ExchangeVersionsAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not SshException and not OperationCanceledException)
        {
            throw new SshConnectionException($"The SFTP stream failed during the version exchange: {ex.Message} Open a new session.", ex);
        }

        session._reader = Task.Run(session.ReadLoopAsync, CancellationToken.None);
        return session;
    }

    /// <summary>
    /// Sends a request and returns once it's on the wire. The frame is the session's from here on, even on failure.
    /// </summary>
    public async ValueTask<SftpPendingRequest> SendAsync(SftpFrame frame, byte requestType, byte expectedType, CancellationToken cancellationToken)
    {
        bool frameTaken = false;
        bool slotTaken = false;
        bool writeLockTaken = false;
        try
        {
            await AcquireAsync(_slots, cancellationToken).ConfigureAwait(false);
            slotTaken = true;
            await AcquireAsync(_writeLock, cancellationToken).ConfigureAwait(false);
            writeLockTaken = true;

            SftpPendingRequest pending;
            lock (_gate)
            {
                ThrowIfEnded();
                while (_pending.ContainsKey(_nextId))
                {
                    _nextId++;
                }

                pending = new SftpPendingRequest(_nextId++, requestType, expectedType);
                _pending.Add(pending.Id, pending);
            }

            Span<byte> header = frame.Buffer.AsSpan(0, SftpFrames.HeaderLength);
            BinaryPrimitives.WriteUInt32BigEndian(header, (uint)(frame.Length - 4));
            header[4] = requestType;
            BinaryPrimitives.WriteUInt32BigEndian(header[5..], pending.Id);

            // From here the write finishes whatever the caller does, or the frame would be torn.
            frameTaken = true;
            slotTaken = false;
            writeLockTaken = false;
            Task write = WriteAndReleaseAsync(frame);
            bool handedOver = false;
            try
            {
                await write.WaitAsync(cancellationToken).ConfigureAwait(false);
                handedOver = true;
                return pending;
            }
            finally
            {
                // The caller never gets the request, so nobody will await it. A write that failed has ended the session, which fails every
                // request still outstanding, this one too, and that failure would be left unobserved.
                if (!handedOver)
                {
                    pending.Abandon();
                }
            }
        }
        finally
        {
            if (writeLockTaken)
            {
                _writeLock.Release();
            }

            if (slotTaken)
            {
                _slots.Release();
            }

            if (!frameTaken)
            {
                ReturnFrame(frame);
            }
        }
    }

    /// <summary>Ends the session. Everything waiting gets <paramref name="failure"/>. Only the first failure counts.</summary>
    public void Fail(Exception failure)
    {
        SftpPendingRequest[] pending;
        lock (_gate)
        {
            if (_failure is not null)
            {
                return;
            }

            _failure = failure;
            pending = [.. _pending.Values];
            _pending.Clear();
        }

        foreach (SftpPendingRequest request in pending)
        {
            request.Fail(failure);
        }

        _shutdown.Cancel();
    }

    /// <summary>Runs a parser over a response. Malformed content ends the session, like any other protocol violation.</summary>
    public T Parse<T>(SftpResponse response, Func<SftpResponse, T> parse)
    {
        try
        {
            return parse(response);
        }
        catch (SshProtocolException ex)
        {
            Fail(ex);
            throw;
        }
    }

    /// <summary>Runs a parser that takes an argument, so a caller needs no closure per response.</summary>
    public T Parse<TState, T>(SftpResponse response, TState state, Func<SftpResponse, TState, T> parse)
    {
        try
        {
            return parse(response, state);
        }
        catch (SshProtocolException ex)
        {
            Fail(ex);
            throw;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        Fail(new SshConnectionException("The SFTP session was closed by this side. Open a new one with OpenSftpAsync."));
        if (_reader is { } reader)
        {
            try
            {
                await reader.WaitAsync(ReaderStopLimit).ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                // A stream that ignores cancellation. Closing it below is what stops the read.
            }
        }

        await CloseTransportAsync().ConfigureAwait(false);
    }

    private static void ReturnFrame(SftpFrame frame) => ArrayPool<byte>.Shared.Return(frame.Buffer, clearArray: true);

    private static SshProtocolException Truncated() =>
        new("The SFTP stream ended in the middle of a packet. The server has gone wrong; open a new session.");

    private async Task ExchangeVersionsAsync(CancellationToken cancellationToken)
    {
        byte[] init = new byte[SftpFrames.HeaderLength];
        BinaryPrimitives.WriteUInt32BigEndian(init, 5);
        init[4] = SftpMessage.Init;
        BinaryPrimitives.WriteUInt32BigEndian(init.AsSpan(5), ProtocolVersion);
        await _output.WriteAsync(init, cancellationToken).ConfigureAwait(false);

        byte[] header = new byte[5];
        if (await _input.ReadAtLeastAsync(header, header.Length, throwOnEndOfStream: false, cancellationToken).ConfigureAwait(false) < header.Length)
        {
            throw new SshConnectionException("The server closed the SFTP session before it sent its version. It may not support SFTP.");
        }

        int bodyLength = CheckVersionHeader(header);
        byte[] body = ArrayPool<byte>.Shared.Rent(Math.Max(bodyLength, 16));
        try
        {
            if (await _input.ReadAtLeastAsync(body.AsMemory(0, bodyLength), bodyLength, throwOnEndOfStream: false, cancellationToken).ConfigureAwait(false) < bodyLength)
            {
                throw Truncated();
            }

            _extensions = ParseVersion(body.AsSpan(0, bodyLength));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(body, clearArray: true);
        }
    }

    private int CheckVersionHeader(ReadOnlySpan<byte> header)
    {
        SshReader reader = new(header);
        uint length = reader.ReadUInt32();
        byte type = reader.ReadByte();
        if (type != SftpMessage.Version)
        {
            throw new SshProtocolException($"The SFTP server sent packet type {type} instead of its version.");
        }

        CheckLength(length);
        return (int)length - 1;
    }

    private Dictionary<string, string> ParseVersion(ReadOnlySpan<byte> body)
    {
        SshReader reader = new(body);
        uint version = reader.ReadUInt32();
        if (version != ProtocolVersion)
        {
            throw new SshProtocolException($"The SFTP server answered with version {version}. Zorg.Ssh speaks version {ProtocolVersion} only.");
        }

        Dictionary<string, string> extensions = new(StringComparer.Ordinal);
        while (reader.Remaining != 0)
        {
            if (extensions.Count == Limits.MaxExtensions)
            {
                throw new SshProtocolException($"The SFTP server listed more than {Limits.MaxExtensions} extensions.");
            }

            string name = SftpParser.DecodeString(reader.ReadBinary());
            string value = SftpParser.DecodeString(reader.ReadBinary());
            extensions.TryAdd(name, value);
        }

        return extensions;
    }

    private void CheckLength(uint length)
    {
        if (length < MinPacketLength)
        {
            throw new SshProtocolException($"The SFTP server sent a packet of {length} bytes, which is too short to be one.");
        }

        if (length > (uint)Limits.MaxPacketLength)
        {
            throw new SshProtocolException($"The SFTP server sent a packet of {length} bytes. The limit is {Limits.MaxPacketLength}.");
        }
    }

    private async Task ReadLoopAsync()
    {
        Exception failure;
        byte[] header = new byte[ResponseHeaderLength];
        try
        {
            while (true)
            {
                int read = await _input.ReadAtLeastAsync(header, header.Length, throwOnEndOfStream: false, _shutdownToken).ConfigureAwait(false);
                if (read == 0)
                {
                    throw new SshConnectionException("The server closed the SFTP session. Open a new one with OpenSftpAsync.");
                }

                if (read < header.Length)
                {
                    throw Truncated();
                }

                (SftpPendingRequest pending, int bodyLength, byte type) = CheckResponseHeader(header);
                await ReadBodyAsync(pending, type, bodyLength).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException ex)
        {
            failure = new SshConnectionException("The SFTP session has ended. Open a new one with OpenSftpAsync.", ex);
        }
        catch (SshException ex)
        {
            failure = ex;
        }
#pragma warning disable CA1031 // Whatever the stream throws must end the session, as an SshException, not leave callers waiting.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            failure = new SshConnectionException($"The SFTP stream failed: {ex.Message} Open a new session.", ex);
        }

        Fail(failure);
        await CloseTransportAsync().ConfigureAwait(false);
    }

    /// <summary>Reads a body into a pooled buffer. Ownership passes to the request, unless the session ended meanwhile.</summary>
    // Runs once per packet or reply, so its state machine comes from a pool instead of a new allocation each time.
    [AsyncMethodBuilder(typeof(PoolingAsyncValueTaskMethodBuilder))]
    private async ValueTask ReadBodyAsync(SftpPendingRequest pending, byte type, int bodyLength)
    {
        byte[] body = ArrayPool<byte>.Shared.Rent(Math.Max(bodyLength, 16));
        SftpResponse? response = new(type, body, bodyLength);
        try
        {
            if (await _input.ReadAtLeastAsync(body.AsMemory(0, bodyLength), bodyLength, throwOnEndOfStream: false, _shutdownToken).ConfigureAwait(false) < bodyLength)
            {
                throw Truncated();
            }

            bool removed;
            lock (_gate)
            {
                removed = _pending.Remove(pending.Id);
            }

            if (removed)
            {
                _slots.Release();
                pending.Complete(response);
                response = null;
            }
        }
        finally
        {
            response?.Dispose();
        }
    }

    private (SftpPendingRequest Pending, int BodyLength, byte Type) CheckResponseHeader(ReadOnlySpan<byte> header)
    {
        SshReader reader = new(header);
        uint length = reader.ReadUInt32();
        byte type = reader.ReadByte();
        uint id = reader.ReadUInt32();
        CheckLength(length);

        SftpPendingRequest? pending;
        lock (_gate)
        {
            _pending.TryGetValue(id, out pending);
        }

        if (pending is null)
        {
            throw new SshProtocolException($"The SFTP server sent a response (type {type}) with id {id}, which matches no outstanding request. Don't trust this server; open a new session if you must continue.");
        }

        if (type != SftpMessage.Status && type != pending.ExpectedType)
        {
            throw new SshProtocolException($"The SFTP server answered request type {pending.RequestType} with response type {type}, which that request doesn't allow.");
        }

        return (pending, (int)length - MinPacketLength, type);
    }

    private async ValueTask AcquireAsync(SemaphoreSlim semaphore, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (await semaphore.WaitAsync(0, CancellationToken.None).ConfigureAwait(false))
        {
            return;
        }

        using CancellationTokenSource either = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _shutdownToken);
        try
        {
            await semaphore.WaitAsync(either.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            lock (_gate)
            {
                ThrowIfEnded();
            }

            throw;
        }
    }

    private async Task WriteAndReleaseAsync(SftpFrame frame)
    {
        try
        {
            await _output.WriteAsync(frame.Buffer.AsMemory(0, frame.Length), _shutdownToken).ConfigureAwait(false);
        }
        catch (SshException ex)
        {
            Fail(ex);
            throw;
        }
#pragma warning disable CA1031 // Whatever the stream throws is reported as an SshException.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            SshConnectionException failure = new("The SFTP session has ended, so the request couldn't be sent. Open a new session.", ex);
            Fail(failure);
            throw failure;
        }
        finally
        {
            _writeLock.Release();
            ReturnFrame(frame);
        }
    }

    private void ThrowIfEnded()
    {
        if (_failure is { } failure)
        {
            throw new SshConnectionException($"The SFTP session has ended: {failure.Message}", failure);
        }
    }

    private async ValueTask CloseTransportAsync()
    {
        if (Interlocked.Exchange(ref _transportClosed, 1) != 0)
        {
            return;
        }

        try
        {
            if (_owner is not null)
            {
                await _owner.DisposeAsync().ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is SshException or IOException or ObjectDisposedException or OperationCanceledException)
        {
            // The session is over either way.
        }
    }
}

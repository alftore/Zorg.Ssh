using System;
using System.Buffers;
using System.IO;
using System.IO.Pipelines;
using System.Threading;
using System.Threading.Tasks;

namespace Zorg.Ssh.Connection;

/// <summary>Reads what a channel received. Reading is what grows the window, so a slow reader slows the peer.</summary>
internal sealed class ChannelReadStream(SshChannel channel, PipeReader reader) : Stream
{
    private readonly Lock _gate = new();
    private bool _disposed;
    private bool _reading;

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (buffer.IsEmpty)
            {
                return 0;
            }

            _reading = true;
        }

        try
        {
            ReadResult result = await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            ReadOnlySequence<byte> available = result.Buffer;
            int count = (int)Math.Min(available.Length, buffer.Length);
            available.Slice(0, count).CopyTo(buffer.Span);
            reader.AdvanceTo(available.GetPosition(count));
            if (count != 0)
            {
                channel.OnConsumed(count);
            }

            return count;
        }
        finally
        {
            bool complete;
            lock (_gate)
            {
                _reading = false;
                complete = _disposed;
            }

            if (complete)
            {
                await reader.CompleteAsync().ConfigureAwait(false);
            }
        }
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override int Read(byte[] buffer, int offset, int count) =>
        ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            // A jump host's transport can close this stream under its own read. Completing a pipe mid-read would
            // leave that read waiting for ever, so the read is released, and it completes the pipe on its way out.
            bool complete = false;
            lock (_gate)
            {
                if (!_disposed)
                {
                    _disposed = true;
                    complete = !_reading;
                    if (_reading)
                    {
                        reader.CancelPendingRead();
                    }
                }
            }

            if (complete)
            {
                reader.Complete();
            }
        }

        base.Dispose(disposing);
    }
}

/// <summary>
/// A channel as one two-way stream, for what a TCP connection carries. Disposing it closes the channel.
/// </summary>
internal sealed class ChannelStream(SshChannel channel) : Stream
{
    private int _disposed;

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
        channel.Output.ReadAsync(buffer, cancellationToken);

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        channel.Output.ReadAsync(buffer, offset, count, cancellationToken);

    public override int Read(byte[] buffer, int offset, int count) => channel.Output.Read(buffer, offset, count);

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
        channel.Input.WriteAsync(buffer, cancellationToken);

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        channel.Input.WriteAsync(buffer, offset, count, cancellationToken);

    public override void Write(byte[] buffer, int offset, int count) => channel.Input.Write(buffer, offset, count);

    public override void Flush()
    {
    }

    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            await channel.DisposeAsync().ConfigureAwait(false);
        }

        await base.DisposeAsync().ConfigureAwait(false);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            channel.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }

        base.Dispose(disposing);
    }
}

/// <summary>
/// Sends channel data. Disposing it sends EOF, so the far side sees the end of its stdin. That never waits: the EOF
/// goes through the connection's sender loop, so a full send queue delays it and can't lose it.
/// </summary>
internal sealed class ChannelWriteStream(SshChannel channel, uint? extendedType = null) : Stream
{
    private bool _disposed;

    public override bool CanRead => false;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return channel.WriteAsync(buffer, cancellationToken, extendedType);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override void Write(byte[] buffer, int offset, int count) =>
        WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override void Flush()
    {
    }

    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            _disposed = true;
            if (extendedType is null)
            {
                channel.QueueEof();
            }
        }

        base.Dispose(disposing);
    }
}

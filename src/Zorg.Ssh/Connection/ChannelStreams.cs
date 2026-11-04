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
    private bool _disposed;

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
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (buffer.IsEmpty)
        {
            return 0;
        }

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
        if (disposing && !_disposed)
        {
            _disposed = true;
            reader.Complete();
        }

        base.Dispose(disposing);
    }
}

/// <summary>Sends channel data. Disposing it sends EOF, so the far side sees the end of its stdin.</summary>
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

    public override async ValueTask DisposeAsync()
    {
        if (!_disposed)
        {
            _disposed = true;
            try
            {
                using CancellationTokenSource limit = new(TimeSpan.FromSeconds(5));
                if (extendedType is null)
                {
                    await channel.SendEofAsync(limit.Token).ConfigureAwait(false);
                }
            }
            catch (Exception ex) when (ex is SshException or OperationCanceledException)
            {
                // The connection has gone, so there's nobody to tell.
            }
        }

        await base.DisposeAsync().ConfigureAwait(false);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            DisposeAsync().AsTask().GetAwaiter().GetResult();
        }

        base.Dispose(disposing);
    }
}

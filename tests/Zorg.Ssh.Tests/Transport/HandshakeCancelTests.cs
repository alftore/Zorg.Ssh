using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Zorg.Ssh.Tests.Transport;

/// <summary>
/// A connect cancelled or timed out during the identification exchange ends with the documented exception types, even
/// when the stream reports the abort as an <see cref="IOException"/>. Windows sockets can: a read cancelled at the same
/// moment it fails ends with "The I/O operation has been aborted", and an 8-hour soak caught one reaching the caller.
/// </summary>
public sealed class HandshakeCancelTests
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(20);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static SshClientOptions Options(TimeSpan connectTimeout) => new()
    {
        Host = "test",
        UserName = "user",
        HostKeyPolicy = HostKeyPolicy.AcceptAnyUnsafe(),
        ConnectTimeout = connectTimeout,
    };

    [Fact]
    public async Task A_cancelled_connect_throws_OperationCanceledException_when_the_read_aborts_with_an_IOException()
    {
        using CancellationTokenSource cancel = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        AbortingStream stream = new();
        Task<SshClient> connect = SshClient.ConnectOverStreamAsync(stream, Options(TimeSpan.FromMinutes(5)), cancel.Token);
        await stream.ReadStarted.WaitAsync(Limit, Ct);

        await cancel.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => connect.WaitAsync(Limit, Ct));
        Assert.True(stream.Disposed);
    }

    [Fact]
    public async Task A_connect_that_times_out_throws_SshConnectionException_when_the_read_aborts_with_an_IOException()
    {
        AbortingStream stream = new();
        Task<SshClient> connect = SshClient.ConnectOverStreamAsync(stream, Options(TimeSpan.FromMilliseconds(200)), Ct);

        await Assert.ThrowsAsync<SshConnectionException>(() => connect.WaitAsync(Limit, Ct));
        Assert.True(stream.Disposed);
    }

    /// <summary>Takes every write, never answers, and ends a cancelled read with an <see cref="IOException"/>, as an aborted socket read can.</summary>
    private sealed class AbortingStream : Stream
    {
        private readonly TaskCompletionSource _readStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task ReadStarted => _readStarted.Task;

        public bool Disposed { get; private set; }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            _readStarted.TrySetResult();
            try
            {
                await Task.Delay(Timeout.Infinite, cancellationToken);
            }
            catch (OperationCanceledException)
            {
            }

            throw new IOException("Unable to read data from the transport connection: The I/O operation has been aborted because of either a thread exit or an application request.");
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) => ValueTask.CompletedTask;

        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            Disposed = true;
            base.Dispose(disposing);
        }
    }
}

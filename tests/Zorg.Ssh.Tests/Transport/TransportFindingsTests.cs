using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Transport;
using static Zorg.Ssh.Tests.Transport.TransportHarness;

namespace Zorg.Ssh.Tests.Transport;

/// <summary>Regression tests for the transport findings of the pre-audit, and for transport advisories.</summary>
public sealed class TransportFindingsTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>Swallows writes once muted, so the observed side can't fail on its own writes to a closed pipe.</summary>
    private sealed class MuteStream(Stream inner) : Stream
    {
        public volatile bool Muted;

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() => inner.Flush();

        public override Task FlushAsync(CancellationToken cancellationToken) => Muted ? Task.CompletedTask : inner.FlushAsync(cancellationToken);

        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            inner.ReadAsync(buffer, cancellationToken);

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
            Muted ? ValueTask.CompletedTask : inner.WriteAsync(buffer, cancellationToken);

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
            }

            base.Dispose(disposing);
        }
    }

    private static async Task ReceiveUntilFailureAsync(SshTransport transport)
    {
        while (true)
        {
            await transport.ReceiveAsync(Ct).AsTask().WaitAsync(TimeSpan.FromSeconds(30), Ct);
        }
    }

    // T1: DISCONNECT may precede NEWKEYS, so a close while our KEXINIT is out must send it, and must not wait for the grace time.
    [Fact]
    public async Task T1_a_close_during_a_key_exchange_sends_DISCONNECT_without_the_grace_wait()
    {
        (Stream clientStream, Stream serverStream) = DuplexStream.CreatePair();
        MuteStream mute = new(serverStream);
        Task<SshTransport> serverTask = SshTransport.StartAsync(mute, ServerOptions(), Ct);
        Task<SshTransport> clientTask = SshTransport.StartAsync(clientStream, ClientOptions(), Ct);
        SshTransport client = await clientTask;
        SshTransport server = await serverTask;
        await using (client)
        await using (server)
        {
            MarkConnected(client, server);

            // Our KEXINIT is out and the server hasn't read it, so the client stays parked.
            client.RequestRekey();
            Stopwatch watch = Stopwatch.StartNew();
            await client.CloseAsync();
            watch.Stop();
            Assert.True(watch.ElapsedMilliseconds < 900, $"CloseAsync took {watch.ElapsedMilliseconds} ms");

            mute.Muted = true;
            await Assert.ThrowsAsync<SshDisconnectedException>(async () => await ReceiveUntilFailureAsync(server));
        }
    }
}

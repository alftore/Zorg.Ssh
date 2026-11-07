using System;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Connection;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Tests.Transport;

namespace Zorg.Ssh.Tests.Fuzzing.Stateful;

/// <summary>A stream whose writes wait while the gate is shut, so a test decides which packets the send loop is stuck on.</summary>
internal sealed class GatedStream(Stream inner) : Stream
{
    private volatile TaskCompletionSource _open = Opened();

    public override bool CanRead => inner.CanRead;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public void Shut() => _open = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

    public void Open() => _open.TrySetResult();

    public override void Flush() => inner.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);

    public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => inner.ReadAsync(buffer, cancellationToken);

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        await _open.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        await inner.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _open.TrySetResult();
            inner.Dispose();
        }

        base.Dispose(disposing);
    }

    private static TaskCompletionSource Opened()
    {
        TaskCompletionSource open = new(TaskCreationOptions.RunContinuationsAsynchronously);
        open.SetResult();
        return open;
    }
}

/// <summary>
/// One test for each finding the stateful fuzzing has made, named for what it found. Each builds its input in code, so the fix stays
/// when the fuzzer's corpus or mutator changes. The comment on each says which target found it and with which seed.
/// </summary>
public sealed class StatefulRegressionTests
{
    // Found by a one minute run on Windows: target "Stateful client, after login", seed 10262672204391169388 (and two more that stalled the same way).
    // The scripted server sent CHANNEL_OPEN_FAILURE for a channel the client had already opened and been given. The client rightly ends the
    // connection over that, but HandleOpenFailure took the channel out of the connection's table before it checked that the channel was being
    // opened. Ending the connection fails every channel in the table, so this one was never told: ExecuteAsync, which was waiting for the
    // command's output, waited for ever on a connection that was long gone.
    [Fact]
    public async Task A_channel_open_failure_for_an_open_channel_ends_a_command_that_is_waiting_on_it()
    {
        CancellationToken test = TestContext.Current.CancellationToken;
        (Stream peerStream, Stream sutStream) = DuplexStream.CreatePair();
        SshClientOptions options = new()
        {
            Host = "fuzz.test",
            UserName = Wire.UserName,
            HostKeyPolicy = HostKeyPolicy.Fingerprint(HostKeyPolicy.ComputeFingerprint(TransportHarness.HostKey.PublicKey.Blob.Span)),
            Algorithms = StatefulLimits.FastAlgorithms,
            Credentials = [SshCredential.FromPassword(Wire.Secret)],
        };
        Task<SshClient> connecting = SshClient.ConnectOverStreamAsync(sutStream, options, test);
        await using StatefulPeer peer = await StatefulPeer.StartAsync(peerStream, TransportHarness.ServerOptions(kex: ["curve25519-sha256"]), test);
        Assert.True(await Wait(peer, MessageNumber.ServiceRequest));
        await peer.SendAsync(Wire.ServiceAccept());
        Assert.True(await Wait(peer, MessageNumber.UserAuthRequest));
        await peer.SendAsync(Wire.AuthFailure(false, "password"));
        Assert.True(await Wait(peer, MessageNumber.UserAuthRequest, 1));
        await peer.SendAsync(Wire.AuthSuccess());
        await using SshClient client = await connecting;

        Task<SshCommandResult> running = Task.Run(() => client.ExecuteAsync("echo hi", test), test);
        Assert.True(await Wait(peer, MessageNumber.ChannelOpen));
        await peer.SendAsync(Wire.ChannelOpenConfirmation(0, 100));
        Assert.True(await Wait(peer, MessageNumber.ChannelRequest));
        await peer.SendAsync(Wire.ChannelSuccess(0));

        // The channel is open. A server that now says it refused to open it is lying, and the client ends the connection.
        await peer.SendAsync(Wire.ChannelOpenFailure(0, 1));

        // Everything waiting on the lost connection must end: no token is passed to the wait except the test's own, and the limit is generous.
        Task finished = await Task.WhenAny(running, Task.Delay(TimeSpan.FromSeconds(20), test));
        Assert.True(ReferenceEquals(finished, running), "ExecuteAsync is still waiting on a connection that has ended.");
        Exception? failure = await Record.ExceptionAsync(() => running);
        Assert.IsAssignableFrom<SshException>(failure);
        await Task.WhenAny(client.Connection.Ended, Task.Delay(TimeSpan.FromSeconds(20), test));
        Assert.True(client.Connection.Ended.IsCompleted);
    }

    // Found by a one minute run on Windows: targets "Stateful SFTP, server side" and "Stateful server, rekey and order", seeds 10584398800514286644 and
    // 11771235840302608811. The scripted client sent its channel open straight behind its password, without waiting for the answer. The server
    // sent CHANNEL_OPEN_CONFIRMATION first and USERAUTH_SUCCESS after it, so a peer in the auth phase saw a connection message it had to refuse.
    // The server had logged the user in before it handled the open, so nothing ran early. But the success waits in the send queue like any other
    // message, while the connection's replies skip the queue (the receive loop must never wait), and when the send loop is busy writing something
    // else the reply wins. The test holds the SUT's writes still at that moment, which makes the race certain.
    [Fact]
    public async Task USERAUTH_SUCCESS_reaches_the_wire_before_the_reply_to_a_channel_open_that_was_pipelined_behind_the_login()
    {
        CancellationToken test = TestContext.Current.CancellationToken;
        SshConnection? connection = null;
        SshServerOptions options = new()
        {
            Address = IPAddress.Loopback,
            HostKeys = [new SshHostKey(TransportHarness.HostKey)],
            Algorithms = StatefulLimits.FastAlgorithms,
            PasswordHandler = (request, _) => ValueTask.FromResult(request.Password == Wire.Secret ? SshAuthDecision.Accept : SshAuthDecision.Reject),
            SessionHandler = (_, _) => Task.FromResult(0),
            ConnectionStarted = started => Volatile.Write(ref connection, started),
        };
        await using SshServer server = await SshServer.StartAsync(options, test);
        (Stream peerStream, Stream sutStream) = DuplexStream.CreatePair();
        GatedStream gated = new(sutStream);
        Task serving = server.ServeStreamAsync(gated, test);
        await using StatefulPeer peer = await StatefulPeer.StartAsync(peerStream, TransportHarness.ClientOptions(kex: ["curve25519-sha256"]), test);

        // The server's EXT_INFO follows its NEWKEYS. Let it out, so that the first thing held back is the answer to the service request.
        for (int i = 0; i < 500 && peer.Transport.PeerExtensions.Count == 0; i++)
        {
            await Task.Delay(10, test);
        }

        Assert.NotEmpty(peer.Transport.PeerExtensions);
        gated.Shut();
        await peer.SendAsync(Wire.ServiceRequest());
        await peer.SendAsync(Wire.AuthPassword(Wire.Secret));
        await peer.SendAsync(Wire.ChannelOpen("session", 100));

        // Give the server time to read all three. Where the login does not wait for its success to leave the queue, the connection starts at once and
        // holds the open, with its confirmation queued ahead of the success. Where it does wait, nothing more happens until the gate opens.
        for (int i = 0; i < 100 && Volatile.Read(ref connection)?.ChannelCount != 1; i++)
        {
            await Task.Delay(10, test);
        }

        gated.Open();

        Assert.True(await Wait(peer, MessageNumber.ChannelOpenConfirmation), "The server never confirmed the channel. " + StatefulNotes.Describe(peer));
        PeerMessage[] seen = [.. peer.Snapshot()];
        int success = Array.FindIndex(seen, m => m.Number == MessageNumber.UserAuthSuccess);
        int confirmation = Array.FindIndex(seen, m => m.Number == MessageNumber.ChannelOpenConfirmation);
        Assert.True(success >= 0 && success < confirmation, "CHANNEL_OPEN_CONFIRMATION went out before USERAUTH_SUCCESS. " + StatefulNotes.Describe(peer));
        peer.Vanish();
        await serving.WaitAsync(TimeSpan.FromSeconds(20), test);
    }

    // Found by a one minute run on Windows: target "Stateful SFTP, client side", seed 2022856350504775239. The scripted server closed the SFTP channel
    // and its answers to the client's last requests were still going out, so CHANNEL_DATA arrived for a channel the server had closed. OnData wrote to
    // the channel's output pipe, which CLOSE had completed, and the pipe threw InvalidOperationException. The receive loop's catch-all turned that into
    // "The connection failed unexpectedly. This is a bug in Zorg.Ssh." The peer broke the protocol, and the connection should say so.
    [Fact]
    public async Task Channel_data_after_the_peers_CLOSE_ends_the_connection_as_a_protocol_error_and_not_as_a_bug_in_the_library()
    {
        CancellationToken test = TestContext.Current.CancellationToken;
        (Stream peerStream, Stream sutStream) = DuplexStream.CreatePair();
        SshClientOptions options = new()
        {
            Host = "fuzz.test",
            UserName = Wire.UserName,
            HostKeyPolicy = HostKeyPolicy.Fingerprint(HostKeyPolicy.ComputeFingerprint(TransportHarness.HostKey.PublicKey.Blob.Span)),
            Algorithms = StatefulLimits.FastAlgorithms,
            Credentials = [SshCredential.FromPassword(Wire.Secret)],
        };
        Task<SshClient> connecting = SshClient.ConnectOverStreamAsync(sutStream, options, test);
        await using StatefulPeer peer = await StatefulPeer.StartAsync(peerStream, TransportHarness.ServerOptions(kex: ["curve25519-sha256"]), test);
        Assert.True(await Wait(peer, MessageNumber.ServiceRequest));
        await peer.SendAsync(Wire.ServiceAccept());
        Assert.True(await Wait(peer, MessageNumber.UserAuthRequest));
        await peer.SendAsync(Wire.AuthFailure(false, "password"));
        Assert.True(await Wait(peer, MessageNumber.UserAuthRequest, 1));
        await peer.SendAsync(Wire.AuthSuccess());
        await using SshClient client = await connecting;

        // A shell that nobody reads keeps the channel registered after the server's CLOSE, until the client's own CLOSE has gone out.
        await using SshProcess process = await StartAndAcceptAsync(client, peer, test);
        await peer.SendAsync(Wire.ChannelClose(0));
        await peer.SendAsync(Wire.ChannelData(0, "late"u8.ToArray()));

        await client.Connection.Ended.WaitAsync(TimeSpan.FromSeconds(20), test);
        SshException ended = await Assert.ThrowsAsync<SshConnectionException>(() => client.ExecuteAsync("again", test));
        Assert.IsType<SshProtocolException>(ended.InnerException);
        Assert.DoesNotContain(SutExceptions.BugMarker, ended.ToString(), StringComparison.Ordinal);
    }

    private static async Task<SshProcess> StartAndAcceptAsync(SshClient client, StatefulPeer peer, CancellationToken test)
    {
        Task<SshProcess> starting = client.StartProcessAsync("cat", null, test);
        Assert.True(await Wait(peer, MessageNumber.ChannelOpen));
        await peer.SendAsync(Wire.ChannelOpenConfirmation(0, 100));
        Assert.True(await Wait(peer, MessageNumber.ChannelRequest));
        await peer.SendAsync(Wire.ChannelSuccess(0));
        return await starting;
    }

    private static async Task<bool> Wait(StatefulPeer peer, byte number, int skip = 0)
    {
        int seen = 0;
        int found = await peer.WaitForAsync(0, m => m.Number == number && seen++ >= skip, TimeSpan.FromSeconds(10));
        return found >= 0;
    }
}

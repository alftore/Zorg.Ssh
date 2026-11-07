using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Sftp;
using Zorg.Ssh.Tests.Connection;
using Zorg.Ssh.Tests.Transport;

namespace Zorg.Ssh.Tests.Server;

/// <summary>Keepalive through the public client and server, joined in memory, with no token passed to what's waiting.</summary>
public sealed class KeepAliveClientServerTests : IDisposable
{
    // Either keepalive failure. Which comes first here can depend on a preempted write, because this clock can cross
    // three intervals in the time a real write takes. KeepAliveTests holds that still, and checks each one exactly.
    private const string PeerGone = "The peer stopped";

    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(20);

    private readonly SshHostKey _hostKey = SshHostKey.GenerateEd25519();
    private readonly ManualClock _clock = new();
    private readonly TaskCompletionSource _handlerStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource<Exception?> _handlerEnded = new(TaskCreationOptions.RunContinuationsAsynchronously);

#pragma warning disable CA2213 // Each transport owns its stream.
    private FaultStream _clientLink = null!;
    private FaultStream _serverLink = null!;
#pragma warning restore CA2213
    private Task _served = Task.CompletedTask;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => _hostKey.Dispose();

    private static bool Mentions(Exception? exception, string text)
    {
        for (; exception is not null; exception = exception.InnerException)
        {
            if (exception.Message.Contains(text, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Kills the path both ways, with no goodbye: what a pulled cable looks like from each end.</summary>
    private void KillPath()
    {
        _clientLink.Drop();
        _serverLink.Drop();
    }

    private SshServerOptions ServerOptions(
        Func<SshServerSession, CancellationToken, Task<int>> handler,
        bool keepAlive,
        Func<SshPasswordRequest, CancellationToken, ValueTask<SshAuthDecision>>? password = null) => new()
        {
            HostKeys = [_hostKey],
            PasswordHandler = password ?? ((_, _) => ValueTask.FromResult(SshAuthDecision.Accept)),
            SessionHandler = handler,
            KeepAliveInterval = keepAlive ? Interval : TimeSpan.Zero,
            TimeProvider = keepAlive ? _clock : TimeProvider.System,
        };

    private SshClientOptions ClientOptions(bool keepAlive) => new()
    {
        Host = "in-memory",
        UserName = "alice",
        Credentials = [SshCredential.FromPassword("pw")],
        HostKeyPolicy = HostKeyPolicy.Fingerprint(_hostKey.Sha256Fingerprint),
        KeepAliveInterval = keepAlive ? Interval : TimeSpan.Zero,
        TimeProvider = keepAlive ? _clock : TimeProvider.System,
    };

    private async Task<SshClient> ConnectAsync(SshServer server, bool clientKeepAlive)
    {
        (Stream clientSide, Stream serverSide) = DuplexStream.CreatePair();
        _clientLink = new FaultStream(clientSide);
        _serverLink = new FaultStream(serverSide);
        _served = server.ServeStreamAsync(_serverLink, Ct);
        return await SshClient.ConnectOverStreamAsync(_clientLink, ClientOptions(clientKeepAlive), Ct);
    }

    /// <summary>A handler that waits for ever, unless the connection's end cancels it.</summary>
    private async Task<int> WaitForeverAsync(SshServerSession session, CancellationToken cancellationToken)
    {
        _handlerStarted.TrySetResult();
        await Task.Delay(Timeout.Infinite, cancellationToken);
        return 0;
    }

    /// <summary>A handler that reads with no token, as one holding a session slot might.</summary>
    private async Task<int> ReadWithNoTokenAsync(SshServerSession session, CancellationToken cancellationToken)
    {
        _handlerStarted.TrySetResult();
        try
        {
            _ = await session.Input.ReadAsync(new byte[16], CancellationToken.None);
            _handlerEnded.TrySetResult(null);
        }
        catch (SshException ex)
        {
            _handlerEnded.TrySetResult(ex);
        }

        return 0;
    }

    private Task ElapseAsync(int intervals, Func<bool> finished) => _clock.AdvanceAsync(Interval * intervals, finished);

    [Fact]
    public async Task The_defaults_are_5_minutes_and_3_on_both_roles()
    {
        await using SshServer server = await SshServer.StartAsync(new SshServerOptions { HostKeys = [_hostKey], SessionHandler = WaitForeverAsync, PasswordHandler = (_, _) => ValueTask.FromResult(SshAuthDecision.Accept) }, Ct);
        SshClientOptions options = new() { Host = "h", UserName = "u", HostKeyPolicy = HostKeyPolicy.AcceptAnyUnsafe() };
        SshServerOptions serverOptions = new() { HostKeys = [], SessionHandler = WaitForeverAsync };

        Assert.Equal(TimeSpan.FromMinutes(5), options.KeepAliveInterval);
        Assert.Equal(3, options.KeepAliveCountMax);
        Assert.Equal(TimeSpan.FromMinutes(5), serverOptions.KeepAliveInterval);
        Assert.Equal(3, serverOptions.KeepAliveCountMax);

        (Stream clientSide, Stream serverSide) = DuplexStream.CreatePair();
        Task served = server.ServeStreamAsync(serverSide, Ct);
        SshClient client = await SshClient.ConnectOverStreamAsync(
            clientSide,
            new SshClientOptions { Host = "h", UserName = "u", Credentials = [SshCredential.FromPassword("p")], HostKeyPolicy = HostKeyPolicy.Fingerprint(_hostKey.Sha256Fingerprint) },
            Ct);
        await using (client)
        {
            Assert.NotNull(client.Connection.KeepAlive);
        }

        await served.WaitAsync(Limit, Ct);
    }

    [Theory]
    [InlineData(-1, 3)]
    [InlineData(1, 0)]
    [InlineData(1, -1)]
    [InlineData(1, 1001)]
    [InlineData(0, 0)]
    [InlineData(86_401, 3)]
    public async Task Bad_values_are_refused_on_both_roles(int seconds, int count)
    {
        await AssertRefusedAsync(TimeSpan.FromSeconds(seconds), count);
    }

    [Fact]
    public async Task An_interval_under_a_second_is_refused_on_both_roles()
    {
        await AssertRefusedAsync(TimeSpan.FromMilliseconds(999), 3);
    }

    private async Task AssertRefusedAsync(TimeSpan interval, int count)
    {
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => SshServer.StartAsync(
            new SshServerOptions
            {
                HostKeys = [_hostKey],
                PasswordHandler = (_, _) => ValueTask.FromResult(SshAuthDecision.Accept),
                SessionHandler = WaitForeverAsync,
                KeepAliveInterval = interval,
                KeepAliveCountMax = count,
            },
            Ct));

        SshClientOptions options = new()
        {
            Host = "127.0.0.1",
            Port = 1,
            UserName = "u",
            HostKeyPolicy = HostKeyPolicy.AcceptAnyUnsafe(),
            KeepAliveInterval = interval,
            KeepAliveCountMax = count,
        };
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => SshClient.ConnectAsync(options, Ct));

        (Stream stream, Stream other) = DuplexStream.CreatePair();
        await using (stream)
        await using (other)
        {
            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => SshClient.ConnectOverStreamAsync(stream, options, Ct));
        }
    }

    [Fact]
    public async Task Our_client_and_server_keep_each_other_alive_through_a_long_silence()
    {
        await using SshServer server = await SshServer.StartAsync(ServerOptions((_, _) => Task.FromResult(5), keepAlive: false), Ct);
        await using SshClient client = await ConnectAsync(server, clientKeepAlive: true);
        await _clock.WaitForTimerAsync();

        for (int i = 1; i <= 10; i++)
        {
            await ElapseAsync(1, () => client.Connection.Ended.IsCompleted);
            int expected = i;
            while (client.Connection.KeepAlive!.ProbesAnswered < expected || client.Connection.KeepAlive.ProbeOutstanding)
            {
                await Task.Delay(1, Ct);
            }
        }

        SshCommandResult result = await client.ExecuteAsync("anything", Ct);
        Assert.Equal(5, result.ExitCode);
    }

    [Fact]
    public async Task ExecuteAsync_with_no_token_ends_when_the_server_dies()
    {
        await using SshServer server = await SshServer.StartAsync(ServerOptions(WaitForeverAsync, keepAlive: false), Ct);
        await using SshClient client = await ConnectAsync(server, clientKeepAlive: true);
        await _clock.WaitForTimerAsync();

        Task<SshCommandResult> execute = client.ExecuteAsync("wait", CancellationToken.None);
        await _handlerStarted.Task.WaitAsync(Limit, Ct);

        // The handler starts as soon as its exec reply is queued, so that reply can still be on its way, and can land
        // after the clock has moved. It's a packet, so it rightly restarts the count: the end then comes up to four
        // intervals later than four from here. One packet can do that once, because the path is dead behind it.
        KillPath();
        for (int i = 0; i < 9 && !client.Connection.Ended.IsCompleted; i++)
        {
            await ElapseAsync(1, () => client.Connection.Ended.IsCompleted);
        }

        Assert.True(client.Connection.Ended.IsCompleted, "Nine silent intervals must end the connection.");
        SshConnectionException ex = await Assert.ThrowsAnyAsync<SshConnectionException>(() => execute.WaitAsync(Limit, Ct));
        Assert.True(Mentions(ex, PeerGone), ex.ToString());
    }

    [Fact]
    public async Task A_stream_read_with_no_token_ends_when_the_server_dies()
    {
        await using SshServer server = await SshServer.StartAsync(ServerOptions(WaitForeverAsync, keepAlive: false), Ct);
        await using SshClient client = await ConnectAsync(server, clientKeepAlive: true);
        await _clock.WaitForTimerAsync();

        await using SshProcess process = await client.StartProcessAsync("wait", null, Ct);
        await _handlerStarted.Task.WaitAsync(Limit, Ct);
        Task<int> read = process.StandardOutput.ReadAsync(new byte[16], CancellationToken.None).AsTask();
        Task exit = process.WaitForExitAsync(CancellationToken.None);

        KillPath();
        await ElapseAsync(4, () => client.Connection.Ended.IsCompleted);

        SshConnectionException ex = await Assert.ThrowsAnyAsync<SshConnectionException>(() => read.WaitAsync(Limit, Ct));
        Assert.True(Mentions(ex, PeerGone), ex.ToString());
        await Assert.ThrowsAnyAsync<SshConnectionException>(() => exit.WaitAsync(Limit, Ct));
    }

    [Fact]
    public async Task An_sftp_call_with_no_token_ends_when_the_server_dies()
    {
        using TempDirectory root = new();
        await using SshServer server = await SshServer.StartAsync(
            ServerOptions((session, ct) => SftpServer.ServeAsync(session, new SftpServerOptions { RootDirectory = root.Path }, ct), keepAlive: false),
            Ct);
        await using SshClient client = await ConnectAsync(server, clientKeepAlive: true);
        await _clock.WaitForTimerAsync();
        await using SftpClient sftp = await client.OpenSftpAsync(Ct);

        KillPath();
        Task<SftpAttributes> call = sftp.GetAttributesAsync("/", CancellationToken.None);
        await ElapseAsync(4, () => client.Connection.Ended.IsCompleted);

        SshConnectionException ex = await Assert.ThrowsAnyAsync<SshConnectionException>(() => call.WaitAsync(Limit, Ct));
        Assert.True(Mentions(ex, PeerGone), ex.ToString());
    }

    [Fact]
    public async Task A_handler_reading_with_no_token_wakes_and_frees_its_slot_when_the_client_dies()
    {
        await using SshServer server = await SshServer.StartAsync(ServerOptions(ReadWithNoTokenAsync, keepAlive: true), Ct);
        await using SshClient client = await ConnectAsync(server, clientKeepAlive: false);
        await using SshProcess process = await client.StartProcessAsync("wait", null, Ct);
        await _handlerStarted.Task.WaitAsync(Limit, Ct);
        await _clock.WaitForTimerAsync();

        KillPath();
        await ElapseAsync(4, () => _handlerEnded.Task.IsCompleted);

        Exception? ex = await _handlerEnded.Task.WaitAsync(Limit, Ct);
        Assert.True(Mentions(ex, PeerGone), ex?.ToString());

        // The connection's task ending is what gives back the slot.
        await _served.WaitAsync(Limit, Ct);
    }

    [Fact]
    public async Task A_handler_waiting_on_its_token_is_cancelled_when_the_client_dies()
    {
        await using SshServer server = await SshServer.StartAsync(ServerOptions(WaitForeverAsync, keepAlive: true), Ct);
        await using SshClient client = await ConnectAsync(server, clientKeepAlive: false);
        await using SshProcess process = await client.StartProcessAsync("wait", null, Ct);
        await _handlerStarted.Task.WaitAsync(Limit, Ct);
        await _clock.WaitForTimerAsync();

        KillPath();
        await ElapseAsync(4, () => _served.IsCompleted);

        await _served.WaitAsync(Limit, Ct);
    }

    [Fact]
    public async Task A_client_that_stops_reading_ends_a_writing_handler_through_the_stall_check()
    {
        byte[] block = new byte[16 * 1024];
        await using SshServer server = await SshServer.StartAsync(
            ServerOptions(
                async (session, _) =>
                {
                    _handlerStarted.TrySetResult();
                    try
                    {
                        while (true)
                        {
                            await session.Output.WriteAsync(block, CancellationToken.None);
                        }
                    }
                    catch (SshException ex)
                    {
                        _handlerEnded.TrySetResult(ex);
                    }

                    return 0;
                },
                keepAlive: true),
            Ct);
        await using SshClient client = await ConnectAsync(server, clientKeepAlive: false);
        await using SshProcess process = await client.StartProcessAsync("write", null, Ct);
        await _handlerStarted.Task.WaitAsync(Limit, Ct);
        await _clock.WaitForTimerAsync();

        _serverLink.Hold();
        while (_serverLink.WritesWaiting == 0)
        {
            await Task.Delay(1, Ct);
        }

        await ElapseAsync(3, () => _handlerEnded.Task.IsCompleted);

        Exception? ex = await _handlerEnded.Task.WaitAsync(Limit, Ct);
        Assert.True(Mentions(ex, "stopped reading"), ex?.ToString());
        await _served.WaitAsync(Limit, Ct);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task No_probe_and_no_timer_runs_before_auth(bool clientWatches)
    {
        TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource asked = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await using SshServer server = await SshServer.StartAsync(
            ServerOptions(
                WaitForeverAsync,
                keepAlive: !clientWatches,
                password: async (_, _) =>
                {
                    asked.TrySetResult();
                    await release.Task;
                    return SshAuthDecision.Accept;
                }),
            Ct);

        Task<SshClient> connecting = ConnectAsync(server, clientKeepAlive: clientWatches);
        await asked.Task.WaitAsync(Limit, Ct);

        // Auth is stuck, and many intervals pass: nothing may fire, because nothing may be armed.
        Assert.Equal(0, _clock.ActiveTimers);
        await _clock.AdvanceAsync(Interval * 20, () => true);
        Assert.False(connecting.IsCompleted);

        release.SetResult();
        await using SshClient client = await connecting.WaitAsync(Limit, Ct);
        await _clock.WaitForTimerAsync();
        Assert.False(client.Connection.Ended.IsCompleted);
        Assert.Equal(0, client.Connection.KeepAlive?.ProbesSent ?? 0);
    }

    private sealed class TempDirectory : IDisposable
    {
        public string Path { get; } = Directory.CreateTempSubdirectory("zorg-keepalive").FullName;

        public void Dispose() => Directory.Delete(Path, recursive: true);
    }
}

using System;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Tests.Transport;

namespace Zorg.Ssh.Tests.Server;

/// <summary><see cref="SshServer.Create"/> makes a server that serves streams you give it and never opens a socket.</summary>
public sealed class ServerWithoutListenerTests : IDisposable
{
    private readonly SshHostKey _hostKey = SshHostKey.GenerateEd25519();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => _hostKey.Dispose();

    private SshServerOptions Options(Func<SshServerSession, CancellationToken, Task<int>>? handler = null) => new()
    {
        HostKeys = [_hostKey],
        PasswordHandler = static (_, _) => ValueTask.FromResult(SshAuthDecision.Accept),
        SessionHandler = handler ?? ((session, _) => Task.FromResult(3)),
    };

    private SshClientOptions ClientOptions() => new()
    {
        Host = "in-memory",
        UserName = "alice",
        Credentials = [SshCredential.FromPassword("pw")],
        HostKeyPolicy = HostKeyPolicy.Fingerprint(_hostKey.Sha256Fingerprint),
    };

    [Fact]
    public async Task A_stream_is_served_and_a_command_runs()
    {
        await using SshServer server = SshServer.Create(Options());
        (Stream clientSide, Stream serverSide) = DuplexStream.CreatePair();
        Task serving = server.ServeStreamAsync(serverSide, Ct);
        await using SshClient client = await SshClient.ConnectOverStreamAsync(clientSide, ClientOptions(), Ct);

        SshCommandResult result = await client.ExecuteAsync("anything", Ct);

        Assert.Equal(3, result.ExitCode);
        await client.DisposeAsync();
        await serving.WaitAsync(TimeSpan.FromSeconds(10), Ct);
    }

    [Fact]
    public async Task LocalEndPoint_says_what_to_do_instead_of_returning_something_false()
    {
        SshServer server = SshServer.Create(Options());
        InvalidOperationException ex = Assert.Throws<InvalidOperationException>(() => server.LocalEndPoint);
        Assert.Contains("ServeStreamAsync", ex.Message);
        await server.DisposeAsync();
    }

    [Fact]
    public async Task Address_and_port_are_ignored_and_nothing_listens()
    {
        // A port that is taken would make StartAsync fail. Create doesn't look at it.
        using System.Net.Sockets.TcpListener taken = new(IPAddress.Loopback, 0);
        taken.Start();
        int port = ((IPEndPoint)taken.LocalEndpoint).Port;
        await using SshServer server = SshServer.Create(Options() with { Port = port, Address = IPAddress.Loopback });

        (Stream clientSide, Stream serverSide) = DuplexStream.CreatePair();
        Task serving = server.ServeStreamAsync(serverSide, Ct);
        await using SshClient client = await SshClient.ConnectOverStreamAsync(clientSide, ClientOptions(), Ct);
        Assert.Equal(3, (await client.ExecuteAsync("x", Ct)).ExitCode);
        Assert.False(taken.Pending());
    }

    [Fact]
    public async Task Dispose_stops_sessions_and_cancels_the_handler_token()
    {
        TaskCompletionSource started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource<bool> cancelled = new(TaskCreationOptions.RunContinuationsAsynchronously);
        SshServer server = SshServer.Create(Options(async (_, ct) =>
        {
            started.TrySetResult();
            try
            {
                await Task.Delay(Timeout.Infinite, ct);
            }
            catch (OperationCanceledException)
            {
                cancelled.TrySetResult(true);
            }

            return 0;
        }));
        (Stream clientSide, Stream serverSide) = DuplexStream.CreatePair();
        Task serving = server.ServeStreamAsync(serverSide, Ct);
        await using SshClient client = await SshClient.ConnectOverStreamAsync(clientSide, ClientOptions(), Ct);
        Task<SshCommandResult> command = client.ExecuteAsync("wait", Ct);
        await started.Task.WaitAsync(TimeSpan.FromSeconds(10), Ct);

        await server.DisposeAsync();

        Assert.True(await cancelled.Task.WaitAsync(TimeSpan.FromSeconds(10), Ct));
        await serving.WaitAsync(TimeSpan.FromSeconds(10), Ct);
        await server.DisposeAsync();
        try
        {
            await command.WaitAsync(TimeSpan.FromSeconds(10), Ct);
        }
        catch (SshException)
        {
            // The connection ended under it, which is the point.
        }
    }

    [Fact]
    public async Task A_stream_given_to_a_disposed_server_is_refused()
    {
        SshServer server = SshServer.Create(Options());
        await server.DisposeAsync();
        (_, Stream serverSide) = DuplexStream.CreatePair();
        await Assert.ThrowsAsync<SshConnectionException>(() => server.ServeStreamAsync(serverSide, Ct));
    }

    [Fact]
    public void The_options_are_checked_as_StartAsync_checks_them()
    {
        Assert.Throws<ArgumentNullException>(() => SshServer.Create(null!));
        Assert.Throws<ArgumentException>(() => SshServer.Create(Options() with { HostKeys = [] }));
        Assert.Throws<ArgumentException>(() => SshServer.Create(Options() with { PasswordHandler = null }));
        Assert.Throws<ArgumentOutOfRangeException>(() => SshServer.Create(Options() with { MaxUnauthenticatedPerAddress = 0 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => SshServer.Create(Options() with { IdleTimeout = TimeSpan.Zero }));
        Assert.Throws<ArgumentOutOfRangeException>(() => SshServer.Create(Options() with { KeepAliveInterval = TimeSpan.FromSeconds(-5) }));
    }

    [Fact]
    public async Task StartAsync_and_Create_refuse_the_same_options()
    {
        SshServerOptions bad = Options() with { HostKeys = [] };
        ArgumentException create = Assert.Throws<ArgumentException>(() => SshServer.Create(bad));
        ArgumentException start = await Assert.ThrowsAsync<ArgumentException>(() => SshServer.StartAsync(bad, Ct));
        Assert.Equal(start.Message, create.Message);
    }
}

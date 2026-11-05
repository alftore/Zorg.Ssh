using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Transport;

namespace Zorg.Ssh.Tests.Server;

public sealed class PublicServerTests : IDisposable
{
    private readonly SshHostKey _hostKey = SshHostKey.GenerateEd25519();
    private int _handlerRuns;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => _hostKey.Dispose();

    private SshServerOptions Options(Action<SshServerOptionsBuilder>? change = null)
    {
        SshServerOptionsBuilder builder = new();
        change?.Invoke(builder);
        return new SshServerOptions
        {
            HostKeys = [_hostKey],
            PasswordHandler = (r, _) => ValueTask.FromResult(r.Password == "pw" ? SshAuthDecision.Accept : SshAuthDecision.Reject),
            SessionHandler = (_, _) =>
            {
                Interlocked.Increment(ref _handlerRuns);
                return Task.FromResult(0);
            },
            MaxUnauthenticatedConnections = builder.MaxUnauthenticated,
            LoginGraceTime = builder.Grace,
        };
    }

    private static async Task<SshTransport> ConnectTransportAsync(SshServer server)
    {
        TcpClient socket = new();
        await socket.ConnectAsync(IPAddress.Loopback, server.LocalEndPoint.Port, Ct);
        return await SshTransport.StartAsync(
            socket.GetStream(),
            new TransportOptions { Role = SshRole.Client, HostKeyValidator = static (_, _) => ValueTask.FromResult(true) },
            Ct);
    }

    private SshClientOptions ClientOptions(SshServer server, string password = "pw") => new()
    {
        Host = "127.0.0.1",
        Port = server.LocalEndPoint.Port,
        UserName = "alice",
        Credentials = [SshCredential.FromPassword(password)],
        HostKeyPolicy = HostKeyPolicy.Fingerprint(_hostKey.Sha256Fingerprint),
    };

    [Fact]
    public async Task Binds_to_loopback_by_default()
    {
        await using SshServer server = await SshServer.StartAsync(Options(), Ct);
        Assert.True(IPAddress.IsLoopback(server.LocalEndPoint.Address));
    }

    [Fact]
    public async Task A_server_nobody_can_log_in_to_is_refused_at_start()
    {
        SshServerOptions options = new()
        {
            HostKeys = [_hostKey],
            SessionHandler = (_, _) => Task.FromResult(0),
        };
        await Assert.ThrowsAsync<ArgumentException>(() => SshServer.StartAsync(options, Ct));
    }

    // Erlang CVE-2025-32433, end to end: an exec before login must never reach a handler.
    [Theory]
    [InlineData(MessageNumber.ChannelOpen)]
    [InlineData(MessageNumber.ChannelRequest)]
    [InlineData(MessageNumber.GlobalRequest)]
    public async Task A_connection_message_before_login_closes_the_connection_and_runs_nothing(byte message)
    {
        await using SshServer server = await SshServer.StartAsync(Options(), Ct);
        await using SshTransport transport = await ConnectTransportAsync(server);

        SshWriter writer = new();
        writer.WriteByte(message);
        writer.WriteUtf8String("session");
        writer.WriteUInt32(0);
        writer.WriteUInt32(1 << 20);
        writer.WriteUInt32(1 << 15);
        byte[] payload = writer.ToArray();
        writer.Dispose();
        await transport.SendAsync(payload, Ct);

        await Assert.ThrowsAnyAsync<SshConnectionException>(async () =>
        {
            while (true)
            {
                await transport.ReceiveAsync(Ct);
            }
        });
        Assert.Equal(0, Volatile.Read(ref _handlerRuns));
    }

    [Fact]
    public async Task A_wrong_password_never_reaches_the_session_handler()
    {
        await using SshServer server = await SshServer.StartAsync(Options(), Ct);
        await Assert.ThrowsAsync<SshAuthenticationException>(() => SshClient.ConnectAsync(ClientOptions(server, "bad"), Ct));
        Assert.Equal(0, Volatile.Read(ref _handlerRuns));
    }

    [Fact]
    public async Task A_client_that_never_logs_in_is_dropped_at_the_grace_time()
    {
        await using SshServer server = await SshServer.StartAsync(Options(b => b.Grace = TimeSpan.FromMilliseconds(300)), Ct);
        await using SshTransport transport = await ConnectTransportAsync(server);
        Task<SshConnectionException> dropped = Assert.ThrowsAnyAsync<SshConnectionException>(async () => await transport.ReceiveAsync(Ct));
        await dropped.WaitAsync(TimeSpan.FromSeconds(10), Ct);
    }

    [Fact]
    public async Task A_silent_tcp_connection_is_dropped_at_the_grace_time()
    {
        await using SshServer server = await SshServer.StartAsync(Options(b => b.Grace = TimeSpan.FromMilliseconds(300)), Ct);
        using TcpClient socket = new();
        await socket.ConnectAsync(IPAddress.Loopback, server.LocalEndPoint.Port, Ct);
        NetworkStream stream = socket.GetStream();
        byte[] buffer = new byte[1024];
        using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        limit.CancelAfter(TimeSpan.FromSeconds(10));

        try
        {
            while (await stream.ReadAsync(buffer, limit.Token) != 0)
            {
            }
        }
        catch (Exception ex) when (ex is System.IO.IOException)
        {
            // A reset is a drop too.
        }

        Assert.False(limit.IsCancellationRequested);
    }

    [Fact]
    public async Task The_unauthenticated_limit_refuses_extra_connections_and_recovers()
    {
        await using SshServer server = await SshServer.StartAsync(Options(b => b.MaxUnauthenticated = 2), Ct);
        using TcpClient first = new();
        using TcpClient second = new();
        await first.ConnectAsync(IPAddress.Loopback, server.LocalEndPoint.Port, Ct);
        await second.ConnectAsync(IPAddress.Loopback, server.LocalEndPoint.Port, Ct);
        await Task.Delay(200, Ct);

        await Assert.ThrowsAnyAsync<SshException>(() => SshClient.ConnectAsync(ClientOptions(server), Ct));

        first.Close();
        second.Close();
        await Task.Delay(300, Ct);
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server), Ct);
        Assert.Equal(0, (await client.ExecuteAsync("x", Ct)).ExitCode);
    }

    [Fact]
    public async Task Disposing_the_server_ends_a_running_handler()
    {
        TaskCompletionSource started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        SshServer server = await SshServer.StartAsync(
            new SshServerOptions
            {
                HostKeys = [_hostKey],
                PasswordHandler = (_, _) => ValueTask.FromResult(SshAuthDecision.Accept),
                SessionHandler = async (_, ct) =>
                {
                    started.SetResult();
                    await Task.Delay(Timeout.Infinite, ct);
                    return 0;
                },
            },
            Ct);

        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server), Ct);
        await using SshProcess process = await client.StartProcessAsync("x", null, Ct);
        await started.Task.WaitAsync(TimeSpan.FromSeconds(10), Ct);
        await server.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(15), Ct);
    }

    private sealed class SshServerOptionsBuilder
    {
        public int MaxUnauthenticated { get; set; } = 20;

        public TimeSpan Grace { get; set; } = TimeSpan.FromSeconds(30);
    }
}

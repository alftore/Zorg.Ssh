using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Zorg.Ssh.Tests.Forwarding;

/// <summary>Local forwarding, jump hosts and the server's direct-tcpip handler, our client against our server.</summary>
public sealed class ForwardingTests : IDisposable
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(20);

    private readonly SshHostKey _hostKey = SshHostKey.GenerateEd25519();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => _hostKey.Dispose();

    private Task<SshServer> StartServerAsync(
        Func<SshDirectTcpRequest, CancellationToken, ValueTask<SshForwardDecision>>? handler,
        int maxSessions = 100,
        TimeSpan? grace = null) => SshServer.StartAsync(
        new SshServerOptions
        {
            HostKeys = [_hostKey],
            PasswordHandler = static (_, _) => ValueTask.FromResult(SshAuthDecision.Accept),
            SessionHandler = static (_, _) => Task.FromResult(5),
            DirectTcpHandler = handler,
            MaxSessionsPerConnection = maxSessions,
            LoginGraceTime = grace ?? TimeSpan.FromSeconds(30),
        },
        Ct);

    private static Task<SshServer> StartOpenServerAsync(ForwardingTests test, int maxSessions = 100) =>
        test.StartServerAsync(static (_, _) => ValueTask.FromResult(SshForwardDecision.Allow), maxSessions);

    private SshClientOptions ClientOptions(SshServer server, int maxForwarded = 64, SshClient? jumpHost = null, string? fingerprint = null) => new()
    {
        Host = "127.0.0.1",
        Port = server.LocalEndPoint.Port,
        UserName = "alice",
        Credentials = [SshCredential.FromPassword("pw")],
        HostKeyPolicy = HostKeyPolicy.Fingerprint(fingerprint ?? _hostKey.Sha256Fingerprint),
        MaxForwardedConnections = maxForwarded,
        JumpHost = jumpHost,
    };

    private static async Task<TcpClient> ConnectAsync(SshLocalForward forward)
    {
        TcpClient client = new() { NoDelay = true };
        await client.ConnectAsync(forward.LocalEndPoint, Ct);
        return client;
    }

    private static async Task AssertEchoesAsync(Stream stream, int size = 1000)
    {
        byte[] sent = RandomNumberGenerator.GetBytes(size);
        byte[] received = new byte[size];
        Task writing = stream.WriteAsync(sent, Ct).AsTask();
        await stream.ReadExactlyAsync(received, Ct).AsTask().WaitAsync(Limit, Ct);
        await writing;
        Assert.Equal(sent, received);
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        limit.CancelAfter(Limit);
        while (!condition())
        {
            await Task.Delay(10, limit.Token);
        }
    }

    /// <summary>Repeats an attempt until the server stops refusing it: a slot comes back a moment after a close.</summary>
    private static async Task RetryAsync(Func<Task> attempt)
    {
        using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        limit.CancelAfter(Limit);
        while (true)
        {
            try
            {
                await attempt();
                return;
            }
            catch (SshException)
            {
                await Task.Delay(10, limit.Token);
            }
        }
    }

    [Fact]
    public async Task A_stream_round_trips_data_through_the_server()
    {
        await using TcpService echo = TcpService.Echo();
        await using SshServer server = await StartOpenServerAsync(this);
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server), Ct);
        await using Stream stream = await client.OpenTcpStreamAsync("127.0.0.1", echo.Port, Ct);

        // Well past the 2 MiB window, both ways, so window adjusts have to work on the relay's channel.
        await AssertEchoesAsync(stream, 6_000_000);
    }

    [Fact]
    public async Task Without_a_handler_direct_tcpip_is_refused_and_the_connection_lives()
    {
        await using TcpService echo = TcpService.Echo();
        await using SshServer server = await StartServerAsync(null);
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server), Ct);

        await Assert.ThrowsAsync<SshException>(() => client.OpenTcpStreamAsync("127.0.0.1", echo.Port, Ct));
        Assert.Equal(0, echo.Accepted);
        Assert.Equal(5, (await client.ExecuteAsync("x", Ct)).ExitCode);
    }

    [Fact]
    public async Task The_handler_sees_the_request_and_can_deny_it()
    {
        await using TcpService echo = TcpService.Echo();
        SshDirectTcpRequest? seen = null;
        await using SshServer server = await StartServerAsync((request, _) =>
        {
            seen = request;
            return ValueTask.FromResult(SshForwardDecision.Deny);
        });
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server), Ct);

        SshException ex = await Assert.ThrowsAsync<SshException>(() => client.OpenTcpStreamAsync("127.0.0.1", echo.Port, Ct));
        Assert.Contains("reason 1", ex.Message);
        Assert.Equal(0, echo.Accepted);
        Assert.Equal("alice", seen!.Principal.UserName);
        Assert.Equal("127.0.0.1", seen.Host);
        Assert.Equal(echo.Port, seen.Port);
    }

    [Fact]
    public async Task A_throwing_handler_is_a_denial_and_tells_the_client_nothing()
    {
        await using SshServer server = await StartServerAsync((_, _) => throw new InvalidOperationException("database down"));
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server), Ct);

        SshException ex = await Assert.ThrowsAsync<SshException>(() => client.OpenTcpStreamAsync("127.0.0.1", 9, Ct));
        Assert.DoesNotContain("database", ex.Message);
        Assert.Equal(5, (await client.ExecuteAsync("x", Ct)).ExitCode);
    }

    [Fact]
    public async Task A_handler_that_ignores_its_token_cannot_keep_a_slot_past_the_grace_time()
    {
        await using SshServer server = await StartServerAsync(
            static async (_, _) =>
            {
                await Task.Delay(TimeSpan.FromMinutes(5), CancellationToken.None);
                return SshForwardDecision.Allow;
            },
            maxSessions: 1,
            grace: TimeSpan.FromMilliseconds(300));
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server), Ct);

        await Assert.ThrowsAsync<SshException>(() => client.OpenTcpStreamAsync("127.0.0.1", 9, Ct).WaitAsync(Limit, Ct));
        await RetryAsync(() => client.ExecuteAsync("x", Ct));
    }

    [Fact]
    public async Task A_target_nobody_listens_on_is_a_refused_channel()
    {
        using TcpListener unused = new(IPAddress.Loopback, 0);
        unused.Start();
        int port = ((IPEndPoint)unused.LocalEndpoint).Port;
        unused.Stop();

        await using SshServer server = await StartOpenServerAsync(this);
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server), Ct);

        SshException ex = await Assert.ThrowsAsync<SshException>(() => client.OpenTcpStreamAsync("127.0.0.1", port, Ct));
        Assert.Contains("reason 2", ex.Message);
    }

    [Fact]
    public async Task Direct_tcpip_counts_towards_the_session_limit_until_it_ends()
    {
        await using TcpService echo = TcpService.Echo();
        await using SshServer server = await StartOpenServerAsync(this, maxSessions: 1);
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server), Ct);

        Stream first = await client.OpenTcpStreamAsync("127.0.0.1", echo.Port, Ct);
        await Assert.ThrowsAsync<SshException>(() => client.OpenTcpStreamAsync("127.0.0.1", echo.Port, Ct));

        await first.DisposeAsync();
        await RetryAsync(async () => await (await client.OpenTcpStreamAsync("127.0.0.1", echo.Port, Ct)).DisposeAsync());
    }

    // The server has no remote forwarding yet, and refusing it must not hurt the connection.
    [Fact]
    public async Task The_server_refuses_tcpip_forward()
    {
        await using SshServer server = await StartOpenServerAsync(this);
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server), Ct);

        await Assert.ThrowsAsync<SshException>(() => client.ForwardRemotePortAsync("127.0.0.1", 0, "127.0.0.1", 9, Ct).WaitAsync(Limit, Ct));
        Assert.Equal(5, (await client.ExecuteAsync("x", Ct)).ExitCode);
    }

    [Theory]
    [InlineData("", 22)]
    [InlineData("a\0b", 22)]
    [InlineData("host", 0)]
    [InlineData("host", 65536)]
    public async Task A_bad_target_never_reaches_the_server(string host, int port)
    {
        await using SshServer server = await StartOpenServerAsync(this);
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server), Ct);

        await Assert.ThrowsAnyAsync<ArgumentException>(() => client.OpenTcpStreamAsync(host, port, Ct));
        await Assert.ThrowsAnyAsync<ArgumentException>(() => client.ForwardLocalPortAsync(host, port, Ct));
    }

    [Fact]
    public async Task A_local_forward_binds_loopback_and_carries_data_both_ways()
    {
        await using TcpService echo = TcpService.Echo();
        await using SshServer server = await StartOpenServerAsync(this);
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server), Ct);
        await using SshLocalForward forward = await client.ForwardLocalPortAsync("127.0.0.1", echo.Port, Ct);

        Assert.True(IPAddress.IsLoopback(forward.LocalEndPoint.Address));
        Assert.NotEqual(0, forward.LocalEndPoint.Port);

        using TcpClient connection = await ConnectAsync(forward);
        await AssertEchoesAsync(connection.GetStream(), 6_000_000);
        Assert.Equal(1, forward.ActiveConnections);
    }

    [Fact]
    public async Task Several_connections_share_a_forward_at_full_speed()
    {
        await using TcpService echo = TcpService.Echo();
        await using SshServer server = await StartOpenServerAsync(this);
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server), Ct);
        await using SshLocalForward forward = await client.ForwardLocalPortAsync("127.0.0.1", echo.Port, Ct);

        await Task.WhenAll(Enumerable.Range(0, 4).Select(async _ =>
        {
            using TcpClient connection = await ConnectAsync(forward);
            await AssertEchoesAsync(connection.GetStream(), 3_000_000);
        }));
    }

    // Flat out in both directions, with sends parked by each rekey. A receive loop that ever waited would stall here.
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    public async Task Rekeys_during_full_duplex_forwarded_traffic_lose_nothing(int round)
    {
        await using TcpService echo = TcpService.Echo();
        await using SshServer server = await StartOpenServerAsync(this);
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server), Ct);
        await using SshLocalForward forward = await client.ForwardLocalPortAsync("127.0.0.1", echo.Port, Ct);

        using CancellationTokenSource done = CancellationTokenSource.CreateLinkedTokenSource(Ct);
#pragma warning disable CA2025 // Awaited below, before the source is disposed.
        Task rekeys = RekeyUntilAsync(client, done.Token);
#pragma warning restore CA2025

        // A fast machine can move the data in less time than two rekeys take (a run took 28 ms, and Task.Delay(5) is
        // about 15 ms on Windows), so the traffic goes on until at least two rekeys have overlapped it.
        for (int pass = 0; pass < 20 && (pass == 0 || client.CompletedKeyExchanges < 3); pass++)
        {
            await Task.WhenAll(Enumerable.Range(0, 2 + round).Select(async _ =>
            {
                using TcpClient connection = await ConnectAsync(forward);
                await AssertEchoesAsync(connection.GetStream(), 6_000_000);
            }));
        }

        await done.CancelAsync();
        await rekeys;

        Assert.True(client.CompletedKeyExchanges >= 3, $"{client.CompletedKeyExchanges} key exchanges ran.");
    }

    private static async Task RekeyUntilAsync(SshClient client, CancellationToken cancellationToken)
    {
        try
        {
            while (true)
            {
                await Task.Delay(5, cancellationToken);
                client.RequestRekey();
            }
        }
        catch (OperationCanceledException)
        {
            // The transfer has finished.
        }
    }

    [Fact]
    public async Task A_port_in_use_is_a_clear_error()
    {
        using TcpListener taken = new(IPAddress.Loopback, 0);
        taken.Start();
        await using SshServer server = await StartOpenServerAsync(this);
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server), Ct);

        await Assert.ThrowsAsync<SshException>(() => client.ForwardLocalPortAsync("127.0.0.1", 9, (IPEndPoint)taken.LocalEndpoint, Ct));
    }

    [Fact]
    public async Task Half_closing_the_local_side_still_delivers_the_answer()
    {
        // Reads everything, and only then answers, as a request and response protocol does.
        await using TcpService service = new(static async (stream, ct) =>
        {
            byte[] buffer = new byte[1024];
            long total = 0;
            int read;
            while ((read = await stream.ReadAsync(buffer, ct)) != 0)
            {
                total += read;
            }

            await stream.WriteAsync(BitConverter.GetBytes(total), ct);
        });
        await using SshServer server = await StartOpenServerAsync(this);
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server), Ct);
        await using SshLocalForward forward = await client.ForwardLocalPortAsync("127.0.0.1", service.Port, Ct);

        using TcpClient connection = await ConnectAsync(forward);
        NetworkStream stream = connection.GetStream();
        await stream.WriteAsync(new byte[100_000], Ct);
        connection.Client.Shutdown(SocketShutdown.Send);

        byte[] answer = new byte[8];
        await stream.ReadExactlyAsync(answer, Ct).AsTask().WaitAsync(Limit, Ct);
        Assert.Equal(100_000, BitConverter.ToInt64(answer));
        Assert.Equal(0, await stream.ReadAsync(answer, Ct).AsTask().WaitAsync(Limit, Ct));
    }

    [Fact]
    public async Task Data_sent_just_before_the_far_side_closes_still_arrives()
    {
        byte[] farewell = RandomNumberGenerator.GetBytes(3_000_000);
        await using TcpService service = new(async (stream, ct) => await stream.WriteAsync(farewell, ct));
        await using SshServer server = await StartOpenServerAsync(this);
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server), Ct);
        await using SshLocalForward forward = await client.ForwardLocalPortAsync("127.0.0.1", service.Port, Ct);

        using TcpClient connection = await ConnectAsync(forward);
        await Task.Delay(100, Ct);
        using MemoryStream all = new();
        await connection.GetStream().CopyToAsync(all, Ct).WaitAsync(Limit, Ct);
        Assert.True(farewell.AsSpan().SequenceEqual(all.ToArray()));
    }

    [Fact]
    public async Task Connections_past_the_cap_are_closed_and_the_slot_comes_back()
    {
        await using TcpService echo = TcpService.Echo();
        await using SshServer server = await StartOpenServerAsync(this);
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server, maxForwarded: 2), Ct);
        await using SshLocalForward forward = await client.ForwardLocalPortAsync("127.0.0.1", echo.Port, Ct);

        using TcpClient first = await ConnectAsync(forward);
        using TcpClient second = await ConnectAsync(forward);
        await AssertEchoesAsync(first.GetStream());
        await AssertEchoesAsync(second.GetStream());

        using (TcpClient third = await ConnectAsync(forward))
        {
            byte[] buffer = new byte[1];
            Assert.True(await ReadsToEndAsync(third.GetStream(), buffer));
        }

        Assert.Equal(2, forward.ActiveConnections);
        first.Close();
        await WaitUntilAsync(() => forward.ActiveConnections == 1);

        using TcpClient fourth = await ConnectAsync(forward);
        await AssertEchoesAsync(fourth.GetStream());
    }

    private static async Task<bool> ReadsToEndAsync(Stream stream, byte[] buffer)
    {
        try
        {
            return await stream.ReadAsync(buffer, Ct).AsTask().WaitAsync(Limit, Ct) == 0;
        }
        catch (IOException)
        {
            return true;
        }
    }

    // A forwarded connection nobody reads holds its own window shut, and nothing else.
    [Fact]
    public async Task A_stalled_connection_does_not_stall_the_others()
    {
        byte[] chunk = new byte[64 * 1024];
        await using TcpService flood = new(async (stream, ct) =>
        {
            while (true)
            {
                await stream.WriteAsync(chunk, ct);
            }
        });
        await using TcpService echo = TcpService.Echo();
        await using SshServer server = await StartOpenServerAsync(this);
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server), Ct);
        await using SshLocalForward stalled = await client.ForwardLocalPortAsync("127.0.0.1", flood.Port, Ct);
        await using SshLocalForward healthy = await client.ForwardLocalPortAsync("127.0.0.1", echo.Port, Ct);

        using TcpClient neverRead = await ConnectAsync(stalled);
        await WaitUntilAsync(() => stalled.ActiveConnections == 1);

        // Long enough for its window and socket buffers to fill.
        await Task.Delay(300, Ct);

        using TcpClient other = await ConnectAsync(healthy);
        await AssertEchoesAsync(other.GetStream(), 3_000_000);
        Assert.Equal(5, (await client.ExecuteAsync("x", Ct)).ExitCode);
    }

    [Fact]
    public async Task Closing_a_forward_mid_transfer_ends_its_connections_and_nothing_else()
    {
        byte[] chunk = new byte[64 * 1024];
        await using TcpService flood = new(async (stream, ct) =>
        {
            while (true)
            {
                await stream.WriteAsync(chunk, ct);
            }
        });
        await using TcpService echo = TcpService.Echo();
        await using SshServer server = await StartOpenServerAsync(this);
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server), Ct);
        await using Stream bystander = await client.OpenTcpStreamAsync("127.0.0.1", echo.Port, Ct);

        SshLocalForward forward = await client.ForwardLocalPortAsync("127.0.0.1", flood.Port, Ct);
        IPEndPoint endPoint = forward.LocalEndPoint;
        using TcpClient connection = await ConnectAsync(forward);
        NetworkStream stream = connection.GetStream();
        byte[] buffer = new byte[1024 * 1024];
        await stream.ReadExactlyAsync(buffer, Ct).AsTask().WaitAsync(Limit, Ct);

        await forward.DisposeAsync().AsTask().WaitAsync(Limit, Ct);
        await forward.DisposeAsync();
        Assert.Equal(0, forward.ActiveConnections);

        // Whatever was in flight drains, and then the connection has ended.
        await DrainAsync(stream, buffer);

        using TcpClient late = new();
        await Assert.ThrowsAnyAsync<SocketException>(() => late.ConnectAsync(endPoint, Ct).AsTask());

        await AssertEchoesAsync(bystander);
        Assert.Equal(5, (await client.ExecuteAsync("x", Ct)).ExitCode);
    }

    private static async Task DrainAsync(Stream stream, byte[] buffer)
    {
        try
        {
            while (await stream.ReadAsync(buffer, Ct).AsTask().WaitAsync(Limit, Ct) != 0)
            {
            }
        }
        catch (IOException)
        {
            // A reset is as good an end as any.
        }
    }

    [Fact]
    public async Task Closing_the_client_closes_its_forwards()
    {
        await using TcpService echo = TcpService.Echo();
        await using SshServer server = await StartOpenServerAsync(this);
        SshClient client = await SshClient.ConnectAsync(ClientOptions(server), Ct);

        // A port below every system's ephemeral range: macOS gave a freed ephemeral port to another test's listener at once,
        // and the late connect below reached that. Nothing that binds port 0 gets one of these.
        SshLocalForward forward = await client.ForwardLocalPortAsync("127.0.0.1", echo.Port, new IPEndPoint(IPAddress.Loopback, FreePortBelowEphemeralRange()), Ct);
        using TcpClient connection = await ConnectAsync(forward);
        await AssertEchoesAsync(connection.GetStream());

        await client.DisposeAsync().AsTask().WaitAsync(Limit, Ct);
        await client.DisposeAsync();

        using TcpClient late = new();
        await Assert.ThrowsAnyAsync<SocketException>(() => late.ConnectAsync(forward.LocalEndPoint, Ct).AsTask());
        await Assert.ThrowsAsync<SshConnectionException>(() => client.ForwardLocalPortAsync("127.0.0.1", echo.Port, Ct));
    }

    /// <summary>A free loopback port from 20000 to 29999, which no system hands out for port 0.</summary>
    private static int FreePortBelowEphemeralRange()
    {
        for (int port = 20000 + RandomNumberGenerator.GetInt32(5000); port < 30000; port++)
        {
            try
            {
                using Socket probe = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                probe.Bind(new IPEndPoint(IPAddress.Loopback, port));
                return port;
            }
            catch (SocketException)
            {
                // In use; try the next.
            }
        }

        throw new InvalidOperationException("No free port from 20000 to 29999.");
    }

    [Fact]
    public async Task Losing_the_connection_closes_the_listener()
    {
        await using TcpService echo = TcpService.Echo();
        SshServer server = await StartOpenServerAsync(this);
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server), Ct);
        await using SshLocalForward forward = await client.ForwardLocalPortAsync("127.0.0.1", echo.Port, Ct);
        await server.DisposeAsync();

        await WaitUntilAsync(() =>
        {
            using TcpClient probe = new();
            try
            {
                probe.Connect(forward.LocalEndPoint);
                return false;
            }
            catch (SocketException)
            {
                return true;
            }
        });
    }

    [Fact]
    public async Task A_jump_host_reaches_a_second_server_and_runs_a_command()
    {
        using SshHostKey innerKey = SshHostKey.GenerateEd25519();
        await using SshServer inner = await StartInnerServerAsync(innerKey);
        await using SshServer outer = await StartOpenServerAsync(this);

        await using SshClient jump = await SshClient.ConnectAsync(ClientOptions(outer), Ct);
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(inner, jumpHost: jump, fingerprint: innerKey.Sha256Fingerprint), Ct);

        SshCommandResult result = await client.ExecuteAsync("x", Ct);
        Assert.Equal(11, result.ExitCode);
        Assert.Equal("inner", result.StandardOutput);
    }

    // The hop's own policy decides. Getting there through a trusted jump host proves nothing about the target.
    [Fact]
    public async Task The_second_hop_is_checked_against_its_own_policy()
    {
        using SshHostKey innerKey = SshHostKey.GenerateEd25519();
        int attempts = 0;
        await using SshServer inner = await SshServer.StartAsync(
            new SshServerOptions
            {
                HostKeys = [innerKey],
                PasswordHandler = (_, _) =>
                {
                    Interlocked.Increment(ref attempts);
                    return ValueTask.FromResult(SshAuthDecision.Accept);
                },
                SessionHandler = static (_, _) => Task.FromResult(0),
            },
            Ct);
        await using SshServer outer = await StartOpenServerAsync(this);
        await using SshClient jump = await SshClient.ConnectAsync(ClientOptions(outer), Ct);

        // The jump host's own fingerprint is the wrong one here.
        await Assert.ThrowsAsync<SshHostKeyException>(() => SshClient.ConnectAsync(ClientOptions(inner, jumpHost: jump), Ct));
        Assert.Equal(0, attempts);

        Assert.Equal(5, (await jump.ExecuteAsync("x", Ct)).ExitCode);
    }

    [Fact]
    public async Task Hops_chain_and_each_ends_with_the_one_before()
    {
        using SshHostKey innerKey = SshHostKey.GenerateEd25519();
        await using SshServer inner = await StartInnerServerAsync(innerKey);
        await using SshServer middle = await StartOpenServerAsync(this);
        await using SshServer outer = await StartOpenServerAsync(this);

        SshClient first = await SshClient.ConnectAsync(ClientOptions(outer), Ct);
        await using (first)
        {
            await using SshClient second = await SshClient.ConnectAsync(ClientOptions(middle, jumpHost: first), Ct);
            await using SshClient third = await SshClient.ConnectAsync(ClientOptions(inner, jumpHost: second, fingerprint: innerKey.Sha256Fingerprint), Ct);
            Assert.Equal(11, (await third.ExecuteAsync("x", Ct)).ExitCode);

            await first.DisposeAsync();
            await Assert.ThrowsAnyAsync<SshException>(() => third.ExecuteAsync("x", Ct).WaitAsync(Limit, Ct));
        }
    }

    [Fact]
    public async Task A_refused_jump_is_an_exception_and_leaves_the_jump_host_alive()
    {
        await using SshServer inner = await StartOpenServerAsync(this);
        await using SshServer outer = await StartServerAsync(static (_, _) => ValueTask.FromResult(SshForwardDecision.Deny));
        await using SshClient jump = await SshClient.ConnectAsync(ClientOptions(outer), Ct);

        await Assert.ThrowsAsync<SshException>(() => SshClient.ConnectAsync(ClientOptions(inner, jumpHost: jump), Ct));
        Assert.Equal(5, (await jump.ExecuteAsync("x", Ct)).ExitCode);
    }

    [Fact]
    public async Task Many_connections_in_a_row_leave_nothing_behind()
    {
        await using TcpService echo = TcpService.Echo();
        await using SshServer server = await StartOpenServerAsync(this, maxSessions: 8);
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server), Ct);
        await using SshLocalForward forward = await client.ForwardLocalPortAsync("127.0.0.1", echo.Port, Ct);

        // Far past the 256 channels a connection allows, and the server's 8, so a leak of either fails here.
        for (int round = 0; round < 75; round++)
        {
            TcpClient[] connections = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => ConnectAsync(forward)));
            await Task.WhenAll(connections.Select(c => AssertEchoesAsync(c.GetStream(), 100)));
            foreach (TcpClient connection in connections)
            {
                connection.Dispose();
            }

            await WaitUntilAsync(() => forward.ActiveConnections == 0);
        }
    }

    private static Task<SshServer> StartInnerServerAsync(SshHostKey key) => SshServer.StartAsync(
        new SshServerOptions
        {
            HostKeys = [key],
            PasswordHandler = static (_, _) => ValueTask.FromResult(SshAuthDecision.Accept),
            SessionHandler = static async (session, ct) =>
            {
                await session.Output.WriteAsync("inner"u8.ToArray(), ct);
                return 11;
            },
        },
        Ct);
}

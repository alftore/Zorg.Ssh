using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Zorg.Ssh.Tests.Server;

/// <summary>R10: one address can't take every unauthenticated slot.</summary>
public sealed class PerAddressLimitTests : IDisposable
{
    private readonly SshHostKey _hostKey = SshHostKey.GenerateEd25519();
    private readonly List<TcpClient> _sockets = [];

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose()
    {
        foreach (TcpClient socket in _sockets)
        {
            socket.Dispose();
        }

        _hostKey.Dispose();
    }

    // The unit tests below cover the counting. These cover the wiring.

    [Fact]
    public void An_ipv4_mapped_ipv6_address_counts_as_its_ipv4_address()
    {
        Assert.Equal(IPAddress.Parse("192.0.2.7"), PerAddressLimiter.KeyFor(IPAddress.Parse("::ffff:192.0.2.7")));
    }

    [Fact]
    public void Ipv6_addresses_in_one_64_share_a_key_and_other_64s_do_not()
    {
        IPAddress a = PerAddressLimiter.KeyFor(IPAddress.Parse("2001:db8:1:2:aaaa:bbbb:cccc:dddd"));
        IPAddress b = PerAddressLimiter.KeyFor(IPAddress.Parse("2001:db8:1:2::1"));
        IPAddress c = PerAddressLimiter.KeyFor(IPAddress.Parse("2001:db8:1:3::1"));

        Assert.Equal(a, b);
        Assert.NotEqual(a, c);
    }

    [Fact]
    public void The_limiter_refuses_at_the_limit_per_key_and_frees_on_release()
    {
        PerAddressLimiter limiter = new(2);
        IPAddress one = IPAddress.Parse("192.0.2.1");
        IPAddress two = IPAddress.Parse("192.0.2.2");

        Assert.True(limiter.TryAcquire(one));
        Assert.True(limiter.TryAcquire(IPAddress.Parse("::ffff:192.0.2.1")));
        Assert.False(limiter.TryAcquire(one));
        Assert.True(limiter.TryAcquire(two));
        Assert.Equal(2, limiter.Entries);

        limiter.Release(one);
        Assert.True(limiter.TryAcquire(one));
    }

    [Fact]
    public void An_entry_is_removed_at_zero_so_the_table_cannot_grow()
    {
        PerAddressLimiter limiter = new(3);
        for (byte i = 1; i <= 50; i++)
        {
            IPAddress address = new([192, 0, 2, i]);
            Assert.True(limiter.TryAcquire(address));
            limiter.Release(address);
        }

        Assert.Equal(0, limiter.Entries);
        limiter.Release(IPAddress.Parse("192.0.2.200"));
        Assert.Equal(0, limiter.Entries);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public async Task A_per_address_limit_below_one_is_refused_at_start(int limit)
    {
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => SshServer.StartAsync(Options(perAddress: limit), Ct));
    }

    [Fact]
    public async Task One_address_at_its_limit_cannot_lock_out_another()
    {
        // 127.0.0.2 is loopback on Windows and on Linux (the whole of 127.0.0.0/8 is), so no seam is needed.
        await using SshServer server = await SshServer.StartAsync(Options(perAddress: 3), Ct);
        int port = server.LocalEndPoint.Port;
        IPAddress hostile = IPAddress.Parse("127.0.0.2");
        for (int i = 0; i < 3; i++)
        {
            await ConnectFromAsync(hostile, port);
        }

        // The hostile address is now refused: its next socket is closed with nothing sent.
        TcpClient extra = await ConnectFromAsync(hostile, port);
        await AssertClosedWithoutDataAsync(extra);

        // A different address still logs in, although 3 of 20 global slots are taken.
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(port), Ct);
        Assert.Equal(0, (await client.ExecuteAsync("x", Ct)).ExitCode);
    }

    [Fact]
    public async Task Closing_a_connection_frees_its_per_address_count()
    {
        await using SshServer server = await SshServer.StartAsync(Options(perAddress: 1), Ct);
        int port = server.LocalEndPoint.Port;
        TcpClient first = await ConnectFromAsync(IPAddress.Parse("127.0.0.2"), port);
        TcpClient refused = await ConnectFromAsync(IPAddress.Parse("127.0.0.2"), port);
        await AssertClosedWithoutDataAsync(refused);

        first.Dispose();
        await WaitForAsync(() => server.UnauthenticatedAddressCount == 0);

        TcpClient again = await ConnectFromAsync(IPAddress.Parse("127.0.0.2"), port);
        Assert.True(again.Connected);
        await WaitForAsync(() => server.UnauthenticatedAddressCount == 1);
    }

    [Fact]
    public async Task Every_way_a_connection_can_end_returns_the_table_to_empty()
    {
        SshServer server = await SshServer.StartAsync(Options(grace: TimeSpan.FromMilliseconds(400)), Ct);
        int port = server.LocalEndPoint.Port;

        // Auth success, then a clean close.
        await using (SshClient ok = await SshClient.ConnectAsync(ClientOptions(port), Ct))
        {
            Assert.Equal(0, (await ok.ExecuteAsync("x", Ct)).ExitCode);
        }

        // Auth failure.
        await Assert.ThrowsAsync<SshAuthenticationException>(() => SshClient.ConnectAsync(ClientOptions(port, "bad"), Ct));

        // Dropped by the client mid-handshake, and expired at the grace time.
        for (int i = 0; i < 4; i++)
        {
            (await ConnectFromAsync(IPAddress.Parse("127.0.0.2"), port)).Dispose();
        }

        await ConnectFromAsync(IPAddress.Parse("127.0.0.3"), port);
        await WaitForAsync(() => server.UnauthenticatedAddressCount == 0);

        // Still unauthenticated when the server stops.
        SshServer stopping = await SshServer.StartAsync(Options(), Ct);
        for (int i = 0; i < 3; i++)
        {
            await ConnectFromAsync(IPAddress.Parse("127.0.0.2"), stopping.LocalEndPoint.Port);
        }

        await WaitForAsync(() => stopping.UnauthenticatedAddressCount == 1);
        await stopping.DisposeAsync();
        Assert.Equal(0, stopping.UnauthenticatedAddressCount);

        await server.DisposeAsync();
        Assert.Equal(0, server.UnauthenticatedAddressCount);
    }

    [Fact]
    public async Task A_stream_served_by_hand_is_not_counted_per_address()
    {
        await using SshServer server = await SshServer.StartAsync(Options(perAddress: 1), Ct);
        using TcpListener pair = new(IPAddress.Loopback, 0);
        pair.Start();
        List<Task> served = [];
        for (int i = 0; i < 3; i++)
        {
            TcpClient peer = await ConnectFromAsync(IPAddress.Loopback, ((IPEndPoint)pair.LocalEndpoint).Port);
            TcpClient accepted = await pair.AcceptTcpClientAsync(Ct);
            _sockets.Add(accepted);
            served.Add(server.ServeStreamAsync(accepted.GetStream(), Ct));
            Assert.NotNull(peer);
        }

        await Task.Delay(300, Ct);

        // Three streams with a limit of 1 per address, and none refused.
        Assert.All(served, t => Assert.False(t.IsCompleted));
        Assert.Equal(0, server.UnauthenticatedAddressCount);
    }

    private SshServerOptions Options(int perAddress = 5, TimeSpan? grace = null) => new()
    {
        HostKeys = [_hostKey],
        Address = IPAddress.Loopback,
        PasswordHandler = (r, _) => ValueTask.FromResult(r.Password == "pw" ? SshAuthDecision.Accept : SshAuthDecision.Reject),
        SessionHandler = (_, _) => Task.FromResult(0),
        MaxUnauthenticatedPerAddress = perAddress,
        LoginGraceTime = grace ?? TimeSpan.FromSeconds(30),
    };

    private SshClientOptions ClientOptions(int port, string password = "pw") => new()
    {
        Host = "127.0.0.1",
        Port = port,
        UserName = "alice",
        Credentials = [SshCredential.FromPassword(password)],
        HostKeyPolicy = HostKeyPolicy.Fingerprint(_hostKey.Sha256Fingerprint),
    };

    private async Task<TcpClient> ConnectFromAsync(IPAddress source, int port)
    {
        TcpClient socket = new(new IPEndPoint(source, 0));
        _sockets.Add(socket);

        // The source is any 127.0.0.x, which is loopback on Windows and Linux. The server listens on 127.0.0.1 only.
        await socket.ConnectAsync(IPAddress.Loopback, port, Ct);
        return socket;
    }

    private static async Task AssertClosedWithoutDataAsync(TcpClient socket)
    {
        using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        limit.CancelAfter(TimeSpan.FromSeconds(10));
        byte[] buffer = new byte[16];
        int read;
        try
        {
            read = await socket.GetStream().ReadAsync(buffer, limit.Token);
        }
        catch (System.IO.IOException)
        {
            read = 0;
        }

        Assert.Equal(0, read);
    }

    private static async Task WaitForAsync(Func<bool> condition)
    {
        using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        limit.CancelAfter(TimeSpan.FromSeconds(15));
        while (!condition())
        {
            await Task.Delay(20, limit.Token);
        }
    }
}

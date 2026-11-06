using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Zorg.Ssh.Tests.Forwarding;

/// <summary>The SOCKS5 listener. Anyone local can connect to it, so most of these are clients that misbehave.</summary>
public sealed class SocksTests : IAsyncLifetime
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(20);

    private readonly SshHostKey _hostKey = SshHostKey.GenerateEd25519();
    private readonly TcpService _echo = TcpService.Echo();
    private int _handlerCalls;
    private SshServer _server = null!;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public async ValueTask InitializeAsync() => _server = await SshServer.StartAsync(
        new SshServerOptions
        {
            HostKeys = [_hostKey],
            PasswordHandler = static (_, _) => ValueTask.FromResult(SshAuthDecision.Accept),
            SessionHandler = static (_, _) => Task.FromResult(0),
            DirectTcpHandler = (request, _) =>
            {
                Interlocked.Increment(ref _handlerCalls);
                return ValueTask.FromResult(request.Port == _echo.Port ? SshForwardDecision.Allow : SshForwardDecision.Deny);
            },
        },
        Ct);

    public async ValueTask DisposeAsync()
    {
        await _server.DisposeAsync();
        await _echo.DisposeAsync();
        _hostKey.Dispose();
    }

    private Task<SshClient> ConnectAsync(int maxForwarded = 64, TimeSpan? handshake = null) => SshClient.ConnectAsync(
        new SshClientOptions
        {
            Host = "127.0.0.1",
            Port = _server.LocalEndPoint.Port,
            UserName = "alice",
            Credentials = [SshCredential.FromPassword("pw")],
            HostKeyPolicy = HostKeyPolicy.Fingerprint(_hostKey.Sha256Fingerprint),
            MaxForwardedConnections = maxForwarded,
            SocksHandshakeTimeout = handshake ?? TimeSpan.FromSeconds(10),
        },
        Ct);

    private static async Task<TcpClient> RawAsync(SshForward proxy, params byte[] bytes)
    {
        TcpClient client = new();
        await client.ConnectAsync(proxy.LocalEndPoint, Ct);
        await client.GetStream().WriteAsync(bytes, Ct);
        return client;
    }

    private static async Task AssertClosedAsync(TcpClient client)
    {
        try
        {
            byte[] buffer = new byte[16];
            Assert.Equal(0, await client.GetStream().ReadAsync(buffer, Ct).AsTask().WaitAsync(Limit, Ct));
        }
        catch (IOException)
        {
            // A reset is a close too.
        }
    }

    private static async Task AssertEchoesAsync(TcpClient client)
    {
        NetworkStream stream = client.GetStream();
        await stream.WriteAsync("through the proxy"u8.ToArray(), Ct);
        byte[] echoed = new byte[17];
        await stream.ReadExactlyAsync(echoed, Ct).AsTask().WaitAsync(Limit, Ct);
        Assert.Equal("through the proxy"u8.ToArray(), echoed);
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

    [Fact]
    public async Task A_proxy_binds_loopback_and_connects_by_name_and_by_address()
    {
        await using SshClient client = await ConnectAsync();
        await using SshForward proxy = await client.ForwardDynamicPortAsync(null, Ct);
        Assert.True(IPAddress.IsLoopback(proxy.LocalEndPoint.Address));

        using TcpClient byAddress = await Socks.GreetAsync(proxy.LocalEndPoint, Ct);
        Assert.Equal(0, await Socks.RequestAsync(byAddress, Socks.IPv4Request(IPAddress.Loopback, _echo.Port), Ct));
        await AssertEchoesAsync(byAddress);

        using TcpClient byName = await Socks.GreetAsync(proxy.LocalEndPoint, Ct);
        Assert.Equal(0, await Socks.RequestAsync(byName, Socks.DomainRequest("localhost", _echo.Port), Ct));
        await AssertEchoesAsync(byName);
    }

    [Fact]
    public async Task A_target_the_server_refuses_gets_a_reply_saying_so()
    {
        await using SshClient client = await ConnectAsync();
        await using SshForward proxy = await client.ForwardDynamicPortAsync(null, Ct);

        using TcpClient connection = await Socks.GreetAsync(proxy.LocalEndPoint, Ct);
        Assert.Equal(5, await Socks.RequestAsync(connection, Socks.IPv4Request(IPAddress.Loopback, 9), Ct));
        await AssertClosedAsync(connection);
    }

    [Fact]
    public async Task Only_CONNECT_is_supported()
    {
        await using SshClient client = await ConnectAsync();
        await using SshForward proxy = await client.ForwardDynamicPortAsync(null, Ct);

        using TcpClient bind = await Socks.GreetAsync(proxy.LocalEndPoint, Ct);
        Assert.Equal(7, await Socks.RequestAsync(bind, Socks.DomainRequest("localhost", _echo.Port, command: 2), Ct));
        await AssertClosedAsync(bind);
        Assert.Equal(0, Volatile.Read(ref _handlerCalls));
    }

    [Fact]
    public async Task An_unknown_address_type_is_refused()
    {
        await using SshClient client = await ConnectAsync();
        await using SshForward proxy = await client.ForwardDynamicPortAsync(null, Ct);

        using TcpClient connection = await Socks.GreetAsync(proxy.LocalEndPoint, Ct);
        Assert.Equal(8, await Socks.RequestAsync(connection, [5, 1, 0, 9], Ct));
        await AssertClosedAsync(connection);
    }

    [Fact]
    public async Task SOCKS4_is_dropped_without_a_word()
    {
        await using SshClient client = await ConnectAsync();
        await using SshForward proxy = await client.ForwardDynamicPortAsync(null, Ct);

        using TcpClient connection = await RawAsync(proxy, 4, 1, 0, 80, 127, 0, 0, 1, 0);
        await AssertClosedAsync(connection);
        Assert.Equal(0, Volatile.Read(ref _handlerCalls));
    }

    [Fact]
    public async Task A_client_that_offers_only_passwords_is_turned_away()
    {
        await using SshClient client = await ConnectAsync();
        await using SshForward proxy = await client.ForwardDynamicPortAsync(null, Ct);

        using TcpClient connection = await RawAsync(proxy, 5, 1, 2);
        byte[] answer = new byte[2];
        await connection.GetStream().ReadExactlyAsync(answer, Ct).AsTask().WaitAsync(Limit, Ct);
        Assert.Equal(new byte[] { 5, 0xFF }, answer);
        await AssertClosedAsync(connection);
    }

    [Fact]
    public async Task A_greeting_with_no_methods_is_turned_away()
    {
        await using SshClient client = await ConnectAsync();
        await using SshForward proxy = await client.ForwardDynamicPortAsync(null, Ct);

        using TcpClient connection = await RawAsync(proxy, 5, 0);
        byte[] answer = new byte[2];
        await connection.GetStream().ReadExactlyAsync(answer, Ct).AsTask().WaitAsync(Limit, Ct);
        Assert.Equal(new byte[] { 5, 0xFF }, answer);
    }

    [Fact]
    public async Task The_largest_greeting_the_format_allows_is_handled()
    {
        await using SshClient client = await ConnectAsync();
        await using SshForward proxy = await client.ForwardDynamicPortAsync(null, Ct);

        byte[] greeting = new byte[257];
        greeting[0] = 5;
        greeting[1] = 255;
        greeting.AsSpan(2).Fill(0x80);
        greeting[^1] = 0;
        using TcpClient connection = await RawAsync(proxy, greeting);
        byte[] answer = new byte[2];
        await connection.GetStream().ReadExactlyAsync(answer, Ct).AsTask().WaitAsync(Limit, Ct);
        Assert.Equal(new byte[] { 5, 0 }, answer);
    }

    // 255 fits the length byte, but no host name is that long, so the server never hears of it.
    [Theory]
    [InlineData(254)]
    [InlineData(255)]
    public async Task An_oversized_host_name_is_refused_before_it_reaches_the_server(int length)
    {
        await using SshClient client = await ConnectAsync();
        await using SshForward proxy = await client.ForwardDynamicPortAsync(null, Ct);

        using TcpClient connection = await Socks.GreetAsync(proxy.LocalEndPoint, Ct);
        Assert.Equal(1, await Socks.RequestAsync(connection, Socks.DomainRequest(new string('a', length), _echo.Port), Ct));
        await AssertClosedAsync(connection);
        Assert.Equal(0, Volatile.Read(ref _handlerCalls));
        Assert.Equal(0, _echo.Accepted);
    }

    [Theory]
    [InlineData("")]
    [InlineData("a\0b")]
    [InlineData("a\nb")]
    [InlineData("a b")]
    public async Task A_host_name_that_is_no_name_is_refused(string host)
    {
        await using SshClient client = await ConnectAsync();
        await using SshForward proxy = await client.ForwardDynamicPortAsync(null, Ct);

        using TcpClient connection = await Socks.GreetAsync(proxy.LocalEndPoint, Ct);
        Assert.Equal(1, await Socks.RequestAsync(connection, Socks.DomainRequest(host, _echo.Port), Ct));
        Assert.Equal(0, Volatile.Read(ref _handlerCalls));
    }

    [Fact]
    public async Task Port_zero_is_refused()
    {
        await using SshClient client = await ConnectAsync();
        await using SshForward proxy = await client.ForwardDynamicPortAsync(null, Ct);

        using TcpClient connection = await Socks.GreetAsync(proxy.LocalEndPoint, Ct);
        Assert.Equal(1, await Socks.RequestAsync(connection, Socks.DomainRequest("localhost", 0), Ct));
    }

    // What a client sends after its request is tunnel data, so the handshake must leave it where it is.
    [Fact]
    public async Task Bytes_after_the_request_go_through_the_tunnel()
    {
        await using SshClient client = await ConnectAsync();
        await using SshForward proxy = await client.ForwardDynamicPortAsync(null, Ct);

        using TcpClient connection = await Socks.GreetAsync(proxy.LocalEndPoint, Ct);
        byte[] request = Socks.IPv4Request(IPAddress.Loopback, _echo.Port);
        NetworkStream stream = connection.GetStream();
        await stream.WriteAsync(request.Concat("early"u8.ToArray()).ToArray(), Ct);

        byte[] reply = new byte[15];
        await stream.ReadExactlyAsync(reply, Ct).AsTask().WaitAsync(Limit, Ct);
        Assert.Equal(0, reply[1]);
        Assert.Equal("early"u8.ToArray(), reply[10..]);
    }

    [Theory]
    [InlineData(0)] // Nothing at all.
    [InlineData(1)] // Part of the greeting.
    [InlineData(3)] // A greeting, then no request.
    [InlineData(6)] // Stops in the middle of the request.
    public async Task A_client_that_stalls_is_dropped_and_loses_its_slot(int bytes)
    {
        await using SshClient client = await ConnectAsync(maxForwarded: 1, handshake: TimeSpan.FromMilliseconds(300));
        await using SshForward proxy = await client.ForwardDynamicPortAsync(null, Ct);

        byte[] script = [5, 1, 0, 5, 1, 0];
        using TcpClient stalled = await RawAsync(proxy, script[..bytes]);

        // In this order: the count can read zero before the socket is even accepted, and the slot is freed just after
        // the socket closes. So the drop comes first, and then the count can only be on its way to zero.
        await AssertDroppedAsync(stalled);
        await WaitUntilAsync(() => proxy.ActiveConnections == 0);

        using TcpClient next = await Socks.GreetAsync(proxy.LocalEndPoint, Ct);
        Assert.Equal(0, await Socks.RequestAsync(next, Socks.IPv4Request(IPAddress.Loopback, _echo.Port), Ct));
        await AssertEchoesAsync(next);
    }

    private static async Task AssertDroppedAsync(TcpClient client)
    {
        byte[] buffer = new byte[16];
        try
        {
            // The two greeting bytes may be waiting ahead of the close.
            while (await client.GetStream().ReadAsync(buffer, Ct).AsTask().WaitAsync(Limit, Ct) != 0)
            {
            }
        }
        catch (IOException)
        {
            // A reset is a close too.
        }
    }

    [Fact]
    public async Task Stalled_clients_cannot_take_more_than_the_cap_and_cost_the_rest_nothing()
    {
        await using SshClient client = await ConnectAsync(maxForwarded: 3, handshake: TimeSpan.FromSeconds(30));
        await using SshForward proxy = await client.ForwardDynamicPortAsync(null, Ct);
        await using SshForward other = await client.ForwardLocalPortAsync(null, "127.0.0.1", _echo.Port, Ct);

        using TcpClient first = await RawAsync(proxy);
        using TcpClient second = await RawAsync(proxy);
        using TcpClient third = await RawAsync(proxy);
        await WaitUntilAsync(() => proxy.ActiveConnections == 3);

        using TcpClient fourth = await RawAsync(proxy);
        await AssertClosedAsync(fourth);
        Assert.Equal(3, proxy.ActiveConnections);

        using TcpClient unrelated = new();
        await unrelated.ConnectAsync(other.LocalEndPoint, Ct);
        await AssertEchoesAsync(unrelated);

        // Closing the forward doesn't wait for the handshake timeout.
        await proxy.DisposeAsync().AsTask().WaitAsync(Limit, Ct);
        await AssertClosedAsync(first);
    }
}

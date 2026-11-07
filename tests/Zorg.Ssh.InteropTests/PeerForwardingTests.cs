using System;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Zorg.Ssh.InteropTests;

/// <summary>
/// Forwarding against the two older servers: OpenSSH 7.4 and Dropbear. <see cref="ForwardingTests"/> covers OpenSSH 10.
/// Each server is used the same way. A service runs in the container and local forwards reach it. A remote forward's
/// target runs here, and a client in the container reaches it through the tunnel. SOCKS rides on direct-tcpip, so
/// it works wherever local forwarding does. The refusal tests start each server with forwarding turned off and assert
/// that the library reports it and the connection lives.
/// </summary>
/// <remarks>
/// Debian 9 has no <c>nc</c>, so the 7.4 container runs small Perl programs, and Dropbear's Alpine image uses BusyBox
/// <c>nc</c>. <see cref="PeerShell"/> hides the difference.
/// </remarks>
public class PeerForwardingTests
{
    private const string User = "zorg";
    private const string Password = "zorg-test";
    private const int EchoPort = 7000;
    private const int RemoteBytes = 3_000_000;

    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(60);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public static TheoryData<string> Peers() => new("openssh-7.4", "dropbear");

    private static async Task<SshPeerContainer> StartAsync(string peer, bool forwarding = true)
    {
        PeerTools.RequireContainers();
        string image = await SshPeerContainer.BuildImageAsync($"zorg-ssh-test/{peer}", Path.Combine(PeerTools.PeersPath, peer), Ct);
        string[]? command = forwarding ? null : peer switch
        {
            "openssh-7.4" => ["/usr/sbin/sshd", "-D", "-e", "-o", "AllowTcpForwarding=no"],

            // -j turns off local forwarding and -k remote forwarding.
            "dropbear" => ["/usr/sbin/dropbear", "-R", "-F", "-E", "-p", "22", "-j", "-k"],
            _ => throw new ArgumentOutOfRangeException(nameof(peer)),
        };
        return await SshPeerContainer.StartAsync(image, command, cancellationToken: Ct);
    }

    private static Task<SshClient> ConnectAsync(SshPeerContainer container) =>
        SshClient.ConnectAsync(
            new SshClientOptions
            {
                Host = container.Host,
                Port = container.Port,
                UserName = User,
                Credentials = [SshCredential.FromPassword(Password)],
                HostKeyPolicy = HostKeyPolicy.AcceptAnyUnsafe(),
            },
            Ct);

    /// <summary>Starts the echo service in the container and waits until a direct-tcpip stream reaches it.</summary>
    private static async Task<SshProcess> StartEchoAsync(string peer, SshClient client)
    {
        SshProcess service = await client.StartProcessAsync(PeerShell.EchoServer(peer, EchoPort), null, Ct);
        using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        limit.CancelAfter(Limit);
        while (true)
        {
            try
            {
                await using Stream probe = await client.OpenTcpStreamAsync("127.0.0.1", EchoPort, limit.Token);
                return service;
            }
            catch (SshException) when (!limit.IsCancellationRequested)
            {
                await Task.Delay(50, limit.Token);
            }
        }
    }

    [InteropTheory]
    [MemberData(nameof(Peers))]
    public async Task A_stream_reads_the_servers_own_banner(string peer)
    {
        await using SshPeerContainer container = await StartAsync(peer);
        await using SshClient client = await ConnectAsync(container);

        await using Stream stream = await client.OpenTcpStreamAsync("127.0.0.1", 22, Ct);
        byte[] buffer = new byte[64];
        int read = await stream.ReadAsync(buffer, Ct).AsTask().WaitAsync(Limit, Ct);

        // The banner of the server on the other end of the tunnel is the one the outer connection saw.
        Assert.StartsWith(container.Banner, Encoding.ASCII.GetString(buffer, 0, read), StringComparison.Ordinal);
    }

    [InteropTheory]
    [MemberData(nameof(Peers))]
    public async Task A_stream_carries_data_past_the_window_both_ways(string peer)
    {
        await using SshPeerContainer container = await StartAsync(peer);
        await using SshClient client = await ConnectAsync(container);
        await using SshProcess echo = await StartEchoAsync(peer, client);

        await using Stream stream = await client.OpenTcpStreamAsync("127.0.0.1", EchoPort, Ct);
        await ForwardingTests.AssertEchoesAsync(stream, 8_000_000);
    }

    [InteropTheory]
    [MemberData(nameof(Peers))]
    public async Task A_local_forward_carries_several_connections_at_once(string peer)
    {
        await using SshPeerContainer container = await StartAsync(peer);
        await using SshClient client = await ConnectAsync(container);
        await using SshProcess echo = await StartEchoAsync(peer, client);
        await using SshLocalForward forward = await client.ForwardLocalPortAsync("127.0.0.1", EchoPort, Ct);

        await Task.WhenAll(Enumerable.Range(0, 4).Select(async _ =>
        {
            using TcpClient connection = new();
            await connection.ConnectAsync(forward.LocalEndPoint, Ct);
            await ForwardingTests.AssertEchoesAsync(connection.GetStream(), 3_000_000);
        }));
    }

    [InteropTheory]
    [MemberData(nameof(Peers))]
    public async Task A_rekey_during_a_forwarded_transfer_loses_nothing(string peer)
    {
        await using SshPeerContainer container = await StartAsync(peer);
        await using SshClient client = await ConnectAsync(container);
        await using SshProcess echo = await StartEchoAsync(peer, client);
        await using Stream stream = await client.OpenTcpStreamAsync("127.0.0.1", EchoPort, Ct);

        for (int i = 0; i < 3; i++)
        {
            await ForwardingTests.AssertEchoesAsync(stream, 3_000_000, client.RequestRekey);
        }

        Assert.True(client.CompletedKeyExchanges >= 3, $"{client.CompletedKeyExchanges} key exchanges ran.");
    }

    [InteropTheory]
    [MemberData(nameof(Peers))]
    public async Task A_stream_to_a_closed_port_is_refused_and_the_connection_lives(string peer)
    {
        await using SshPeerContainer container = await StartAsync(peer);
        await using SshClient client = await ConnectAsync(container);

        await Assert.ThrowsAsync<SshException>(() => client.OpenTcpStreamAsync("127.0.0.1", 7999, Ct));
        Assert.Equal(0, (await client.ExecuteAsync("true", Ct)).ExitCode);
    }

    [InteropTheory]
    [MemberData(nameof(Peers))]
    public async Task A_remote_forward_on_a_chosen_port_carries_data_both_ways(string peer)
    {
        using CancellationTokenSource stop = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        (System.Net.Sockets.TcpListener listener, Task serving) = ForwardingTests.StartLocalTarget(stop.Token);
        using (listener)
        {
            await using SshPeerContainer container = await StartAsync(peer);
            await using SshClient client = await ConnectAsync(container);
            await using SshRemoteForward forward = await client.ForwardRemotePortAsync(
                "127.0.0.1", 0, "127.0.0.1", ForwardingTests.LocalPort(listener), Ct);
            Assert.InRange(forward.RemotePort, 1, 65535);

            SshCommandResult result = await client.ExecuteAsync(PeerShell.RoundTrip(peer, forward.RemotePort, RemoteBytes), Ct).WaitAsync(Limit, Ct);
            Assert.Equal("hello\nsame\n", result.StandardOutput.Replace("\r", string.Empty, StringComparison.Ordinal));
            Assert.Equal(0, result.ExitCode);

            await stop.CancelAsync();
            listener.Stop();
            await serving;
        }
    }

    [InteropTheory]
    [MemberData(nameof(Peers))]
    public async Task A_remote_forward_on_a_fixed_port_serves_connections_at_once_and_closes(string peer)
    {
        using CancellationTokenSource stop = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        (System.Net.Sockets.TcpListener listener, Task serving) = ForwardingTests.StartLocalTarget(stop.Token);
        using (listener)
        {
            await using SshPeerContainer container = await StartAsync(peer);
            await using SshClient client = await ConnectAsync(container);
            SshRemoteForward forward = await client.ForwardRemotePortAsync(
                "127.0.0.1", 7100, "127.0.0.1", ForwardingTests.LocalPort(listener), Ct);
            Assert.Equal(7100, forward.RemotePort);

            SshCommandResult[] results = await Task.WhenAll(Enumerable.Range(0, 4).Select(
                _ => client.ExecuteAsync(PeerShell.RoundTrip(peer, 7100, 100_000), Ct)));
            foreach (SshCommandResult result in results)
            {
                Assert.Equal("hello\nsame\n", result.StandardOutput.Replace("\r", string.Empty, StringComparison.Ordinal));
            }

            Assert.Equal("open\n", (await client.ExecuteAsync(PeerShell.Probe(peer, 7100), Ct)).StandardOutput);
            await forward.DisposeAsync().AsTask().WaitAsync(Limit, Ct);

            // cancel-tcpip-forward has released the port on the server.
            Assert.Equal("closed\n", (await client.ExecuteAsync(PeerShell.Probe(peer, 7100), Ct)).StandardOutput);

            await stop.CancelAsync();
            listener.Stop();
            await serving;
        }
    }

    [InteropTheory]
    [MemberData(nameof(Peers))]
    public async Task A_remote_forward_to_a_dead_target_refuses_the_connection_and_stays_up(string peer)
    {
        using System.Net.Sockets.TcpListener unused = new(System.Net.IPAddress.Loopback, 0);
        unused.Start();
        int port = ForwardingTests.LocalPort(unused);
        unused.Stop();

        await using SshPeerContainer container = await StartAsync(peer);
        await using SshClient client = await ConnectAsync(container);
        await using SshRemoteForward forward = await client.ForwardRemotePortAsync("127.0.0.1", 0, "127.0.0.1", port, Ct);

        // The server accepts the connection and then the channel open is refused, so the client just sees it close.
        SshCommandResult result = await client.ExecuteAsync(PeerShell.RoundTrip(peer, forward.RemotePort, 1000) + "; echo done", Ct).WaitAsync(Limit, Ct);
        Assert.Contains("done", result.StandardOutput);
        Assert.DoesNotContain("same", result.StandardOutput);
        Assert.Equal(0, (await client.ExecuteAsync("true", Ct)).ExitCode);
    }

    [InteropTheory]
    [MemberData(nameof(Peers))]
    public async Task A_SOCKS_client_reaches_a_service_by_address_and_by_name(string peer)
    {
        await using SshPeerContainer container = await StartAsync(peer);
        await using SshClient client = await ConnectAsync(container);
        await using SshProcess echo = await StartEchoAsync(peer, client);
        await using SshLocalForward proxy = await client.ForwardDynamicPortAsync(null, Ct);

        foreach (byte[] target in new[] { ForwardingTests.AddressTarget(EchoPort), ForwardingTests.NameTarget("localhost", EchoPort) })
        {
            using TcpClient connection = new();
            await connection.ConnectAsync(proxy.LocalEndPoint, Ct);
            NetworkStream stream = connection.GetStream();
            await stream.WriteAsync(new byte[] { 5, 1, 0 }, Ct);
            byte[] answer = new byte[2];
            await stream.ReadExactlyAsync(answer, Ct);
            Assert.Equal(new byte[] { 5, 0 }, answer);

            await stream.WriteAsync(target, Ct);
            byte[] reply = new byte[10];
            await stream.ReadExactlyAsync(reply, Ct);
            Assert.Equal(0, reply[1]);
            await ForwardingTests.AssertEchoesAsync(stream, 1_000_000);
        }
    }

    [InteropTheory]
    [MemberData(nameof(Peers))]
    public async Task A_SOCKS_request_for_a_closed_port_gets_a_refusal(string peer)
    {
        await using SshPeerContainer container = await StartAsync(peer);
        await using SshClient client = await ConnectAsync(container);
        await using SshLocalForward proxy = await client.ForwardDynamicPortAsync(null, Ct);

        using TcpClient connection = new();
        await connection.ConnectAsync(proxy.LocalEndPoint, Ct);
        NetworkStream stream = connection.GetStream();
        await stream.WriteAsync(new byte[] { 5, 1, 0 }, Ct);
        await stream.ReadExactlyAsync(new byte[2], Ct);
        await stream.WriteAsync(ForwardingTests.AddressTarget(7999), Ct);
        byte[] reply = new byte[10];
        await stream.ReadExactlyAsync(reply, Ct);
        Assert.Equal(5, reply[1]);
    }

    // Both servers can refuse forwarding by configuration. That is the refusal path of the library against a real peer,
    // and for Dropbear it is the only one: the build in Alpine supports every forwarding type.
    [InteropTheory]
    [MemberData(nameof(Peers))]
    public async Task A_server_that_forbids_forwarding_refuses_all_three_kinds_and_the_connection_lives(string peer)
    {
        await using SshPeerContainer container = await StartAsync(peer, forwarding: false);
        await using SshClient client = await ConnectAsync(container);

        await Assert.ThrowsAsync<SshException>(() => client.OpenTcpStreamAsync("127.0.0.1", 22, Ct));
        await Assert.ThrowsAsync<SshException>(() => client.ForwardRemotePortAsync("127.0.0.1", 0, "127.0.0.1", 9, Ct));

        // A SOCKS proxy starts, but each request it carries is refused.
        await using SshLocalForward proxy = await client.ForwardDynamicPortAsync(null, Ct);
        using TcpClient connection = new();
        await connection.ConnectAsync(proxy.LocalEndPoint, Ct);
        NetworkStream stream = connection.GetStream();
        await stream.WriteAsync(new byte[] { 5, 1, 0 }, Ct);
        await stream.ReadExactlyAsync(new byte[2], Ct);
        await stream.WriteAsync(ForwardingTests.AddressTarget(22), Ct);
        byte[] reply = new byte[10];
        await stream.ReadExactlyAsync(reply, Ct);
        Assert.NotEqual(0, reply[1]);

        Assert.Equal(0, (await client.ExecuteAsync("true", Ct)).ExitCode);
    }

    [InteropTheory]
    [MemberData(nameof(Peers))]
    public async Task A_privileged_port_is_refused_and_the_connection_lives(string peer)
    {
        await using SshPeerContainer container = await StartAsync(peer);
        await using SshClient client = await ConnectAsync(container);

        await Assert.ThrowsAsync<SshException>(() => client.ForwardRemotePortAsync("127.0.0.1", 80, "127.0.0.1", 9, Ct));
        Assert.Equal(0, (await client.ExecuteAsync("true", Ct)).ExitCode);
    }

    /// <summary>The services and clients the tests run inside a container. Debian 9 has Perl and no <c>nc</c>. Alpine has BusyBox <c>nc</c>.</summary>
    private static class PeerShell
    {
        private const string Perl = "perl -MIO::Socket::INET -e ";

        public static string EchoServer(string peer, int port) => peer == "dropbear"
            ? $"nc -lk -p {port} -e /bin/cat"
            : Perl + "'$SIG{CHLD}=\"IGNORE\"; $s=IO::Socket::INET->new(Listen=>16,LocalAddr=>\"127.0.0.1\",LocalPort=>"
              + port + ",ReuseAddr=>1) or die; while($c=$s->accept){ unless(fork){ while(sysread($c,$b,65536)){syswrite($c,$b)} exit } close $c }'";

        /// <summary>Sends random bytes to a port, half-closes, reads the answer. Prints the first line, then "same" if the rest is what was sent.</summary>
        public static string RoundTrip(string peer, int port, int bytes) => peer == "dropbear"
            ? $"head -c {bytes} /dev/urandom > /tmp/sent.$$; nc 127.0.0.1 {port} < /tmp/sent.$$ > /tmp/got.$$; "
              + $"head -n 1 /tmp/got.$$; tail -c {bytes} /tmp/got.$$ | cmp - /tmp/sent.$$ && echo same"
            : Perl + "'$n=" + bytes + "; $s=IO::Socket::INET->new(PeerAddr=>\"127.0.0.1:" + port
              + "\") or die \"connect\"; $d=\"\"; $d.=chr(int(rand(256))) for 1..$n; $o=0; "
              + "while($o<$n){$w=syswrite($s,$d,65536,$o); last unless defined $w; $o+=$w} shutdown($s,1); "
              + "$g=\"\"; while(sysread($s,$b,65536)){$g.=$b} ($h,$r)=split(/\\n/,$g,2); print \"$h\\n\"; "
              + "print(($r eq $d)?\"same\\n\":\"different\\n\")'";

        /// <summary>Prints "open" or "closed" for a connection to a port.</summary>
        public static string Probe(string peer, int port) => peer == "dropbear"
            ? $"if nc -z -w 2 127.0.0.1 {port}; then echo open; else echo closed; fi"
            : Perl + "'print(IO::Socket::INET->new(PeerAddr=>\"127.0.0.1:" + port + "\")?\"open\\n\":\"closed\\n\")'";
    }
}

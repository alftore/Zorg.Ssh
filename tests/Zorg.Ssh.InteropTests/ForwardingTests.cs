using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Zorg.Ssh.InteropTests;

/// <summary>
/// Forwarding and jump hosts against real OpenSSH. Everything the container serves runs in the container, and
/// a remote forward's target runs here and is reached through the tunnel, so no container connects out to the
/// host. Services are BusyBox <c>nc</c>, started over SSH.
/// </summary>
public class ForwardingTests
{
    private const string User = "zorg";
    private const string Password = "zorg-test";
    private const int EchoPort = 7000;
    private const int FloodPort = 7001;
    private const int HttpPort = 7002;

    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(60);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>Starts sshd. Alpine's sshd_config has <c>AllowTcpForwarding no</c>, which a command line option overrides.</summary>
    private static async Task<SshPeerContainer> StartAsync(bool forwarding = true)
    {
        PeerTools.RequireContainers();
        string image = await SshPeerContainer.BuildImageAsync("zorg-ssh-test/openssh-10", Path.Combine(PeerTools.PeersPath, "openssh-10"), Ct);
        string[]? command = forwarding ? ["/usr/sbin/sshd", "-D", "-e", "-o", "AllowTcpForwarding=yes"] : null;
        return await SshPeerContainer.StartAsync(image, command, cancellationToken: Ct);
    }

    private static SshClientOptions Options(string host, int port, SshClient? jumpHost = null, HostKeyPolicy? policy = null) => new()
    {
        Host = host,
        Port = port,
        UserName = User,
        Credentials = [SshCredential.FromPassword(Password)],
        HostKeyPolicy = policy ?? HostKeyPolicy.AcceptAnyUnsafe(),
        JumpHost = jumpHost,
    };

    private static Task<SshClient> ConnectAsync(SshPeerContainer container) =>
        SshClient.ConnectAsync(Options(container.Host, container.Port), Ct);

    /// <summary>Starts a service in the container, and waits until it answers. The process lives as long as its channel.</summary>
    private static async Task<SshProcess> StartServiceAsync(SshClient client, string command, int port)
    {
        SshProcess service = await client.StartProcessAsync(command, null, Ct);
        using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        limit.CancelAfter(Limit);
        while (true)
        {
            SshCommandResult probe = await client.ExecuteAsync($"nc -z -w 1 127.0.0.1 {port}", limit.Token);
            if (probe.ExitCode == 0)
            {
                return service;
            }

            await Task.Delay(50, limit.Token);
        }
    }

    private static Task<SshProcess> StartEchoAsync(SshClient client) =>
        StartServiceAsync(client, $"nc -lk -p {EchoPort} -e /bin/cat", EchoPort);

    /// <summary>
    /// Echoes data in turns, a chunk at a time, not flat out. Podman's published port on this host stalls under
    /// full-duplex load with no SSH involved, even for one raw connection. The unit tests cover the flat-out
    /// case over real TCP. <paramref name="inFlight"/> runs with a chunk on its way, halfway through.
    /// </summary>
    internal static async Task AssertEchoesAsync(Stream stream, int size, Action? inFlight = null)
    {
        const int Chunk = 64 * 1024;
        byte[] sent = RandomNumberGenerator.GetBytes(size);
        byte[] received = new byte[size];
        for (int offset = 0; offset < size; offset += Chunk)
        {
            int length = Math.Min(Chunk, size - offset);
            await stream.WriteAsync(sent.AsMemory(offset, length), Ct);
            if (offset <= size / 2 && size / 2 < offset + Chunk)
            {
                inFlight?.Invoke();
            }

            await stream.ReadExactlyAsync(received.AsMemory(offset, length), Ct).AsTask().WaitAsync(Limit, Ct);
        }

        Assert.True(sent.AsSpan().SequenceEqual(received));
    }

    /// <summary>A target for remote forwards, on this side of the tunnel. It says hello, reads to the end, then sends it all back.</summary>
    internal static (TcpListener Listener, Task Serving) StartLocalTarget(CancellationToken stop)
    {
        TcpListener listener = new(IPAddress.Loopback, 0);
        listener.Start();
        Task serving = Task.Run(
            async () =>
            {
                try
                {
                    while (true)
                    {
                        Socket socket = await listener.AcceptSocketAsync(stop);
                        _ = Task.Run(() => EchoAsync(socket, stop), CancellationToken.None);
                    }
                }
                catch (Exception ex) when (ex is OperationCanceledException or SocketException)
                {
                    // Stopped.
                }
            },
            CancellationToken.None);
        return (listener, serving);
    }

    private static async Task EchoAsync(Socket socket, CancellationToken stop)
    {
        using NetworkStream stream = new(socket, ownsSocket: true);
        try
        {
            await stream.WriteAsync("hello\n"u8.ToArray(), stop);

            // Everything first, then the answer, so the two directions never run flat out together. Podman's
            // published port on this host can stall under that, with real ssh -R and with no SSH at all.
            using MemoryStream all = new();
            await stream.CopyToAsync(all, stop);
            await stream.WriteAsync(all.GetBuffer().AsMemory(0, (int)all.Length), stop);
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException)
        {
            // The far side went.
        }
    }

    internal static int LocalPort(TcpListener listener) => ((IPEndPoint)listener.LocalEndpoint).Port;

    [InteropFact]
    public async Task A_stream_reaches_a_service_inside_the_container()
    {
        await using SshPeerContainer container = await StartAsync();
        await using SshClient client = await ConnectAsync(container);
        await using SshProcess echo = await StartEchoAsync(client);

        await using Stream stream = await client.OpenTcpStreamAsync("127.0.0.1", EchoPort, Ct);

        // Well past the window, both ways.
        await AssertEchoesAsync(stream, 8_000_000);
    }

    [InteropFact]
    public async Task A_local_forward_carries_several_connections_at_once()
    {
        await using SshPeerContainer container = await StartAsync();
        await using SshClient client = await ConnectAsync(container);
        await using SshProcess echo = await StartEchoAsync(client);
        await using SshLocalForward forward = await client.ForwardLocalPortAsync("127.0.0.1", EchoPort, Ct);

        await Task.WhenAll(Enumerable.Range(0, 4).Select(async _ =>
        {
            using TcpClient connection = new();
            await connection.ConnectAsync(forward.LocalEndPoint, Ct);
            await AssertEchoesAsync(connection.GetStream(), 3_000_000);
        }));
    }

    [InteropFact]
    public async Task A_rekey_during_a_forwarded_transfer_loses_nothing()
    {
        await using SshPeerContainer container = await StartAsync();
        await using SshClient client = await ConnectAsync(container);
        await using SshProcess echo = await StartEchoAsync(client);
        await using Stream stream = await client.OpenTcpStreamAsync("127.0.0.1", EchoPort, Ct);

        for (int i = 0; i < 4; i++)
        {
            await AssertEchoesAsync(stream, 4_000_000, client.RequestRekey);
        }

        Assert.True(client.CompletedKeyExchanges >= 3, $"{client.CompletedKeyExchanges} key exchanges ran.");
    }

    // OpenSSH ends the whole connection over one stray message for a channel it has closed.
    [InteropFact]
    public async Task Closing_a_forward_mid_transfer_keeps_OpenSSH_happy()
    {
        await using SshPeerContainer container = await StartAsync();
        await using SshClient client = await ConnectAsync(container);
        await using SshProcess flood = await StartServiceAsync(client, $"nc -lk -p {FloodPort} -e /usr/bin/yes", FloodPort);
        await using SshProcess echo = await StartEchoAsync(client);
        await using Stream bystander = await client.OpenTcpStreamAsync("127.0.0.1", EchoPort, Ct);

        for (int round = 0; round < 10; round++)
        {
            SshLocalForward forward = await client.ForwardLocalPortAsync("127.0.0.1", FloodPort, Ct);
            using TcpClient connection = new();
            await connection.ConnectAsync(forward.LocalEndPoint, Ct);
            byte[] buffer = new byte[256 * 1024];
            await connection.GetStream().ReadExactlyAsync(buffer, Ct).AsTask().WaitAsync(Limit, Ct);

            await forward.DisposeAsync().AsTask().WaitAsync(Limit, Ct);
            await AssertEchoesAsync(bystander, 1000);
        }

        Assert.Equal(0, (await client.ExecuteAsync("true", Ct)).ExitCode);
    }

    [InteropFact]
    public async Task A_stream_to_a_closed_port_is_refused_and_the_connection_lives()
    {
        await using SshPeerContainer container = await StartAsync();
        await using SshClient client = await ConnectAsync(container);

        await Assert.ThrowsAsync<SshException>(() => client.OpenTcpStreamAsync("127.0.0.1", 7999, Ct));
        Assert.Equal(0, (await client.ExecuteAsync("true", Ct)).ExitCode);
    }

    [InteropFact]
    public async Task A_server_that_forbids_forwarding_refuses_both_directions()
    {
        await using SshPeerContainer container = await StartAsync(forwarding: false);
        await using SshClient client = await ConnectAsync(container);

        await Assert.ThrowsAsync<SshException>(() => client.OpenTcpStreamAsync("127.0.0.1", 22, Ct));
        await Assert.ThrowsAsync<SshException>(() => client.ForwardRemotePortAsync("127.0.0.1", 0, "127.0.0.1", 9, Ct));
        Assert.Equal(0, (await client.ExecuteAsync("true", Ct)).ExitCode);
    }

    [InteropFact]
    public async Task A_remote_forward_on_a_chosen_port_carries_data_both_ways()
    {
        using CancellationTokenSource stop = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        (TcpListener listener, Task serving) = StartLocalTarget(stop.Token);
        using (listener)
        {
            await using SshPeerContainer container = await StartAsync();
            await using SshClient client = await ConnectAsync(container);
            await using SshRemoteForward forward = await client.ForwardRemotePortAsync("127.0.0.1", 0, "127.0.0.1", LocalPort(listener), Ct);
            Assert.InRange(forward.RemotePort, 1, 65535);

            // In the container, this is a client like any other. What it sends comes back through the tunnel,
            // after the hello that the target sends first.
            SshCommandResult result = await client.ExecuteAsync(
                $"head -c 3000000 /dev/urandom > /tmp/sent; nc 127.0.0.1 {forward.RemotePort} < /tmp/sent > /tmp/got; "
                + "head -n 1 /tmp/got; tail -c 3000000 /tmp/got | cmp - /tmp/sent && echo same",
                Ct).WaitAsync(Limit, Ct);
            Assert.Equal("hello\nsame\n", result.StandardOutput.Replace("\r", string.Empty, StringComparison.Ordinal));
            Assert.Equal(0, result.ExitCode);

            await stop.CancelAsync();
            listener.Stop();
            await serving;
        }
    }

    [InteropFact]
    public async Task A_remote_forward_on_a_fixed_port_serves_connections_at_once_and_closes()
    {
        using CancellationTokenSource stop = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        (TcpListener listener, Task serving) = StartLocalTarget(stop.Token);
        using (listener)
        {
            await using SshPeerContainer container = await StartAsync();
            await using SshClient client = await ConnectAsync(container);
            SshRemoteForward forward = await client.ForwardRemotePortAsync("127.0.0.1", 7100, "127.0.0.1", LocalPort(listener), Ct);
            Assert.Equal(7100, forward.RemotePort);

            SshCommandResult[] results = await Task.WhenAll(Enumerable.Range(0, 4).Select(
                i => client.ExecuteAsync($"echo ping{i} | nc 127.0.0.1 7100", Ct)));
            for (int i = 0; i < 4; i++)
            {
                Assert.Equal($"hello\nping{i}\n", results[i].StandardOutput);
            }

            Assert.Equal(0, (await client.ExecuteAsync("nc -z -w 2 127.0.0.1 7100", Ct)).ExitCode);
            await forward.DisposeAsync().AsTask().WaitAsync(Limit, Ct);

            // cancel-tcpip-forward has released the port on the server.
            Assert.NotEqual(0, (await client.ExecuteAsync("nc -z -w 2 127.0.0.1 7100", Ct)).ExitCode);

            await stop.CancelAsync();
            listener.Stop();
            await serving;
        }
    }

    [InteropFact]
    public async Task A_remote_forward_to_a_dead_target_refuses_the_connection_and_stays_up()
    {
        using TcpListener unused = new(IPAddress.Loopback, 0);
        unused.Start();
        int port = LocalPort(unused);
        unused.Stop();

        await using SshPeerContainer container = await StartAsync();
        await using SshClient client = await ConnectAsync(container);
        await using SshRemoteForward forward = await client.ForwardRemotePortAsync("127.0.0.1", 0, "127.0.0.1", port, Ct);

        SshCommandResult result = await client.ExecuteAsync($"nc -w 3 127.0.0.1 {forward.RemotePort} < /dev/null; echo done", Ct);
        Assert.Contains("done", result.StandardOutput);
        Assert.Equal(0, (await client.ExecuteAsync("true", Ct)).ExitCode);
    }

    [InteropFact]
    public async Task A_privileged_port_is_refused_and_the_connection_lives()
    {
        await using SshPeerContainer container = await StartAsync();
        await using SshClient client = await ConnectAsync(container);

        await Assert.ThrowsAsync<SshException>(() => client.ForwardRemotePortAsync("127.0.0.1", 80, "127.0.0.1", 9, Ct));
        Assert.Equal(0, (await client.ExecuteAsync("true", Ct)).ExitCode);
    }

    [InteropFact]
    public async Task A_SOCKS_client_reaches_services_by_address_and_by_name()
    {
        await using SshPeerContainer container = await StartAsync();
        await using SshClient client = await ConnectAsync(container);
        await using SshProcess echo = await StartEchoAsync(client);
        await using SshLocalForward proxy = await client.ForwardDynamicPortAsync(null, Ct);

        foreach (byte[] target in new[] { AddressTarget(EchoPort), NameTarget("localhost", EchoPort) })
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
            await AssertEchoesAsync(stream, 1_000_000);
        }
    }

    [InteropFact]
    public async Task A_SOCKS_request_for_a_closed_port_gets_a_refusal()
    {
        await using SshPeerContainer container = await StartAsync();
        await using SshClient client = await ConnectAsync(container);
        await using SshLocalForward proxy = await client.ForwardDynamicPortAsync(null, Ct);

        using TcpClient connection = new();
        await connection.ConnectAsync(proxy.LocalEndPoint, Ct);
        NetworkStream stream = connection.GetStream();
        await stream.WriteAsync(new byte[] { 5, 1, 0 }, Ct);
        await stream.ReadExactlyAsync(new byte[2], Ct);
        await stream.WriteAsync(AddressTarget(7999), Ct);
        byte[] reply = new byte[10];
        await stream.ReadExactlyAsync(reply, Ct);
        Assert.Equal(5, reply[1]);
    }

    // An independent SOCKS5 client: .NET's own, in HttpClient.
    [InteropFact]
    public async Task HttpClient_works_through_the_proxy()
    {
        await using SshPeerContainer container = await StartAsync();
        await using SshClient client = await ConnectAsync(container);
        await client.ExecuteAsync(
            "printf '#!/bin/sh\\nprintf \"HTTP/1.0 200 OK\\\\r\\\\nContent-Length: 5\\\\r\\\\n\\\\r\\\\nhello\"\\n' > /tmp/http.sh; chmod +x /tmp/http.sh",
            Ct);
        await using SshProcess http = await StartServiceAsync(client, $"nc -lk -p {HttpPort} -e /tmp/http.sh", HttpPort);
        await using SshLocalForward proxy = await client.ForwardDynamicPortAsync(null, Ct);

        using SocketsHttpHandler handler = new() { Proxy = new WebProxy($"socks5://{proxy.LocalEndPoint}"), UseProxy = true };
        using HttpClient browser = new(handler);
        Assert.Equal("hello", await browser.GetStringAsync(new Uri($"http://127.0.0.1:{HttpPort}/"), Ct));
    }

    [InteropFact]
    public async Task A_jump_through_one_container_reaches_a_second_one()
    {
        await using SshPeerContainer outer = await StartAsync();
        await using SshPeerContainer inner = await StartAsync(forwarding: false);
        string address = await ContainerAddressAsync(inner);

        await using SshClient jump = await ConnectAsync(outer);
        await using SshClient client = await SshClient.ConnectAsync(Options(address, 22, jump), Ct);

        Assert.Equal(inner.Id[..12], (await client.ExecuteAsync("hostname", Ct)).StandardOutput.Trim());
        Assert.NotEqual(inner.Id[..12], (await jump.ExecuteAsync("hostname", Ct)).StandardOutput.Trim());

        // Nested windows, a nested key exchange, and SFTP on the far side.
        SshCommandResult large = await client.ExecuteAsync("head -c 10000000 /dev/zero | tr '\\0' 'x'", Ct);
        Assert.Equal(10_000_000, large.StandardOutput.Length);
        client.RequestRekey();
        await using Sftp.SftpClient sftp = await client.OpenSftpAsync(Ct);
        Assert.True((await sftp.ReadAllBytesAsync("/etc/passwd", Ct)).Length > 0);
    }

    // The inner connection's packets travel as channel data inside the outer one. A rekey of either must neither
    // lose nor reorder a byte of the other, and the two can be in their key exchanges at the same time.
    [InteropFact]
    public async Task Rekeys_of_the_outer_and_inner_connections_during_a_transfer_through_a_jump_lose_nothing()
    {
        await using SshPeerContainer outer = await StartAsync();
        await using SshPeerContainer inner = await StartAsync();
        string address = await ContainerAddressAsync(inner);

        await using SshClient jump = await ConnectAsync(outer);
        await using SshClient client = await SshClient.ConnectAsync(Options(address, 22, jump), Ct);
        await using SshProcess echo = await StartEchoAsync(client);
        await using Stream stream = await client.OpenTcpStreamAsync("127.0.0.1", EchoPort, Ct);
        int outerBefore = jump.CompletedKeyExchanges;
        int innerBefore = client.CompletedKeyExchanges;

        // One at a time, in the middle of a chunk: the outer one, the inner one, then both together.
        await AssertEchoesAsync(stream, 3_000_000, jump.RequestRekey);
        await AssertEchoesAsync(stream, 3_000_000, client.RequestRekey);
        await AssertEchoesAsync(stream, 3_000_000, () =>
        {
            jump.RequestRekey();
            client.RequestRekey();
        });

        // Then a steady stream of requests from a second thread for as long as the transfer lasts.
        using CancellationTokenSource done = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        Task rekeying = Task.Run(
            async () =>
            {
                try
                {
                    while (true)
                    {
                        jump.RequestRekey();
                        await Task.Delay(40, done.Token);
                        client.RequestRekey();
                        await Task.Delay(40, done.Token);
                    }
                }
                catch (OperationCanceledException)
                {
                    // The transfer ended.
                }
            },
            CancellationToken.None);
        await AssertEchoesAsync(stream, 12_000_000);
        await done.CancelAsync();
        await rekeying;

        int outerRuns = jump.CompletedKeyExchanges - outerBefore;
        int innerRuns = client.CompletedKeyExchanges - innerBefore;
        Assert.True(outerRuns >= 4, $"The outer connection ran {outerRuns} key exchanges.");
        Assert.True(innerRuns >= 4, $"The inner connection ran {innerRuns} key exchanges.");

        // Both connections still work after all of it.
        Assert.Equal(inner.Id[..12], (await client.ExecuteAsync("hostname", Ct)).StandardOutput.Trim());
        Assert.Equal(outer.Id[..12], (await jump.ExecuteAsync("hostname", Ct)).StandardOutput.Trim());
    }

    [InteropFact]
    public async Task A_jump_to_the_same_container_by_loopback_works()
    {
        await using SshPeerContainer container = await StartAsync();
        await using SshClient jump = await ConnectAsync(container);
        await using SshClient client = await SshClient.ConnectAsync(Options("127.0.0.1", 22, jump), Ct);
        Assert.Equal("hi\n", (await client.ExecuteAsync("echo hi", Ct)).StandardOutput);
    }

    [InteropFact]
    public async Task The_second_hop_is_checked_against_its_own_policy()
    {
        await using SshPeerContainer outer = await StartAsync();
        await using SshPeerContainer inner = await StartAsync(forwarding: false);
        string address = await ContainerAddressAsync(inner);
        await using SshClient jump = await ConnectAsync(outer);

        await Assert.ThrowsAsync<SshHostKeyException>(
            () => SshClient.ConnectAsync(Options(address, 22, jump, HostKeyPolicy.Fingerprint("SHA256:not-the-right-key")), Ct));

        string log = await inner.GetLogsAsync(Ct);
        Assert.DoesNotContain("Failed password", log);
        Assert.DoesNotContain("Accepted password", log);
        Assert.Equal(0, (await jump.ExecuteAsync("true", Ct)).ExitCode);
    }

    internal static byte[] AddressTarget(int port) =>
        [5, 1, 0, 1, 127, 0, 0, 1, (byte)(port >> 8), (byte)port];

    internal static byte[] NameTarget(string name, int port)
    {
        byte[] bytes = System.Text.Encoding.ASCII.GetBytes(name);
        return [5, 1, 0, 3, (byte)bytes.Length, .. bytes, (byte)(port >> 8), (byte)port];
    }

    private static async Task<string> ContainerAddressAsync(SshPeerContainer container)
    {
        // Per network: Docker 29 dropped the top-level NetworkSettings.IPAddress, which Podman still fills. Both fill this.
        string addresses = await ContainerCli.RunAsync(
            TimeSpan.FromSeconds(30), Ct, "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", container.Id);
        string? address = addresses.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault();
        Assert.True(address is not null, "The container has no address on its network.");
        return address;
    }
}

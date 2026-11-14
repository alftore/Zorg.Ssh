using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Sftp;
using Zorg.Ssh.Tests.Sftp;
using Zorg.Ssh.Tests.Forwarding;

namespace Zorg.Ssh.Tests.Leaks;

/// <summary>
/// Nothing may keep a connection alive after it is disposed or has failed: no event handler, timer, static cache, token registration,
/// queued work item or socket callback. Each test builds its objects in a method of their own that hands back only weak references,
/// then forces collections and fails with the names of whatever survives. A disposed object that stays reachable is a leak
/// for a long-running program that makes connections one after another.
/// </summary>
// Serial: forced collections are process-wide, and the tests that run beside these start and stop connections of their own.
[Collection(SftpSerialTests.Name)]
public sealed class CollectabilityTests
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(30);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task A_client_that_ran_a_command_is_collected_after_it_is_disposed()
    {
        Tracked tracked = new();
        await RunCommandAsync(tracked, Ct);
        await tracked.AssertAllCollectedAsync(Ct);
    }

    [Fact]
    public async Task A_client_and_its_sftp_session_are_collected_after_a_transfer_and_a_listing()
    {
        Tracked tracked = new();
        await SftpAsync(tracked, Ct);
        await tracked.AssertAllCollectedAsync(Ct);
    }

    [Fact]
    public async Task A_client_and_its_process_streams_are_collected_after_the_process_ran()
    {
        Tracked tracked = new();
        await ProcessAsync(tracked, Ct);
        await tracked.AssertAllCollectedAsync(Ct);
    }

    [Fact]
    public async Task A_client_and_its_local_forward_are_collected_after_a_connection_went_through_it()
    {
        Tracked tracked = new();
        await LocalForwardAsync(tracked, Ct);
        await tracked.AssertAllCollectedAsync(Ct);
    }

    [Fact]
    public async Task A_client_and_its_remote_forward_are_collected_after_a_forwarded_connection()
    {
        Tracked tracked = new();
        await RemoteForwardAsync(tracked, Ct);
        await tracked.AssertAllCollectedAsync(Ct);
    }

    [Fact]
    public async Task A_client_whose_forward_request_was_refused_is_collected()
    {
        Tracked tracked = new();
        await RefusedRemoteForwardAsync(tracked, Ct);
        await tracked.AssertAllCollectedAsync(Ct);
    }

    [Fact]
    public async Task A_server_and_its_sessions_are_collected_after_it_served_clients_and_was_disposed()
    {
        Tracked tracked = new();
        await ServerAsync(tracked, Ct);
        await tracked.AssertAllCollectedAsync(Ct);
    }

    [Fact]
    public async Task A_server_disposed_while_a_client_is_still_in_a_session_leaves_nothing_behind()
    {
        Tracked tracked = new();
        await ServerDisposedUnderClientAsync(tracked, Ct);
        await tracked.AssertAllCollectedAsync(Ct);
    }

    [Fact]
    public async Task A_connection_that_failed_authentication_is_collected()
    {
        Tracked tracked = new();
        await FailedAuthenticationAsync(tracked, Ct);
        await tracked.AssertAllCollectedAsync(Ct);
    }

    [Fact]
    public async Task A_client_whose_peer_cut_the_socket_is_collected_after_it_is_disposed()
    {
        Tracked tracked = new();
        await CutSocketAsync(tracked, Ct);
        await tracked.AssertAllCollectedAsync(Ct);
    }

    [Fact]
    public async Task A_connection_that_hit_a_protocol_error_before_login_is_collected()
    {
        Tracked tracked = new();
        await GarbageAfterBannerAsync(tracked, Ct);
        await tracked.AssertAllCollectedAsync(Ct);
    }

    [Fact]
    public async Task A_client_that_hit_a_protocol_error_after_login_is_collected_after_it_is_disposed()
    {
        Tracked tracked = new();
        await GarbageAfterLoginAsync(tracked, Ct);
        await tracked.AssertAllCollectedAsync(Ct);
    }

    [Fact]
    public async Task A_connect_to_a_port_nobody_listens_on_leaves_nothing_behind()
    {
        Tracked tracked = new();
        await NothingListeningAsync(tracked, Ct);
        await tracked.AssertAllCollectedAsync(Ct);
    }

    [Fact]
    public async Task A_connect_that_the_host_key_policy_refused_leaves_nothing_behind()
    {
        Tracked tracked = new();
        await HostKeyMismatchAsync(tracked, Ct);
        await tracked.AssertAllCollectedAsync(Ct);
    }

    // The control: the check has to be able to fail, or every other test here proves nothing.
    [Fact]
    public async Task The_check_names_an_object_that_is_still_referenced()
    {
        object kept = new();
        Tracked tracked = new();
        tracked.Add("kept object", kept);
        Exception failure = await Assert.ThrowsAnyAsync<Exception>(() => tracked.AssertAllCollectedAsync(Ct));
        Assert.Contains("kept object", failure.Message, StringComparison.Ordinal);
        GC.KeepAlive(kept);
    }

    // The scenarios are in methods of their own, never inlined, so that no local of a test's frame points at what it checks. Each one
    // has finished, with every object disposed, before it returns.
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static async Task RunCommandAsync(Tracked tracked, CancellationToken cancellationToken)
    {
        await using LeakRig rig = await LeakRig.StartAsync(null, cancellationToken);
        SshClient client = tracked.Add("client", await SshClient.ConnectAsync(rig.ClientOptions(), cancellationToken));
        SshCommandResult result = await client.ExecuteAsync("echo", cancellationToken).WaitAsync(Limit, cancellationToken);
        Assert.Equal("hello", result.StandardOutput);
        Assert.Equal(0, result.ExitCode);
        await client.DisposeAsync();
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static async Task SftpAsync(Tracked tracked, CancellationToken cancellationToken)
    {
        await using LeakRig rig = await LeakRig.StartAsync(null, cancellationToken);
        SshClient client = tracked.Add("client", await SshClient.ConnectAsync(rig.ClientOptions(), cancellationToken));
        SftpClient sftp = tracked.Add("sftp client", await client.OpenSftpAsync(cancellationToken).WaitAsync(Limit, cancellationToken));
        byte[] contents = new byte[100_000];
        Random.Shared.NextBytes(contents);
        await sftp.WriteAllBytesAsync("/a.bin", contents, cancellationToken).WaitAsync(Limit, cancellationToken);
        using (MemoryStream source = new(contents))
        {
            await sftp.UploadFileAsync(source, "/b.bin", cancellationToken).WaitAsync(Limit, cancellationToken);
        }

        SftpFile file = tracked.Add("sftp file", await sftp.OpenAsync("/a.bin", FileMode.Open, FileAccess.Read, cancellationToken).WaitAsync(Limit, cancellationToken));
        byte[] buffer = new byte[1000];
        Assert.True(await file.ReadAsync(buffer, cancellationToken) > 0);
        await file.DisposeAsync();
        Assert.Equal(contents, await sftp.ReadAllBytesAsync("/b.bin", cancellationToken).WaitAsync(Limit, cancellationToken));
        int entries = 0;
        await foreach (SftpEntry entry in sftp.ListDirectoryAsync("/", cancellationToken))
        {
            _ = entry;
            entries++;
        }

        Assert.True(entries >= 2, $"Listed {entries} entries.");
        await sftp.DisposeAsync();
        await client.DisposeAsync();
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static async Task ProcessAsync(Tracked tracked, CancellationToken cancellationToken)
    {
        await using LeakRig rig = await LeakRig.StartAsync(null, cancellationToken);
        SshClient client = tracked.Add("client", await SshClient.ConnectAsync(rig.ClientOptions(), cancellationToken));
        SshProcess process = tracked.Add("process", await client.StartProcessAsync("cat", cancellationToken: cancellationToken).WaitAsync(Limit, cancellationToken));
        Stream input = tracked.Add("stdin", process.StandardInput);
        Stream output = tracked.Add("stdout", process.StandardOutput);
        tracked.Add("stderr", process.StandardError);
        await input.WriteAsync("ping"u8.ToArray(), cancellationToken);
        await input.DisposeAsync();
        using MemoryStream received = new();
        await output.CopyToAsync(received, cancellationToken).WaitAsync(Limit, cancellationToken);
        Assert.Equal("ping", System.Text.Encoding.ASCII.GetString(received.ToArray()));
        await process.WaitForExitAsync(cancellationToken).WaitAsync(Limit, cancellationToken);
        await process.DisposeAsync();
        await client.DisposeAsync();
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static async Task LocalForwardAsync(Tracked tracked, CancellationToken cancellationToken)
    {
        await using TcpService echo = TcpService.Echo();
        await using LeakRig rig = await LeakRig.StartAsync(null, cancellationToken, request => request.Port == echo.Port);
        SshClient client = tracked.Add("client", await SshClient.ConnectAsync(rig.ClientOptions(), cancellationToken));
        SshLocalForward forward = tracked.Add("local forward", await client.ForwardLocalPortAsync("127.0.0.1", echo.Port, new IPEndPoint(IPAddress.Loopback, 0), cancellationToken));
        using (TcpClient local = new())
        {
            await local.ConnectAsync(forward.LocalEndPoint, cancellationToken);
            NetworkStream stream = local.GetStream();
            await stream.WriteAsync("ping"u8.ToArray(), cancellationToken);
            byte[] buffer = new byte[4];
            await stream.ReadExactlyAsync(buffer, cancellationToken).AsTask().WaitAsync(Limit, cancellationToken);
            Assert.Equal("ping", System.Text.Encoding.ASCII.GetString(buffer));
        }

        await forward.DisposeAsync();
        await client.DisposeAsync();
    }

    // The library's server has no remote forwarding, so a scripted server grants it and then opens a forwarded channel to a local target.
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static async Task RemoteForwardAsync(Tracked tracked, CancellationToken cancellationToken)
    {
        await using TcpService echo = TcpService.Echo();
        (ScriptedServer server, SshClient client) = await ScriptedServer.ConnectAsync(cancellationToken);
        await using (server)
        {
            tracked.Add("client", client);
            Task<SshRemoteForward> requested = client.ForwardRemotePortAsync("127.0.0.1", 8000, "127.0.0.1", echo.Port, cancellationToken);
            await server.ExpectAsync(MessageNumber.GlobalRequest, cancellationToken);
            await server.SendAsync([MessageNumber.RequestSuccess], cancellationToken);
            SshRemoteForward forward = tracked.Add("remote forward", await requested.WaitAsync(Limit, cancellationToken));
            await server.SendAsync(ScriptedServer.ForwardedOpen(1, "127.0.0.1", 8000), cancellationToken);
            (uint? refusal, _) = await server.OpenReplyAsync(cancellationToken);
            Assert.Null(refusal);
            await echo.WaitForAcceptedAsync(1, cancellationToken);
            await forward.DisposeAsync();
            await client.DisposeAsync();
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static async Task RefusedRemoteForwardAsync(Tracked tracked, CancellationToken cancellationToken)
    {
        await using LeakRig rig = await LeakRig.StartAsync(null, cancellationToken);
        SshClient client = tracked.Add("client", await SshClient.ConnectAsync(rig.ClientOptions(), cancellationToken));
        SshException refused = await Assert.ThrowsAnyAsync<SshException>(() => client.ForwardRemotePortAsync("127.0.0.1", 0, "127.0.0.1", 9, cancellationToken).WaitAsync(Limit, cancellationToken));
        tracked.Add("exception", refused);
        await client.DisposeAsync();
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static async Task ServerAsync(Tracked tracked, CancellationToken cancellationToken)
    {
        LeakRig rig = await LeakRig.StartAsync(tracked, cancellationToken);
        tracked.Add("server", rig.Server);
        for (int i = 0; i < 3; i++)
        {
            await using SshClient client = await SshClient.ConnectAsync(rig.ClientOptions(), cancellationToken);
            Assert.Equal("hello", (await client.ExecuteAsync("echo", cancellationToken).WaitAsync(Limit, cancellationToken)).StandardOutput);
            await using SftpClient sftp = await client.OpenSftpAsync(cancellationToken).WaitAsync(Limit, cancellationToken);
            await sftp.WriteAllBytesAsync("/x", new byte[10], cancellationToken).WaitAsync(Limit, cancellationToken);
        }

        await rig.DisposeAsync();
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static async Task ServerDisposedUnderClientAsync(Tracked tracked, CancellationToken cancellationToken)
    {
        LeakRig rig = await LeakRig.StartAsync(tracked, cancellationToken);
        tracked.Add("server", rig.Server);
        SshClient client = tracked.Add("client", await SshClient.ConnectAsync(rig.ClientOptions(), cancellationToken));
        SshProcess process = tracked.Add("process", await client.StartProcessAsync("hang", cancellationToken: cancellationToken).WaitAsync(Limit, cancellationToken));
        await rig.DisposeAsync();
        await client.WaitForCloseAsync(cancellationToken).WaitAsync(Limit, cancellationToken);
        await process.DisposeAsync();
        await client.DisposeAsync();
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static async Task FailedAuthenticationAsync(Tracked tracked, CancellationToken cancellationToken)
    {
        await using LeakRig rig = await LeakRig.StartAsync(null, cancellationToken);

        // The failed connect returns no client, so the stream it was given stands for the connection: the transport and everything
        // on it hold the stream, and if it can be collected they have gone.
        using TcpClient socket = new();
        await socket.ConnectAsync(IPAddress.Loopback, rig.Server.LocalEndPoint.Port, cancellationToken);
        Stream stream = tracked.Add("stream", socket.GetStream());
        SshAuthenticationException failure = await Assert.ThrowsAsync<SshAuthenticationException>(
            () => SshClient.ConnectOverStreamAsync(stream, rig.ClientOptions(password: "wrong"), cancellationToken).WaitAsync(Limit, cancellationToken));
        tracked.Add("exception", failure);

        SshAuthenticationException direct = await Assert.ThrowsAsync<SshAuthenticationException>(
            () => SshClient.ConnectAsync(rig.ClientOptions(password: "wrong"), cancellationToken).WaitAsync(Limit, cancellationToken));
        tracked.Add("exception from ConnectAsync", direct);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static async Task CutSocketAsync(Tracked tracked, CancellationToken cancellationToken)
    {
        await using LeakRig rig = await LeakRig.StartAsync(null, cancellationToken);
        await using Relay relay = new(rig.Server.LocalEndPoint.Port);
        SshClient client = tracked.Add("client", await SshClient.ConnectAsync(rig.ClientOptions(port: relay.Port), cancellationToken));
        SshProcess process = tracked.Add("process", await client.StartProcessAsync("hang", cancellationToken: cancellationToken).WaitAsync(Limit, cancellationToken));
        await relay.CutAsync(cancellationToken);
        SshException? ended = await client.WaitForCloseAsync(cancellationToken).WaitAsync(Limit, cancellationToken);
        Assert.NotNull(ended);
        await process.DisposeAsync();
        await client.DisposeAsync();
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static async Task GarbageAfterBannerAsync(Tracked tracked, CancellationToken cancellationToken)
    {
        TcpListener listener = new(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            Task peer = Task.Run(
                async () =>
                {
                    using Socket accepted = await listener.AcceptSocketAsync(cancellationToken);
                    await accepted.SendAsync("SSH-2.0-hostile\r\n"u8.ToArray(), cancellationToken);
                    byte[] noise = new byte[4096];
                    new Random(7).NextBytes(noise);
                    await accepted.SendAsync(noise, cancellationToken);
                    byte[] sink = new byte[4096];
                    while (await accepted.ReceiveAsync(sink, cancellationToken) > 0)
                    {
                    }
                },
                cancellationToken);
            using TcpClient socket = new();
            await socket.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port, cancellationToken);
            Stream stream = tracked.Add("stream", socket.GetStream());
            SshClientOptions options = new()
            {
                Host = "127.0.0.1",
                UserName = "alice",
                Credentials = [SshCredential.FromPassword("pw")],
                HostKeyPolicy = HostKeyPolicy.AcceptAnyUnsafe(),
            };
            SshException failure = await Assert.ThrowsAnyAsync<SshException>(() => SshClient.ConnectOverStreamAsync(stream, options, cancellationToken).WaitAsync(Limit, cancellationToken));
            tracked.Add("exception", failure);
            socket.Close();
            await peer.WaitAsync(Limit, cancellationToken);
        }
        finally
        {
            listener.Stop();
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static async Task GarbageAfterLoginAsync(Tracked tracked, CancellationToken cancellationToken)
    {
        await using LeakRig rig = await LeakRig.StartAsync(null, cancellationToken);
        await using Relay relay = new(rig.Server.LocalEndPoint.Port);
        SshClient client = tracked.Add("client", await SshClient.ConnectAsync(rig.ClientOptions(port: relay.Port), cancellationToken));
        SshProcess process = tracked.Add("process", await client.StartProcessAsync("hang", cancellationToken: cancellationToken).WaitAsync(Limit, cancellationToken));

        // Bytes that are not an encrypted packet: the integrity check fails, which ends the connection.
        byte[] noise = new byte[256];
        new Random(11).NextBytes(noise);
        await relay.InjectToClientAsync(noise, cancellationToken);
        SshException? ended = await client.WaitForCloseAsync(cancellationToken).WaitAsync(Limit, cancellationToken);
        Assert.NotNull(ended);
        await process.DisposeAsync();
        await client.DisposeAsync();
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static async Task NothingListeningAsync(Tracked tracked, CancellationToken cancellationToken)
    {
        int port;
        using (TcpListener probe = new(IPAddress.Loopback, 0))
        {
            probe.Start();
            port = ((IPEndPoint)probe.LocalEndpoint).Port;
        }

        SshClientOptions options = new()
        {
            Host = "127.0.0.1",
            Port = port,
            UserName = "alice",
            Credentials = [SshCredential.FromPassword("pw")],
            HostKeyPolicy = HostKeyPolicy.AcceptAnyUnsafe(),
        };
        SshException failure = await Assert.ThrowsAnyAsync<SshException>(() => SshClient.ConnectAsync(options, cancellationToken).WaitAsync(Limit, cancellationToken));
        tracked.Add("exception", failure);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static async Task HostKeyMismatchAsync(Tracked tracked, CancellationToken cancellationToken)
    {
        await using LeakRig rig = await LeakRig.StartAsync(null, cancellationToken);
        using SshHostKey other = SshHostKey.GenerateEd25519();
        using TcpClient socket = new();
        await socket.ConnectAsync(IPAddress.Loopback, rig.Server.LocalEndPoint.Port, cancellationToken);
        Stream stream = tracked.Add("stream", socket.GetStream());
        SshHostKeyException failure = await Assert.ThrowsAsync<SshHostKeyException>(
            () => SshClient.ConnectOverStreamAsync(stream, rig.ClientOptions(fingerprint: other.Sha256Fingerprint), cancellationToken).WaitAsync(Limit, cancellationToken));
        tracked.Add("exception", failure);

        SshHostKeyException direct = await Assert.ThrowsAsync<SshHostKeyException>(
            () => SshClient.ConnectAsync(rig.ClientOptions(fingerprint: other.Sha256Fingerprint), cancellationToken).WaitAsync(Limit, cancellationToken));
        tracked.Add("exception from ConnectAsync", direct);
    }
}

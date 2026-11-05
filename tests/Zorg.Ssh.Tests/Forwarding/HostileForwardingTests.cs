using System;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Tests.Transport;
using Zorg.Ssh.Transport;
using static Zorg.Ssh.Tests.Forwarding.ScriptedServer;

namespace Zorg.Ssh.Tests.Forwarding;

/// <summary>A server that lies about forwarding. It gets real keys and a real login, and then does what the script says.</summary>
public sealed class HostileForwardingTests
{
    private const uint Prohibited = 1;
    private const uint ConnectFailed = 2;
    private const uint ResourceShortage = 4;
    private const string Address = "127.0.0.1";

    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(20);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static byte[] Success(params byte[] data) => [MessageNumber.RequestSuccess, .. data];

    private static byte[] Failure() => [MessageNumber.RequestFailure];

    private static byte[] Port(int port) => Message(w => w.UInt32((uint)port));

    private static (string Name, string Address, uint Port) ParseForwardRequest(byte[] message)
    {
        SshReader reader = new(message);
        reader.ReadByte();
        string name = reader.ReadUtf8String();
        reader.ReadBoolean();
        return (name, reader.ReadUtf8String(), reader.ReadUInt32());
    }

    /// <summary>Grants the client's next tcpip-forward, and returns the forward.</summary>
    private static async Task<SshRemoteForward> GrantAsync(ScriptedServer server, SshClient client, int port, int targetPort)
    {
        Task<SshRemoteForward> forward = client.ForwardRemotePortAsync(Address, port, "127.0.0.1", targetPort, Ct);
        await server.ExpectAsync(MessageNumber.GlobalRequest, Ct);
        await server.SendAsync(Success(), Ct);
        return await forward.WaitAsync(Limit, Ct);
    }

    [Fact]
    public async Task A_forwarded_channel_for_a_port_we_never_asked_for_is_refused()
    {
        await using TcpService target = TcpService.Echo();
        (ScriptedServer server, SshClient client) = await ConnectAsync(Ct);
        await using (server)
        await using (client)
        {
            await server.SendAsync(ForwardedOpen(1, Address, target.Port), Ct);
            Assert.Equal(Prohibited, (await server.OpenReplyAsync(Ct)).Refusal);
            Assert.Equal(0, target.Accepted);
            await server.PingAsync(Ct);
        }
    }

    [Fact]
    public async Task A_forwarded_channel_for_another_port_than_the_one_asked_for_is_refused()
    {
        await using TcpService target = TcpService.Echo();
        (ScriptedServer server, SshClient client) = await ConnectAsync(Ct);
        await using (server)
        await using (client)
        {
            await using SshRemoteForward forward = await GrantAsync(server, client, 8000, target.Port);

            await server.SendAsync(ForwardedOpen(1, Address, 8001), Ct);
            Assert.Equal(Prohibited, (await server.OpenReplyAsync(Ct)).Refusal);

            await server.SendAsync(ForwardedOpen(2, "10.0.0.1", 8000), Ct);
            Assert.Equal(Prohibited, (await server.OpenReplyAsync(Ct)).Refusal);

            await server.SendAsync(ForwardedOpen(3, Address, 70000 + 8000), Ct);
            Assert.Equal(Prohibited, (await server.OpenReplyAsync(Ct)).Refusal);
            Assert.Equal(0, target.Accepted);
        }
    }

    [Fact]
    public async Task A_forwarded_channel_before_the_grant_is_refused()
    {
        await using TcpService target = TcpService.Echo();
        (ScriptedServer server, SshClient client) = await ConnectAsync(Ct);
        await using (server)
        await using (client)
        {
            Task<SshRemoteForward> forward = client.ForwardRemotePortAsync(Address, 8000, "127.0.0.1", target.Port, Ct);
            await server.ExpectAsync(MessageNumber.GlobalRequest, Ct);

            await server.SendAsync(ForwardedOpen(1, Address, 8000), Ct);
            Assert.Equal(Prohibited, (await server.OpenReplyAsync(Ct)).Refusal);
            Assert.Equal(0, target.Accepted);

            await server.SendAsync(Success(), Ct);
            await using SshRemoteForward granted = await forward.WaitAsync(Limit, Ct);
        }
    }

    [Fact]
    public async Task A_refused_forward_never_opens_the_port()
    {
        await using TcpService target = TcpService.Echo();
        (ScriptedServer server, SshClient client) = await ConnectAsync(Ct);
        await using (server)
        await using (client)
        {
            Task<SshRemoteForward> forward = client.ForwardRemotePortAsync(Address, 8000, "127.0.0.1", target.Port, Ct);
            await server.ExpectAsync(MessageNumber.GlobalRequest, Ct);
            await server.SendAsync(Failure(), Ct);
            await Assert.ThrowsAsync<SshException>(() => forward.WaitAsync(Limit, Ct));

            await server.SendAsync(ForwardedOpen(1, Address, 8000), Ct);
            Assert.Equal(Prohibited, (await server.OpenReplyAsync(Ct)).Refusal);
        }
    }

    [Fact]
    public async Task A_granted_port_reaches_the_target_with_data_both_ways()
    {
        await using TcpService target = TcpService.Echo();
        (ScriptedServer server, SshClient client) = await ConnectAsync(Ct);
        await using (server)
        await using (client)
        {
            await using SshRemoteForward forward = await GrantAsync(server, client, 8000, target.Port);
            Assert.Equal(8000, forward.RemotePort);

            await server.SendAsync(ForwardedOpen(1, Address, 8000), Ct);
            (uint? refusal, uint channel) = await server.OpenReplyAsync(Ct);
            Assert.Null(refusal);

            await server.SendAsync(
                Message(w =>
                {
                    w.Byte(MessageNumber.ChannelData);
                    w.UInt32(channel);
                    w.Bytes(Encoding.ASCII.GetBytes("hello"));
                }),
                Ct);

            byte[] data = await server.ExpectAsync(MessageNumber.ChannelData, Ct);
            SshReader reader = new(data);
            reader.ReadRaw(5);
            Assert.Equal("hello", Encoding.ASCII.GetString(reader.ReadBinary()));
        }
    }

    // The port is only known from the reply, and a client can connect the moment the port is bound.
    [Fact]
    public async Task A_connection_straight_after_a_chosen_port_is_granted_is_accepted()
    {
        await using TcpService target = TcpService.Echo();
        (ScriptedServer server, SshClient client) = await ConnectAsync(Ct);
        await using (server)
        await using (client)
        {
            for (int i = 0; i < 20; i++)
            {
                Task<SshRemoteForward> forward = client.ForwardRemotePortAsync(Address, 0, "127.0.0.1", target.Port, Ct);
                await server.ExpectAsync(MessageNumber.GlobalRequest, Ct);
                int port = 9000 + i;
                await server.SendAsync(Success(Port(port)), Ct);
                await server.SendAsync(ForwardedOpen((uint)i, Address, port), Ct);
                Assert.Null((await server.OpenReplyAsync(Ct)).Refusal);
                Assert.Equal(port, (await forward.WaitAsync(Limit, Ct)).RemotePort);
            }
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(65536)]
    public async Task A_chosen_port_that_does_not_exist_ends_the_connection(int port)
    {
        (ScriptedServer server, SshClient client) = await ConnectAsync(Ct);
        await using (server)
        await using (client)
        {
            Task<SshRemoteForward> forward = client.ForwardRemotePortAsync(Address, 0, "127.0.0.1", 9, Ct);
            await server.ExpectAsync(MessageNumber.GlobalRequest, Ct);
            await server.SendAsync(Success(Port(port)), Ct);
            await Assert.ThrowsAnyAsync<SshException>(() => forward.WaitAsync(Limit, Ct));
        }
    }

    [Fact]
    public async Task A_chosen_port_with_no_data_ends_the_connection()
    {
        (ScriptedServer server, SshClient client) = await ConnectAsync(Ct);
        await using (server)
        await using (client)
        {
            Task<SshRemoteForward> forward = client.ForwardRemotePortAsync(Address, 0, "127.0.0.1", 9, Ct);
            await server.ExpectAsync(MessageNumber.GlobalRequest, Ct);
            await server.SendAsync(Success(), Ct);
            await Assert.ThrowsAnyAsync<SshException>(() => forward.WaitAsync(Limit, Ct));
        }
    }

    [Fact]
    public async Task A_server_that_hands_out_a_forwarded_port_twice_cannot_take_it_over()
    {
        await using TcpService first = TcpService.Echo();
        await using TcpService second = TcpService.Echo();
        (ScriptedServer server, SshClient client) = await ConnectAsync(Ct);
        await using (server)
        await using (client)
        {
            await using SshRemoteForward forward = await GrantAsync(server, client, 8000, first.Port);

            Task<SshRemoteForward> again = client.ForwardRemotePortAsync(Address, 0, "127.0.0.1", second.Port, Ct);
            await server.ExpectAsync(MessageNumber.GlobalRequest, Ct);
            await server.SendAsync(Success(Port(8000)), Ct);
            await Assert.ThrowsAsync<SshException>(() => again.WaitAsync(Limit, Ct));

            await server.SendAsync(ForwardedOpen(1, Address, 8000), Ct);
            Assert.Null((await server.OpenReplyAsync(Ct)).Refusal);
            Assert.Equal(1, first.Accepted);
            Assert.Equal(0, second.Accepted);
        }
    }

    [Fact]
    public async Task A_port_already_forwarded_is_refused_without_asking_the_server()
    {
        (ScriptedServer server, SshClient client) = await ConnectAsync(Ct);
        await using (server)
        await using (client)
        {
            await using SshRemoteForward forward = await GrantAsync(server, client, 8000, 9);
            await Assert.ThrowsAsync<SshException>(() => client.ForwardRemotePortAsync(Address, 8000, "127.0.0.1", 9, Ct));
        }
    }

    [Fact]
    public async Task Closing_a_forward_tells_the_server_and_refuses_the_port_from_then_on()
    {
        await using TcpService target = TcpService.Echo();
        (ScriptedServer server, SshClient client) = await ConnectAsync(Ct);
        await using (server)
        await using (client)
        {
            server.AnswerCancels = false;
            SshRemoteForward forward = await GrantAsync(server, client, 8000, target.Port);
            Task closing = forward.DisposeAsync().AsTask();

            (string name, string address, uint port) = ParseForwardRequest(await server.ExpectAsync(MessageNumber.GlobalRequest, Ct));
            Assert.Equal("cancel-tcpip-forward", name);
            Assert.Equal(Address, address);
            Assert.Equal(8000u, port);
            await server.SendAsync(Success(), Ct);
            await closing.WaitAsync(Limit, Ct);

            await server.SendAsync(ForwardedOpen(1, Address, 8000), Ct);
            Assert.Equal(Prohibited, (await server.OpenReplyAsync(Ct)).Refusal);
        }
    }

    [Fact]
    public async Task Closing_a_forward_closes_its_active_channels()
    {
        await using TcpService target = TcpService.Echo();
        (ScriptedServer server, SshClient client) = await ConnectAsync(Ct);
        await using (server)
        await using (client)
        {
            server.AnswerCancels = false;
            SshRemoteForward forward = await GrantAsync(server, client, 8000, target.Port);
            await server.SendAsync(ForwardedOpen(7, Address, 8000), Ct);
            Assert.Null((await server.OpenReplyAsync(Ct)).Refusal);
            Assert.Equal(1, forward.ActiveConnections);

            Task closing = forward.DisposeAsync().AsTask();
            byte[] close = await server.ExpectAsync(MessageNumber.ChannelClose, Ct);
            SshReader reader = new(close);
            reader.ReadByte();
            Assert.Equal(7u, reader.ReadUInt32());

            await server.ExpectAsync(MessageNumber.GlobalRequest, Ct);
            await server.SendAsync(Success(), Ct);
            await closing.WaitAsync(Limit, Ct);
        }
    }

    [Fact]
    public async Task A_server_that_never_answers_the_cancel_cannot_hold_the_close()
    {
        (ScriptedServer server, SshClient client) = await ConnectAsync(Ct);
        await using (server)
        await using (client)
        {
            server.AnswerCancels = false;
            SshRemoteForward forward = await GrantAsync(server, client, 8000, 9);
            await forward.DisposeAsync().AsTask().WaitAsync(Limit, Ct);
        }
    }

    // Go CVE-2026-39830: with no request waiting, a reply is dropped. It must not block the loop, grow a queue,
    // or sit there to answer the next request.
    [Fact]
    public async Task A_flood_of_global_replies_is_dropped_and_cannot_answer_a_later_request()
    {
        await using TcpService target = TcpService.Echo();
        (ScriptedServer server, SshClient client) = await ConnectAsync(Ct);
        await using (server)
        await using (client)
        {
            for (int i = 0; i < 20_000; i++)
            {
                await server.SendAsync(i % 2 == 0 ? Success() : Failure(), Ct);
            }

            await server.PingAsync(Ct);

            // Had one been kept, this would already have its answer, and it would be a refusal or a port of 0.
            Task<SshRemoteForward> forward = client.ForwardRemotePortAsync(Address, 0, "127.0.0.1", target.Port, Ct);
            await server.ExpectAsync(MessageNumber.GlobalRequest, Ct);
            await Task.Delay(100, Ct);
            Assert.False(forward.IsCompleted);

            await server.SendAsync(Success(Port(4242)), Ct);
            SshRemoteForward granted = await forward.WaitAsync(Limit, Ct);
            Assert.Equal(4242, granted.RemotePort);

            // One reply too many, after a real one, costs nothing either.
            await server.SendAsync(Failure(), Ct);
            await server.PingAsync(Ct);
            Assert.Equal(4242, granted.RemotePort);
        }
    }

    [Fact]
    public async Task Replies_go_to_requests_in_the_order_they_were_sent()
    {
        (ScriptedServer server, SshClient client) = await ConnectAsync(Ct);
        await using (server)
        await using (client)
        {
            Task<SshRemoteForward>[] forwards = [.. Enumerable.Range(0, 5).Select(i => client.ForwardRemotePortAsync($"host{i}", 0, "127.0.0.1", 9, Ct))];

            string[] order = new string[5];
            for (int i = 0; i < 5; i++)
            {
                order[i] = ParseForwardRequest(await server.ExpectAsync(MessageNumber.GlobalRequest, Ct)).Address;
            }

            for (int i = 0; i < 5; i++)
            {
                await server.SendAsync(i == 2 ? Failure() : Success(Port(5000 + i)), Ct);
            }

            for (int i = 0; i < 5; i++)
            {
                Task<SshRemoteForward> forward = forwards[int.Parse(order[i].AsSpan(4), provider: null)];
                if (i == 2)
                {
                    await Assert.ThrowsAsync<SshException>(() => forward.WaitAsync(Limit, Ct));
                }
                else
                {
                    Assert.Equal(5000 + i, (await forward.WaitAsync(Limit, Ct)).RemotePort);
                }
            }
        }
    }

    // The reply is still coming, so the request keeps its place in the line, or the next request gets its answer.
    [Fact]
    public async Task A_cancelled_request_keeps_its_place_and_gives_back_a_late_grant()
    {
        await using TcpService target = TcpService.Echo();
        (ScriptedServer server, SshClient client) = await ConnectAsync(Ct);
        await using (server)
        await using (client)
        {
            server.AnswerCancels = false;
            using CancellationTokenSource cancel = new();
            Task<SshRemoteForward> cancelled = client.ForwardRemotePortAsync(Address, 8000, "127.0.0.1", target.Port, cancel.Token);
            await server.ExpectAsync(MessageNumber.GlobalRequest, Ct);
            await cancel.CancelAsync();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelled.WaitAsync(Limit, Ct));

            Task<SshRemoteForward> next = client.ForwardRemotePortAsync(Address, 8001, "127.0.0.1", target.Port, Ct);
            await server.ExpectAsync(MessageNumber.GlobalRequest, Ct);

            // The late yes to the first, then a no to the second.
            await server.SendAsync(Success(), Ct);
            await server.SendAsync(Failure(), Ct);
            await Assert.ThrowsAsync<SshException>(() => next.WaitAsync(Limit, Ct));

            (string name, _, uint port) = ParseForwardRequest(await server.ExpectAsync(MessageNumber.GlobalRequest, Ct));
            Assert.Equal("cancel-tcpip-forward", name);
            Assert.Equal(8000u, port);
            await server.SendAsync(Success(), Ct);

            // Nobody owns that port, so it's refused like any other.
            await server.SendAsync(ForwardedOpen(1, Address, 8000), Ct);
            Assert.Equal(Prohibited, (await server.OpenReplyAsync(Ct)).Refusal);
        }
    }

    [Fact]
    public async Task The_connection_ending_fails_every_waiting_request()
    {
        (ScriptedServer server, SshClient client) = await ConnectAsync(Ct);
        await using (client)
        {
            Task<SshRemoteForward> forward = client.ForwardRemotePortAsync(Address, 8000, "127.0.0.1", 9, Ct);
            await server.ExpectAsync(MessageNumber.GlobalRequest, Ct);
            await server.DisposeAsync();
            await Assert.ThrowsAnyAsync<SshConnectionException>(() => forward.WaitAsync(Limit, Ct));
        }
    }

    // Guarantee 3: a server that answers nothing can't make the line grow without limit.
    [Fact]
    public async Task Requests_a_silent_server_never_answers_are_capped()
    {
        (ScriptedServer server, SshClient client) = await ConnectAsync(Ct);
        await using (server)
        await using (client)
        {
            using CancellationTokenSource give = new();
            Task<SshRemoteForward>[] waiting = [.. Enumerable.Range(0, 32).Select(i => client.ForwardRemotePortAsync(Address, 8000 + i, "127.0.0.1", 9, give.Token))];
            for (int i = 0; i < 32; i++)
            {
                await server.ExpectAsync(MessageNumber.GlobalRequest, Ct);
            }

            await Assert.ThrowsAsync<SshException>(() => client.ForwardRemotePortAsync(Address, 9000, "127.0.0.1", 9, Ct));
            await give.CancelAsync();
            await Task.WhenAll(waiting.Select(static t => t.ContinueWith(static _ => { }, TaskScheduler.Default)));
        }
    }

    [Fact]
    public async Task Opens_past_the_cap_are_refused_without_touching_the_target()
    {
        TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await using TcpService target = new(async (_, ct) => await release.Task.WaitAsync(ct));
        (ScriptedServer server, SshClient client) = await ConnectAsync(Ct, maxForwarded: 2);
        await using (server)
        await using (client)
        {
            await using SshRemoteForward forward = await GrantAsync(server, client, 8000, target.Port);
            for (uint i = 0; i < 2; i++)
            {
                await server.SendAsync(ForwardedOpen(i, Address, 8000), Ct);
                Assert.Null((await server.OpenReplyAsync(Ct)).Refusal);
            }

            // A flood, all in one go, and the loop stays free: nothing here waits for the target.
            for (uint i = 2; i < 200; i++)
            {
                await server.SendAsync(ForwardedOpen(i, Address, 8000), Ct);
            }

            for (uint i = 2; i < 200; i++)
            {
                Assert.Equal(ResourceShortage, (await server.OpenReplyAsync(Ct)).Refusal);
            }

            Assert.Equal(2, target.Accepted);
            await server.PingAsync(Ct);
            release.SetResult();
        }
    }

    [Fact]
    public async Task A_dead_target_is_a_refused_channel()
    {
        using TcpListener unused = new(System.Net.IPAddress.Loopback, 0);
        unused.Start();
        int port = ((System.Net.IPEndPoint)unused.LocalEndpoint).Port;
        unused.Stop();

        (ScriptedServer server, SshClient client) = await ConnectAsync(Ct);
        await using (server)
        await using (client)
        {
            await using SshRemoteForward forward = await GrantAsync(server, client, 8000, port);
            await server.SendAsync(ForwardedOpen(1, Address, 8000), Ct);
            Assert.Equal(ConnectFailed, (await server.OpenReplyAsync(Ct)).Refusal);
            Assert.Equal(0, forward.ActiveConnections);
        }
    }

    [Fact]
    public async Task Every_other_channel_type_is_still_refused()
    {
        (ScriptedServer server, SshClient client) = await ConnectAsync(Ct);
        await using (server)
        await using (client)
        {
            foreach (string type in new[] { "session", "x11", "direct-tcpip", "auth-agent@openssh.com" })
            {
                await server.SendAsync(
                    Message(w =>
                    {
                        w.Byte(MessageNumber.ChannelOpen);
                        w.String(type);
                        w.UInt32(1);
                        w.UInt32(1024);
                        w.UInt32(1024);
                    }),
                    Ct);
                Assert.Equal(Prohibited, (await server.OpenReplyAsync(Ct)).Refusal);
            }
        }
    }

    [Fact]
    public async Task A_forwarded_channel_with_a_zero_packet_size_ends_the_connection()
    {
        (ScriptedServer server, SshClient client) = await ConnectAsync(Ct);
        await using (server)
        await using (client)
        {
            await server.SendAsync(
                Message(static w =>
                {
                    w.Byte(MessageNumber.ChannelOpen);
                    w.String("forwarded-tcpip");
                    w.UInt32(1);
                    w.UInt32(1024);
                    w.UInt32(0);
                    w.String(Address);
                    w.UInt32(8000);
                }),
                Ct);
            await Assert.ThrowsAnyAsync<SshException>(() => client.ExecuteAsync("x", Ct).WaitAsync(Limit, Ct));
        }
    }

    [Fact]
    public async Task A_truncated_forwarded_channel_ends_the_connection_with_an_ssh_exception()
    {
        (ScriptedServer server, SshClient client) = await ConnectAsync(Ct);
        await using (server)
        await using (client)
        {
            await server.SendAsync(
                Message(static w =>
                {
                    w.Byte(MessageNumber.ChannelOpen);
                    w.String("forwarded-tcpip");
                    w.UInt32(1);
                    w.UInt32(1024);
                    w.UInt32(1024);
                }),
                Ct);
            await Assert.ThrowsAnyAsync<SshException>(() => client.ExecuteAsync("x", Ct).WaitAsync(Limit, Ct));
        }
    }

    // Our own server, attacked: a client can't reach a channel the handler hasn't decided on yet.
    [Fact]
    public async Task Channel_messages_cannot_reach_an_open_the_server_has_not_accepted()
    {
        using SshHostKey hostKey = SshHostKey.GenerateEd25519();
        TaskCompletionSource decide = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await using SshServer sshServer = await SshServer.StartAsync(
            new SshServerOptions
            {
                HostKeys = [hostKey],
                PasswordHandler = static (_, _) => ValueTask.FromResult(SshAuthDecision.Accept),
                SessionHandler = static (_, _) => Task.FromResult(0),
                DirectTcpHandler = async (_, ct) =>
                {
                    await decide.Task.WaitAsync(ct);
                    return SshForwardDecision.Deny;
                },
            },
            Ct);

        TcpClient socket = new();
        await socket.ConnectAsync(sshServer.LocalEndPoint, Ct);
        await using SshTransport transport = await SshTransport.StartAsync(socket.GetStream(), TransportHarness.ClientOptions(), Ct);
        await new Zorg.Ssh.Auth.ClientAuthenticator(transport, "alice", null).AuthenticateAsync([SshCredential.FromPassword("pw")], Ct);

        await transport.SendAsync(
            Message(static w =>
            {
                w.Byte(MessageNumber.ChannelOpen);
                w.String("direct-tcpip");
                w.UInt32(1);
                w.UInt32(1024);
                w.UInt32(1024);
                w.String("example.com");
                w.UInt32(80);
                w.String("127.0.0.1");
                w.UInt32(1);
            }),
            Ct);

        // Channel 0 is the first id the server would hand out.
        await transport.SendAsync(
            Message(static w =>
            {
                w.Byte(MessageNumber.ChannelData);
                w.UInt32(0);
                w.Bytes([1, 2, 3]);
            }),
            Ct);

        await Assert.ThrowsAnyAsync<SshException>(async () =>
        {
            while (true)
            {
                await transport.ReceiveAsync(Ct).AsTask().WaitAsync(Limit, Ct);
            }
        });
        decide.SetResult();
    }

    [Fact]
    public async Task A_malformed_direct_tcpip_never_reaches_the_handler()
    {
        using SshHostKey hostKey = SshHostKey.GenerateEd25519();
        int calls = 0;
        await using SshServer sshServer = await SshServer.StartAsync(
            new SshServerOptions
            {
                HostKeys = [hostKey],
                PasswordHandler = static (_, _) => ValueTask.FromResult(SshAuthDecision.Accept),
                SessionHandler = static (_, _) => Task.FromResult(0),
                DirectTcpHandler = (_, _) =>
                {
                    Interlocked.Increment(ref calls);
                    return ValueTask.FromResult(SshForwardDecision.Allow);
                },
            },
            Ct);

        TcpClient socket = new();
        await socket.ConnectAsync(sshServer.LocalEndPoint, Ct);
        await using SshTransport transport = await SshTransport.StartAsync(socket.GetStream(), TransportHarness.ClientOptions(), Ct);
        await new Zorg.Ssh.Auth.ClientAuthenticator(transport, "alice", null).AuthenticateAsync([SshCredential.FromPassword("pw")], Ct);

        byte[][] bad =
        [
            Open(static _ => { }),
            Open(static w => w.String("host")),
            Open(static w => Target(w, "host", 0)),
            Open(static w => Target(w, "host", 70000)),
            Open(static w => Target(w, string.Empty, 80)),
            Open(static w => Target(w, "a\nb", 80)),
            Open(static w => Target(w, new string('a', 256), 80)),
        ];
        foreach (byte[] open in bad)
        {
            await transport.SendAsync(open, Ct);
            ReadOnlyMemory<byte> reply = await transport.ReceiveAsync(Ct).AsTask().WaitAsync(Limit, Ct);
            Assert.Equal(MessageNumber.ChannelOpenFailure, reply.Span[0]);
        }

        Assert.Equal(0, calls);
    }

    private static byte[] Open(Action<Zorg.Ssh.Auth.SshRequestWriter> target) => Message(w =>
    {
        w.Byte(MessageNumber.ChannelOpen);
        w.String("direct-tcpip");
        w.UInt32(1);
        w.UInt32(1024);
        w.UInt32(1024);
        target(w);
    });

    private static void Target(Zorg.Ssh.Auth.SshRequestWriter writer, string host, uint port)
    {
        writer.String(host);
        writer.UInt32(port);
        writer.String("127.0.0.1");
        writer.UInt32(1);
    }

    // The relay's channel has to be real enough for the stream: this drives the read-side close a jump host relies on.
    [Fact]
    public async Task Disposing_a_channel_stream_releases_a_read_in_progress()
    {
        await using TcpService silent = new(static async (stream, ct) => await stream.ReadExactlyAsync(new byte[1], ct));
        using SshHostKey hostKey = SshHostKey.GenerateEd25519();
        await using SshServer sshServer = await SshServer.StartAsync(
            new SshServerOptions
            {
                HostKeys = [hostKey],
                PasswordHandler = static (_, _) => ValueTask.FromResult(SshAuthDecision.Accept),
                SessionHandler = static (_, _) => Task.FromResult(0),
                DirectTcpHandler = static (_, _) => ValueTask.FromResult(SshForwardDecision.Allow),
            },
            Ct);
        await using SshClient client = await SshClient.ConnectAsync(
            new SshClientOptions
            {
                Host = "127.0.0.1",
                Port = sshServer.LocalEndPoint.Port,
                UserName = "alice",
                Credentials = [SshCredential.FromPassword("pw")],
                HostKeyPolicy = HostKeyPolicy.Fingerprint(hostKey.Sha256Fingerprint),
            },
            Ct);

        System.IO.Stream stream = await client.OpenTcpStreamAsync("127.0.0.1", silent.Port, Ct);
        Task<int> reading = stream.ReadAsync(new byte[16], Ct).AsTask();
        await Task.Delay(50, Ct);
        Assert.False(reading.IsCompleted);

        await stream.DisposeAsync();
        Assert.Equal(0, await reading.WaitAsync(Limit, Ct));
    }
}

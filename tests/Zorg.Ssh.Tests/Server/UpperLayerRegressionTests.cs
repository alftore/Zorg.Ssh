using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Auth;
using Zorg.Ssh.Connection;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Transport;

namespace Zorg.Ssh.Tests.Server;

/// <summary>Each test is a finding from the independent review of the upper layers. R numbers refer to it.</summary>
public sealed class UpperLayerRegressionTests : IDisposable
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(20);

    private readonly SshHostKey _hostKey = SshHostKey.GenerateEd25519();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => _hostKey.Dispose();

    private SshServerOptions Options(Func<SshServerSession, CancellationToken, Task<int>> handler, int maxSessions = 10, TimeSpan? grace = null) => new()
    {
        HostKeys = [_hostKey],
        PasswordHandler = (_, _) => ValueTask.FromResult(SshAuthDecision.Accept),
        SessionHandler = handler,
        MaxSessionsPerConnection = maxSessions,
        LoginGraceTime = grace ?? TimeSpan.FromSeconds(30),
    };

    private SshClientOptions ClientOptions(SshServer server, int? maxOutput = null) => new()
    {
        Host = "127.0.0.1",
        Port = server.LocalEndPoint.Port,
        UserName = "alice",
        Credentials = [SshCredential.FromPassword("pw")],
        HostKeyPolicy = HostKeyPolicy.Fingerprint(_hostKey.Sha256Fingerprint),
        MaxCommandOutputBytes = maxOutput ?? 64 * 1024 * 1024,
    };

    // R1: closing one channel used to kill the connection, because messages followed CLOSE.
    [Fact]
    public async Task R1_closing_a_running_process_leaves_the_connection_and_other_sessions_alive()
    {
        byte[] chunk = new byte[16 * 1024];
        await using SshServer server = await SshServer.StartAsync(
            Options(async (session, ct) =>
            {
                if (session.Command == "quick")
                {
                    await session.Output.WriteAsync("ok"u8.ToArray(), ct);
                    return 0;
                }

                // Streams flat out, so data is always queued when the client closes.
                while (true)
                {
                    await session.Output.WriteAsync(chunk, ct);
                }
            }),
            Ct);

        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server), Ct);
        for (int i = 0; i < 30; i++)
        {
            SshProcess process = await client.StartProcessAsync("stream", null, Ct);
            byte[] buffer = new byte[1024];
            await process.StandardOutput.ReadExactlyAsync(buffer, Ct);
            await process.DisposeAsync();
            Assert.Equal("ok", (await client.ExecuteAsync("quick", Ct)).StandardOutput);
        }
    }

    // R1, third cause: the handler's output could reach the client ahead of the reply to exec.
    [Fact]
    public async Task R1_a_command_that_finishes_at_once_never_fails_under_load()
    {
        await using SshServer server = await SshServer.StartAsync(Options((_, _) => Task.FromResult(9), maxSessions: 100), Ct);
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server), Ct);
        for (int round = 0; round < 40; round++)
        {
            SshCommandResult[] results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => client.ExecuteAsync("x", Ct)));
            Assert.All(results, r => Assert.Equal(9, r.ExitCode));
        }
    }

    // R3: exec then CLOSE, repeated, used to pile up handlers past the limit.
    [Fact]
    public async Task R3_closing_channels_does_not_free_slots_while_handlers_run()
    {
        int running = 0;
        int peak = 0;
        TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await using SshServer server = await SshServer.StartAsync(
            Options(
                async (_, _) =>
                {
                    int now = Interlocked.Increment(ref running);
                    InterlockedMax(ref peak, now);

                    // Ignores its token on purpose: that's the case the slot has to survive.
                    await release.Task;
                    Interlocked.Decrement(ref running);
                    return 0;
                },
                maxSessions: 2),
            Ct);

        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server), Ct);
        for (int i = 0; i < 6; i++)
        {
            try
            {
                SshProcess process = await client.StartProcessAsync("x", null, Ct);
                await process.DisposeAsync();
            }
            catch (SshException)
            {
                // Refused because of the limit, which is right.
            }
        }

        await Task.Delay(200, Ct);
        Assert.True(Volatile.Read(ref peak) <= 2, $"{peak} handlers ran with a limit of 2.");
        release.SetResult();
    }

    private static void InterlockedMax(ref int target, int value)
    {
        int current;
        do
        {
            current = Volatile.Read(ref target);
        }
        while (value > current && Interlocked.CompareExchange(ref target, value, current) != current);
    }

    // R4 and R6: requests after the start must neither orphan the handler nor change what it was given.
    [Fact]
    public async Task R4_R6_a_late_or_malformed_request_cannot_touch_a_running_handler()
    {
        TaskCompletionSource<string?> seen = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await using SshServer server = await SshServer.StartAsync(
            Options(async (session, ct) =>
            {
                await release.Task.WaitAsync(ct);
                seen.SetResult(session.Environment.TryGetValue("LATE", out string? late) ? late : null);
                await session.Output.WriteAsync("done"u8.ToArray(), ct);
                return 0;
            }),
            Ct);

        await using SshTransport transport = await ConnectRawAsync(server);
        SshConnection connection = new(transport);
        await using (connection)
        {
            connection.Start();
            SshChannel channel = await connection.OpenChannelAsync("session", Ct);
            SshRequestWriter exec = new();
            exec.String("x");
            Assert.True(await channel.SendRequestAsync("exec", exec.ToArray(), Ct));

            SshRequestWriter env = new();
            env.String("LATE");
            env.String("value");
            Assert.False(await channel.SendRequestAsync("env", env.ToArray(), Ct));
            Assert.False(await channel.SendRequestAsync("env", [0xFF, 0xFF, 0xFF, 0xFF], Ct));

            release.SetResult();
            Assert.Null(await seen.Task.WaitAsync(Limit, Ct));
        }
    }

    // R5: the handler has to hear that the client went.
    [Fact]
    public async Task R5_the_handler_token_fires_when_the_client_goes()
    {
        TaskCompletionSource started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource cancelled = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await using SshServer server = await SshServer.StartAsync(
            Options(async (_, ct) =>
            {
                started.SetResult();
                try
                {
                    await Task.Delay(Timeout.Infinite, ct);
                }
                catch (OperationCanceledException)
                {
                    cancelled.SetResult();
                    throw;
                }

                return 0;
            }),
            Ct);

        SshClient client = await SshClient.ConnectAsync(ClientOptions(server), Ct);
        await using (client)
        {
            await client.StartProcessAsync("x", null, Ct);
            await started.Task.WaitAsync(Limit, Ct);
        }

        await cancelled.Task.WaitAsync(Limit, Ct);
    }

    // R7: going over the cap used to hang, because the other stream never ended.
    [Fact]
    public async Task R7_output_past_the_limit_fails_instead_of_hanging()
    {
        byte[] chunk = new byte[32 * 1024];
        await using SshServer server = await SshServer.StartAsync(
            Options(async (session, ct) =>
            {
                while (true)
                {
                    await session.Output.WriteAsync(chunk, ct);
                }
            }),
            Ct);

        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server, maxOutput: 100_000), Ct);
        await Assert.ThrowsAsync<SshException>(() => client.ExecuteAsync("x", Ct).WaitAsync(Limit, Ct));
    }

    // R8 and R9.
    [Fact]
    public async Task R8_a_throwing_auth_handler_is_a_rejection()
    {
        await using SshServer server = await SshServer.StartAsync(
            new SshServerOptions
            {
                HostKeys = [_hostKey],
                PasswordHandler = (_, _) => throw new InvalidOperationException("database down"),
                SessionHandler = (_, _) => Task.FromResult(0),
            },
            Ct);

        SshAuthenticationException ex = await Assert.ThrowsAsync<SshAuthenticationException>(() => SshClient.ConnectAsync(ClientOptions(server), Ct));
        Assert.DoesNotContain("database", ex.Message);
    }

    [Fact]
    public async Task R9_an_auth_handler_that_ignores_its_token_cannot_outlast_the_grace_time()
    {
        await using SshServer server = await SshServer.StartAsync(
            new SshServerOptions
            {
                HostKeys = [_hostKey],
                LoginGraceTime = TimeSpan.FromMilliseconds(500),
                PasswordHandler = async (_, _) =>
                {
                    await Task.Delay(TimeSpan.FromSeconds(30), CancellationToken.None);
                    return SshAuthDecision.Accept;
                },
                SessionHandler = (_, _) => Task.FromResult(0),
            },
            Ct);

        await Assert.ThrowsAnyAsync<SshException>(() => SshClient.ConnectAsync(ClientOptions(server), Ct).WaitAsync(Limit, Ct));
    }

    // R2: requiring two methods has to be enforced by the server, not left to handlers.
    [Fact]
    public async Task R2_one_method_is_not_enough_when_two_are_required()
    {
        using SshPrivateKey key = SshPrivateKey.GenerateEd25519();
        await using SshServer server = await SshServer.StartAsync(
            new SshServerOptions
            {
                HostKeys = [_hostKey],
                RequiredAuthMethods = ["publickey", "password"],
                PublicKeyHandler = (_, _) => ValueTask.FromResult(SshAuthDecision.Accept),
                PasswordHandler = (_, _) => ValueTask.FromResult(SshAuthDecision.Accept),
                SessionHandler = (s, _) => Task.FromResult(s.Principal.Methods.Count),
            },
            Ct);

        // The password alone is not enough, even though its handler says yes.
        await Assert.ThrowsAsync<SshAuthenticationException>(() => SshClient.ConnectAsync(ClientOptions(server), Ct));

        SshClientOptions both = new()
        {
            Host = "127.0.0.1",
            Port = server.LocalEndPoint.Port,
            UserName = "alice",
            Credentials = [new PrivateKeyCredential(() => key, ownsKey: false), SshCredential.FromPassword("pw")],
            HostKeyPolicy = HostKeyPolicy.Fingerprint(_hostKey.Sha256Fingerprint),
        };
        await using SshClient client = await SshClient.ConnectAsync(both, Ct);

        // Go CVE-2026-39828: every step reaches the final session.
        Assert.Equal(2, (await client.ExecuteAsync("x", Ct)).ExitCode);
    }

    // R13: a cancelled open used to leak its slot, and 256 of them ended the client.
    [Fact]
    public async Task R13_cancelled_opens_do_not_use_up_channels()
    {
        await using SshServer server = await SshServer.StartAsync(Options((_, _) => Task.FromResult(0), maxSessions: 300), Ct);
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server), Ct);
        for (int i = 0; i < 300; i++)
        {
            using CancellationTokenSource cancelled = new();
            await cancelled.CancelAsync();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.StartProcessAsync("x", null, cancelled.Token));
        }

        Assert.Equal(0, (await client.ExecuteAsync("x", Ct)).ExitCode);
    }

    // R15: messages 60-79 used to be read as a USERAUTH_REQUEST.
    [Fact]
    public async Task R15_a_method_message_with_no_method_waiting_ends_the_connection()
    {
        await using SshServer server = await SshServer.StartAsync(Options((_, _) => Task.FromResult(0)), Ct);
        await using SshTransport transport = await ConnectRawAsync(server, login: false);
        SshRequestWriter service = new();
        service.Byte(MessageNumber.ServiceRequest);
        service.String("ssh-userauth");
        await transport.SendAsync(service.ToArray(), Ct);
        transport.SetPhase(TransportPhase.AwaitService);
        await transport.ReceiveAsync(Ct);
        transport.SetPhase(TransportPhase.Auth);

        await transport.SendAsync(new byte[] { 60, 0, 0, 0, 0 }, Ct);
        await Assert.ThrowsAnyAsync<SshConnectionException>(async () =>
        {
            while (true)
            {
                await transport.ReceiveAsync(Ct);
            }
        });
    }

    // R20.
    [Fact]
    public async Task R20_dispose_twice_is_harmless_and_late_streams_are_refused()
    {
        SshServer server = await SshServer.StartAsync(Options((_, _) => Task.FromResult(0)), Ct);
        await server.DisposeAsync();
        await server.DisposeAsync();
        (System.IO.Stream a, System.IO.Stream _) = Transport.DuplexStream.CreatePair();
        await Assert.ThrowsAsync<SshConnectionException>(() => server.ServeStreamAsync(a, Ct));
    }

    // Found by the SFTP server work: closing a session first must not break the connection for the next one.
    [Fact]
    public async Task R1_closing_an_sftp_session_leaves_the_connection_usable()
    {
        System.IO.DirectoryInfo root = System.IO.Directory.CreateTempSubdirectory("zorg-ssh-r1");
        try
        {
            Zorg.Ssh.Sftp.SftpServerOptions sftp = new() { RootDirectory = root.FullName };
            await using SshServer server = await SshServer.StartAsync(
                Options((session, ct) => session.Kind == SshSessionKind.Subsystem
                    ? Zorg.Ssh.Sftp.SftpServer.ServeAsync(session, sftp, ct)
                    : Task.FromResult(4)),
                Ct);

            await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server), Ct);
            for (int i = 0; i < 5; i++)
            {
                Zorg.Ssh.Sftp.SftpClient session = await client.OpenSftpAsync(Ct);
                await session.WriteAllBytesAsync($"file{i}", new byte[] { 1, 2, 3 }, Ct);
                await session.DisposeAsync();
                Assert.Equal(4, (await client.ExecuteAsync("x", Ct)).ExitCode);
            }
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    // R21.
    [Fact]
    public async Task R21_a_lost_connection_is_not_reported_as_an_exit()
    {
        TaskCompletionSource started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await using SshServer server = await SshServer.StartAsync(
            Options(async (_, ct) =>
            {
                started.SetResult();
                await Task.Delay(Timeout.Infinite, ct);
                return 0;
            }),
            Ct);

        (System.IO.Stream clientSide, System.IO.Stream serverSide) = Transport.DuplexStream.CreatePair();
        using CancellationTokenSource cut = new();
        Task serving = server.ServeStreamAsync(serverSide, cut.Token);
        await using SshClient client = await SshClient.ConnectOverStreamAsync(clientSide, ClientOptions(server), Ct);
        await using SshProcess process = await client.StartProcessAsync("x", null, Ct);
        await started.Task.WaitAsync(Limit, Ct);

        // Closes the stream with no goodbye, as a dropped network link would.
        await cut.CancelAsync();
        await Assert.ThrowsAnyAsync<SshConnectionException>(() => process.WaitForExitAsync(Ct).WaitAsync(Limit, Ct));
        await serving.WaitAsync(Limit, Ct);
    }

    private static async Task<SshTransport> ConnectRawAsync(SshServer server, bool login = true)
    {
        TcpClient socket = new();
        await socket.ConnectAsync(IPAddress.Loopback, server.LocalEndPoint.Port, Ct);
        SshTransport transport = await SshTransport.StartAsync(
            socket.GetStream(),
            new TransportOptions { Role = SshRole.Client, HostKeyValidator = static (_, _) => ValueTask.FromResult(true) },
            Ct);
        if (login)
        {
            await new ClientAuthenticator(transport, "alice", null).AuthenticateAsync([SshCredential.FromPassword("pw")], Ct);
        }

        return transport;
    }
}

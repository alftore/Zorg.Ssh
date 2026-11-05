using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Agent;
using Zorg.Ssh.Auth;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Tests.Crypto;
using Zorg.Ssh.Transport;
using static Zorg.Ssh.Tests.Agent.FakeAgent;
using static Zorg.Ssh.Tests.Transport.TransportHarness;

namespace Zorg.Ssh.Tests.Agent;

/// <summary>The agent client against a fake agent, which is what can be hostile on demand. Real agents are in the interop tests.</summary>
public class SshAgentTests
{
    private static readonly TimeSpan Short = TimeSpan.FromMilliseconds(200);
    private static readonly SshPrivateKey Key = SshPrivateKey.GenerateEd25519();
    private static readonly SshPrivateKey Rsa = SshPrivateKey.GenerateRsa(2048);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static SshAgentConnection Connection(Func<byte[], byte[]?> respond, TimeSpan? timeout = null) =>
        new(new FakeAgentStream(respond), timeout ?? TimeSpan.FromSeconds(10));

    private static AgentCredential Credential(FakeAgent agent, int max = AgentCredential.DefaultMaxKeysOffered) =>
        new(_ => ValueTask.FromResult(agent.Connect()), max, isOptional: false);

    private static ServerAuthOptions Accepting(params SshPublicKey[] keys) => new()
    {
        PublicKey = (_, key, _) => ValueTask.FromResult(
            keys.Any(k => k.Blob.Span.SequenceEqual(key.Blob.Span)) ? AuthDecision.Accept : AuthDecision.Reject),
        Password = (_, password, _) => ValueTask.FromResult(password == "secret" ? AuthDecision.Accept : AuthDecision.Reject),
    };

    private static async Task<(AuthenticatedUser? User, Exception? ClientFailure)> LogInAsync(ServerAuthOptions server, params SshCredential[] credentials)
    {
        (SshTransport client, SshTransport serverTransport) = await ConnectAsync(ClientOptions(), ServerOptions(), Ct);
        await using (client)
        await using (serverTransport)
        {
            Task<AuthenticatedUser> serverTask = new ServerAuthenticator(serverTransport, server).AuthenticateAsync(Ct);
            Exception? failure = null;
            try
            {
                await new ClientAuthenticator(client, "alice", null).AuthenticateAsync(credentials, Ct);
            }
            catch (SshException ex)
            {
                failure = ex;
                await client.DisposeAsync();
            }

            try
            {
                return (await serverTask, failure);
            }
            catch (SshException)
            {
                return (null, failure);
            }
        }
    }

    private static async Task<string> ListFailureAsync(byte[]? reply, TimeSpan? timeout = null)
    {
        await using SshAgentConnection agent = Connection(_ => reply, timeout);
        return (await Assert.ThrowsAsync<SshAgentException>(() => agent.ListIdentitiesAsync(Ct))).Message;
    }

    [Fact]
    public async Task Keys_are_listed()
    {
        FakeAgent fake = new(Key, Rsa);
        await using SshAgentConnection agent = Connection(fake.Respond);
        IReadOnlyList<SshAgentIdentity> identities = await agent.ListIdentitiesAsync(Ct);
        Assert.Equal(2, identities.Count);
        Assert.Equal(["ssh-ed25519"], identities[0].SignatureAlgorithms);
        Assert.Equal(["rsa-sha2-512", "rsa-sha2-256"], identities[1].SignatureAlgorithms);
    }

    [Fact]
    public async Task A_key_of_an_unknown_type_is_skipped_not_fatal()
    {
        byte[] unknown = [.. String("sk-ssh-ed25519@openssh.com"u8.ToArray()), .. String(new byte[32])];
        byte[] reply = Frame([12], UInt32(2), String(unknown), String([]), String(Key.PublicKey.Blob.ToArray()), String([]));
        await using SshAgentConnection agent = Connection(_ => reply);
        Assert.Single(await agent.ListIdentitiesAsync(Ct));
    }

    [Fact]
    public async Task A_comment_that_is_not_text_is_harmless()
    {
        byte[] reply = Frame([12], UInt32(1), String(Key.PublicKey.Blob.ToArray()), String([0xFF, 0xFE, 0x1B]));
        await using SshAgentConnection agent = Connection(_ => reply);
        Assert.Single(await agent.ListIdentitiesAsync(Ct));
    }

    [Theory]
    [InlineData(0u)]
    [InlineData(SshAgentConnection.MaxFrameLength + 1u)]
    [InlineData(uint.MaxValue)]
    public async Task A_frame_length_out_of_range_is_refused_before_reading_it(uint length)
    {
        Assert.Contains("outside the limit", await ListFailureAsync(UInt32(length)));
    }

    [Fact]
    public async Task A_key_count_over_the_cap_is_refused()
    {
        Assert.Contains("claims to hold", await ListFailureAsync(Frame([12], UInt32(SshAgentConnection.MaxIdentities + 1))));
    }

    [Fact]
    public async Task A_key_count_beyond_the_frame_is_malformed()
    {
        Assert.Contains("malformed", await ListFailureAsync(Frame([12], UInt32(5), String(Key.PublicKey.Blob.ToArray()), String([]))));
    }

    [Fact]
    public async Task Trailing_data_is_malformed()
    {
        Assert.Contains("malformed", await ListFailureAsync(Frame([12], UInt32(0), [1])));
    }

    [Theory]
    [InlineData(new byte[] { 12 })]
    [InlineData(new byte[] { 12, 0, 0 })]
    [InlineData(new byte[] { 12, 0, 0, 0, 1, 0xFF, 0xFF, 0xFF, 0xFF })]
    public async Task Short_answers_are_malformed(byte[] body)
    {
        Assert.Contains("malformed", await ListFailureAsync(Frame(body)));
    }

    [Fact]
    public async Task A_reply_of_the_wrong_type_is_refused()
    {
        Assert.Contains("wrong type", await ListFailureAsync(Frame([14], String([]))));
    }

    [Fact]
    public async Task A_refused_list_says_so()
    {
        Assert.Contains("refused", await ListFailureAsync(Frame([5])));
    }

    [Fact]
    public async Task A_frame_cut_short_is_a_failure()
    {
        byte[] whole = Frame([12], UInt32(0));
        await using SshAgentConnection agent = new(new FakeAgentStream(_ => whole[..6]) { CloseAfterReply = true }, TimeSpan.FromSeconds(10));
        Assert.Contains("part way", (await Assert.ThrowsAsync<SshAgentException>(() => agent.ListIdentitiesAsync(Ct))).Message);
    }

    [Fact]
    public async Task An_agent_that_closes_is_a_failure()
    {
        Assert.Contains("part way", await ListFailureAsync([]));
    }

    [Fact]
    public async Task An_agent_that_never_answers_times_out()
    {
        Assert.Contains("didn't answer", await ListFailureAsync(null, Short));
    }

    [Fact]
    public async Task A_stream_that_ignores_cancellation_still_times_out()
    {
        await using SshAgentConnection agent = new(new DeafStream(), Short);
        Assert.Contains("didn't answer", (await Assert.ThrowsAsync<SshAgentException>(() => agent.ListIdentitiesAsync(Ct))).Message);
    }

    [Fact]
    public async Task The_caller_can_cancel_a_wait()
    {
        await using SshAgentConnection agent = Connection(_ => null);
        using CancellationTokenSource cancel = new(Short);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => agent.ListIdentitiesAsync(cancel.Token));
    }

    [Fact]
    public async Task A_refused_signature_is_null()
    {
        await using SshAgentConnection agent = Connection(_ => Frame([5]));
        Assert.Null(await agent.SignAsync([1], [2], 0, Ct));
    }

    [Fact]
    public async Task A_failure_with_extra_fields_is_still_a_failure()
    {
        await using SshAgentConnection agent = Connection(_ => Frame([5], [1, 2, 3]));
        Assert.Null(await agent.SignAsync([1], [2], 0, Ct));
    }

    [Theory]
    [InlineData(new byte[] { 14 })]
    [InlineData(new byte[] { 14, 0, 0, 0, 9, 1 })]
    [InlineData(new byte[] { 14, 0, 0, 0, 0, 1 })]
    public async Task A_malformed_signature_reply_is_refused(byte[] body)
    {
        await using SshAgentConnection agent = Connection(_ => Frame(body));
        await Assert.ThrowsAsync<SshAgentException>(() => agent.SignAsync([1], [2], 0, Ct));
    }

    [Theory]
    [InlineData("rsa-sha2-256", 2u)]
    [InlineData("rsa-sha2-512", 4u)]
    [InlineData("rsa-sha2-256-cert-v01@openssh.com", 2u)]
    [InlineData("rsa-sha2-512-cert-v01@openssh.com", 4u)]
    [InlineData("ssh-ed25519", 0u)]
    [InlineData("ecdsa-sha2-nistp256", 0u)]
    [InlineData("ssh-ed25519-cert-v01@openssh.com", 0u)]
    public void Flags_follow_the_algorithm(string algorithm, uint flags)
    {
        Assert.Equal(flags, SshAgentConnection.FlagsFor(algorithm));
    }

    [Fact]
    public async Task A_key_in_the_agent_logs_in()
    {
        FakeAgent agent = new(Key);
        (AuthenticatedUser? user, Exception? failure) = await LogInAsync(Accepting(Key.PublicKey), Credential(agent));
        Assert.Null(failure);
        Assert.Equal(["publickey"], user!.Methods);
        Assert.Equal(1, agent.SignRequests);
    }

    [Fact]
    public async Task An_RSA_key_asks_for_SHA_2_by_flag()
    {
        FakeAgent agent = new(Rsa);
        (AuthenticatedUser? user, Exception? failure) = await LogInAsync(Accepting(Rsa.PublicKey), Credential(agent));
        Assert.Null(failure);
        Assert.NotNull(user);
        Assert.Contains(agent.Flags.Single(), new uint[] { 2, 4 });
    }

    [Fact]
    public async Task Only_keys_the_server_would_take_are_signed_with()
    {
        using SshPrivateKey other = SshPrivateKey.GenerateEd25519();
        FakeAgent agent = new(other, Key);
        (AuthenticatedUser? user, _) = await LogInAsync(Accepting(Key.PublicKey), Credential(agent));
        Assert.NotNull(user);
        Assert.Equal(1, agent.SignRequests);
    }

    [Fact]
    public async Task A_lying_agent_is_caught_before_the_signature_is_sent()
    {
        using SshPrivateKey wrong = SshPrivateKey.GenerateEd25519();
        FakeAgent agent = new(Key) { SignWith = wrong };
        int proofs = 0;
        ServerAuthOptions server = new()
        {
            PublicKey = (_, _, _) =>
            {
                proofs++;
                return ValueTask.FromResult(AuthDecision.Accept);
            },
            MaxAttempts = 6,
        };

        (AuthenticatedUser? user, Exception? failure) = await LogInAsync(server, Credential(agent));
        Assert.Null(user);
        Assert.Contains("doesn't verify", Assert.IsType<SshAuthenticationException>(failure).Message);
        Assert.Equal(1, proofs); // The query only. A signature would have run the handler a second time.
    }

    [Fact]
    public async Task A_credential_after_a_lying_agent_still_works()
    {
        using SshPrivateKey wrong = SshPrivateKey.GenerateEd25519();
        FakeAgent agent = new(Key) { SignWith = wrong };
        (AuthenticatedUser? user, Exception? failure) = await LogInAsync(Accepting(Key.PublicKey), Credential(agent), SshCredential.FromPassword("secret"));
        Assert.Null(failure);
        Assert.Equal(["password"], user!.Methods);
    }

    [Fact]
    public async Task An_agent_that_ignores_the_hash_flag_is_refused()
    {
        FakeAgent agent = new(Rsa) { ForceAlgorithm = "rsa-sha2-256" };
        FakeAgent other = new(Rsa) { ForceAlgorithm = "rsa-sha2-512" };

        (AuthenticatedUser? first, Exception? firstFailure) = await LogInAsync(Accepting(Rsa.PublicKey), Credential(agent));
        (AuthenticatedUser? second, Exception? secondFailure) = await LogInAsync(Accepting(Rsa.PublicKey), Credential(other));

        // The client asks for one of the two. Whichever it is, the agent that used the other is the one refused.
        Assert.True(first is null != second is null);
        Assert.Contains("doesn't verify", ((firstFailure ?? secondFailure)!).Message);
    }

    [Fact]
    public async Task A_key_the_agent_refuses_moves_on_to_the_next()
    {
        using SshPrivateKey second = SshPrivateKey.GenerateEd25519();
        FakeAgent agent = new(Key, second) { Refuses = blob => blob.AsSpan().SequenceEqual(Key.PublicKey.Blob.Span) };
        (AuthenticatedUser? user, Exception? failure) = await LogInAsync(Accepting(Key.PublicKey, second.PublicKey), Credential(agent));
        Assert.Null(failure);
        Assert.NotNull(user);
        Assert.Equal(2, agent.SignRequests);
    }

    [Fact]
    public async Task Offers_stop_at_the_cap_and_the_failure_says_why()
    {
        SshPrivateKey[] keys = [.. Enumerable.Range(0, 8).Select(_ => SshPrivateKey.GenerateEd25519())];
        int offers = 0;
        ServerAuthOptions server = new()
        {
            PublicKey = (_, _, _) =>
            {
                offers++;
                return ValueTask.FromResult(AuthDecision.Reject);
            },
            MaxAttempts = 6,
        };

        (_, Exception? failure) = await LogInAsync(server, Credential(new FakeAgent(keys)));

        SshAuthenticationException refused = Assert.IsType<SshAuthenticationException>(failure);
        Assert.Equal(AgentCredential.DefaultMaxKeysOffered, offers);
        Assert.Contains("holds 8 usable keys", refused.Message);
        Assert.Contains("only 5 were offered", refused.Message);
        Assert.Contains("MaxAuthTries", refused.Message);
    }

    [Fact]
    public async Task The_cap_counts_keys_already_refused_in_this_login()
    {
        SshPrivateKey[] keys = [.. Enumerable.Range(0, 8).Select(_ => SshPrivateKey.GenerateEd25519())];
        using SshPrivateKey fileKey = SshPrivateKey.GenerateEd25519();
        int offers = 0;
        ServerAuthOptions server = new()
        {
            PublicKey = (_, _, _) =>
            {
                offers++;
                return ValueTask.FromResult(AuthDecision.Reject);
            },
            MaxAttempts = 6,
        };

        await LogInAsync(server, new PrivateKeyCredential(() => fileKey, ownsKey: false), Credential(new FakeAgent(keys)));
        Assert.Equal(AgentCredential.DefaultMaxKeysOffered, offers);
    }

    [Fact]
    public async Task A_password_after_a_capped_agent_still_gets_its_turn()
    {
        SshPrivateKey[] keys = [.. Enumerable.Range(0, 8).Select(_ => SshPrivateKey.GenerateEd25519())];
        (AuthenticatedUser? user, Exception? failure) = await LogInAsync(Accepting(), Credential(new FakeAgent(keys)), SshCredential.FromPassword("secret"));
        Assert.Null(failure);
        Assert.Equal(["password"], user!.Methods);
    }

    [Fact]
    public async Task The_cap_can_be_raised()
    {
        SshPrivateKey[] keys = [.. Enumerable.Range(0, 7).Select(_ => SshPrivateKey.GenerateEd25519())];
        ServerAuthOptions server = Accepting(keys[6].PublicKey);
        server = new ServerAuthOptions { PublicKey = server.PublicKey, MaxAttempts = 10 };
        (AuthenticatedUser? user, _) = await LogInAsync(server, Credential(new FakeAgent(keys), max: 7));
        Assert.NotNull(user);
    }

    [Fact]
    public async Task An_empty_agent_says_so()
    {
        (_, Exception? failure) = await LogInAsync(Accepting(), Credential(new FakeAgent()));
        Assert.Contains("holds no keys", failure!.Message);
    }

    [Fact]
    public async Task A_missing_agent_says_so_and_later_credentials_still_run()
    {
        string path = Path.Combine(Path.GetTempPath(), $"zorg-no-agent-{Guid.NewGuid():N}");
        SshCredential agent = SshCredential.FromAgent(path);

        (_, Exception? failure) = await LogInAsync(Accepting(), agent);
        Assert.Contains("Couldn't reach the ssh-agent", failure!.Message);

        (AuthenticatedUser? user, _) = await LogInAsync(Accepting(), agent, SshCredential.FromPassword("secret"));
        Assert.NotNull(user);
    }

    [Fact]
    public async Task An_optional_agent_that_is_missing_stays_quiet()
    {
        AgentCredential agent = new(_ => throw new SshAgentException("nothing there"), 5, isOptional: true);
        (_, Exception? failure) = await LogInAsync(Accepting(), agent);
        Assert.DoesNotContain("nothing there", failure!.Message);
    }

    [Fact]
    public void The_limit_must_be_at_least_one()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => SshCredential.FromAgent(maxKeysOffered: 0));
    }

    [Fact]
    public void The_path_given_beats_the_environment_and_the_environment_beats_the_default()
    {
        string? saved = Environment.GetEnvironmentVariable(SshAgentEndpoint.Variable);
        try
        {
            Environment.SetEnvironmentVariable(SshAgentEndpoint.Variable, "/run/from-env");
            Assert.Equal("/run/from-env", SshAgentEndpoint.Resolve(null));
            Assert.Equal("/run/given", SshAgentEndpoint.Resolve("/run/given"));

            Environment.SetEnvironmentVariable(SshAgentEndpoint.Variable, null);
            Assert.Equal(OperatingSystem.IsWindows() ? @"\\.\pipe\openssh-ssh-agent" : null, SshAgentEndpoint.Resolve(null));
        }
        finally
        {
            Environment.SetEnvironmentVariable(SshAgentEndpoint.Variable, saved);
        }
    }

    [Fact]
    public async Task The_named_pipe_transport_carries_the_protocol()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Named pipes are the Windows transport.");
        string name = $"zorg-agent-test-{Guid.NewGuid():N}";
        await using NamedPipeServerStream server = new(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        Task serving = ServeOneListAsync(server, () => server.WaitForConnectionAsync(Ct));

        await using SshAgentConnection agent = new(await SshAgentEndpoint.ConnectAsync($@"\\.\pipe\{name}", Ct), TimeSpan.FromSeconds(10));
        Assert.Single(await agent.ListIdentitiesAsync(Ct));
        await serving;
    }

    [Fact]
    public async Task The_unix_socket_transport_carries_the_protocol()
    {
        using TempDirectory directory = new();
        string path = Path.Combine(directory.Path, "agent.sock");
        using Socket listener = new(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        listener.Bind(new UnixDomainSocketEndPoint(path));
        listener.Listen(1);
        Task serving = Task.Run(
            async () =>
            {
                using Socket accepted = await listener.AcceptAsync(Ct);
                await using NetworkStream stream = new(accepted);
                await ServeOneListAsync(stream, () => Task.CompletedTask);
            },
            Ct);

        await using SshAgentConnection agent = new(await SshAgentEndpoint.ConnectAsync(path, Ct), TimeSpan.FromSeconds(10));
        Assert.Single(await agent.ListIdentitiesAsync(Ct));
        await serving;
    }

    private static async Task ServeOneListAsync(Stream stream, Func<Task> connected)
    {
        await connected();
        byte[] request = new byte[5];
        await stream.ReadExactlyAsync(request, Ct);
        Assert.Equal(11, request[4]);
        await stream.WriteAsync(new FakeAgent(Key).Respond([11])!, Ct);
        await stream.FlushAsync(Ct);
    }

    /// <summary>A stream whose reads never finish, and which doesn't look at its token.</summary>
    private sealed class DeafStream : MemoryStream
    {
        private readonly TaskCompletionSource<int> _never = new();

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) => ValueTask.CompletedTask;

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => new(_never.Task);
    }
}

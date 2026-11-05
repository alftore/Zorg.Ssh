using System;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Auth;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Transport;
using static Zorg.Ssh.Tests.Transport.TransportHarness;

namespace Zorg.Ssh.Tests.Auth;

public class AuthTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static readonly SshPrivateKey UserKey = SshPrivateKey.GenerateEd25519();

    private static ServerAuthOptions PasswordOnly(string good = "secret") => new()
    {
        Password = (_, password, _) => ValueTask.FromResult(password == good ? AuthDecision.Accept : AuthDecision.Reject),
    };

    private static async Task<(AuthenticatedUser? User, Exception? ClientFailure)> RunAsync(ServerAuthOptions server, params SshCredential[] credentials)
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

    [Fact]
    public async Task A_good_password_logs_in()
    {
        (AuthenticatedUser? user, Exception? failure) = await RunAsync(PasswordOnly(), SshCredential.FromPassword("secret"));
        Assert.Null(failure);
        Assert.Equal("alice", user!.Name);
        Assert.Equal(["password"], user.Methods);
    }

    [Fact]
    public async Task A_bad_password_fails_without_echoing_it()
    {
        (AuthenticatedUser? user, Exception? failure) = await RunAsync(PasswordOnly(), SshCredential.FromPassword("hunter2"));
        Assert.Null(user);
        SshAuthenticationException ex = Assert.IsType<SshAuthenticationException>(failure);
        Assert.DoesNotContain("hunter2", ex.Message);
    }

    [Fact]
    public async Task A_public_key_needs_a_real_signature()
    {
        ServerAuthOptions options = new()
        {
            PublicKey = (_, key, _) => ValueTask.FromResult(
                key.Blob.Span.SequenceEqual(UserKey.PublicKey.Blob.Span) ? AuthDecision.Accept : AuthDecision.Reject),
        };
        (AuthenticatedUser? user, Exception? failure) = await RunAsync(options, new PrivateKeyCredential(() => UserKey, ownsKey: false));
        Assert.Null(failure);
        Assert.Equal(["publickey"], user!.Methods);
        Assert.True(user.Key!.Blob.Span.SequenceEqual(UserKey.PublicKey.Blob.Span));
    }

    private static byte[] Request(string user, string service, string method, Action<SshRequestWriter>? body = null)
    {
        SshRequestWriter w = new();
        w.Byte(MessageNumber.UserAuthRequest);
        w.String(user);
        w.String(service);
        w.String(method);
        body?.Invoke(w);
        return w.ToArray();
    }

    private static byte[] ServiceRequest()
    {
        SshRequestWriter w = new();
        w.Byte(MessageNumber.ServiceRequest);
        w.String("ssh-userauth");
        return w.ToArray();
    }

    /// <summary>Connects a raw client to the server authenticator, past the service request.</summary>
    private static async Task WithRawClient(ServerAuthOptions options, Func<SshTransport, Task<AuthenticatedUser>, Task> script)
    {
        (SshTransport client, SshTransport server) = await ConnectAsync(ClientOptions(), ServerOptions(), Ct);
        await using (client)
        await using (server)
        {
            Task<AuthenticatedUser> auth = new ServerAuthenticator(server, options).AuthenticateAsync(Ct);
            await client.SendAsync(ServiceRequest(), Ct);
            client.SetPhase(TransportPhase.AwaitService);
            ReadOnlyMemory<byte> accept = await client.ReceiveAsync(Ct);
            Assert.Equal(MessageNumber.ServiceAccept, accept.Span[0]);
            client.SetPhase(TransportPhase.Auth);
            await script(client, auth);
        }
    }

    [Fact]
    public Task Too_many_failures_end_the_connection() => WithRawClient(
        PasswordOnly(),
        async (client, auth) =>
        {
            byte[] attempt = Request("alice", "ssh-connection", "password", w =>
            {
                w.Bool(false);
                w.String("nope");
            });
            for (int i = 0; i < 6; i++)
            {
                await client.SendAsync(attempt, Ct);
            }

            await Assert.ThrowsAsync<SshProtocolException>(() => auth);
        });

    [Fact]
    public Task A_change_of_user_ends_the_connection() => WithRawClient(
        PasswordOnly(),
        async (client, auth) =>
        {
            await client.SendAsync(Request("alice", "ssh-connection", "none"), Ct);
            await client.SendAsync(Request("root", "ssh-connection", "none"), Ct);
            await Assert.ThrowsAsync<SshProtocolException>(() => auth);
        });

    [Fact]
    public Task An_unknown_service_ends_the_connection() => WithRawClient(
        PasswordOnly(),
        async (client, auth) =>
        {
            await client.SendAsync(Request("alice", "ssh-evil", "none"), Ct);
            await Assert.ThrowsAsync<SshProtocolException>(() => auth);
        });

    [Fact]
    public Task A_forged_signature_never_logs_in() => WithRawClient(
        new ServerAuthOptions { PublicKey = (_, _, _) => ValueTask.FromResult(AuthDecision.Accept) },
        async (client, auth) =>
        {
            byte[] forged = UserKey.Sign("ssh-ed25519", "something else entirely"u8);
            byte[] blob = UserKey.PublicKey.Blob.ToArray();
            await client.SendAsync(
                Request("alice", "ssh-connection", "publickey", w =>
                {
                    w.Bool(true);
                    w.String("ssh-ed25519");
                    w.Bytes(blob);
                    w.Bytes(forged);
                }),
                Ct);
            ReadOnlyMemory<byte> reply = await client.ReceiveAsync(Ct);
            Assert.Equal(MessageNumber.UserAuthFailure, reply.Span[0]);
            Assert.False(auth.IsCompleted);
        });

    // AsyncSSH CVE-2023-46446 shape: a server can't skip the client's auth by sending success early.
    [Fact]
    public async Task USERAUTH_SUCCESS_before_the_auth_phase_ends_the_connection()
    {
        (SshTransport client, SshTransport server) = await ConnectAsync(ClientOptions(), ServerOptions(), Ct);
        await using (client)
        await using (server)
        {
            await server.SendAsync(new byte[] { MessageNumber.UserAuthSuccess }, Ct);
            await Assert.ThrowsAnyAsync<SshProtocolException>(
                () => new ClientAuthenticator(client, "alice", null).AuthenticateAsync([], Ct));
        }
    }

    [Fact]
    public Task A_flood_of_prompts_is_refused() => WithPromptReply(100);

    private static async Task WithPromptReply(uint count)
    {
        (SshTransport client, SshTransport server) = await ConnectAsync(ClientOptions(), ServerOptions(), Ct);
        await using (client)
        await using (server)
        {
            Task clientAuth = new ClientAuthenticator(client, "alice", null).AuthenticateAsync(
                [SshCredential.FromKeyboardInteractive((_, _) => throw new InvalidOperationException("must not run"))],
                Ct);

            server.SetPhase(TransportPhase.AwaitService);
            await server.ReceiveAsync(Ct);
            SshRequestWriter accept = new();
            accept.Byte(MessageNumber.ServiceAccept);
            accept.String("ssh-userauth");
            await server.SendAsync(accept.ToArray(), Ct);
            server.SetPhase(TransportPhase.Auth);

            await server.ReceiveAsync(Ct);
            SshRequestWriter methods = new();
            methods.Byte(MessageNumber.UserAuthFailure);
            methods.Bytes("keyboard-interactive"u8.ToArray());
            methods.Bool(false);
            await server.SendAsync(methods.ToArray(), Ct);

            await server.ReceiveAsync(Ct);
            SshRequestWriter prompts = new();
            prompts.Byte(60);
            prompts.String(string.Empty);
            prompts.String(string.Empty);
            prompts.String(string.Empty);
            prompts.UInt32(count);
            await server.SendAsync(prompts.ToArray(), Ct);

            await Assert.ThrowsAsync<SshProtocolException>(() => clientAuth);
        }
    }
}

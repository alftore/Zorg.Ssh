using System;
using System.Collections.Generic;
using System.Linq;
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

    /// <summary>A publickey request with a real signature over this session.</summary>
    private static byte[] SignedKeyRequest(SshTransport client, SshPrivateKey key)
    {
        byte[] blob = key.PublicKey.Blob.ToArray();
        SshWriter signed = new(512);
        byte[] data;
        try
        {
            signed.WriteBinary(client.SessionId.Span);
            signed.WriteByte(MessageNumber.UserAuthRequest);
            signed.WriteUtf8String("alice");
            signed.WriteUtf8String("ssh-connection");
            signed.WriteUtf8String("publickey");
            signed.WriteBoolean(true);
            signed.WriteUtf8String("ssh-ed25519");
            signed.WriteBinary(blob);
            data = signed.ToArray();
        }
        finally
        {
            signed.Dispose();
        }

        byte[] signature = key.Sign("ssh-ed25519", data);
        return Request("alice", "ssh-connection", "publickey", w =>
        {
            w.Bool(true);
            w.String("ssh-ed25519");
            w.Bytes(blob);
            w.Bytes(signature);
        });
    }

    private static byte[] PasswordRequest() => Request("alice", "ssh-connection", "password", w =>
    {
        w.Bool(false);
        w.String("pw");
    });

    /// <summary>Reads the server's answer to a request, and returns whether it said the login is only partly done.</summary>
    private static async Task<bool> ExpectFailureAsync(SshTransport client)
    {
        ReadOnlyMemory<byte> reply = await client.ReceiveAsync(Ct);
        Assert.Equal(MessageNumber.UserAuthFailure, reply.Span[0]);
        SshReader reader = new(reply.Span);
        reader.ReadByte();
        reader.ReadNameList();
        return reader.ReadBoolean();
    }

    private static ServerAuthOptions KeyThenPassword() => new()
    {
        PublicKey = (_, _, _) => ValueTask.FromResult(AuthDecision.Accept),
        Password = (_, _, _) => ValueTask.FromResult(AuthDecision.Accept),
        RequiredMethods = ["publickey", "password"],
        MaxAttempts = 100,
    };

    // R18: the second key used to overwrite the first on the record, though only the first step counted.
    [Fact]
    public Task Every_key_proven_in_a_partial_login_stays_on_the_record() => WithRawClient(
        KeyThenPassword(),
        async (client, auth) =>
        {
            using SshPrivateKey first = SshPrivateKey.GenerateEd25519();
            using SshPrivateKey second = SshPrivateKey.GenerateEd25519();

            await client.SendAsync(SignedKeyRequest(client, first), Ct);
            Assert.True(await ExpectFailureAsync(client));

            // Go CVE-2026-39828: a second key can't stand in for the second required method.
            await client.SendAsync(SignedKeyRequest(client, second), Ct);
            Assert.False(await ExpectFailureAsync(client));
            Assert.False(auth.IsCompleted);

            await client.SendAsync(PasswordRequest(), Ct);
            AuthenticatedUser user = await auth.WaitAsync(TimeSpan.FromSeconds(20), Ct);

            Assert.Equal(["publickey", "password"], user.Methods);
            Assert.Equal(2, user.ProvenKeys.Count);
            Assert.True(user.ProvenKeys[0].Blob.Span.SequenceEqual(first.PublicKey.Blob.Span));
            Assert.True(user.ProvenKeys[1].Blob.Span.SequenceEqual(second.PublicKey.Blob.Span));
            Assert.True(user.Key!.Blob.Span.SequenceEqual(second.PublicKey.Blob.Span));
        });

    [Fact]
    public Task The_same_key_offered_twice_is_recorded_once() => WithRawClient(
        KeyThenPassword(),
        async (client, auth) =>
        {
            using SshPrivateKey key = SshPrivateKey.GenerateEd25519();
            await client.SendAsync(SignedKeyRequest(client, key), Ct);
            Assert.True(await ExpectFailureAsync(client));
            await client.SendAsync(SignedKeyRequest(client, key), Ct);
            Assert.False(await ExpectFailureAsync(client));
            await client.SendAsync(PasswordRequest(), Ct);

            AuthenticatedUser user = await auth.WaitAsync(TimeSpan.FromSeconds(20), Ct);
            Assert.Single(user.ProvenKeys);
        });

    [Fact]
    public Task The_list_of_proven_keys_is_bounded_and_a_key_over_the_limit_is_refused() => WithRawClient(
        KeyThenPassword(),
        async (client, auth) =>
        {
            SshPrivateKey[] keys = [.. Enumerable.Range(0, 9).Select(static _ => SshPrivateKey.GenerateEd25519())];
            try
            {
                for (int i = 0; i < keys.Length; i++)
                {
                    await client.SendAsync(SignedKeyRequest(client, keys[i]), Ct);
                    Assert.Equal(i == 0, await ExpectFailureAsync(client));
                }

                await client.SendAsync(PasswordRequest(), Ct);
                AuthenticatedUser user = await auth.WaitAsync(TimeSpan.FromSeconds(20), Ct);

                // The ninth key was refused, so it is on no record: the principal never claims a key it did not keep.
                Assert.Equal(8, user.ProvenKeys.Count);
                Assert.True(user.Key!.Blob.Span.SequenceEqual(keys[7].PublicKey.Blob.Span));
            }
            finally
            {
                foreach (SshPrivateKey key in keys)
                {
                    key.Dispose();
                }
            }
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

    // A handler of the application's that throws stops the login with an honest SshAuthenticationException.
    [Fact]
    public async Task A_keyboard_interactive_handler_that_throws_stops_the_login()
    {
        SshAuthenticationException ex = await Assert.ThrowsAsync<SshAuthenticationException>(
            () => WithOnePrompt((_, _) => throw new InvalidOperationException("the application's own failure")));

        Assert.IsType<InvalidOperationException>(ex.InnerException);
        Assert.Contains("keyboard-interactive handler threw InvalidOperationException", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("the application's own failure", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("bug", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_keyboard_interactive_handler_with_the_wrong_number_of_answers_stops_the_login()
    {
        SshAuthenticationException ex = await Assert.ThrowsAsync<SshAuthenticationException>(
            () => WithOnePrompt((_, _) => ValueTask.FromResult<IReadOnlyList<string>>(["a", "b"])));

        Assert.Contains("returned 2 answers for 1 prompts", ex.Message, StringComparison.Ordinal);
    }

    private static async Task WithOnePrompt(Func<IReadOnlyList<SshPrompt>, CancellationToken, ValueTask<IReadOnlyList<string>>> respond)
    {
        (SshTransport client, SshTransport server) = await ConnectAsync(ClientOptions(), ServerOptions(), Ct);
        await using (client)
        await using (server)
        {
            Task clientAuth = new ClientAuthenticator(client, "alice", null).AuthenticateAsync([SshCredential.FromKeyboardInteractive(respond)], Ct);

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
            prompts.UInt32(1);
            prompts.String("Code: ");
            prompts.Bool(false);
            await server.SendAsync(prompts.ToArray(), Ct);

            await clientAuth;
        }
    }

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

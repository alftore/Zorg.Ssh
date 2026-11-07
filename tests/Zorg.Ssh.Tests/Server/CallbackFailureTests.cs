using System;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Tests.Fuzzing.Stateful;

namespace Zorg.Ssh.Tests.Server;

/// <summary>
/// Application callbacks that throw fail closed, with an exception that says whose code failed. None of them is
/// reported as a bug in the library, and the application's own message stays out of the library's text.
/// </summary>
public sealed class CallbackFailureTests : IDisposable
{
    private const string Password = "pw-that-must-not-be-logged-5d1";
    private const string Secret = "the application's own message";

    private readonly SshHostKey _hostKey = SshHostKey.GenerateEd25519();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => _hostKey.Dispose();

    [Fact]
    public async Task A_custom_host_key_check_that_throws_is_a_host_key_failure()
    {
        await using SshServer server = await StartAsync();
        SshHostKeyException ex = await Assert.ThrowsAsync<SshHostKeyException>(() => SshClient.ConnectAsync(
            ClientOptions(server) with { HostKeyPolicy = HostKeyPolicy.Custom((_, _) => throw new InvalidOperationException(Secret)) },
            Ct));

        Assert.IsType<InvalidOperationException>(ex.InnerException);
        Assert.Contains("host key check threw InvalidOperationException", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("bug", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_host_key_check_that_cancels_on_its_own_is_a_host_key_failure_too()
    {
        await using SshServer server = await StartAsync();
        SshHostKeyException ex = await Assert.ThrowsAsync<SshHostKeyException>(() => SshClient.ConnectAsync(
            ClientOptions(server) with { HostKeyPolicy = HostKeyPolicy.Custom((_, _) => throw new OperationCanceledException()) },
            Ct));

        Assert.IsType<OperationCanceledException>(ex.InnerException);
    }

    [Fact]
    public async Task A_banner_handler_that_throws_stops_the_login()
    {
        await using SshServer server = await StartAsync(banner: "Authorised use only.");
        SshAuthenticationException ex = await Assert.ThrowsAsync<SshAuthenticationException>(() => SshClient.ConnectAsync(
            ClientOptions(server) with { BannerHandler = _ => throw new FormatException(Secret) },
            Ct));

        Assert.IsType<FormatException>(ex.InnerException);
        Assert.Contains("banner handler threw FormatException", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_password_handler_that_throws_rejects_the_attempt_and_says_so()
    {
        CaptureLoggerFactory logs = new();
        await using SshServer server = await StartAsync(
            password: (_, _) => throw new InvalidOperationException("database down"),
            logs: logs);

        SshAuthenticationException ex = await Assert.ThrowsAsync<SshAuthenticationException>(() => SshClient.ConnectAsync(ClientOptions(server), Ct));
        Assert.Contains("password", ex.AttemptedMethods);

        Assert.Contains(logs.Entries, e => e.Contains("An auth handler threw, so the login attempt was rejected", StringComparison.Ordinal));
        Assert.DoesNotContain(logs.Entries, e => e.Contains(Password, StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_session_handler_that_throws_ends_the_session_with_exit_code_1()
    {
        CaptureLoggerFactory logs = new();
        await using SshServer server = await StartAsync(session: (_, _) => throw new InvalidOperationException("broken"), logs: logs);
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(server), Ct);

        Assert.Equal(1, (await client.ExecuteAsync("x", Ct)).ExitCode);
        Assert.Contains(logs.Entries, e => e.Contains("The session handler threw", StringComparison.Ordinal));
        Assert.DoesNotContain(logs.Entries, e => e.Contains("bug in Zorg.Ssh", StringComparison.Ordinal));
    }

    private Task<SshServer> StartAsync(
        string? banner = null,
        Func<SshPasswordRequest, CancellationToken, ValueTask<SshAuthDecision>>? password = null,
        Func<SshServerSession, CancellationToken, Task<int>>? session = null,
        CaptureLoggerFactory? logs = null) => SshServer.StartAsync(
        new SshServerOptions
        {
            HostKeys = [_hostKey],
            Banner = banner,
            PasswordHandler = password ?? ((request, _) => ValueTask.FromResult(request.Password == Password ? SshAuthDecision.Accept : SshAuthDecision.Reject)),
            SessionHandler = session ?? ((_, _) => Task.FromResult(0)),
            LoggerFactory = logs,
        },
        Ct);

    private SshClientOptions ClientOptions(SshServer server) => new()
    {
        Host = "127.0.0.1",
        Port = server.LocalEndPoint.Port,
        UserName = "alice",
        Credentials = [SshCredential.FromPassword(Password)],
        HostKeyPolicy = HostKeyPolicy.Fingerprint(_hostKey.Sha256Fingerprint),
    };
}

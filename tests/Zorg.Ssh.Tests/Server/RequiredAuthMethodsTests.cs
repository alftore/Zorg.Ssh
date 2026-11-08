using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Zorg.Ssh.Tests.Server;

/// <summary>A5: RequiredAuthMethods is checked when the server is made, not found out at the first login.</summary>
public sealed class RequiredAuthMethodsTests : IDisposable
{
    private readonly SshHostKey _hostKey = SshHostKey.GenerateEd25519();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => _hostKey.Dispose();

    private SshServerOptions Options(IReadOnlyList<string>? required, bool password = true, bool publicKey = true) => new()
    {
        HostKeys = [_hostKey],
        PasswordHandler = password ? static (_, _) => ValueTask.FromResult(SshAuthDecision.Accept) : null,
        PublicKeyHandler = publicKey ? static (_, _) => ValueTask.FromResult(SshAuthDecision.Accept) : null,
        SessionHandler = static (_, _) => Task.FromResult(0),
        RequiredAuthMethods = required,
    };

    [Theory]
    [InlineData("pasword")]
    [InlineData("keyboard-interactive")]
    [InlineData("password,publickey")]
    [InlineData("")]
    public async Task A5_an_unknown_method_name_is_refused(string name)
    {
        SshServerOptions options = Options(["publickey", name]);
        Assert.Throws<ArgumentException>(() => SshServer.Create(options));
        await Assert.ThrowsAsync<ArgumentException>(() => SshServer.StartAsync(options, Ct));
    }

    [Fact]
    public async Task A5_an_empty_list_is_refused()
    {
        Assert.Throws<ArgumentException>(() => SshServer.Create(Options([])));
        await Assert.ThrowsAsync<ArgumentException>(() => SshServer.StartAsync(Options([]), Ct));
    }

    [Fact]
    public void A5_a_null_entry_and_a_repeated_entry_are_refused()
    {
        Assert.Throws<ArgumentException>(() => SshServer.Create(Options(["password", null!])));
        Assert.Throws<ArgumentException>(() => SshServer.Create(Options(["password", "password"])));
    }

    [Fact]
    public async Task A5_a_required_method_without_a_handler_is_refused()
    {
        ArgumentException ex = Assert.Throws<ArgumentException>(() => SshServer.Create(Options(["publickey", "password"], password: false)));
        Assert.Contains("PasswordHandler", ex.Message);
        ex = await Assert.ThrowsAsync<ArgumentException>(() => SshServer.StartAsync(Options(["publickey"], publicKey: false), Ct));
        Assert.Contains("PublicKeyHandler", ex.Message);
    }

    [Fact]
    public async Task A5_valid_lists_still_start()
    {
        await using SshServer both = SshServer.Create(Options(["publickey", "password"]));
        await using SshServer one = SshServer.Create(Options(["password"], publicKey: false));
        await using SshServer started = await SshServer.StartAsync(Options(null), Ct);
    }
}

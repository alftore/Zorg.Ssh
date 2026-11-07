using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Tests.Fuzzing;

namespace Zorg.Ssh.Tests;

/// <summary>
/// The options types are records, so <c>with</c> works on them. Guarantee 4: their printed form holds no secret, because
/// the generated one would print every member, credentials and handlers included.
/// </summary>
public sealed class OptionsRecordTests
{
    private const string Password = "correct-horse-battery-staple-7f3a";
    private const string Passphrase = "passphrase-that-must-not-print-91c";

    [Fact]
    public void Client_options_print_the_host_port_and_user_only()
    {
        string keyText = FuzzKeys.Ed25519OpenSsh;
        SshClientOptions options = new()
        {
            Host = "example.com",
            Port = 2022,
            UserName = "alice",
            Credentials = [SshCredential.FromPassword(Password), SshCredential.FromPrivateKey(keyText, Passphrase)],
            HostKeyPolicy = HostKeyPolicy.Fingerprint("SHA256:abc"),
            BannerHandler = _ => { },
        };

        string text = options.ToString();

        Assert.Equal("SshClientOptions { Host = example.com, Port = 2022, UserName = alice }", text);
        Assert.DoesNotContain(Password, text, StringComparison.Ordinal);
        Assert.DoesNotContain(Passphrase, text, StringComparison.Ordinal);
        foreach (string line in keyText.Split('\n').Where(l => l.Length > 20 && !l.StartsWith("-----", StringComparison.Ordinal)))
        {
            Assert.DoesNotContain(line.Trim(), text, StringComparison.Ordinal);
        }

        // String interpolation goes through the same ToString.
        Assert.DoesNotContain(Password, $"{options}", StringComparison.Ordinal);
    }

    [Fact]
    public void Server_options_print_the_address_and_port_only()
    {
        using SshHostKey key = SshHostKey.GenerateEd25519();
        SshServerOptions options = new()
        {
            Port = 2222,
            HostKeys = [key],
            PasswordHandler = (request, _) => ValueTask.FromResult(request.Password == Password ? SshAuthDecision.Accept : SshAuthDecision.Reject),
            SessionHandler = (_, _) => Task.FromResult(0),
            Banner = "welcome",
        };

        Assert.Equal("SshServerOptions { Address = 127.0.0.1, Port = 2222 }", options.ToString());
    }

    [Fact]
    public void With_copies_options_and_equal_copies_work_as_keys()
    {
        SshClientOptions options = new()
        {
            Host = "example.com",
            UserName = "alice",
            Credentials = [SshCredential.FromPassword(Password)],
            HostKeyPolicy = HostKeyPolicy.Fingerprint("SHA256:abc"),
        };

        SshClientOptions copy = options with { };
        SshClientOptions slower = options with { ConnectTimeout = TimeSpan.FromMinutes(2) };

        Assert.Equal(options, copy);
        Assert.NotEqual(options, slower);
        Assert.Same(options.Credentials, slower.Credentials);
        Assert.Equal(TimeSpan.FromMinutes(2), slower.ConnectTimeout);

        Dictionary<SshClientOptions, int> seen = new() { [options] = 1 };
        Assert.True(seen.ContainsKey(copy));
        Assert.False(seen.ContainsKey(slower));
    }
}

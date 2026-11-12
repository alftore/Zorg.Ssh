using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Auth;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.Keys;

namespace Zorg.Ssh.Tests.Server;

/// <summary>
/// A4: <c>Algorithms.UserKeys</c>, apart from <c>HostKeys</c> as OpenSSH keeps PubkeyAcceptedAlgorithms apart from
/// HostKeyAlgorithms, limits the signature algorithms a server accepts from user keys and what it advertises, and the
/// algorithms a client signs with.
/// </summary>
public sealed class UserKeyAlgorithmTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static async Task<(SshServer Server, SshHostKey HostKey)> StartAsync(SshAlgorithms algorithms, Action<string> seen)
    {
        SshHostKey hostKey = SshHostKey.GenerateEd25519();
        SshServer server = await SshServer.StartAsync(
            new SshServerOptions
            {
                HostKeys = [hostKey],
                Algorithms = algorithms,
                PublicKeyHandler = (request, _) =>
                {
                    seen(request.KeyType);
                    return ValueTask.FromResult(SshAuthDecision.Accept);
                },
                SessionHandler = static (_, _) => Task.FromResult(0),
            },
            Ct);
        return (server, hostKey);
    }

    private static SshClientOptions Options(SshServer server, SshHostKey hostKey, SshPrivateKey userKey, SshAlgorithms? algorithms = null) => new()
    {
        Host = "127.0.0.1",
        Port = server.LocalEndPoint.Port,
        UserName = "alice",
        Credentials = [new PrivateKeyCredential(() => userKey, ownsKey: false)],
        HostKeyPolicy = HostKeyPolicy.Fingerprint(hostKey.Sha256Fingerprint),
        Algorithms = algorithms ?? SshAlgorithms.Default,
    };

    [Fact]
    public async Task A4_narrowing_HostKeys_alone_no_longer_refuses_an_rsa_user_key()
    {
        using SshPrivateKey rsa = SshPrivateKey.GenerateRsa(2048);
        string? keyType = null;
        (SshServer server, SshHostKey hostKey) = await StartAsync(new SshAlgorithms { HostKeys = ["ssh-ed25519"] }, t => keyType = t);
        await using (server)
        using (hostKey)
        {
            await using SshClient client = await SshClient.ConnectAsync(Options(server, hostKey, rsa), Ct);
            Assert.Equal("ssh-rsa", keyType);
        }
    }

    [Fact]
    public async Task A4_an_rsa_user_key_is_refused_before_the_handler_when_UserKeys_names_no_rsa_algorithm()
    {
        using SshPrivateKey rsa = SshPrivateKey.GenerateRsa(2048);
        int handlerCalls = 0;
        (SshServer server, SshHostKey hostKey) = await StartAsync(new SshAlgorithms { UserKeys = ["ssh-ed25519"] }, _ => handlerCalls++);
        await using (server)
        using (hostKey)
        {
            await Assert.ThrowsAsync<SshAuthenticationException>(() => SshClient.ConnectAsync(Options(server, hostKey, rsa), Ct));
            Assert.Equal(0, handlerCalls);
        }
    }

    // OpenSSH CVE-2026-35387: allowing one ECDSA algorithm also let in the other ECDSA curves. Algorithm lists are exact names:
    // with only nistp256 named, a nistp384 user key is refused before the handler, and a nistp256 one logs in.
    [Theory]
    [InlineData("ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", false)]
    [InlineData("ecdsa-sha2-nistp256", "ecdsa-sha2-nistp521", false)]
    [InlineData("ecdsa-sha2-nistp384", "ecdsa-sha2-nistp256", false)]
    [InlineData("ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256", true)]
    public async Task OpenSSH_CVE_2026_35387_naming_one_ECDSA_algorithm_admits_no_other_curve(string allowed, string keyType, bool logsIn)
    {
        using SshPrivateKey key = SshPrivateKey.GenerateEcdsa(keyType);
        int handlerCalls = 0;
        (SshServer server, SshHostKey hostKey) = await StartAsync(new SshAlgorithms { UserKeys = [allowed, "ssh-ed25519"] }, _ => handlerCalls++);
        await using (server)
        using (hostKey)
        {
            if (logsIn)
            {
                await using SshClient client = await SshClient.ConnectAsync(Options(server, hostKey, key), Ct);
                Assert.True(handlerCalls > 0);
            }
            else
            {
                // The client is free to sign with this curve (its own list names it), so the refusal is the server's.
                await Assert.ThrowsAsync<SshAuthenticationException>(() => SshClient.ConnectAsync(Options(server, hostKey, key, new SshAlgorithms { UserKeys = [keyType] }), Ct));
                Assert.Equal(0, handlerCalls);
            }
        }
    }

    [Fact]
    public async Task A4_an_ed25519_user_key_still_logs_in_when_UserKeys_is_narrowed()
    {
        using SshPrivateKey ed = SshPrivateKey.GenerateEd25519();
        string? keyType = null;
        (SshServer server, SshHostKey hostKey) = await StartAsync(new SshAlgorithms { UserKeys = ["ssh-ed25519"] }, t => keyType = t);
        await using (server)
        using (hostKey)
        {
            await using SshClient client = await SshClient.ConnectAsync(Options(server, hostKey, ed), Ct);
            Assert.Equal("ssh-ed25519", keyType);
        }
    }

    [Fact]
    public async Task A4_an_rsa_user_key_logs_in_when_UserKeys_names_an_rsa_algorithm()
    {
        using SshPrivateKey rsa = SshPrivateKey.GenerateRsa(2048);
        string? keyType = null;
        (SshServer server, SshHostKey hostKey) = await StartAsync(new SshAlgorithms { HostKeys = ["ssh-ed25519"], UserKeys = ["ssh-ed25519", "rsa-sha2-256"] }, t => keyType = t);
        await using (server)
        using (hostKey)
        {
            await using SshClient client = await SshClient.ConnectAsync(Options(server, hostKey, rsa), Ct);
            Assert.Equal("ssh-rsa", keyType);
        }
    }

    [Fact]
    public void A4_server_sig_algs_follows_UserKeys_and_not_HostKeys()
    {
        Assert.Equal(HostKeyAlgorithms.Default, SshAlgorithms.Default.ServerSignatureAlgorithms);
        Assert.Equal(HostKeyAlgorithms.Default, new SshAlgorithms { HostKeys = ["ssh-ed25519"] }.ServerSignatureAlgorithms);
        Assert.Equal(["rsa-sha2-256", "ssh-ed25519"], new SshAlgorithms { UserKeys = ["rsa-sha2-256", "ssh-ed25519"] }.ServerSignatureAlgorithms);
        Assert.Equal([.. HostKeyAlgorithms.Default, "ssh-rsa"], SshAlgorithms.LegacyUnsafe.ServerSignatureAlgorithms);
        Assert.DoesNotContain("ssh-rsa", (SshAlgorithms.LegacyUnsafe with { UserKeys = ["rsa-sha2-512"] }).ServerSignatureAlgorithms);
    }

    [Fact]
    public void A4_ssh_rsa_SHA_1_for_user_keys_needs_UserKeys_to_name_it()
    {
        Assert.False(SshAlgorithms.Default.UserKeysAllowRsaSha1);
        Assert.True(SshAlgorithms.LegacyUnsafe.UserKeysAllowRsaSha1);

        // HostKeys naming ssh-rsa allows it for host keys only.
        Assert.False((SshAlgorithms.LegacyUnsafe with { UserKeys = ["rsa-sha2-512", "rsa-sha2-256"] }).UserKeysAllowRsaSha1);

        // And UserKeys naming it doesn't need HostKeys to.
        SshAlgorithms userOnly = SshAlgorithms.LegacyUnsafe with { HostKeys = ["ssh-ed25519"], UserKeys = ["ssh-rsa"] };
        userOnly.Validate();
        Assert.True(userOnly.UserKeysAllowRsaSha1);
    }

    [Fact]
    public void A4_UserKeys_is_validated_like_the_other_lists()
    {
        Assert.Contains("can't be empty", Assert.Throws<ArgumentException>(() => new SshAlgorithms { UserKeys = [] }.Validate()).Message, StringComparison.Ordinal);
        Assert.Contains("SshAlgorithms.UserKeys", Assert.Throws<ArgumentException>(() => new SshAlgorithms { UserKeys = ["ssh-dss"] }.Validate()).Message, StringComparison.Ordinal);
        Assert.Contains("UserKeys = [", SshAlgorithms.Default.ToString(), StringComparison.Ordinal);
        Assert.NotEqual(SshAlgorithms.Default, SshAlgorithms.Default with { UserKeys = ["ssh-ed25519"] });
    }

    [Fact]
    public void A4_a_client_signs_only_with_what_UserKeys_names_and_certificates_count_as_their_plain_name()
    {
        using SshPrivateKey rsa = SshPrivateKey.GenerateRsa(2048);
        Assert.Equal(rsa.SignatureAlgorithms, ClientAuthenticator.Permitted(rsa.SignatureAlgorithms, null));
        Assert.Equal(["rsa-sha2-256"], ClientAuthenticator.Permitted(rsa.SignatureAlgorithms, ["ssh-ed25519", "rsa-sha2-256"]));
        Assert.Empty(ClientAuthenticator.Permitted(rsa.SignatureAlgorithms, ["ssh-ed25519"]));

        string[] certificate = ["rsa-sha2-512-cert-v01@openssh.com", "rsa-sha2-256-cert-v01@openssh.com"];
        Assert.Equal(["rsa-sha2-256-cert-v01@openssh.com"], ClientAuthenticator.Permitted(certificate, ["rsa-sha2-256"]));

        // With only ssh-rsa left, a key signs with it, whatever server-sig-algs says.
        Dictionary<string, byte[]> extensions = new() { ["server-sig-algs"] = "rsa-sha2-512"u8.ToArray() };
        Assert.Equal("ssh-rsa", ClientAuthenticator.SignatureAlgorithmFor([], extensions, rsaSha1: true));
    }

    [Fact]
    public async Task A4_a_client_skips_a_key_UserKeys_leaves_nothing_for_and_says_so()
    {
        using SshPrivateKey rsa = SshPrivateKey.GenerateRsa(2048);
        int handlerCalls = 0;
        (SshServer server, SshHostKey hostKey) = await StartAsync(SshAlgorithms.Default, _ => handlerCalls++);
        await using (server)
        using (hostKey)
        {
            SshAuthenticationException failure = await Assert.ThrowsAsync<SshAuthenticationException>(
                () => SshClient.ConnectAsync(Options(server, hostKey, rsa, new SshAlgorithms { UserKeys = ["ssh-ed25519"] }), Ct));
            Assert.Contains("SshAlgorithms.UserKeys names none of its signature algorithms", failure.Message, StringComparison.Ordinal);
            Assert.Equal(0, handlerCalls);
        }
    }
}

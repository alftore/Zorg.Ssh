using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Zorg.Ssh.Tests.Server;

/// <summary>A7: a client-chosen user name can't forge log lines through the descriptions of the server's request and principal types.</summary>
public sealed class UserNameDisplayTests
{
    private const string Forged = "bob\r\n2026-11-08 INFO accepted publickey for admin‮";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public void A7_ToString_removes_control_characters_and_caps_the_length()
    {
        string description = new SshPasswordRequest { UserName = Forged, Password = "pw" }.ToString();
        Assert.DoesNotContain('\n', description);
        Assert.DoesNotContain('\r', description);
        Assert.DoesNotContain('‮', description);
        Assert.Contains("bob2026-11-08 INFO accepted publickey for admin", description);

        string longName = new('a', 10_000);
        Assert.True(new SshPublicKeyRequest { UserName = longName, KeyType = "ssh-ed25519", Sha256Fingerprint = "SHA256:x" }.ToString().Length < 512);
    }

    [Fact]
    public void A7_the_public_key_request_and_the_principal_are_cleaned_too()
    {
        string request = new SshPublicKeyRequest { UserName = Forged, KeyType = "ssh-ed25519", Sha256Fingerprint = "SHA256:x" }.ToString();
        Assert.DoesNotContain('\n', request);
        Assert.Contains("KeyType = ssh-ed25519", request);
        Assert.Contains("SHA256:x", request);

        string principal = new SshPrincipal { UserName = Forged, Methods = ["publickey"], KeyFingerprints = ["SHA256:x"] }.ToString();
        Assert.DoesNotContain('\n', principal);
        Assert.DoesNotContain('‮', principal);
        Assert.Contains("publickey", principal);
    }

    [Fact]
    public async Task A7_the_name_property_stays_exact_and_the_principal_description_is_clean_end_to_end()
    {
        using SshHostKey hostKey = SshHostKey.GenerateEd25519();
        string? passwordUser = null;
        string? principalText = null;
        string? principalName = null;
        await using SshServer server = await SshServer.StartAsync(
            new SshServerOptions
            {
                HostKeys = [hostKey],
                PasswordHandler = (request, _) =>
                {
                    passwordUser = request.UserName;
                    return ValueTask.FromResult(SshAuthDecision.Accept);
                },
                SessionHandler = (session, _) =>
                {
                    principalName = session.Principal.UserName;
                    principalText = session.Principal.ToString();
                    return Task.FromResult(0);
                },
            },
            Ct);
        await using SshClient client = await SshClient.ConnectAsync(
            new SshClientOptions
            {
                Host = "127.0.0.1",
                Port = server.LocalEndPoint.Port,
                UserName = Forged,
                Credentials = [SshCredential.FromPassword("pw")],
                HostKeyPolicy = HostKeyPolicy.Fingerprint(hostKey.Sha256Fingerprint),
            },
            Ct);
        await client.ExecuteAsync("x", Ct);
        Assert.Equal(Forged, passwordUser);
        Assert.Equal(Forged, principalName);
        Assert.NotNull(principalText);
        Assert.DoesNotContain('\n', principalText);
    }
}

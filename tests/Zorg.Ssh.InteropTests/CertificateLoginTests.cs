using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Zorg.Ssh.InteropTests;

/// <summary>
/// Certificates against real sshd, all made by real <c>ssh-keygen -s</c>. In these tests known_hosts holds only a
/// <c>@cert-authority</c> line, so a connection that works can only have come through the certificate.
/// </summary>
public sealed class CertificateLoginTests : IDisposable
{
    private readonly KeygenTool _keygen = new();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => _keygen.Dispose();

    /// <summary>Starts sshd with this host key and certificate, trusting this user CA. It has no authorized_keys.</summary>
    private static async Task<SshPeerContainer> StartAsync(string hostKey, string hostCertificate, string userCa)
    {
        PeerTools.RequireContainers();
        string image = await SshPeerContainer.BuildImageAsync("zorg-ssh-test/openssh-10", Path.Combine(PeerTools.PeersPath, "openssh-10"), Ct);
        string script = ContainerScript.WriteFile(hostKey, "/etc/ssh/test_host_key", "600")
            + ContainerScript.WriteFile(hostCertificate, "/etc/ssh/test_host_cert.pub")
            + ContainerScript.WriteFile(userCa + ".pub", "/etc/ssh/user_ca.pub")
            + "exec /usr/sbin/sshd -D -e -h /etc/ssh/test_host_key -o HostCertificate=/etc/ssh/test_host_cert.pub"
            + " -o TrustedUserCAKeys=/etc/ssh/user_ca.pub -o PasswordAuthentication=no";
        return await SshPeerContainer.StartAsync(image, ["/bin/sh", "-c", script], cancellationToken: Ct);
    }

    private string KnownHosts(string prefix, string marker, string key)
    {
        string path = _keygen.PathOf($"known_hosts-{Guid.NewGuid():N}");
        File.WriteAllText(path, $"{marker} {prefix} {File.ReadAllText(key + ".pub")}");
        return path;
    }

    private static SshClientOptions Options(SshPeerContainer container, string knownHosts, SshCredential credential, string? host = null) => new()
    {
        Host = host ?? container.Host,
        Port = container.Port,
        UserName = "zorg",
        Credentials = [credential],
        HostKeyPolicy = HostKeyPolicy.KnownHostsFile(knownHosts),
    };

    private static async Task AssertLogsInAsync(SshClientOptions options)
    {
        await using SshClient client = await SshClient.ConnectAsync(options, Ct);
        Assert.Equal("zorg\n", (await client.ExecuteAsync("whoami", Ct)).StandardOutput);
    }

    private async Task<(string User, string UserCertificate, string HostCa, string UserCa, string HostKey, string HostCertificate)> MakeAsync(
        string type = "ed25519",
        string bits = "256",
        string validity = "always:forever",
        string? principal = null)
    {
        string hostCa = await _keygen.GenerateAsync("ed25519", "256");
        string userCa = await _keygen.GenerateAsync("ed25519", "256");
        string hostKey = await _keygen.GenerateAsync(type, bits);
        string user = await _keygen.GenerateAsync(type, bits);
        string hostCertificate = await _keygen.SignAsync(hostCa, hostKey, "-h", "-n", principal ?? "127.0.0.1", "-V", validity);
        string userCertificate = await _keygen.SignAsync(userCa, user, "-n", "zorg");
        return (user, userCertificate, hostCa, userCa, hostKey, hostCertificate);
    }

    [InteropTheory]
    [InlineData("ed25519", "256")]
    [InlineData("ecdsa", "256")]
    [InlineData("ecdsa", "384")]
    [InlineData("ecdsa", "521")]
    [InlineData("rsa", "3072")]
    public async Task A_user_certificate_logs_in_and_a_host_certificate_is_verified(string type, string bits)
    {
        var made = await MakeAsync(type, bits);
        await using SshPeerContainer container = await StartAsync(made.HostKey, made.HostCertificate, made.UserCa);
        string knownHosts = KnownHosts($"[{container.Host}]:{container.Port}", "@cert-authority", made.HostCa);

        await AssertLogsInAsync(Options(container, knownHosts, SshCredential.FromPrivateKeyFile(made.User, null, made.UserCertificate)));
    }

    [InteropTheory]
    [InlineData("rsa", "3072")]
    [InlineData("ecdsa", "384")]
    public async Task A_CA_of_another_type_works_for_users_and_hosts(string caType, string caBits)
    {
        string ca = await _keygen.GenerateAsync(caType, caBits);
        string hostKey = await _keygen.GenerateAsync("ed25519", "256");
        string user = await _keygen.GenerateAsync("ed25519", "256");
        string hostCertificate = await _keygen.SignAsync(ca, hostKey, "-h", "-n", "127.0.0.1");
        string userCertificate = await _keygen.SignAsync(ca, user, "-n", "zorg");
        await using SshPeerContainer container = await StartAsync(hostKey, hostCertificate, ca);
        string knownHosts = KnownHosts($"[{container.Host}]:{container.Port}", "@cert-authority", ca);

        await AssertLogsInAsync(Options(container, knownHosts, SshCredential.FromPrivateKeyFile(user, null, userCertificate)));
    }

    [InteropFact]
    public async Task A_key_without_its_certificate_is_refused_by_sshd()
    {
        var made = await MakeAsync();
        await using SshPeerContainer container = await StartAsync(made.HostKey, made.HostCertificate, made.UserCa);
        string knownHosts = KnownHosts($"[{container.Host}]:{container.Port}", "@cert-authority", made.HostCa);

        await Assert.ThrowsAsync<SshAuthenticationException>(
            () => SshClient.ConnectAsync(Options(container, knownHosts, SshCredential.FromPrivateKeyFile(made.User)), Ct));
    }

    [InteropFact]
    public async Task A_user_certificate_sshd_rejects_fails_the_login()
    {
        var made = await MakeAsync();
        string wrongName = await _keygen.GenerateAsync("ed25519", "256");
        string wrongNameCertificate = await _keygen.SignAsync(made.UserCa, wrongName, "-n", "somebody-else");
        string expired = await _keygen.GenerateAsync("ed25519", "256");
        string expiredCertificate = await _keygen.SignAsync(made.UserCa, expired, "-n", "zorg", "-V", "20200101:20200201");
        string otherCa = await _keygen.GenerateAsync("ed25519", "256");
        string untrusted = await _keygen.GenerateAsync("ed25519", "256");
        string untrustedCertificate = await _keygen.SignAsync(otherCa, untrusted, "-n", "zorg");
        await using SshPeerContainer container = await StartAsync(made.HostKey, made.HostCertificate, made.UserCa);
        string knownHosts = KnownHosts($"[{container.Host}]:{container.Port}", "@cert-authority", made.HostCa);

        foreach ((string key, string certificate) in new[] { (wrongName, wrongNameCertificate), (expired, expiredCertificate), (untrusted, untrustedCertificate) })
        {
            await Assert.ThrowsAsync<SshAuthenticationException>(
                () => SshClient.ConnectAsync(Options(container, knownHosts, SshCredential.FromPrivateKeyFile(key, null, certificate)), Ct));
        }
    }

    [InteropFact]
    public async Task An_expired_host_certificate_from_sshd_is_refused()
    {
        var made = await MakeAsync(validity: "20200101:20200201");
        await using SshPeerContainer container = await StartAsync(made.HostKey, made.HostCertificate, made.UserCa);
        string knownHosts = KnownHosts($"[{container.Host}]:{container.Port}", "@cert-authority", made.HostCa);

        SshHostKeyException refused = await Assert.ThrowsAsync<SshHostKeyException>(
            () => SshClient.ConnectAsync(Options(container, knownHosts, SshCredential.FromPrivateKeyFile(made.User, null, made.UserCertificate)), Ct));
        Assert.Contains("has expired", refused.Message);
    }

    [InteropFact]
    public async Task A_host_certificate_not_yet_valid_from_sshd_is_refused()
    {
        var made = await MakeAsync(validity: "20990101:21000101");
        await using SshPeerContainer container = await StartAsync(made.HostKey, made.HostCertificate, made.UserCa);
        string knownHosts = KnownHosts($"[{container.Host}]:{container.Port}", "@cert-authority", made.HostCa);

        SshHostKeyException refused = await Assert.ThrowsAsync<SshHostKeyException>(
            () => SshClient.ConnectAsync(Options(container, knownHosts, SshCredential.FromPrivateKeyFile(made.User, null, made.UserCertificate)), Ct));
        Assert.Contains("isn't valid yet", refused.Message);
    }

    [InteropFact]
    public async Task Host_certificate_refusals_from_sshd()
    {
        var made = await MakeAsync(principal: "server.example.com,127.0.0.1");
        string other = await _keygen.GenerateAsync("ed25519", "256");
        await using SshPeerContainer container = await StartAsync(made.HostKey, made.HostCertificate, made.UserCa);
        SshCredential credential = SshCredential.FromPrivateKeyFile(made.User, null, made.UserCertificate);
        string name = $"[{container.Host}]:{container.Port}";

        async Task<string> RefusedAsync(string knownHosts, string? host = null) =>
            (await Assert.ThrowsAsync<SshHostKeyException>(() => SshClient.ConnectAsync(Options(container, knownHosts, credential, host), Ct))).Message;

        // A name the certificate doesn't list, under a CA line that does match that name.
        string wrongName = KnownHosts($"[localhost]:{container.Port}", "@cert-authority", made.HostCa);
        Assert.Contains("isn't valid for this host name", await RefusedAsync(wrongName, "localhost"));

        // Another CA for the host: certificates are offered, and this one isn't from it.
        Assert.Contains("doesn't list", await RefusedAsync(KnownHosts(name, "@cert-authority", other)));

        // Revoked CA and revoked host key, each beside a good CA line.
        string good = KnownHosts(name, "@cert-authority", made.HostCa);
        string revokedCa = KnownHosts(name, "@revoked", made.HostCa);
        await File.AppendAllTextAsync(revokedCa, await File.ReadAllTextAsync(good, Ct), Ct);
        Assert.Contains("CA marked revoked", await RefusedAsync(revokedCa));

        string revokedKey = KnownHosts(name, "@revoked", made.HostKey);
        await File.AppendAllTextAsync(revokedKey, await File.ReadAllTextAsync(good, Ct), Ct);
        Assert.Contains("revoked", await RefusedAsync(revokedKey));

        await AssertLogsInAsync(Options(container, good, credential));
    }

    [InteropFact]
    public async Task With_no_CA_line_the_plain_host_key_is_asked_for()
    {
        var made = await MakeAsync();
        await using SshPeerContainer container = await StartAsync(made.HostKey, made.HostCertificate, made.UserCa);

        // sshd offers the certificate too, so this passes only if the client doesn't ask for it.
        string knownHosts = _keygen.PathOf("known_hosts-plain");
        await File.WriteAllTextAsync(knownHosts, $"[{container.Host}]:{container.Port} {await File.ReadAllTextAsync(made.HostKey + ".pub", Ct)}", Ct);
        await AssertLogsInAsync(Options(container, knownHosts, SshCredential.FromPrivateKeyFile(made.User, null, made.UserCertificate)));
    }
}

using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.Keys;
using Zorg.Ssh.KnownHosts;
using Zorg.Ssh.Tests.Certificates;
using Zorg.Ssh.Tests.Crypto;

namespace Zorg.Ssh.Tests.KnownHosts;

/// <summary>A2: the key types already recorded for a host come first in the offer, as with OpenSSH's order_hostkeyalgs.</summary>
public sealed class HostKeyOrderTests : IDisposable
{
    private readonly TempDirectory _directory = new();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => _directory.Dispose();

    private string WriteFile(string text)
    {
        string path = Path.Combine(_directory.Path, "known_hosts");
        File.WriteAllText(path, text);
        return path;
    }

    [Fact]
    public async Task A2_a_host_recorded_with_ecdsa_only_connects_when_the_server_also_has_ed25519()
    {
        using SshHostKey ed = SshHostKey.GenerateEd25519();
        using SshHostKey ecdsa = new(SshPrivateKey.GenerateEcdsa("ecdsa-sha2-nistp256"));
        await using SshServer server = await SshServer.StartAsync(
            new SshServerOptions
            {
                HostKeys = [ed, ecdsa],
                PasswordHandler = static (_, _) => ValueTask.FromResult(SshAuthDecision.Accept),
                SessionHandler = static (_, _) => Task.FromResult(0),
            },
            Ct);
        int port = server.LocalEndPoint.Port;
        string path = WriteFile(KnownHostsFile.FormatLine("127.0.0.1", port, ecdsa.Key.PublicKey, hashed: false) + "\n");
        await using SshClient client = await SshClient.ConnectAsync(
            new SshClientOptions
            {
                Host = "127.0.0.1",
                Port = port,
                UserName = "alice",
                Credentials = [SshCredential.FromPassword("pw")],
                HostKeyPolicy = HostKeyPolicy.KnownHostsFile(path),
            },
            Ct);
        Assert.Equal("ecdsa-sha2-nistp256", client.HostKey.KeyType);
    }

    [Fact]
    public async Task A2_a_server_with_only_another_type_is_still_changed()
    {
        using SshHostKey ed = SshHostKey.GenerateEd25519();
        using SshHostKey ecdsa = new(SshPrivateKey.GenerateEcdsa("ecdsa-sha2-nistp256"));
        await using SshServer server = await SshServer.StartAsync(
            new SshServerOptions
            {
                HostKeys = [ed],
                PasswordHandler = static (_, _) => ValueTask.FromResult(SshAuthDecision.Accept),
                SessionHandler = static (_, _) => Task.FromResult(0),
            },
            Ct);
        int port = server.LocalEndPoint.Port;
        string path = WriteFile(KnownHostsFile.FormatLine("127.0.0.1", port, ecdsa.Key.PublicKey, hashed: false) + "\n");
        SshHostKeyException ex = await Assert.ThrowsAsync<SshHostKeyException>(() => SshClient.ConnectAsync(
            new SshClientOptions
            {
                Host = "127.0.0.1",
                Port = port,
                UserName = "alice",
                Credentials = [SshCredential.FromPassword("pw")],
                HostKeyPolicy = HostKeyPolicy.KnownHostsFile(path),
            },
            Ct));
        Assert.Contains("has changed", ex.Message);
    }

    [Fact]
    public void A2_recorded_types_move_to_the_front_in_default_order()
    {
        SshPrivateKey ecdsa384 = SshPrivateKey.GenerateEcdsa("ecdsa-sha2-nistp384");
        string path = WriteFile(
            CertificateBuilder.Line(string.Empty, "other.example.com", SshPrivateKey.GenerateEd25519().PublicKey).TrimStart()
            + CertificateBuilder.Line(string.Empty, "web.example.com", ecdsa384.PublicKey).TrimStart());
        HostKeyPolicy policy = HostKeyPolicy.KnownHostsFile(path);
        Assert.Equal(
            ["ecdsa-sha2-nistp384", "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp521", "rsa-sha2-512", "rsa-sha2-256"],
            policy.HostKeyAlgorithmsFor("web.example.com", 22));
        Assert.Equal(HostKeyAlgorithms.Default, policy.HostKeyAlgorithmsFor("unknown.example.com", 22));
    }

    [Fact]
    public void A2_an_rsa_line_moves_both_sha2_algorithms()
    {
        SshPrivateKey rsa = SshPrivateKey.GenerateRsa(2048);
        string path = WriteFile(CertificateBuilder.Line(string.Empty, "web", rsa.PublicKey).TrimStart());
        Assert.Equal(
            ["rsa-sha2-512", "rsa-sha2-256", "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"],
            HostKeyPolicy.KnownHostsFile(path).HostKeyAlgorithmsFor("web", 22));
    }

    [Fact]
    public void A2_certificate_forms_of_a_recorded_type_come_first_with_a_CA_line()
    {
        SshPrivateKey ca = SshPrivateKey.GenerateEd25519();
        SshPrivateKey ecdsa = SshPrivateKey.GenerateEcdsa("ecdsa-sha2-nistp256");
        string path = WriteFile(
            CertificateBuilder.CaLine("*", ca)
            + CertificateBuilder.Line(string.Empty, "web", ecdsa.PublicKey).TrimStart());
        string[] algorithms = [.. HostKeyPolicy.KnownHostsFile(path).HostKeyAlgorithmsFor("web", 22)];
        Assert.Equal(["ecdsa-sha2-nistp256-cert-v01@openssh.com", "ecdsa-sha2-nistp256"], algorithms.Take(2));
        Assert.Equal(SshCertificate.HostKeyAlgorithmNames.Count + HostKeyAlgorithms.Default.Count, algorithms.Length);
    }

    [Fact]
    public void A2_revoked_and_CA_lines_do_not_count_as_recorded_types()
    {
        SshPrivateKey ca = SshPrivateKey.GenerateEcdsa("ecdsa-sha2-nistp256");
        SshPrivateKey revoked = SshPrivateKey.GenerateEcdsa("ecdsa-sha2-nistp384");
        string path = WriteFile(CertificateBuilder.Line("@revoked", "web", revoked.PublicKey) + CertificateBuilder.CaLine("web", ca));
        Assert.Equal(
            [.. SshCertificate.HostKeyAlgorithmNames, .. HostKeyAlgorithms.Default],
            HostKeyPolicy.KnownHostsFile(path).HostKeyAlgorithmsFor("web", 22));
    }
}

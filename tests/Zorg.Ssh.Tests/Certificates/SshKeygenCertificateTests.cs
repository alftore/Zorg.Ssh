using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.Keys;
using Zorg.Ssh.Tests.Crypto;

namespace Zorg.Ssh.Tests.Certificates;

/// <summary>Certificates made by real <c>ssh-keygen -s</c> at test time, which is what proves the format was read right.</summary>
public sealed class SshKeygenCertificateTests : IDisposable
{
    private const string Host = "host.example.com";

    private readonly TempDirectory _directory = new();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => _directory.Dispose();

    private string Generate(string name, string type, string? bits = null)
    {
        string path = Path.Combine(_directory.Path, name);
        List<string> arguments = ["-q", "-t", type, "-N", string.Empty, "-f", path];
        if (bits is not null)
        {
            arguments.AddRange(["-b", bits]);
        }

        Run(arguments);
        return path;
    }

    private static void Run(IEnumerable<string> arguments)
    {
        (int exitCode, string output) = OpenSshTools.Run(OpenSshTools.Require("ssh-keygen"), arguments);
        Assert.True(exitCode == 0, output);
    }

    private static SshCertificate Sign(string ca, string key, params string[] options)
    {
        Run(["-q", "-s", ca, "-I", "zorg-test", .. options, key + ".pub"]);
        string[] fields = File.ReadAllText(key + "-cert.pub").Split(' ');
        return SshCertificate.ParseCertificate(Convert.FromBase64String(fields[1]));
    }

    private KnownHostsPolicy TrustingCa(string ca, DateTimeOffset? now = null)
    {
        string path = Path.Combine(_directory.Path, $"known_hosts-{Guid.NewGuid():N}");
        File.WriteAllText(path, "@cert-authority *.example.com " + File.ReadAllText(ca + ".pub"));
        return new KnownHostsPolicy([path], false, new FixedTime(now ?? DateTimeOffset.UtcNow));
    }

    private async Task<string> RefusedAsync(KnownHostsPolicy policy, SshCertificate certificate) =>
        (await Assert.ThrowsAsync<SshHostKeyException>(async () => await policy.CheckAsync(Host, 22, certificate, Ct))).Message;

    [Theory]
    [InlineData("ed25519", null, "ssh-ed25519-cert-v01@openssh.com")]
    [InlineData("ecdsa", "256", "ecdsa-sha2-nistp256-cert-v01@openssh.com")]
    [InlineData("ecdsa", "384", "ecdsa-sha2-nistp384-cert-v01@openssh.com")]
    [InlineData("ecdsa", "521", "ecdsa-sha2-nistp521-cert-v01@openssh.com")]
    [InlineData("rsa", "2048", "ssh-rsa-cert-v01@openssh.com")]
    public async Task Each_subject_key_type_reads_and_verifies(string type, string? bits, string certificateType)
    {
        string ca = Generate("ca", "ed25519");
        string key = Generate("key", type, bits);
        SshCertificate certificate = Sign(ca, key, "-h", "-n", Host, "-z", "42");

        Assert.Equal(certificateType, certificate.KeyType);
        Assert.Equal(42UL, certificate.Serial);
        Assert.Equal(SshCertificate.HostType, certificate.CertificateType);
        Assert.Equal("zorg-test", certificate.KeyId);
        Assert.Equal([Host], certificate.Principals);
        Assert.Equal(0UL, certificate.ValidAfter);
        Assert.Equal(ulong.MaxValue, certificate.ValidBefore);
        Assert.True(await TrustingCa(ca).CheckAsync(Host, 22, certificate, Ct));
    }

    [Theory]
    [InlineData("ecdsa", "256")]
    [InlineData("ecdsa", "384")]
    [InlineData("ecdsa", "521")]
    [InlineData("rsa", "2048")]
    public async Task Each_CA_key_type_verifies(string type, string bits)
    {
        string ca = Generate("ca", type, bits);
        string key = Generate("key", "ed25519");
        Assert.True(await TrustingCa(ca).CheckAsync(Host, 22, Sign(ca, key, "-h", "-n", Host), Ct));
    }

    [Theory]
    [InlineData("rsa-sha2-256")]
    [InlineData("rsa-sha2-512")]
    public async Task An_RSA_CA_with_a_SHA_2_signature_verifies(string algorithm)
    {
        string ca = Generate("ca", "rsa", "2048");
        string key = Generate("key", "ed25519");
        Assert.True(await TrustingCa(ca).CheckAsync(Host, 22, Sign(ca, key, "-t", algorithm, "-h", "-n", Host), Ct));
    }

    [Fact]
    public async Task An_RSA_CA_with_a_SHA_1_signature_is_refused()
    {
        string ca = Generate("ca", "rsa", "2048");
        string key = Generate("key", "ed25519");
        string message = await RefusedAsync(TrustingCa(ca), Sign(ca, key, "-t", "ssh-rsa", "-h", "-n", Host));
        Assert.Contains("SHA-1", message);
    }

    [Fact]
    public void User_certificate_options_read_as_ssh_keygen_wrote_them()
    {
        string ca = Generate("ca", "ed25519");
        string key = Generate("key", "ed25519");
        SshCertificate certificate = Sign(ca, key, "-n", "alice,bob", "-O", "force-command=/bin/true", "-O", "source-address=10.0.0.0/8", "-V", "20260101:20270101");

        Assert.Equal(SshCertificate.UserType, certificate.CertificateType);
        Assert.Equal(["alice", "bob"], certificate.Principals);
        Assert.Equal(["force-command", "source-address"], certificate.CriticalOptions);
        Assert.Contains("permit-pty", certificate.Extensions);
        Assert.True(certificate.ValidAfter < certificate.ValidBefore);
    }

    [Fact]
    public async Task An_expired_certificate_is_refused()
    {
        string ca = Generate("ca", "ed25519");
        string key = Generate("key", "ed25519");
        SshCertificate certificate = Sign(ca, key, "-h", "-n", Host, "-V", "20200101:20200201");
        Assert.Contains("has expired", await RefusedAsync(TrustingCa(ca), certificate));
    }

    [Fact]
    public async Task A_certificate_not_yet_valid_is_refused()
    {
        string ca = Generate("ca", "ed25519");
        string key = Generate("key", "ed25519");
        SshCertificate certificate = Sign(ca, key, "-h", "-n", Host, "-V", "20990101:21000101");
        Assert.Contains("isn't valid yet", await RefusedAsync(TrustingCa(ca), certificate));
    }

    [Fact]
    public async Task The_clock_given_decides_the_validity_period()
    {
        string ca = Generate("ca", "ed25519");
        string key = Generate("key", "ed25519");
        SshCertificate certificate = Sign(ca, key, "-h", "-n", Host, "-V", "20200101:20200201");
        Assert.True(await TrustingCa(ca, new DateTimeOffset(2020, 1, 15, 0, 0, 0, TimeSpan.Zero)).CheckAsync(Host, 22, certificate, Ct));
    }

    [Fact]
    public async Task A_wrong_principal_is_refused()
    {
        string ca = Generate("ca", "ed25519");
        string key = Generate("key", "ed25519");
        Assert.Contains("isn't valid for this host name", await RefusedAsync(TrustingCa(ca), Sign(ca, key, "-h", "-n", "other.example.com")));
    }

    [Fact]
    public async Task A_user_certificate_is_refused_as_a_host_certificate()
    {
        string ca = Generate("ca", "ed25519");
        string key = Generate("key", "ed25519");
        Assert.Contains("a user certificate", await RefusedAsync(TrustingCa(ca), Sign(ca, key, "-n", Host)));
    }

    [Fact]
    public async Task An_unknown_critical_option_is_refused()
    {
        string ca = Generate("ca", "ed25519");
        string key = Generate("key", "ed25519");
        SshCertificate certificate = Sign(ca, key, "-n", Host, "-O", "critical:must-understand@example.com");
        Assert.Equal(["must-understand@example.com"], certificate.CriticalOptions);

        // Only a user certificate can carry one through ssh-keygen, so the type check speaks first here.
        Assert.Contains("a user certificate", await RefusedAsync(TrustingCa(ca), certificate));
    }

    [Fact]
    public async Task A_CA_mismatch_is_refused()
    {
        string ca = Generate("ca", "ed25519");
        string other = Generate("other", "ed25519");
        string key = Generate("key", "ed25519");
        Assert.Contains("doesn't list", await RefusedAsync(TrustingCa(other), Sign(ca, key, "-h", "-n", Host)));
    }

    [Fact]
    public async Task A_tampered_certificate_is_refused()
    {
        string ca = Generate("ca", "ed25519");
        string key = Generate("key", "ed25519");
        byte[] blob = Sign(ca, key, "-h", "-n", Host, "-z", "1").Blob.ToArray();

        // The nonce sits right after the type: a change there leaves the structure whole.
        blob[40] ^= 0xFF;
        Assert.Contains("signature doesn't verify", await RefusedAsync(TrustingCa(ca), SshCertificate.ParseCertificate(blob)));
    }

    [Fact]
    public void A_certificate_loads_beside_its_key_as_a_client_credential()
    {
        string ca = Generate("ca", "ed25519");
        string key = Generate("key", "ed25519");
        Sign(ca, key, "-n", "alice");
        SshCredential credential = SshCredential.FromPrivateKeyFile(key, null, key + "-cert.pub");
        using SshPrivateKey loaded = Assert.IsType<PrivateKeyCredential>(credential).Load();
        Assert.IsType<SshCertificate>(loaded.PublicKey);
        Assert.Equal(["ssh-ed25519-cert-v01@openssh.com"], loaded.SignatureAlgorithms);
    }

    [Fact]
    public void A_private_key_with_the_wrong_certificate_says_so()
    {
        string ca = Generate("ca", "ed25519");
        string key = Generate("key", "ed25519");
        string other = Generate("other", "ed25519");
        Sign(ca, key, "-n", "alice");
        SshCredential credential = SshCredential.FromPrivateKeyFile(other, null, key + "-cert.pub");
        SshKeyFileException failure = Assert.Throws<SshKeyFileException>(() => Assert.IsType<PrivateKeyCredential>(credential).Load());
        Assert.Contains("different key", failure.Message);
    }
}

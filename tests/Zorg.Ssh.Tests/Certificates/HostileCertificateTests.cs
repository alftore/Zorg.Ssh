using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.Keys;
using Zorg.Ssh.Tests.Crypto;

namespace Zorg.Ssh.Tests.Certificates;

/// <summary>Host certificates against the known_hosts policy, with each way one can be wrong.</summary>
public sealed class HostileCertificateTests : IDisposable
{
    private const string Host = "host.example.com";

    private static readonly DateTimeOffset Now = new(2026, 11, 5, 12, 0, 0, TimeSpan.Zero);
    private static readonly ulong NowSeconds = (ulong)Now.ToUnixTimeSeconds();
    private static readonly SshPrivateKey Ca = SshPrivateKey.GenerateEd25519();
    private static readonly SshPrivateKey Subject = SshPrivateKey.GenerateEd25519();

    private readonly TempDirectory _directory = new();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => _directory.Dispose();

    private static CertificateBuilder Good() => new(Subject, Ca);

    private KnownHostsPolicy Policy(string text, bool addUnknown = false)
    {
        string path = Path.Combine(_directory.Path, $"known_hosts-{Guid.NewGuid():N}");
        File.WriteAllText(path, text);
        return new KnownHostsPolicy([path], addUnknown, new FixedTime(Now));
    }

    private KnownHostsPolicy TrustingCa() => Policy(CertificateBuilder.CaLine("*.example.com", Ca));

    private async Task<string> RefusedAsync(SshPublicKey key, KnownHostsPolicy? policy = null, string host = Host) =>
        (await Assert.ThrowsAsync<SshHostKeyException>(
            async () => await (policy ?? TrustingCa()).CheckAsync(host, 22, key, Ct))).Message;

    [Fact]
    public async Task A_good_certificate_is_trusted()
    {
        Assert.True(await TrustingCa().CheckAsync(Host, 22, Good().Parse(), Ct));
    }

    [Fact]
    public void Parsing_keeps_every_field()
    {
        SshCertificate certificate = new CertificateBuilder(Subject, Ca)
        {
            Serial = 42,
            KeyId = "id",
            Principals = ["a", "b"],
            ValidAfter = 1,
            ValidBefore = 2,
            CriticalOptions = ["force-command", "source-address"],
            Extensions = ["permit-pty"],
        }.Parse();

        Assert.Equal("ssh-ed25519-cert-v01@openssh.com", certificate.KeyType);
        Assert.Equal(42UL, certificate.Serial);
        Assert.Equal("id", certificate.KeyId);
        Assert.Equal(["a", "b"], certificate.Principals);
        Assert.Equal(1UL, certificate.ValidAfter);
        Assert.Equal(2UL, certificate.ValidBefore);
        Assert.Equal(["force-command", "source-address"], certificate.CriticalOptions);
        Assert.Equal(["permit-pty"], certificate.Extensions);
        Assert.Equal(Subject.PublicKey.Blob.ToArray(), certificate.Key.Blob.ToArray());
        Assert.Equal(Ca.PublicKey.Blob.ToArray(), certificate.SignatureKeyBlob.ToArray());
    }

    [Fact]
    public void Every_truncation_is_a_protocol_error()
    {
        byte[] blob = Good().Build();
        for (int length = 0; length < blob.Length; length++)
        {
            Assert.Throws<SshProtocolException>(() => SshCertificate.ParseCertificate(blob.AsSpan(0, length)));
        }
    }

    [Fact]
    public void Trailing_data_is_refused()
    {
        byte[] blob = [.. Good().Build(), 0];
        Assert.Throws<SshProtocolException>(() => SshCertificate.ParseCertificate(blob));
    }

    // No single flipped bit may leave a certificate trusted, wherever it lands.
    [Fact]
    public async Task Every_tampered_byte_is_refused()
    {
        byte[] good = Good().Build();
        KnownHostsPolicy policy = TrustingCa();
        for (int i = 0; i < good.Length; i++)
        {
            byte[] tampered = (byte[])good.Clone();
            tampered[i] ^= 0x01;
            try
            {
                SshPublicKey key = SshCertificate.ParseAny(tampered);
                await Assert.ThrowsAsync<SshHostKeyException>(async () => await policy.CheckAsync(Host, 22, key, Ct));
            }
            catch (SshProtocolException)
            {
                // Refused earlier, which is as good.
            }
        }
    }

    [Fact]
    public async Task A_signature_by_another_key_is_refused()
    {
        using SshPrivateKey impostor = SshPrivateKey.GenerateEd25519();

        // It names the trusted CA, but the impostor signed it.
        byte[] forged = new CertificateBuilder(Subject, impostor) { SignatureKeyBlob = Ca.PublicKey.Blob.ToArray() }.Build();
        Assert.Contains("signature doesn't verify", await RefusedAsync(SshCertificate.ParseCertificate(forged)));
    }

    [Fact]
    public async Task An_expired_certificate_is_refused_and_says_so()
    {
        string message = await RefusedAsync(new CertificateBuilder(Subject, Ca) { ValidBefore = NowSeconds - 1 }.Parse());
        Assert.Contains("has expired", message);
    }

    [Fact]
    public async Task The_end_of_the_period_is_excluded_and_the_start_included()
    {
        Assert.Contains("has expired", await RefusedAsync(new CertificateBuilder(Subject, Ca) { ValidBefore = NowSeconds }.Parse()));
        Assert.True(await TrustingCa().CheckAsync(Host, 22, new CertificateBuilder(Subject, Ca) { ValidAfter = NowSeconds }.Parse(), Ct));
    }

    [Fact]
    public async Task A_certificate_not_yet_valid_is_refused_and_says_so()
    {
        string message = await RefusedAsync(new CertificateBuilder(Subject, Ca) { ValidAfter = NowSeconds + 1 }.Parse());
        Assert.Contains("isn't valid yet", message);
    }

    [Fact]
    public async Task A_time_past_any_date_does_not_break_the_message()
    {
        string message = await RefusedAsync(new CertificateBuilder(Subject, Ca) { ValidAfter = ulong.MaxValue - 1 }.Parse());
        Assert.Contains("isn't valid yet", message);
    }

    [Fact]
    public async Task A_wrong_principal_is_refused_and_names_what_it_lists()
    {
        string message = await RefusedAsync(new CertificateBuilder(Subject, Ca) { Principals = ["other.example.com"] }.Parse());
        Assert.Contains("isn't valid for this host name", message);
        Assert.Contains("other.example.com", message);
    }

    // OpenSSH lower-cases the host name it connects to (sshconnect.c, ssh_login: lowercase(host)), then compares it with
    // each principal exactly (sshconnect.c check_host_cert: sshkey_cert_check_host(..., wildcard_principals 0, ...),
    // which reaches strcmp). So the name's case doesn't matter, and the principal's does. See M5 review T9.
    [Fact]
    public async Task The_host_name_is_lower_cased_and_compared_with_each_principal_exactly_as_in_OpenSSH()
    {
        Assert.True(await TrustingCa().CheckAsync("HOST.Example.COM", 22, Good().Parse(), Ct));

        // A principal with capitals can never match, because the name it is compared with is lower case.
        SshCertificate capitals = new CertificateBuilder(Subject, Ca) { Principals = ["HOST.example.com"] }.Parse();
        Assert.Contains("isn't valid for this host name", await RefusedAsync(capitals));
        Assert.Contains("isn't valid for this host name", await RefusedAsync(capitals, host: "HOST.example.com"));
    }

    // Review A3: a principal was matched as a pattern, so a CA-issued certificate naming '*' or '*.example.com' passed for
    // every matching host under the CA. OpenSSH never reads a principal as a pattern; neither does this library.
    [Theory]
    [InlineData("*")]
    [InlineData("*.example.com")]
    [InlineData("?ost.example.com")]
    [InlineData("host.example.*")]
    public async Task A3_a_wildcard_principal_is_a_literal_name_and_matches_no_host(string principal)
    {
        SshCertificate certificate = new CertificateBuilder(Subject, Ca) { Principals = [principal] }.Parse();
        Assert.Contains("isn't valid for this host name", await RefusedAsync(certificate));
        Assert.Contains("isn't valid for this host name", await RefusedAsync(certificate, host: "anything.else.example.com"));

        // The exact name beside it is still accepted.
        Assert.True(await TrustingCa().CheckAsync(Host, 22, new CertificateBuilder(Subject, Ca) { Principals = [principal, Host] }.Parse(), Ct));
    }

    [Fact]
    public async Task A_certificate_with_no_principals_is_refused()
    {
        string message = await RefusedAsync(new CertificateBuilder(Subject, Ca) { Principals = [] }.Parse());
        Assert.Contains("no principals", message);
    }

    [Fact]
    public async Task A_user_certificate_is_not_a_host_certificate()
    {
        string message = await RefusedAsync(new CertificateBuilder(Subject, Ca) { Type = SshCertificate.UserType }.Parse());
        Assert.Contains("a user certificate", message);
    }

    [Fact]
    public async Task An_unknown_certificate_type_is_refused()
    {
        string message = await RefusedAsync(new CertificateBuilder(Subject, Ca) { Type = 3 }.Parse());
        Assert.Contains("unknown certificate type", message);
    }

    [Fact]
    public async Task An_unknown_critical_option_is_refused_and_named()
    {
        string message = await RefusedAsync(new CertificateBuilder(Subject, Ca) { CriticalOptions = ["must-understand@example.com"] }.Parse());
        Assert.Contains("critical option", message);
        Assert.Contains("must-understand@example.com", message);
    }

    [Fact]
    public async Task An_unknown_extension_is_ignored()
    {
        Assert.True(await TrustingCa().CheckAsync(Host, 22, new CertificateBuilder(Subject, Ca) { Extensions = ["whatever@example.com"] }.Parse(), Ct));
    }

    [Theory]
    [InlineData("b", "a")]
    [InlineData("a", "a")]
    public void Repeated_or_unsorted_critical_options_are_malformed(string first, string second)
    {
        byte[] blob = new CertificateBuilder(Subject, Ca) { CriticalOptions = [first, second] }.Build();
        Assert.Throws<SshProtocolException>(() => SshCertificate.ParseCertificate(blob));
    }

    [Fact]
    public void Unsorted_extensions_are_tolerated_as_they_can_be_ignored()
    {
        Assert.Equal(["b", "a"], new CertificateBuilder(Subject, Ca) { Extensions = ["b", "a"] }.Parse().Extensions);
    }

    [Fact]
    public void Too_many_principals_or_options_are_refused()
    {
        string[] names = [.. Enumerable.Range(0, SshCertificate.MaxPrincipals + 1).Select(i => $"p{i:D4}")];
        Assert.Throws<SshProtocolException>(() => new CertificateBuilder(Subject, Ca) { Principals = names }.Parse());
        Assert.Throws<SshProtocolException>(() => new CertificateBuilder(Subject, Ca) { Extensions = names }.Parse());
    }

    [Fact]
    public async Task A_CA_that_is_not_listed_is_refused()
    {
        using SshPrivateKey other = SshPrivateKey.GenerateEd25519();
        string message = await RefusedAsync(Good().Parse(), Policy(CertificateBuilder.CaLine("*.example.com", other)));
        Assert.Contains("doesn't list", message);
    }

    [Fact]
    public async Task A_CA_listed_for_other_hosts_only_is_refused()
    {
        string message = await RefusedAsync(Good().Parse(), Policy(CertificateBuilder.CaLine("*.example.org", Ca)));
        Assert.Contains("doesn't list", message);
    }

    [Fact]
    public async Task A_plain_line_for_the_CA_key_does_not_make_it_a_CA()
    {
        string message = await RefusedAsync(Good().Parse(), Policy(CertificateBuilder.Line(string.Empty, Host, Ca.PublicKey)));
        Assert.Contains("doesn't list", message);
    }

    [Fact]
    public async Task A_CA_that_is_itself_a_certificate_is_refused()
    {
        // The chain: the root signs a certificate for an intermediate, which then signs the host. Even when the
        // file names that certificate as a CA, a CA has to be a plain key.
        using SshPrivateKey intermediate = SshPrivateKey.GenerateEd25519();
        SshCertificate intermediateCertificate = new CertificateBuilder(intermediate, Ca) { Principals = ["*"] }.Parse();
        SshCertificate chained = SshCertificate.ParseCertificate(
            new CertificateBuilder(Subject, intermediate) { SignatureKeyBlob = intermediateCertificate.Blob.ToArray() }.Build());

        string message = await RefusedAsync(chained, Policy(CertificateBuilder.Line("@cert-authority", "*", intermediateCertificate)));
        Assert.Contains("itself a certificate", message);
    }

    [Fact]
    public async Task A_revoked_subject_key_is_refused_even_with_a_good_CA()
    {
        string text = CertificateBuilder.CaLine("*", Ca) + CertificateBuilder.Line("@revoked", "*", Subject.PublicKey);
        Assert.Contains("revoked", await RefusedAsync(Good().Parse(), Policy(text)));
    }

    [Fact]
    public async Task A_revoked_CA_is_refused_wherever_the_line_stands()
    {
        string text = CertificateBuilder.Line("@revoked", "*", Ca.PublicKey) + CertificateBuilder.CaLine("*", Ca);
        Assert.Contains("CA marked revoked", await RefusedAsync(Good().Parse(), Policy(text)));
    }

    [Fact]
    public async Task A_revoked_certificate_is_refused()
    {
        SshCertificate certificate = Good().Parse();
        string text = CertificateBuilder.CaLine("*", Ca) + CertificateBuilder.Line("@revoked", "*", certificate);
        Assert.Contains("revoked", await RefusedAsync(certificate, Policy(text)));
    }

    [Fact]
    public async Task Peer_text_in_a_certificate_is_cleaned_before_it_reaches_a_message()
    {
        string message = await RefusedAsync(new CertificateBuilder(Subject, Ca) { KeyId = "evil\r\nforged log line\u001b[2J", ValidBefore = 1 }.Parse());
        Assert.DoesNotContain('\n', message);
        Assert.DoesNotContain('\u001b', message);
    }

    [Fact]
    public void A_plain_parse_refuses_a_certificate()
    {
        byte[] blob = Good().Build();
        Assert.Throws<SshProtocolException>(() => SshPublicKey.Parse(blob));
    }

    [Fact]
    public void A_certificate_only_verifies_under_its_own_algorithm_name()
    {
        byte[] data = Encoding.ASCII.GetBytes("exchange hash");
        byte[] signature = Subject.Sign("ssh-ed25519", data);
        SshCertificate certificate = Good().Parse();

        Assert.True(certificate.Verify("ssh-ed25519-cert-v01@openssh.com", data, signature));
        Assert.False(certificate.Verify("ssh-ed25519", data, signature));
        Assert.False(certificate.SupportsSignatureAlgorithm("ssh-ed25519"));
    }

    [Fact]
    public void The_RSA_key_type_name_is_not_a_signature_algorithm()
    {
        using SshPrivateKey rsa = SshPrivateKey.GenerateRsa(2048);
        SshCertificate certificate = new CertificateBuilder(rsa, Ca).Parse();
        Assert.Equal("ssh-rsa-cert-v01@openssh.com", certificate.KeyType);
        Assert.False(certificate.SupportsSignatureAlgorithm("ssh-rsa-cert-v01@openssh.com"));
        Assert.True(certificate.SupportsSignatureAlgorithm("rsa-sha2-256-cert-v01@openssh.com"));
        Assert.True(certificate.SupportsSignatureAlgorithm("rsa-sha2-512-cert-v01@openssh.com"));
    }

    [Fact]
    public async Task Other_policies_never_accept_a_certificate()
    {
        bool asked = false;
        HostKeyPolicy policy = HostKeyPolicy.Custom((_, _) =>
        {
            asked = true;
            return ValueTask.FromResult(true);
        });

        await Assert.ThrowsAsync<SshHostKeyException>(async () => await policy.CheckAsync(Host, 22, Good().Parse(), Ct));
        Assert.False(asked);
    }

    [Fact]
    public void Certificate_algorithms_go_first_only_for_a_host_with_a_CA()
    {
        KnownHostsPolicy policy = Policy(CertificateBuilder.CaLine("*.example.com", Ca));
        Assert.StartsWith("ssh-ed25519-cert-v01@openssh.com", policy.HostKeyAlgorithmsFor(Host, 22)[0], StringComparison.Ordinal);
        Assert.Contains("ssh-ed25519", policy.HostKeyAlgorithmsFor(Host, 22));
        Assert.Equal(HostKeyAlgorithms.Default, policy.HostKeyAlgorithmsFor("host.example.org", 22));
        Assert.Equal(HostKeyAlgorithms.Default, Policy(string.Empty).HostKeyAlgorithmsFor(Host, 22));
    }

    [Fact]
    public void Certificate_algorithms_are_never_offered_by_other_policies()
    {
        Assert.Equal(HostKeyAlgorithms.Default, HostKeyPolicy.AcceptAnyUnsafe().HostKeyAlgorithmsFor(Host, 22));
    }

    [Fact]
    public void A_non_standard_port_needs_the_port_in_the_line()
    {
        KnownHostsPolicy policy = Policy(CertificateBuilder.CaLine("[host.example.com]:2222", Ca));
        Assert.Contains("ssh-ed25519-cert-v01@openssh.com", policy.HostKeyAlgorithmsFor(Host, 2222));
        Assert.DoesNotContain("ssh-ed25519-cert-v01@openssh.com", policy.HostKeyAlgorithmsFor(Host, 22));
    }

    // A person in the middle shouldn't get past a CA by offering a plain key and being recorded as a new host.
    [Fact]
    public async Task Accept_new_does_not_record_a_plain_key_for_a_host_under_a_CA()
    {
        KnownHostsPolicy policy = Policy(CertificateBuilder.CaLine("*.example.com", Ca), addUnknown: true);
        await RefusedAsync(Subject.PublicKey, policy);
    }

    [Fact]
    public async Task Accept_new_never_records_a_certificate()
    {
        using SshPrivateKey unknownCa = SshPrivateKey.GenerateEd25519();
        string path = Path.Combine(_directory.Path, "known_hosts");
        KnownHostsPolicy policy = new([path], true, new FixedTime(Now));
        await RefusedAsync(new CertificateBuilder(Subject, unknownCa).Parse(), policy);
        Assert.False(File.Exists(path));
    }

    [Fact]
    public async Task A_revoked_line_in_a_second_file_still_wins()
    {
        string first = Path.Combine(_directory.Path, "first");
        string second = Path.Combine(_directory.Path, "second");
        await File.WriteAllTextAsync(first, CertificateBuilder.Line(string.Empty, Host, Subject.PublicKey), Ct);
        await File.WriteAllTextAsync(second, CertificateBuilder.Line("@revoked", Host, Subject.PublicKey), Ct);
        await RefusedAsync(Subject.PublicKey, new KnownHostsPolicy([first, second], false, TimeProvider.System));
    }

    [Fact]
    public void A_certificate_is_tied_to_its_key_and_to_users()
    {
        using SshPrivateKey other = SshPrivateKey.GenerateEd25519();
        string User(SshPrivateKey key, uint type) =>
            $"ssh-ed25519-cert-v01@openssh.com {Convert.ToBase64String(new CertificateBuilder(key, Ca) { Type = type }.Build())} comment\n";

        Assert.Contains("different key", Assert.Throws<SshKeyFileException>(() => CertifiedPrivateKey.Adopt(other, User(Subject, SshCertificate.UserType))).Message);
        Assert.Contains("host certificate", Assert.Throws<SshKeyFileException>(() => CertifiedPrivateKey.Adopt(Subject, User(Subject, SshCertificate.HostType))).Message);

        using SshPrivateKey mine = SshPrivateKey.GenerateEd25519();
        using CertifiedPrivateKey adopted = CertifiedPrivateKey.Adopt(mine, User(mine, SshCertificate.UserType));
        Assert.Equal(["ssh-ed25519-cert-v01@openssh.com"], adopted.SignatureAlgorithms);
    }

    [Theory]
    [InlineData("")]
    [InlineData("garbage")]
    [InlineData("ssh-ed25519 AAAA comment")]
    [InlineData("ssh-ed25519-cert-v01@openssh.com")]
    [InlineData("ssh-ed25519-cert-v01@openssh.com not-base64!")]
    [InlineData("ssh-ed25519-cert-v01@openssh.com AAAA")]
    public void A_bad_certificate_file_is_a_key_file_error(string text)
    {
        Assert.Throws<SshKeyFileException>(() => CertifiedPrivateKey.Adopt(Subject, text));
    }

    [Fact]
    public void A_file_whose_type_field_disagrees_with_its_blob_is_refused()
    {
        string text = $"ecdsa-sha2-nistp256-cert-v01@openssh.com {Convert.ToBase64String(new CertificateBuilder(Subject, Ca) { Type = SshCertificate.UserType }.Build())}";
        Assert.Throws<SshKeyFileException>(() => CertifiedPrivateKey.Adopt(Subject, text));
    }
}

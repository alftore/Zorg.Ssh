using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.Keys;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Tests.Certificates;
using Zorg.Ssh.Tests.Crypto;

namespace Zorg.Ssh.Tests.KnownHosts;

/// <summary>
/// M5 review T1: one RSA key has unlimited wire encodings (redundant leading zeros in an mpint). OpenSSH compares
/// keys by value, and so must everything here that decides trust.
/// </summary>
public sealed class KeyIdentityByValueTests : IDisposable
{
    private const string Host = "host.example.com";

    private static readonly DateTimeOffset Now = new(2026, 11, 5, 12, 0, 0, TimeSpan.Zero);
    private static readonly Lazy<SshPrivateKey> Rsa = new(() => SshPrivateKey.GenerateRsa(2048));
    private static readonly Lazy<SshPrivateKey> RsaCa = new(() => SshPrivateKey.GenerateRsa(2048));
    private static readonly SshPrivateKey Subject = SshPrivateKey.GenerateEd25519();

    private readonly TempDirectory _directory = new();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => _directory.Dispose();

    /// <summary>Re-encodes an RSA blob with redundant zeros in e and in n.</summary>
    internal static byte[] Pad(ReadOnlySpan<byte> blob, int zerosInE, int zerosInN)
    {
        SshReader reader = new(blob);
        string type = reader.ReadUtf8String();
        byte[] e = reader.ReadBinary().ToArray();
        byte[] n = reader.ReadBinary().ToArray();
        SshWriter writer = new(blob.Length + 16);
        try
        {
            writer.WriteUtf8String(type);
            writer.WriteBinary([.. new byte[zerosInE], .. e]);
            writer.WriteBinary([.. new byte[zerosInN], .. n]);
            return writer.ToArray();
        }
        finally
        {
            writer.Dispose();
        }
    }

    private KnownHostsPolicy Policy(string text, bool addUnknown = false)
    {
        string path = Path.Combine(_directory.Path, $"known_hosts-{Guid.NewGuid():N}");
        File.WriteAllText(path, text);
        return new KnownHostsPolicy([path], addUnknown, new FixedTime(Now));
    }

    private static string Line(string marker, SshPublicKey key, byte[]? blob = null) =>
        $"{marker} {Host} {key.KeyType} {Convert.ToBase64String(blob ?? key.Blob.ToArray())}\n";

    [Theory]
    [InlineData(1, 0)]
    [InlineData(0, 1)]
    [InlineData(2, 2)]
    public void T1_a_padded_RSA_key_has_the_canonical_blob_and_fingerprint(int zerosInE, int zerosInN)
    {
        byte[] canonical = Rsa.Value.PublicKey.Blob.ToArray();
        byte[] padded = Pad(canonical, zerosInE, zerosInN);
        Assert.NotEqual(canonical.Length, padded.Length);

        SshPublicKey parsed = SshPublicKey.Parse(padded);
        Assert.Equal(canonical, parsed.Blob.ToArray());
        Assert.Equal(HostKeyPolicy.ComputeFingerprint(canonical), HostKeyPolicy.ComputeFingerprint(parsed.Blob.Span));
    }

    [Theory]
    [InlineData(1, 0)]
    [InlineData(2, 2)]
    public async Task T1_a_revoked_RSA_key_padded_with_a_zero_byte_is_still_refused_under_accept_new(int zerosInE, int zerosInN)
    {
        SshPublicKey canonical = Rsa.Value.PublicKey;
        SshPublicKey padded = SshPublicKey.Parse(Pad(canonical.Blob.Span, zerosInE, zerosInN));
        KnownHostsPolicy policy = Policy(Line("@revoked", canonical), addUnknown: true);

        SshHostKeyException ex = await Assert.ThrowsAsync<SshHostKeyException>(async () => await policy.CheckAsync(Host, 22, padded, Ct));
        Assert.Contains("revoked", ex.Message);
    }

    [Fact]
    public async Task T1_a_revoked_line_written_with_a_padded_blob_still_revokes_the_canonical_key()
    {
        SshPublicKey canonical = Rsa.Value.PublicKey;
        KnownHostsPolicy policy = Policy(Line("@revoked", canonical, Pad(canonical.Blob.Span, 1, 1)), addUnknown: true);

        await Assert.ThrowsAsync<SshHostKeyException>(async () => await policy.CheckAsync(Host, 22, canonical, Ct));
    }

    [Fact]
    public async Task T1_a_trusted_line_matches_a_key_by_value()
    {
        SshPublicKey canonical = Rsa.Value.PublicKey;
        SshPublicKey padded = SshPublicKey.Parse(Pad(canonical.Blob.Span, 1, 1));
        KnownHostsPolicy policy = Policy(Line(string.Empty, canonical).TrimStart());

        Assert.True(await policy.CheckAsync(Host, 22, padded, Ct));
    }

    [Fact]
    public async Task T1_a_CA_key_padded_with_a_zero_byte_is_still_revoked()
    {
        SshPrivateKey ca = RsaCa.Value;
        byte[] paddedCa = Pad(ca.PublicKey.Blob.Span, 0, 1);
        SshCertificate certificate = new CertificateBuilder(Subject, ca) { SignatureKeyBlob = paddedCa }.Parse();
        string text = Line("@cert-authority", ca.PublicKey) + Line("@revoked", ca.PublicKey);

        SshHostKeyException ex = await Assert.ThrowsAsync<SshHostKeyException>(async () => await Policy(text).CheckAsync(Host, 22, certificate, Ct));
        Assert.Contains("revoked", ex.Message);
    }

    [Fact]
    public async Task T1_a_CA_key_padded_with_a_zero_byte_matches_its_cert_authority_line_by_value()
    {
        SshPrivateKey ca = RsaCa.Value;
        byte[] paddedCa = Pad(ca.PublicKey.Blob.Span, 1, 1);
        SshCertificate certificate = new CertificateBuilder(Subject, ca) { SignatureKeyBlob = paddedCa }.Parse();

        // The CA's signature covers the padded bytes as received, and it still verifies.
        Assert.True(await Policy(Line("@cert-authority", ca.PublicKey)).CheckAsync(Host, 22, certificate, Ct));

        // And a line that holds the padded spelling matches a canonical CA.
        SshCertificate plain = new CertificateBuilder(Subject, ca).Parse();
        Assert.True(await Policy(Line("@cert-authority", ca.PublicKey, paddedCa)).CheckAsync(Host, 22, plain, Ct));
    }

    [Fact]
    public async Task T1_a_certificate_for_a_revoked_RSA_subject_key_padded_with_a_zero_byte_is_refused()
    {
        SshPrivateKey ca = RsaCa.Value;
        SshPrivateKey subject = Rsa.Value;
        byte[] paddedSubjectCert = BuildWithPaddedSubject(subject, ca);
        SshCertificate certificate = SshCertificate.ParseCertificate(paddedSubjectCert);
        string text = Line("@cert-authority", ca.PublicKey) + Line("@revoked", subject.PublicKey);

        SshHostKeyException ex = await Assert.ThrowsAsync<SshHostKeyException>(async () => await Policy(text).CheckAsync(Host, 22, certificate, Ct));
        Assert.Contains("revoked", ex.Message);
    }

    /// <summary>A certificate whose subject key spells n with an extra zero, signed by the CA as received.</summary>
    private static byte[] BuildWithPaddedSubject(SshPrivateKey subject, SshPrivateKey ca)
    {
        byte[] good = new CertificateBuilder(subject, ca).Build();
        SshReader reader = new(good);
        string type = reader.ReadUtf8String();
        reader.ReadBinary(); // nonce
        byte[] e = reader.ReadBinary().ToArray();
        byte[] n = reader.ReadBinary().ToArray();
        int afterKey = good.Length - reader.Remaining;
        int signatureStart;
        {
            // The part from serial up to the CA key is copied as is.
            SshReader tail = new(good.AsSpan(afterKey));
            tail.ReadUInt64();
            tail.ReadUInt32();
            tail.ReadUtf8String();
            tail.ReadBinary();
            tail.ReadUInt64();
            tail.ReadUInt64();
            tail.ReadBinary();
            tail.ReadBinary();
            tail.ReadBinary();
            tail.ReadBinary(); // CA key
            signatureStart = good.Length - afterKey - tail.Remaining;
        }

        SshWriter writer = new(good.Length + 8);
        try
        {
            writer.WriteUtf8String(type);
            writer.WriteBinary(new byte[32]);
            writer.WriteBinary(e);
            writer.WriteBinary([.. new byte[] { 0 }, .. n]);
            writer.WriteRaw(good.AsSpan(afterKey, signatureStart));
            writer.WriteBinary(ca.Sign(ca.SignatureAlgorithms[0], writer.Written));
            return writer.ToArray();
        }
        finally
        {
            writer.Dispose();
        }
    }
}

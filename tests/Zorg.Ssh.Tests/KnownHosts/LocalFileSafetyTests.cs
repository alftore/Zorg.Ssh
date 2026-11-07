using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.Keys;
using Zorg.Ssh.Tests.Certificates;
using Zorg.Ssh.Tests.Crypto;

namespace Zorg.Ssh.Tests.KnownHosts;

/// <summary>
/// M5 review T7, T8 and T10: the local files that decide trust or hold keys are regular files, read with a limit, and
/// anything else is a library exception and not a hang, an out-of-memory or a BCL exception.
/// </summary>
public sealed class LocalFileSafetyTests : IDisposable
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(10);

    private readonly TempDirectory _directory = new();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static string NullDevice => OperatingSystem.IsWindows() ? "NUL" : "/dev/null";

    public void Dispose() => _directory.Dispose();

    /// <summary>Makes a FIFO, or skips: there is no such thing on Windows.</summary>
    private string MakeFifo()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Windows has no FIFOs.");
        string path = Path.Combine(_directory.Path, "fifo");
        using Process process = Process.Start(new ProcessStartInfo("mkfifo", path) { UseShellExecute = false })
            ?? throw new InvalidOperationException("mkfifo did not start.");
        process.WaitForExit();
        Assert.SkipWhen(process.ExitCode != 0, "mkfifo isn't available here.");
        return path;
    }

    private static async Task<T> WithinAsync<T>(Func<T> act) => await Task.Run(act, Ct).WaitAsync(Limit, Ct);

    // T7

    [Fact]
    public void T7_a_null_device_as_known_hosts_is_a_host_key_exception_and_not_a_BCL_one()
    {
        SshHostKeyException ex = Assert.Throws<SshHostKeyException>(() => Zorg.Ssh.KnownHosts.KnownHostsFile.Load(NullDevice));
        Assert.Contains("regular file", ex.Message);
    }

    [Fact]
    public async Task T7_connecting_with_a_null_device_as_known_hosts_fails_with_an_Ssh_exception()
    {
        HostKeyPolicy policy = HostKeyPolicy.KnownHostsFile(NullDevice);
        using SshPrivateKey key = SshPrivateKey.GenerateEd25519();

        // The algorithm list is asked for before the transport starts, so it can't throw anything of its own.
        Assert.Equal(HostKeyAlgorithms.Default, policy.HostKeyAlgorithmsFor("web", 22));
        await Assert.ThrowsAsync<SshHostKeyException>(async () => await policy.CheckAsync("web", 22, key.PublicKey, Ct));
    }

    // T10

    [Fact]
    public void T10_a_directory_as_known_hosts_is_refused()
    {
        Assert.Throws<SshHostKeyException>(() => Zorg.Ssh.KnownHosts.KnownHostsFile.Load(_directory.Path));
    }

    [Fact]
    public async Task T10_a_FIFO_as_known_hosts_does_not_hang()
    {
        string fifo = MakeFifo();

        await Assert.ThrowsAsync<SshHostKeyException>(async () => await WithinAsync(() => Zorg.Ssh.KnownHosts.KnownHostsFile.Load(fifo)));
    }

    [Fact]
    public async Task T10_dev_zero_as_known_hosts_does_not_use_up_memory()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Windows has no /dev/zero.");

        await Assert.ThrowsAsync<SshHostKeyException>(async () => await WithinAsync(() => Zorg.Ssh.KnownHosts.KnownHostsFile.Load("/dev/zero")));
    }

    [Fact]
    public async Task T10_a_FIFO_named_by_Include_is_refused_and_does_not_hang()
    {
        string fifo = MakeFifo();

        SshConfigException ex = await Assert.ThrowsAsync<SshConfigException>(
            async () => await WithinAsync(() => SshConfig.Parse($"Include {fifo}\n", _directory.Path, null)));
        Assert.Contains("regular file", ex.Message);
    }

    [Fact]
    public async Task T10_dev_zero_as_config_is_refused()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Windows has no /dev/zero.");

        await Assert.ThrowsAsync<SshConfigException>(async () => await WithinAsync(() => SshConfig.Load("/dev/zero")));
    }

    [Fact]
    public async Task T10_a_FIFO_as_identity_file_is_refused_and_does_not_hang()
    {
        string fifo = MakeFifo();
        PrivateKeyCredential credential = (PrivateKeyCredential)SshCredential.FromIdentityFile(fifo);

        await Assert.ThrowsAsync<SshKeyFileException>(async () => await WithinAsync(credential.Load));
    }

    [Fact]
    public async Task T10_dev_zero_as_identity_file_does_not_use_up_memory()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Windows has no /dev/zero.");
        PrivateKeyCredential credential = (PrivateKeyCredential)SshCredential.FromIdentityFile("/dev/zero");

        await Assert.ThrowsAsync<SshKeyFileException>(async () => await WithinAsync(credential.Load));
    }

    [Fact]
    public void T10_an_identity_file_over_the_limit_is_refused_before_it_is_read_whole()
    {
        string path = Path.Combine(_directory.Path, "big_key");
        using (FileStream stream = File.Create(path))
        {
            stream.SetLength((1 << 20) + 1);
        }

        PrivateKeyCredential credential = (PrivateKeyCredential)SshCredential.FromIdentityFile(path);

        SshKeyFileException ex = Assert.Throws<SshKeyFileException>(credential.Load);
        Assert.Contains("limit", ex.Message);
    }

    [Fact]
    public void T10_a_limit_is_enforced_while_reading_and_not_from_the_reported_length()
    {
        string path = Path.Combine(_directory.Path, "twenty");
        File.WriteAllBytes(path, new byte[20]);

        IOException ex = Assert.Throws<IOException>(() => LocalFile.ReadAllBytes(path, 19));
        Assert.Contains("limit", ex.Message);
        Assert.Equal(20, LocalFile.ReadAllBytes(path, 20).Length);
    }

    [Fact]
    public void T10_an_ordinary_identity_file_still_loads()
    {
        // The key is generated at test time, never stored.
        string path = Path.Combine(_directory.Path, "id_ed25519");
        File.WriteAllText(path, Fuzzing.FuzzKeys.Ed25519OpenSsh);

        using SshPrivateKey loaded = ((PrivateKeyCredential)SshCredential.FromIdentityFile(path)).Load();

        Assert.Equal(Convert.FromBase64String(Fuzzing.FuzzKeys.Ed25519PublicLine.Split(' ')[1]), loaded.PublicKey.Blob.ToArray());
    }

    // T8

    [Fact]
    public void T8_a_line_over_the_limit_throws_and_is_not_dropped()
    {
        string longHosts = string.Join(',', Enumerable.Repeat("host.example", (Zorg.Ssh.KnownHosts.KnownHostsFile.MaxLineLength / 12) + 1));
        string text = $"@revoked {longHosts} ssh-ed25519 AAAA\n";

        SshHostKeyException ex = Assert.Throws<SshHostKeyException>(() => Zorg.Ssh.KnownHosts.KnownHostsFile.Parse(text));
        Assert.Contains("revocation", ex.Message);
    }

    [Fact]
    public async Task T8_a_revoked_line_for_a_large_certificate_is_not_dropped()
    {
        using SshPrivateKey ca = SshPrivateKey.GenerateEd25519();
        using SshPrivateKey subject = SshPrivateKey.GenerateEd25519();

        // 200 principals of 500 characters: a certificate of about 100 KB, which is about 135 KB as base64.
        string[] principals = [.. Enumerable.Range(0, 200).Select(i => $"p{i}-".PadRight(500, 'x')), "host.example.com"];
        byte[] blob = new CertificateBuilder(subject, ca) { Principals = principals }.Build();
        string certificateType = subject.PublicKey.KeyType + "-cert-v01@openssh.com";
        string encoded = Convert.ToBase64String(blob);
        Assert.True(encoded.Length > 64 * 1024, "the line must be longer than the old limit");

        string text = CertificateBuilder.CaLine("*.example.com", ca) + $"@revoked host.example.com {certificateType} {encoded}\n";
        string path = Path.Combine(_directory.Path, "known_hosts");
        await File.WriteAllTextAsync(path, text, Ct);
        KnownHostsPolicy policy = new([path], false, new FixedTime(new DateTimeOffset(2026, 11, 5, 12, 0, 0, TimeSpan.Zero)));

        SshHostKeyException ex = await Assert.ThrowsAsync<SshHostKeyException>(
            async () => await policy.CheckAsync("host.example.com", 22, SshCertificate.ParseCertificate(blob), Ct));
        Assert.Contains("revoked", ex.Message);
    }
}

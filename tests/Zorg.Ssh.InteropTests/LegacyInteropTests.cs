using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Zorg.Ssh.InteropTests;

/// <summary>
/// <see cref="SshAlgorithms.LegacyUnsafe"/> against real peers. OpenSSH 10 still compiles every one of these algorithms in,
/// so its sshd is started offering only the one under test. OpenSSH 7.4 is an old server's whole profile, and Dropbear runs
/// with only an RSA host key. The OpenSSH client checks our server's side: Diffie-Hellman, an ssh-rsa host key and an
/// ssh-rsa user signature, all at once.
/// </summary>
public sealed class LegacyInteropTests : IDisposable
{
    private const string User = "zorg";
    private const string Password = "zorg-test";

    private readonly string _directory = Directory.CreateTempSubdirectory("zorg-ssh-legacy").FullName;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    [InteropTheory]
    [InlineData("diffie-hellman-group14-sha256")]
    [InlineData("diffie-hellman-group16-sha512")]
    [InlineData("diffie-hellman-group14-sha1")]
    public async Task Each_finite_field_group_works_with_OpenSSH_10(string kex)
    {
        await using SshPeerContainer container = await StartAsync("openssh-10", "-o", $"KexAlgorithms={kex}");
        InteropLog log = await AssertSessionAsync(container, SshAlgorithms.LegacyUnsafe);

        AssertLogged(log, $"kex={kex} ", "strict=True");
        AssertLogged(log, $"[Warning] Using the legacy algorithm {kex}");
    }

    [InteropFact]
    public async Task An_ssh_rsa_host_key_works_with_OpenSSH_10()
    {
        await using SshPeerContainer container = await StartAsync("openssh-10", "-o", "HostKeyAlgorithms=ssh-rsa");
        InteropLog log = await AssertSessionAsync(container, SshAlgorithms.LegacyUnsafe);

        AssertLogged(log, "hostkey=ssh-rsa ");
        AssertLogged(log, "[Warning] Using the legacy algorithm ssh-rsa");
    }

    [InteropTheory]
    [InlineData("hmac-sha1")]
    [InlineData("hmac-sha1-etm@openssh.com")]
    public async Task Each_SHA_1_MAC_works_with_OpenSSH_10(string mac)
    {
        await using SshPeerContainer container = await StartAsync("openssh-10", "-o", "Ciphers=aes128-ctr", "-o", $"MACs={mac}");
        InteropLog log = await AssertSessionAsync(container, SshAlgorithms.LegacyUnsafe);

        AssertLogged(log, $"send=aes128-ctr mac={mac} receive=aes128-ctr mac={mac} strict=True");
    }

    [InteropFact]
    public async Task An_ssh_rsa_user_signature_works_with_OpenSSH_10()
    {
        // sshd takes only ssh-rsa signatures, so a login proves the client signed with SHA-1.
        string key = await GenerateRsaKeyAsync();
        string publicKey = (await File.ReadAllTextAsync(key + ".pub", Ct)).Trim();
        PeerTools.RequireContainers();
        string image = await SshPeerContainer.BuildImageAsync("zorg-ssh-test/openssh-10", Path.Combine(PeerTools.PeersPath, "openssh-10"), Ct);
        string script = $"mkdir -p /home/zorg/.ssh && echo '{publicKey}' > /home/zorg/.ssh/authorized_keys"
            + " && chown -R zorg /home/zorg/.ssh && chmod 700 /home/zorg/.ssh && chmod 600 /home/zorg/.ssh/authorized_keys"
            + " && exec /usr/sbin/sshd -D -e -o PasswordAuthentication=no -o PubkeyAcceptedAlgorithms=ssh-rsa";
        await using SshPeerContainer container = await SshPeerContainer.StartAsync(image, ["/bin/sh", "-c", script], cancellationToken: Ct);

        await AssertSessionAsync(container, SshAlgorithms.LegacyUnsafe, SshCredential.FromPrivateKeyFile(key));

        // Without LegacyUnsafe the same key is refused, because the client won't sign with SHA-1.
        await Assert.ThrowsAsync<SshAuthenticationException>(() => ConnectAsync(container, SshAlgorithms.Default, null, SshCredential.FromPrivateKeyFile(key)));
    }

    [InteropFact]
    public async Task An_old_device_profile_works_with_OpenSSH_10_and_a_default_client_is_pointed_at_LegacyUnsafe()
    {
        // HPE iLO and classic Cisco IOS: group14-sha1, ssh-rsa, aes128-ctr and hmac-sha1, and nothing else.
        string[] profile = ["-o", "KexAlgorithms=diffie-hellman-group14-sha1", "-o", "HostKeyAlgorithms=ssh-rsa", "-o", "Ciphers=aes128-ctr", "-o", "MACs=hmac-sha1"];
        await using SshPeerContainer container = await StartAsync("openssh-10", profile);
        InteropLog log = await AssertSessionAsync(container, SshAlgorithms.LegacyUnsafe);
        AssertLogged(log, "kex=diffie-hellman-group14-sha1 hostkey=ssh-rsa send=aes128-ctr mac=hmac-sha1");

        SshNegotiationException refused = await Assert.ThrowsAsync<SshNegotiationException>(() => ConnectAsync(container, SshAlgorithms.Default, null));
        Assert.Contains("SshAlgorithms.LegacyUnsafe enables", refused.Message, StringComparison.Ordinal);
    }

    [InteropFact]
    public async Task OpenSSH_7_4_with_an_old_profile_works_without_strict_KEX()
    {
        await using SshPeerContainer container = await StartAsync(
            "openssh-7.4", "-o", "KexAlgorithms=diffie-hellman-group14-sha1", "-o", "HostKeyAlgorithms=ssh-rsa", "-o", "Ciphers=aes128-ctr", "-o", "MACs=hmac-sha1");
        InteropLog log = await AssertSessionAsync(container, SshAlgorithms.LegacyUnsafe);

        // 7.4 reads HostKeyAlgorithms=ssh-rsa as the key type, and still signs with SHA-2, which is the better choice.
        AssertLogged(log, "kex=diffie-hellman-group14-sha1 hostkey=rsa-sha2-512 send=aes128-ctr mac=hmac-sha1", "strict=False");
    }

    [InteropTheory]
    [InlineData("diffie-hellman-group14-sha256")]
    [InlineData("diffie-hellman-group16-sha512")]
    public async Task OpenSSH_7_4_completes_each_SHA_2_group(string kex)
    {
        await using SshPeerContainer container = await StartAsync("openssh-7.4", "-o", $"KexAlgorithms={kex}");
        InteropLog log = await AssertSessionAsync(container, SshAlgorithms.LegacyUnsafe);

        AssertLogged(log, $"kex={kex} ");
    }

    [InteropFact]
    public async Task Dropbear_with_only_an_RSA_host_key_works_with_LegacyUnsafe()
    {
        await using SshPeerContainer container = await StartDropbearRsaOnlyAsync();
        InteropLog log = await AssertSessionAsync(container, SshAlgorithms.LegacyUnsafe);

        // A Dropbear with SHA-2 RSA uses it, so LegacyUnsafe changes nothing for it.
        AssertLogged(log, "hostkey=rsa-sha2-256 ");
    }

    [InteropFact]
    public async Task Dropbear_with_only_an_RSA_host_key_no_longer_offers_SHA_1()
    {
        // Dropbear 2025.87 turned SHA-1 RSA off by default, and Alpine's build follows. An older Dropbear (2013 to 2020, with
        // ssh-rsa only) has no image here; OpenSSH 10 offering only ssh-rsa stands in for it above.
        await using SshPeerContainer container = await StartDropbearRsaOnlyAsync();
        SshNegotiationException refused = await Assert.ThrowsAsync<SshNegotiationException>(
            () => ConnectAsync(container, new SshAlgorithms { HostKeys = ["ssh-rsa"] }, null));

        Assert.Equal(["rsa-sha2-256"], refused.PeerAlgorithms);
    }

    [InteropFact]
    public async Task Dropbear_completes_a_finite_field_group()
    {
        await using SshPeerContainer container = await StartDropbearRsaOnlyAsync();
        InteropLog log = await AssertSessionAsync(container, new SshAlgorithms { KeyExchange = ["diffie-hellman-group14-sha256"] });

        AssertLogged(log, "kex=diffie-hellman-group14-sha256 ");
    }

    [InteropFact]
    public async Task The_OpenSSH_client_logs_in_to_our_server_over_Diffie_Hellman_ssh_rsa_and_hmac_sha1()
    {
        string key = await GenerateRsaKeyAsync();
        using SshHostKey hostKey = new(Crypto.SshPrivateKey.GenerateRsa(2048));
        string? keyType = null;
        await using SshServer server = await SshServer.StartAsync(
            new SshServerOptions
            {
                HostKeys = [hostKey],
                Algorithms = new SshAlgorithms
                {
                    KeyExchange = ["diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1"],
                    HostKeys = ["ssh-rsa"],
                    Ciphers = ["aes128-ctr"],
                    Macs = ["hmac-sha1"],
                },
                PublicKeyHandler = (request, _) =>
                {
                    keyType = request.KeyType;
                    return ValueTask.FromResult(SshAuthDecision.Accept);
                },
                SessionHandler = async (session, ct) =>
                {
                    await session.Output.WriteAsync(Encoding.ASCII.GetBytes($"ran {session.Command}\n"), ct);
                    return 5;
                },
            },
            Ct);

        (int exitCode, string log) = await RunSshAsync(
            server.LocalEndPoint,
            ["-i", key, "-o", "IdentitiesOnly=yes", "-o", "PreferredAuthentications=publickey",
             "-o", "KexAlgorithms=diffie-hellman-group14-sha1", "-o", "HostKeyAlgorithms=ssh-rsa", "-o", "PubkeyAcceptedAlgorithms=ssh-rsa",
             "-o", "Ciphers=aes128-ctr", "-o", "MACs=hmac-sha1"]);

        Assert.True(exitCode == 5, log);
        Assert.Contains("ran hello", log, StringComparison.Ordinal);
        Assert.Contains("kex: algorithm: diffie-hellman-group14-sha1", log, StringComparison.Ordinal);
        Assert.Contains("kex: host key algorithm: ssh-rsa", log, StringComparison.Ordinal);
        Assert.Contains("cipher: aes128-ctr MAC: hmac-sha1 compression", log, StringComparison.Ordinal);
        Assert.Equal("ssh-rsa", keyType);
    }

    private async Task<string> GenerateRsaKeyAsync()
    {
        string path = Path.Combine(_directory, "id-rsa-" + Guid.NewGuid().ToString("N"));
        await RunAsync(KeygenPath(), "-q", "-t", "rsa", "-b", "2048", "-N", string.Empty, "-f", path);
        return path;
    }

    private static async Task<SshPeerContainer> StartAsync(string peer, params string[] sshdOptions)
    {
        PeerTools.RequireContainers();
        string image = await SshPeerContainer.BuildImageAsync($"zorg-ssh-test/{peer}", Path.Combine(PeerTools.PeersPath, peer), Ct);
        return await SshPeerContainer.StartAsync(image, ["/usr/sbin/sshd", "-D", "-e", .. sshdOptions], cancellationToken: Ct);
    }

    private static async Task<SshPeerContainer> StartDropbearRsaOnlyAsync()
    {
        PeerTools.RequireContainers();
        string image = await SshPeerContainer.BuildImageAsync("zorg-ssh-test/dropbear", Path.Combine(PeerTools.PeersPath, "dropbear"), Ct);

        // The key is made when the container starts, so no key is in the image or the repository.
        return await SshPeerContainer.StartAsync(
            image,
            ["/bin/sh", "-c", "dropbearkey -t rsa -s 2048 -f /tmp/rsa_host_key >/dev/null && exec /usr/sbin/dropbear -r /tmp/rsa_host_key -F -E -p 22"],
            cancellationToken: Ct);
    }

    private static Task<SshClient> ConnectAsync(SshPeerContainer container, SshAlgorithms algorithms, InteropLog? log, SshCredential? credential = null) =>
        SshClient.ConnectAsync(
            new SshClientOptions
            {
                Host = container.Host,
                Port = container.Port,
                UserName = User,
                Credentials = [credential ?? SshCredential.FromPassword(Password)],
                HostKeyPolicy = HostKeyPolicy.AcceptAnyUnsafe(),
                Algorithms = algorithms,
                LoggerFactory = log,
            },
            Ct);

    /// <summary>Logs in, runs a command, rekeys, and runs another, so the negotiated algorithms carry a real session.</summary>
    private static async Task<InteropLog> AssertSessionAsync(SshPeerContainer container, SshAlgorithms algorithms, SshCredential? credential = null)
    {
        InteropLog log = new();
        await using SshClient client = await ConnectAsync(container, algorithms, log, credential);
        SshCommandResult first = await client.ExecuteAsync("head -c 500000 /dev/zero | tr '\\0' 'a'", Ct);
        Assert.Equal(500_000, first.StandardOutput.Length);

        client.RequestRekey();
        SshCommandResult second = await client.ExecuteAsync("echo after-rekey", Ct);
        Assert.Equal("after-rekey\n", second.StandardOutput);
        Assert.True(client.CompletedKeyExchanges >= 2, $"Only {client.CompletedKeyExchanges} key exchanges completed.");
        return log;
    }

    private static void AssertLogged(InteropLog log, params string[] parts)
    {
        foreach (string line in log.Text.Split(Environment.NewLine))
        {
            if (Array.TrueForAll(parts, part => line.Contains(part, StringComparison.Ordinal)))
            {
                return;
            }
        }

        Assert.Fail($"No log line holds all of [{string.Join("], [", parts)}]:{Environment.NewLine}{log.Text}");
    }

    private static string KeygenPath()
    {
        string ssh = PeerTools.RequireSshClient();
        return Path.Combine(Path.GetDirectoryName(ssh)!, OperatingSystem.IsWindows() ? "ssh-keygen.exe" : "ssh-keygen");
    }

    private static async Task<string> RunAsync(string program, params string[] arguments)
    {
        ProcessStartInfo start = new(program) { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using Process process = Process.Start(start)!;
        Task<string> error = process.StandardError.ReadToEndAsync(Ct);
        string output = await process.StandardOutput.ReadToEndAsync(Ct);
        await process.WaitForExitAsync(Ct);
        Assert.True(process.ExitCode == 0, await error);
        return output;
    }

    private static async Task<(int ExitCode, string Log)> RunSshAsync(IPEndPoint server, string[] extraArguments)
    {
        ProcessStartInfo start = new(PeerTools.RequireSshClient())
        {
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            RedirectStandardInput = true,
        };
        foreach (string argument in (string[])
            ["-vvv", "-F", "none", "-p", server.Port.ToString(System.Globalization.CultureInfo.InvariantCulture),
             "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
             .. extraArguments, "zorg@127.0.0.1", "hello"])
        {
            start.ArgumentList.Add(argument);
        }

        using Process process = Process.Start(start)!;
        process.StandardInput.Close();
        Task<string> output = process.StandardOutput.ReadToEndAsync(Ct);
        Task<string> error = process.StandardError.ReadToEndAsync(Ct);
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(60));
        await process.WaitForExitAsync(timeout.Token);
        return (process.ExitCode, await output + await error);
    }
}

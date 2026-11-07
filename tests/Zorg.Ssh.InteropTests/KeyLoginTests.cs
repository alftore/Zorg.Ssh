using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Zorg.Ssh.InteropTests;

/// <summary>Public key login and known_hosts against real OpenSSH, with keys made by real <c>ssh-keygen</c>.</summary>
public sealed class KeyLoginTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("zorg-ssh-key").FullName;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private static async Task<string> RunAsync(string program, params string[] arguments)
    {
        ProcessStartInfo start = new(program)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
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

    private static string KeygenPath()
    {
        string ssh = PeerTools.RequireSshClient();
        return Path.Combine(Path.GetDirectoryName(ssh)!, OperatingSystem.IsWindows() ? "ssh-keygen.exe" : "ssh-keygen");
    }

    private async Task<string> GenerateAsync(string type, string bits, string passphrase = "")
    {
        string path = Path.Combine(_directory, $"key-{type}-{bits}-{Guid.NewGuid():N}");
        await RunAsync(KeygenPath(), "-q", "-t", type, "-b", bits, "-N", passphrase, "-f", path);
        return path;
    }

    private static async Task<SshPeerContainer> StartWithAuthorizedKeyAsync(string keyPath)
    {
        PeerTools.RequireContainers();
        string image = await SshPeerContainer.BuildImageAsync("zorg-ssh-test/openssh-10", Path.Combine(PeerTools.PeersPath, "openssh-10"), Ct);
        string publicKey = (await File.ReadAllTextAsync(keyPath + ".pub", Ct)).Trim();

        // The key goes in through the command line, so the image stays free of test keys.
        string script = $"mkdir -p /home/zorg/.ssh && echo '{publicKey}' > /home/zorg/.ssh/authorized_keys"
            + " && chown -R zorg /home/zorg/.ssh && chmod 700 /home/zorg/.ssh && chmod 600 /home/zorg/.ssh/authorized_keys"
            + " && exec /usr/sbin/sshd -D -e -o PasswordAuthentication=no";
        return await SshPeerContainer.StartAsync(image, ["/bin/sh", "-c", script], cancellationToken: Ct);
    }

    [InteropTheory]
    [InlineData("ed25519", "256")]
    [InlineData("ecdsa", "256")]
    [InlineData("ecdsa", "384")]
    [InlineData("ecdsa", "521")]
    [InlineData("rsa", "3072")]
    public async Task Each_key_type_logs_in(string type, string bits)
    {
        string key = await GenerateAsync(type, bits);
        await using SshPeerContainer container = await StartWithAuthorizedKeyAsync(key);
        await using SshClient client = await SshClient.ConnectAsync(
            new SshClientOptions
            {
                Host = container.Host,
                Port = container.Port,
                UserName = "zorg",
                Credentials = [SshCredential.FromPrivateKeyFile(key)],
                HostKeyPolicy = HostKeyPolicy.AcceptAnyUnsafe(),
            },
            Ct);
        Assert.Equal("zorg\n", (await client.ExecuteAsync("whoami", Ct)).StandardOutput);
    }

    [InteropFact]
    public async Task An_encrypted_key_logs_in()
    {
        string key = await GenerateAsync("ed25519", "256", "s3cret");
        await using SshPeerContainer container = await StartWithAuthorizedKeyAsync(key);
        await using SshClient client = await SshClient.ConnectAsync(
            new SshClientOptions
            {
                Host = container.Host,
                Port = container.Port,
                UserName = "zorg",
                Credentials = [SshCredential.FromPrivateKeyFile(key, "s3cret")],
                HostKeyPolicy = HostKeyPolicy.AcceptAnyUnsafe(),
            },
            Ct);
        Assert.Equal("zorg\n", (await client.ExecuteAsync("whoami", Ct)).StandardOutput);
    }

    // The plan's M2 exit: offering keys the server doesn't know mustn't use up MaxAuthTries (default 6).
    [InteropFact]
    public async Task Unknown_keys_before_the_right_one_do_not_exhaust_MaxAuthTries()
    {
        string good = await GenerateAsync("ed25519", "256");
        await using SshPeerContainer container = await StartWithAuthorizedKeyAsync(good);
        SshCredential[] credentials = new SshCredential[5];
        for (int i = 0; i < 4; i++)
        {
            credentials[i] = SshCredential.FromPrivateKey(await File.ReadAllTextAsync(await GenerateAsync("ecdsa", (i % 2 == 0 ? 256 : 384).ToString(System.Globalization.CultureInfo.InvariantCulture)), Ct));
        }

        credentials[4] = SshCredential.FromPrivateKeyFile(good);
        await using SshClient client = await SshClient.ConnectAsync(
            new SshClientOptions
            {
                Host = container.Host,
                Port = container.Port,
                UserName = "zorg",
                Credentials = credentials,
                HostKeyPolicy = HostKeyPolicy.AcceptAnyUnsafe(),
            },
            Ct);
        Assert.Equal("zorg\n", (await client.ExecuteAsync("whoami", Ct)).StandardOutput);
    }

    [InteropFact]
    public async Task Known_hosts_trusts_a_recorded_key_and_refuses_a_changed_one()
    {
        string key = await GenerateAsync("ed25519", "256");
        await using SshPeerContainer container = await StartWithAuthorizedKeyAsync(key);
        string knownHosts = Path.Combine(_directory, "known_hosts");

        SshClientOptions Options(HostKeyPolicy policy) => new()
        {
            Host = container.Host,
            Port = container.Port,
            UserName = "zorg",
            Credentials = [SshCredential.FromPrivateKeyFile(key)],
            HostKeyPolicy = policy,
        };

        // Unknown: refused, and the message tells the reader what to do.
        SshHostKeyException unknown = await Assert.ThrowsAsync<SshHostKeyException>(
            () => SshClient.ConnectAsync(Options(HostKeyPolicy.KnownHostsFile(knownHosts)), Ct));
        Assert.Contains("SHA256:", unknown.Message);

        // Accept-new records it, then the strict policy trusts it.
        await (await SshClient.ConnectAsync(Options(HostKeyPolicy.KnownHostsFile(knownHosts, addUnknownHostsUnsafe: true)), Ct)).DisposeAsync();
        await using (SshClient trusted = await SshClient.ConnectAsync(Options(HostKeyPolicy.KnownHostsFile(knownHosts)), Ct))
        {
            Assert.Equal("zorg\n", (await trusted.ExecuteAsync("whoami", Ct)).StandardOutput);
        }

        // The same name with a different key: refused, even when unknown hosts would be accepted.
        using Crypto.SshPrivateKey impostor = Crypto.SshPrivateKey.GenerateEd25519();
        string changedFile = Path.Combine(_directory, "known_hosts_changed");
        KnownHosts.KnownHostsFile.Append(changedFile, container.Host, container.Port, impostor.PublicKey);
        SshHostKeyException changed = await Assert.ThrowsAsync<SshHostKeyException>(
            () => SshClient.ConnectAsync(Options(HostKeyPolicy.KnownHostsFile(changedFile, addUnknownHostsUnsafe: true)), Ct));
        Assert.Contains("attack", changed.Message);
    }
}

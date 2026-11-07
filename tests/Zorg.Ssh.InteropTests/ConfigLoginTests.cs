using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Zorg.Ssh.InteropTests;

/// <summary>A real login with nothing but a config file, against real sshd.</summary>
public sealed class ConfigLoginTests : IDisposable
{
    private readonly KeygenTool _keygen = new();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => _keygen.Dispose();

    private async Task<(SshPeerContainer Container, SshConfig Config, string KnownHosts)> StartAsync(string hostKeyChecking)
    {
        PeerTools.RequireContainers();
        string key = await _keygen.GenerateAsync("ed25519", "256");
        string image = await SshPeerContainer.BuildImageAsync("zorg-ssh-test/openssh-10", Path.Combine(PeerTools.PeersPath, "openssh-10"), Ct);
        string publicKey = (await File.ReadAllTextAsync(key + ".pub", Ct)).Trim();
        string script = $"mkdir -p /home/zorg/.ssh && echo '{publicKey}' > /home/zorg/.ssh/authorized_keys"
            + " && chown -R zorg /home/zorg/.ssh && chmod 700 /home/zorg/.ssh && chmod 600 /home/zorg/.ssh/authorized_keys"
            + " && exec /usr/sbin/sshd -D -e -o PasswordAuthentication=no";
        SshPeerContainer container = await SshPeerContainer.StartAsync(image, ["/bin/sh", "-c", script], cancellationToken: Ct);

        string knownHosts = _keygen.PathOf("known_hosts");
        string text = $"""
            Host peer
              HostName {container.Host}
              Port {container.Port}
              User zorg
              IdentityFile "{key}"
              IdentitiesOnly yes
              UserKnownHostsFile "{knownHosts}"
              StrictHostKeyChecking {hostKeyChecking}
            """;
        return (container, SshConfig.Parse(text), knownHosts);
    }

    [InteropFact]
    public async Task Accept_new_records_the_host_and_then_trusts_it()
    {
        (SshPeerContainer container, SshConfig config, string knownHosts) = await StartAsync("accept-new");
        await using (container)
        {
            for (int i = 0; i < 2; i++)
            {
                await using SshClient client = await SshClient.ConnectAsync(SshClientOptions.FromConfig("peer", config), Ct);
                Assert.Equal("zorg\n", (await client.ExecuteAsync("whoami", Ct)).StandardOutput);
            }

            Assert.Single(await File.ReadAllLinesAsync(knownHosts, Ct));
        }
    }

    [InteropFact]
    public async Task Strict_checking_refuses_an_unknown_host()
    {
        (SshPeerContainer container, SshConfig config, _) = await StartAsync("yes");
        await using (container)
        {
            await Assert.ThrowsAsync<SshHostKeyException>(() => SshClient.ConnectAsync(SshClientOptions.FromConfig("peer", config), Ct));
        }
    }

    [InteropFact]
    public async Task Checking_off_needs_the_callers_own_policy()
    {
        (SshPeerContainer container, SshConfig config, _) = await StartAsync("no");
        await using (container)
        {
            Assert.Throws<SshConfigException>(() => SshClientOptions.FromConfig("peer", config));
            await using SshClient client = await SshClient.ConnectAsync(SshClientOptions.FromConfig("peer", config, HostKeyPolicy.AcceptAnyUnsafe()), Ct);
            Assert.Equal("zorg\n", (await client.ExecuteAsync("whoami", Ct)).StandardOutput);
        }
    }
}

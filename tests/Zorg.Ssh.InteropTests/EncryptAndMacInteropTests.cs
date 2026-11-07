using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Zorg.Ssh.InteropTests;

/// <summary>
/// AES-CTR with encrypt-and-MAC HMAC-SHA-2, against servers configured to offer nothing else: OpenSSH 10 restricted to these
/// MACs, and Dropbear, which has never had an EtM MAC. Each run logs in, moves enough data for many packets, rekeys, and moves
/// more, so the keystream and sequence numbers run on across NEWKEYS. Strict KEX must still be negotiated.
/// </summary>
public class EncryptAndMacInteropTests
{
    private const string User = "zorg";
    private const string Password = "zorg-test";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public static TheoryData<string, string> Suites() => new()
    {
        { "aes128-ctr", "hmac-sha2-256" },
        { "aes256-ctr", "hmac-sha2-512" },
        { "aes256-ctr", "hmac-sha2-256" },
        { "aes128-ctr", "hmac-sha2-512" },
    };

    [InteropTheory]
    [MemberData(nameof(Suites))]
    public async Task Our_client_works_with_OpenSSH_restricted_to_encrypt_and_MAC(string cipher, string mac)
    {
        await using SshPeerContainer container = await StartAsync(
            "openssh-10", ["/usr/sbin/sshd", "-D", "-e", "-o", $"Ciphers={cipher}", "-o", $"MACs={mac}"]);
        await AssertSessionAsync(container, new SshAlgorithms(), cipher, mac);
    }

    [InteropTheory]
    [InlineData("aes128-ctr", "hmac-sha2-256")]
    [InlineData("aes256-ctr", "hmac-sha2-256")]
    public async Task Our_client_works_with_Dropbear_over_encrypt_and_MAC(string cipher, string mac)
    {
        // Dropbear builds leave hmac-sha2-512 out by default (DROPBEAR_SHA2_512_HMAC), and Alpine's does.
        // Dropbear would choose ChaCha20 with our defaults, so the client offers only the suite under test.
        await using SshPeerContainer container = await StartAsync("dropbear", null);
        await AssertSessionAsync(container, new SshAlgorithms { Ciphers = [cipher], Macs = [mac] }, cipher, mac);
    }

    [InteropFact]
    public async Task Our_default_client_falls_back_to_encrypt_and_MAC_when_a_server_has_no_EtM()
    {
        await using SshPeerContainer container = await StartAsync(
            "openssh-10", ["/usr/sbin/sshd", "-D", "-e", "-o", "Ciphers=aes256-ctr", "-o", "MACs=hmac-sha2-512,hmac-sha2-256"]);
        await AssertSessionAsync(container, SshAlgorithms.Default, "aes256-ctr", "hmac-sha2-512");
    }

    private static async Task AssertSessionAsync(SshPeerContainer container, SshAlgorithms algorithms, string cipher, string mac)
    {
        InteropLog log = new();
        SshClientOptions options = new()
        {
            Host = container.Host,
            Port = container.Port,
            UserName = User,
            Credentials = [SshCredential.FromPassword(Password)],
            HostKeyPolicy = HostKeyPolicy.AcceptAnyUnsafe(),
            Algorithms = algorithms,
            LoggerFactory = log,
        };
        await using SshClient client = await SshClient.ConnectAsync(options, Ct);

        SshCommandResult first = await client.ExecuteAsync("head -c 3000000 /dev/zero | tr '\\0' 'a'", Ct);
        Assert.Equal(3_000_000, first.StandardOutput.Length);

        client.RequestRekey();
        SshCommandResult second = await client.ExecuteAsync("echo after-rekey; head -c 1000000 /dev/zero | tr '\\0' 'b' | wc -c", Ct);
        Assert.Equal("after-rekey\n1000000\n", second.StandardOutput.Replace(" ", string.Empty, StringComparison.Ordinal));
        Assert.True(client.CompletedKeyExchanges >= 2, $"Only {client.CompletedKeyExchanges} key exchanges completed.");

        string expected = $"send={cipher} mac={mac} receive={cipher} mac={mac} strict=True";
        Assert.True(log.Contains(expected), $"Expected '{expected}' in the log:{Environment.NewLine}{log.Text}");
    }

    private static async Task<SshPeerContainer> StartAsync(string peer, string[]? command)
    {
        PeerTools.RequireContainers();
        string image = await SshPeerContainer.BuildImageAsync($"zorg-ssh-test/{peer}", Path.Combine(PeerTools.PeersPath, peer), Ct);
        return await SshPeerContainer.StartAsync(image, command, cancellationToken: Ct);
    }
}

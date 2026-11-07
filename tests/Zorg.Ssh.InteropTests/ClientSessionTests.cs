using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Zorg.Ssh.InteropTests;

/// <summary>The public client against real servers, through login, exec and flow control.</summary>
public class ClientSessionTests
{
    private const string User = "zorg";
    private const string Password = "zorg-test";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public static TheoryData<string> PasswordPeers() => new("openssh-10", "openssh-7.4", "dropbear");

    private static async Task<SshPeerContainer> StartAsync(string peer)
    {
        PeerTools.RequireContainers();
        string image = await SshPeerContainer.BuildImageAsync($"zorg-ssh-test/{peer}", Path.Combine(PeerTools.PeersPath, peer), Ct);
        return await SshPeerContainer.StartAsync(image, cancellationToken: Ct);
    }

    private static SshClientOptions Options(SshPeerContainer container, params SshCredential[] credentials) => new()
    {
        Host = container.Host,
        Port = container.Port,
        UserName = User,
        Credentials = credentials,
        HostKeyPolicy = HostKeyPolicy.AcceptAnyUnsafe(),
    };

    [InteropTheory]
    [MemberData(nameof(PasswordPeers))]
    public async Task Password_login_and_exec_work(string peer)
    {
        await using SshPeerContainer container = await StartAsync(peer);
        await using SshClient client = await SshClient.ConnectAsync(Options(container, SshCredential.FromPassword(Password)), Ct);

        SshCommandResult result = await client.ExecuteAsync("echo out; echo err 1>&2; exit 7", Ct);
        Assert.Equal("out\n", result.StandardOutput);
        Assert.Equal("err\n", result.StandardError);
        Assert.Equal(7, result.ExitCode);
    }

    [InteropFact]
    public async Task A_wrong_password_fails_with_a_useful_exception()
    {
        await using SshPeerContainer container = await StartAsync("openssh-10");
        SshAuthenticationException ex = await Assert.ThrowsAsync<SshAuthenticationException>(
            () => SshClient.ConnectAsync(Options(container, SshCredential.FromPassword("wrong")), Ct));
        Assert.Contains("password", ex.AttemptedMethods);
        Assert.Contains("publickey", ex.AllowedMethods);
        Assert.DoesNotContain("wrong", ex.Message);
    }

    [InteropFact]
    public async Task A_host_key_mismatch_stops_before_any_credential_is_sent()
    {
        await using SshPeerContainer container = await StartAsync("openssh-10");
        SshClientOptions options = new()
        {
            Host = container.Host,
            Port = container.Port,
            UserName = User,
            Credentials = [SshCredential.FromPassword(Password)],
            HostKeyPolicy = HostKeyPolicy.Fingerprint("SHA256:not-the-right-key"),
        };
        await Assert.ThrowsAsync<SshHostKeyException>(() => SshClient.ConnectAsync(options, Ct));
        string log = await container.GetLogsAsync(Ct);
        Assert.DoesNotContain("Failed password", log);
        Assert.DoesNotContain("Accepted password", log);
    }

    [InteropFact]
    public async Task Large_output_flows_through_the_window_intact()
    {
        await using SshPeerContainer container = await StartAsync("openssh-10");
        await using SshClient client = await SshClient.ConnectAsync(Options(container, SshCredential.FromPassword(Password)), Ct);

        // Well past the 2 MiB window, so window adjusts have to work.
        SshCommandResult result = await client.ExecuteAsync("head -c 20000000 /dev/zero | tr '\\0' 'x'", Ct);
        Assert.Equal(20_000_000, result.StandardOutput.Length);
        Assert.Equal(0, result.ExitCode);
    }

    [InteropFact]
    public async Task Stdin_round_trips_large_data_while_both_sides_stream()
    {
        await using SshPeerContainer container = await StartAsync("openssh-10");
        await using SshClient client = await SshClient.ConnectAsync(Options(container, SshCredential.FromPassword(Password)), Ct);
        await using SshProcess process = await client.StartProcessAsync("cat", null, Ct);

        // Both sides stream at once, but the writer stays a little ahead of the reader. Flat out both ways, Podman's
        // published port on this host can stall for good, with real ssh and with no SSH at all, so this can't go flat out.
        const int Chunk = 32 * 1024;
        const int MaxLead = 128 * 1024;
        byte[] data = RandomNumberGenerator.GetBytes(8_000_000);
        long read = 0;
        Task writer = Task.Run(async () =>
        {
            for (int offset = 0; offset < data.Length; offset += Chunk)
            {
                while (offset - Volatile.Read(ref read) > MaxLead)
                {
                    await Task.Delay(1, Ct);
                }

                await process.StandardInput.WriteAsync(data.AsMemory(offset, Math.Min(Chunk, data.Length - offset)), Ct);
            }

            await process.StandardInput.DisposeAsync();
        }, Ct);
        using MemoryStream received = new();
        Task reader = Task.Run(async () =>
        {
            byte[] buffer = new byte[64 * 1024];
            int count;
            while ((count = await process.StandardOutput.ReadAsync(buffer, Ct)) != 0)
            {
                await received.WriteAsync(buffer.AsMemory(0, count), Ct);
                Interlocked.Add(ref read, count);
            }
        }, Ct);
        await Task.WhenAll(writer, reader).WaitAsync(TimeSpan.FromSeconds(60), Ct);
        await process.WaitForExitAsync(Ct);
        Assert.True(data.AsSpan().SequenceEqual(received.GetBuffer().AsSpan(0, (int)received.Length)));
        Assert.Equal(0, process.ExitCode);
    }

    [InteropFact]
    public async Task Many_channels_run_at_once()
    {
        await using SshPeerContainer container = await StartAsync("openssh-10");
        await using SshClient client = await SshClient.ConnectAsync(Options(container, SshCredential.FromPassword(Password)), Ct);
        SshCommandResult[] results = await Task.WhenAll(
            Enumerable.Range(0, 8).Select(i => client.ExecuteAsync($"echo {i}", Ct)));
        Assert.Equal(Enumerable.Range(0, 8).Select(i => $"{i}\n"), results.Select(r => r.StandardOutput));
    }

    [InteropFact]
    public async Task A_killed_process_reports_its_signal()
    {
        await using SshPeerContainer container = await StartAsync("openssh-10");
        await using SshClient client = await SshClient.ConnectAsync(Options(container, SshCredential.FromPassword(Password)), Ct);
        SshCommandResult result = await client.ExecuteAsync("kill -9 $$", Ct);
        Assert.Null(result.ExitCode);
        Assert.Equal("KILL", result.ExitSignal);
    }

    [InteropFact]
    public async Task A_shell_with_a_terminal_works()
    {
        await using SshPeerContainer container = await StartAsync("openssh-10");
        await using SshClient client = await SshClient.ConnectAsync(Options(container, SshCredential.FromPassword(Password)), Ct);
        await using SshProcess shell = await client.StartShellAsync(null, Ct);
        await shell.ResizeAsync(100, 30, Ct);
        await shell.StandardInput.WriteAsync("stty size; exit 3\n"u8.ToArray(), Ct);

        using StreamReader reader = new(shell.StandardOutput);
        string all = await reader.ReadToEndAsync(Ct);
        await shell.WaitForExitAsync(Ct);
        Assert.Contains("30 100", all);
        Assert.Equal(3, shell.ExitCode);
    }

    // The M2 exit criterion: a rekey in the middle of a transfer, against real OpenSSH.
    [InteropFact]
    public async Task A_rekey_during_a_transfer_loses_nothing()
    {
        await using SshPeerContainer container = await StartAsync("openssh-10");
        await using SshClient client = await SshClient.ConnectAsync(Options(container, SshCredential.FromPassword(Password)), Ct);
        await using SshProcess process = await client.StartProcessAsync("head -c 30000000 /dev/zero", null, Ct);

        long total = 0;
        int rekeys = 0;
        byte[] buffer = new byte[64 * 1024];
        while (true)
        {
            int read = await process.StandardOutput.ReadAsync(buffer, Ct);
            if (read == 0)
            {
                break;
            }

            long before = total;
            total += read;
            if (before / 5_000_000 != total / 5_000_000 && rekeys < 4)
            {
                client.RequestRekey();
                rekeys++;
            }
        }

        await process.WaitForExitAsync(Ct);
        Assert.Equal(30_000_000, total);
        Assert.Equal(0, process.ExitCode);
        Assert.True(client.CompletedKeyExchanges >= 3, $"{client.CompletedKeyExchanges} key exchanges ran.");
    }

    [InteropFact]
    public async Task Rekeys_started_by_OpenSSH_are_answered_during_a_transfer()
    {
        PeerTools.RequireContainers();
        string image = await SshPeerContainer.BuildImageAsync("zorg-ssh-test/openssh-10", Path.Combine(PeerTools.PeersPath, "openssh-10"), Ct);
        await using SshPeerContainer container = await SshPeerContainer.StartAsync(
            image,
            ["/usr/sbin/sshd", "-D", "-e", "-o", "RekeyLimit=2M"],
            cancellationToken: Ct);
        await using SshClient client = await SshClient.ConnectAsync(Options(container, SshCredential.FromPassword(Password)), Ct);

        SshCommandResult result = await client.ExecuteAsync("head -c 20000000 /dev/zero | tr '\\0' 'y'", Ct);
        Assert.Equal(20_000_000, result.StandardOutput.Length);
        Assert.True(client.CompletedKeyExchanges >= 4, $"{client.CompletedKeyExchanges} key exchanges ran.");
    }
}

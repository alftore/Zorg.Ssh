using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Zorg.Ssh.InteropTests;

/// <summary>
/// Keepalive against real peers, on a real clock. The interval is short and the wait is several intervals with nothing
/// else on the wire, so a peer that didn't answer would be dropped well before the end.
/// </summary>
public sealed class KeepAliveInteropTests : IDisposable
{
    private const string User = "zorg";
    private const string Password = "zorg-test";
    private const int TestTimeoutMs = 120_000;

    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan Quiet = TimeSpan.FromSeconds(6);

    private readonly string _directory = Directory.CreateTempSubdirectory("zorg-ssh-keepalive").FullName;
    private readonly SshHostKey _hostKey = SshHostKey.GenerateEd25519();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public static TheoryData<string> Peers() => new("openssh-10", "openssh-7.4", "dropbear");

    public void Dispose()
    {
        _hostKey.Dispose();
        Directory.Delete(_directory, recursive: true);
    }

    private static async Task<SshPeerContainer> StartAsync(string peer)
    {
        PeerTools.RequireContainers();
        string image = await SshPeerContainer.BuildImageAsync($"zorg-ssh-test/{peer}", Path.Combine(PeerTools.PeersPath, peer), Ct);
        return await SshPeerContainer.StartAsync(image, cancellationToken: Ct);
    }

    private static SshClientOptions ClientOptions(SshPeerContainer container) => new()
    {
        Host = container.Host,
        Port = container.Port,
        UserName = User,
        Credentials = [SshCredential.FromPassword(Password)],
        HostKeyPolicy = HostKeyPolicy.AcceptAnyUnsafe(),
        KeepAliveInterval = Interval,
        KeepAliveCountMax = 2,
    };

    [Theory(Timeout = TestTimeoutMs)]
    [MemberData(nameof(Peers))]
    public async Task Each_server_answers_probes_through_an_idle_stretch(string peer)
    {
        await using SshPeerContainer container = await StartAsync(peer);
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(container), TestContext.Current.CancellationToken);

        await Task.Delay(Quiet, Ct);

        int answered = client.Connection.KeepAlive!.ProbesAnswered;
        Assert.True(answered >= 3, $"{peer} answered {answered} probes.");
        SshCommandResult result = await client.ExecuteAsync("echo still here", Ct);
        Assert.Equal("still here\n", result.StandardOutput);
    }

    [Theory(Timeout = TestTimeoutMs)]
    [MemberData(nameof(Peers))]
    public async Task Each_server_answers_probes_while_a_silent_command_runs(string peer)
    {
        await using SshPeerContainer container = await StartAsync(peer);
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(container), TestContext.Current.CancellationToken);

        SshCommandResult result = await client.ExecuteAsync("sleep 6; echo done", Ct);

        Assert.Equal("done\n", result.StandardOutput);
        int answered = client.Connection.KeepAlive!.ProbesAnswered;
        Assert.True(answered >= 3, $"{peer} answered {answered} probes.");
    }

    [Theory(Timeout = TestTimeoutMs)]
    [MemberData(nameof(Peers))]
    public async Task A_rekey_during_probing_passes_on_each_server(string peer)
    {
        await using SshPeerContainer container = await StartAsync(peer);
        await using SshClient client = await SshClient.ConnectAsync(ClientOptions(container), TestContext.Current.CancellationToken);

        await Task.Delay(TimeSpan.FromSeconds(2.5), Ct);
        int done = client.CompletedKeyExchanges;
        client.RequestRekey();
        using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        limit.CancelAfter(TimeSpan.FromSeconds(20));
        while (client.CompletedKeyExchanges == done)
        {
            await Task.Delay(10, limit.Token);
        }

        int answered = client.Connection.KeepAlive!.ProbesAnswered;
        await Task.Delay(TimeSpan.FromSeconds(3.5), Ct);

        Assert.True(client.Connection.KeepAlive.ProbesAnswered > answered, $"{peer} stopped answering after the rekey.");
        SshCommandResult result = await client.ExecuteAsync("echo still here", Ct);
        Assert.Equal("still here\n", result.StandardOutput);
    }

    [Fact(Timeout = TestTimeoutMs)]
    public async Task Ssh_answers_our_servers_probes_through_a_silent_session()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        string ssh = PeerTools.RequireSshClient();
        string keygen = Path.Combine(Path.GetDirectoryName(ssh)!, OperatingSystem.IsWindows() ? "ssh-keygen.exe" : "ssh-keygen");
        string key = Path.Combine(_directory, "user_key");
        (int code, _) = await RunAsync(keygen, ["-q", "-t", "ed25519", "-N", string.Empty, "-f", key]);
        Assert.Equal(0, code);

        bool cancelled = false;
        await using SshServer server = await SshServer.StartAsync(
            new SshServerOptions
            {
                HostKeys = [_hostKey],
                PublicKeyHandler = (_, _) => ValueTask.FromResult(SshAuthDecision.Accept),
                KeepAliveInterval = Interval,
                KeepAliveCountMax = 2,
                SessionHandler = async (session, ct) =>
                {
                    try
                    {
                        await Task.Delay(Quiet, ct);
                    }
                    catch (OperationCanceledException)
                    {
                        cancelled = true;
                        throw;
                    }

                    await session.Output.WriteAsync("survived\n"u8.ToArray(), ct);
                    return 0;
                },
            },
            Ct);

        (int exit, string log) = await RunAsync(
            ssh,
            ["-vvv", "-F", "none", "-p", server.LocalEndPoint.Port.ToString(System.Globalization.CultureInfo.InvariantCulture),
             "-i", key, "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
             "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=0", $"{User}@{IPAddress.Loopback}", "wait"]);

        Assert.False(cancelled, log);
        Assert.Equal(0, exit);
        Assert.Contains("survived", log, StringComparison.Ordinal);

        // That ssh saw the probes, so it wasn't some other traffic that kept the connection open.
        Assert.Contains("keepalive@openssh.com", log, StringComparison.Ordinal);
    }

    private static async Task<(int Code, string Log)> RunAsync(string program, string[] arguments)
    {
        ProcessStartInfo start = new(program)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (string argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using Process process = Process.Start(start)!;
        process.StandardInput.Close();
        Task<string> output = process.StandardOutput.ReadToEndAsync(Ct);
        Task<string> error = process.StandardError.ReadToEndAsync(Ct);
        using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        limit.CancelAfter(TimeSpan.FromSeconds(60));
        try
        {
            await process.WaitForExitAsync(limit.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            throw;
        }

        return (process.ExitCode, await output + await error);
    }
}

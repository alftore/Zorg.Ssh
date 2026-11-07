using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Zorg.Ssh.InteropTests;

/// <summary>Real OpenSSH <c>ssh</c> logging in to the public server (M4).</summary>
public sealed class ServerSessionTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("zorg-ssh-test").FullName;
    private readonly SshHostKey _hostKey = SshHostKey.GenerateEd25519();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose()
    {
        _hostKey.Dispose();
        Directory.Delete(_directory, recursive: true);
    }

    private async Task<(string KeyPath, string Fingerprint)> GenerateKeyAsync()
    {
        string ssh = PeerTools.RequireSshClient();
        string keygen = Path.Combine(Path.GetDirectoryName(ssh)!, OperatingSystem.IsWindows() ? "ssh-keygen.exe" : "ssh-keygen");
        string path = Path.Combine(_directory, "user_key");
        (int code, string output, _) = await RunAsync(keygen, ["-q", "-t", "ed25519", "-N", string.Empty, "-f", path], null);
        Assert.Equal(0, code);
        (_, output, _) = await RunAsync(keygen, ["-lf", path + ".pub"], null);
        return (path, output.Split(' ')[1]);
    }

    private static async Task<(int Code, string Output, string Error)> RunAsync(string program, IEnumerable<string> arguments, byte[]? input)
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
        Task<string> output = process.StandardOutput.ReadToEndAsync(Ct);
        Task<string> error = process.StandardError.ReadToEndAsync(Ct);
        if (input is not null)
        {
            await process.StandardInput.BaseStream.WriteAsync(input, Ct);
        }

        process.StandardInput.Close();
        using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        limit.CancelAfter(TimeSpan.FromSeconds(30));
        await process.WaitForExitAsync(limit.Token);
        return (process.ExitCode, await output, await error);
    }

    private static string[] SshArguments(SshServer server, string keyPath, params string[] rest) =>
    [
        "-F", "none", "-p", server.LocalEndPoint.Port.ToString(System.Globalization.CultureInfo.InvariantCulture),
        "-i", keyPath, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR", "alice@127.0.0.1", .. rest,
    ];

    [InteropFact]
    public async Task Ssh_logs_in_with_a_key_runs_a_command_and_gets_the_exit_code()
    {
        string ssh = PeerTools.RequireSshClient();
        (string keyPath, string fingerprint) = await GenerateKeyAsync();
        SshPrincipal? seen = null;
        await using SshServer server = await SshServer.StartAsync(
            new SshServerOptions
            {
                HostKeys = [_hostKey],
                PublicKeyHandler = (request, _) => ValueTask.FromResult(
                    request.Sha256Fingerprint == fingerprint ? SshAuthDecision.Accept : SshAuthDecision.Reject),
                SessionHandler = async (session, ct) =>
                {
                    seen = session.Principal;
                    await session.Output.WriteAsync(Encoding.UTF8.GetBytes($"ran: {session.Command}\n"), ct);
                    await session.Error.WriteAsync("warning\n"u8.ToArray(), ct);
                    return 42;
                },
            },
            Ct);

        (int code, string output, string error) = await RunAsync(ssh, SshArguments(server, keyPath, "hello world"), null);
        Assert.Equal("ran: hello world\n", output);
        Assert.Contains("warning", error);
        Assert.Equal(42, code);
        Assert.Equal("alice", seen!.UserName);
        Assert.Equal(["publickey"], seen.Methods);
        Assert.Equal(fingerprint, seen.KeyFingerprint);
    }

    [InteropFact]
    public async Task Ssh_with_an_unknown_key_is_refused_and_the_handler_never_runs()
    {
        string ssh = PeerTools.RequireSshClient();
        (string keyPath, _) = await GenerateKeyAsync();
        bool ran = false;
        await using SshServer server = await SshServer.StartAsync(
            new SshServerOptions
            {
                HostKeys = [_hostKey],
                PublicKeyHandler = (_, _) => ValueTask.FromResult(SshAuthDecision.Reject),
                SessionHandler = (_, _) =>
                {
                    ran = true;
                    return Task.FromResult(0);
                },
            },
            Ct);

        (int code, _, string error) = await RunAsync(ssh, SshArguments(server, keyPath, "x"), null);
        Assert.Equal(255, code);
        Assert.Contains("Permission denied", error);
        Assert.False(ran);
    }

    [InteropFact]
    public async Task Stdin_flows_through_the_server_both_ways()
    {
        string ssh = PeerTools.RequireSshClient();
        (string keyPath, _) = await GenerateKeyAsync();
        await using SshServer server = await SshServer.StartAsync(
            new SshServerOptions
            {
                HostKeys = [_hostKey],
                PublicKeyHandler = (_, _) => ValueTask.FromResult(SshAuthDecision.Accept),
                SessionHandler = async (session, ct) =>
                {
                    await session.Input.CopyToAsync(session.Output, ct);
                    return 0;
                },
            },
            Ct);

        byte[] data = new byte[5_000_000];
        Random.Shared.NextBytes(data);
        string hex = Convert.ToHexString(data.AsSpan(0, 2_000_000));
        (int code, string output, _) = await RunAsync(ssh, SshArguments(server, keyPath, "cat"), Encoding.ASCII.GetBytes(hex));
        Assert.Equal(0, code);
        Assert.Equal(hex, output);
    }

    [InteropFact]
    public async Task Our_client_and_server_work_together_end_to_end()
    {
        await using SshServer server = await SshServer.StartAsync(
            new SshServerOptions
            {
                HostKeys = [_hostKey],
                PasswordHandler = (request, _) => ValueTask.FromResult(
                    request.Password == "pw" ? SshAuthDecision.Accept : SshAuthDecision.Reject),
                SessionHandler = async (session, ct) =>
                {
                    await session.Output.WriteAsync(Encoding.UTF8.GetBytes($"{session.Kind}:{session.Command}:{session.Pty?.Columns}"), ct);
                    return 5;
                },
            },
            Ct);

        await using SshClient client = await SshClient.ConnectAsync(
            new SshClientOptions
            {
                Host = "127.0.0.1",
                Port = server.LocalEndPoint.Port,
                UserName = "alice",
                Credentials = [SshCredential.FromPassword("pw")],
                HostKeyPolicy = HostKeyPolicy.Fingerprint(_hostKey.Sha256Fingerprint),
            },
            Ct);

        SshCommandResult result = await client.ExecuteAsync("do-it", Ct);
        Assert.Equal("Exec:do-it:", result.StandardOutput);
        Assert.Equal(5, result.ExitCode);

        SshCommandResult[] many = await Task.WhenAll(Enumerable.Range(0, 5).Select(i => client.ExecuteAsync($"c{i}", Ct)));
        Assert.Equal(5, many.Count(r => r.ExitCode == 5));
    }

    [InteropFact]
    public async Task A_throwing_handler_gives_exit_code_1_and_reveals_nothing()
    {
        await using SshServer server = await SshServer.StartAsync(
            new SshServerOptions
            {
                HostKeys = [_hostKey],
                PasswordHandler = (_, _) => ValueTask.FromResult(SshAuthDecision.Accept),
                SessionHandler = (_, _) => throw new InvalidOperationException("internal secret detail"),
            },
            Ct);

        await using SshClient client = await SshClient.ConnectAsync(
            new SshClientOptions
            {
                Host = "127.0.0.1",
                Port = server.LocalEndPoint.Port,
                UserName = "alice",
                Credentials = [SshCredential.FromPassword("pw")],
                HostKeyPolicy = HostKeyPolicy.Fingerprint(_hostKey.Sha256Fingerprint),
            },
            Ct);

        SshCommandResult result = await client.ExecuteAsync("x", Ct);
        Assert.Equal(1, result.ExitCode);
        Assert.Empty(result.StandardOutput);
        Assert.Empty(result.StandardError);
    }
}

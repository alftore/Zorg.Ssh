using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Zorg.Ssh.Sftp;

namespace Zorg.Ssh.Examples;

/// <summary>The samples in README.md and docs/client.md.</summary>
internal static class ClientExamples
{
    public static async Task Readme(CancellationToken cancellationToken)
    {
        // doc:readme
        await using SshClient client = await SshClient.ConnectAsync(new SshClientOptions
        {
            Host = "example.com",
            UserName = "alice",
            Credentials = [SshCredential.FromPrivateKeyFile("~/.ssh/id_ed25519")],
            HostKeyPolicy = HostKeyPolicy.KnownHostsFile(),
        }, cancellationToken);

        SshCommandResult result = await client.ExecuteAsync("uname -a", cancellationToken);
        Console.WriteLine(result.StandardOutput);

        await using SftpClient sftp = await client.OpenSftpAsync(cancellationToken);
        await using FileStream local = File.OpenRead("report.pdf");
        await sftp.UploadFileAsync(local, "report.pdf", cancellationToken);
        // end-doc
    }

    public static SshClientOptions Options(string password, string fingerprint, ILoggerFactory loggerFactory)
    {
        // doc:options
        SshClientOptions options = new()
        {
            Host = "example.com",
            Port = 2222,
            UserName = "alice",
            Credentials = [SshCredential.FromPassword(password)],
            HostKeyPolicy = HostKeyPolicy.Fingerprint(fingerprint),
            ConnectTimeout = TimeSpan.FromSeconds(10),
            MaxCommandOutputBytes = 1024 * 1024,
            BannerHandler = banner => Console.WriteLine(banner),
            LoggerFactory = loggerFactory,
        };
        // end-doc
        return options;
    }

    public static IReadOnlyList<SshCredential> Credentials(string passphrase, string password, string deployKey, string oneTimeCode)
    {
        // doc:credentials
        SshCredential[] credentials =
        [
            SshCredential.FromPrivateKeyFile("~/.ssh/id_ed25519", passphrase),
            SshCredential.FromPrivateKey(deployKey),
            SshCredential.FromPassword(password),
            SshCredential.FromKeyboardInteractive((prompts, ct) =>
                ValueTask.FromResult<IReadOnlyList<string>>([.. prompts.Select(_ => oneTimeCode)])),
        ];
        // end-doc
        return credentials;
    }

    public static IReadOnlyList<HostKeyPolicy> HostKeyPolicies()
    {
        // doc:host-key-policies
        HostKeyPolicy usual = HostKeyPolicy.KnownHostsFile();
        HostKeyPolicy ownFile = HostKeyPolicy.KnownHostsFile("/etc/myapp/known_hosts");
        HostKeyPolicy pinned = HostKeyPolicy.Fingerprint("SHA256:n4cHVJ8c0vCpJiQJCbOgLEUxOkKrDhVJzcEKHnSSd9E");
        // end-doc
        return [usual, ownFile, pinned];
    }

    public static HostKeyPolicy CustomPolicy(ISet<string> trusted)
    {
        // doc:host-key-custom
        HostKeyPolicy policy = HostKeyPolicy.Custom((key, ct) =>
        {
            Console.WriteLine($"{key.Host}:{key.Port} offers {key.KeyType} {key.Sha256Fingerprint}");
            return ValueTask.FromResult(trusted.Contains(key.Sha256Fingerprint));
        });
        // end-doc
        return policy;
    }

    public static IReadOnlyList<HostKeyPolicy> UnsafePolicies()
    {
        // doc:host-key-unsafe
        HostKeyPolicy trustOnFirstUse = HostKeyPolicy.KnownHostsFile(addUnknownHostsUnsafe: true);
        HostKeyPolicy noCheckAtAll = HostKeyPolicy.AcceptAnyUnsafe();
        // end-doc
        return [trustOnFirstUse, noCheckAtAll];
    }

    public static async Task Execute(SshClient client, CancellationToken cancellationToken)
    {
        // doc:exec
        SshCommandResult result = await client.ExecuteAsync("df -h /", cancellationToken);

        if (result.ExitCode == 0)
        {
            Console.WriteLine(result.StandardOutput);
        }
        else if (result.ExitSignal is not null)
        {
            Console.Error.WriteLine($"Killed by {result.ExitSignal}");
        }
        else
        {
            Console.Error.WriteLine($"Exit code {result.ExitCode}: {result.StandardError}");
        }
        // end-doc
    }

    public static async Task Concurrent(SshClient client, CancellationToken cancellationToken)
    {
        // doc:exec-concurrent
        Task<SshCommandResult> uptime = client.ExecuteAsync("uptime", cancellationToken);
        Task<SshCommandResult> disk = client.ExecuteAsync("df -h /", cancellationToken);
        await Task.WhenAll(uptime, disk);
        // end-doc
    }

    public static async Task Process(SshClient client, CancellationToken cancellationToken)
    {
        // doc:process
        await using SshProcess process = await client.StartProcessAsync("sort", null, cancellationToken);

        // Both output streams share one flow-control window, so read them both while you write.
        using StreamReader output = new(process.StandardOutput);
        using StreamReader errors = new(process.StandardError);
        Task<string> sorted = output.ReadToEndAsync(cancellationToken);
        Task<string> problems = errors.ReadToEndAsync(cancellationToken);

        await process.StandardInput.WriteAsync("pear\napple\n"u8.ToArray(), cancellationToken);
        await process.StandardInput.DisposeAsync(); // Sends EOF, so sort can finish.

        Console.WriteLine(await sorted);
        Console.Error.WriteLine(await problems);
        await process.WaitForExitAsync(cancellationToken);
        Console.WriteLine($"Exit code {process.ExitCode}");
        // end-doc
    }

    public static async Task Stream(SshClient client, CancellationToken cancellationToken)
    {
        // doc:process-lines
        await using SshProcess process = await client.StartProcessAsync("for i in 1 2 3; do echo $i; sleep 1; done", null, cancellationToken);
        using StreamReader reader = new(process.StandardOutput);

        while (await reader.ReadLineAsync(cancellationToken) is { } line)
        {
            Console.WriteLine(line);
        }
        // end-doc
    }

    public static async Task Environment(SshClient client, CancellationToken cancellationToken)
    {
        // doc:process-options
        SshProcessOptions options = new()
        {
            Pty = new SshPtyOptions { Terminal = "xterm-256color", Columns = 120, Rows = 40 },
            Environment = new Dictionary<string, string> { ["LANG"] = "C.UTF-8" },
        };

        await using SshProcess process = await client.StartProcessAsync("top -b -n 1", options, cancellationToken);
        // end-doc
        await process.StandardOutput.CopyToAsync(System.IO.Stream.Null, cancellationToken);
    }

    public static async Task Shell(SshClient client, CancellationToken cancellationToken)
    {
        // doc:shell
        await using SshProcess shell = await client.StartShellAsync(null, cancellationToken);

        await shell.ResizeAsync(120, 40, cancellationToken);
        await shell.StandardInput.WriteAsync("echo hello; exit\n"u8.ToArray(), cancellationToken);

        // With a terminal, stdout and stderr both arrive on StandardOutput.
        using StreamReader reader = new(shell.StandardOutput);
        Console.WriteLine(await reader.ReadToEndAsync(cancellationToken));
        await shell.WaitForExitAsync(cancellationToken);
        // end-doc
    }

    public static async Task OverStream(SshClientOptions options, CancellationToken cancellationToken)
    {
        // doc:over-stream
        TcpClient tcp = new();
        await tcp.ConnectAsync("jump.example.com", 10022, cancellationToken);

        // The client owns the stream from here on. Host and Port in the options are what the host key check sees.
        await using SshClient client = await SshClient.ConnectOverStreamAsync(tcp.GetStream(), options, cancellationToken);
        // end-doc
    }

    public static async Task Cancel(SshClient client)
    {
        // doc:cancel
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(30));

        try
        {
            await client.ExecuteAsync("sleep 3600", timeout.Token);
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine("Gave up. The channel is closed, and the connection is still usable.");
        }
        // end-doc
    }

    public static SshClientOptions KeepAlive(string password, string knownFingerprint)
    {
        // doc:keepalive
        SshClientOptions options = new()
        {
            Host = "example.com",
            UserName = "alice",
            Credentials = [SshCredential.FromPassword(password)],
            HostKeyPolicy = HostKeyPolicy.Fingerprint(knownFingerprint),
            KeepAliveInterval = TimeSpan.FromSeconds(15),
            KeepAliveCountMax = 4,
        };
        // end-doc
        return options;
    }

    public static async Task JumpHost(SshClientOptions bastionOptions, string password, string innerFingerprint, CancellationToken cancellationToken)
    {
        // doc:jump-host
        await using SshClient bastion = await SshClient.ConnectAsync(bastionOptions, cancellationToken);
        await using SshClient inner = await SshClient.ConnectAsync(new SshClientOptions
        {
            Host = "10.0.0.5",
            UserName = "alice",
            Credentials = [SshCredential.FromPassword(password)],
            HostKeyPolicy = HostKeyPolicy.Fingerprint(innerFingerprint),
            JumpHost = bastion,
        }, cancellationToken);
        // end-doc
    }

    public static async Task Forwarding(SshClient client, CancellationToken cancellationToken)
    {
        // doc:forwarding
        // ssh -L: a local port that leads to a target the server can reach. Null binds a free loopback port.
        await using SshForward local = await client.ForwardLocalPortAsync(null, "db.internal", 5432, cancellationToken);

        // ssh -D: a SOCKS5 proxy, CONNECT only, no login. SOCKS4 isn't supported.
        await using SshForward proxy = await client.ForwardDynamicPortAsync(null, cancellationToken);

        // ssh -R: a port on the server that leads back here. Port 0 lets the server choose.
        await using SshRemoteForward remote = await client.ForwardRemotePortAsync("127.0.0.1", 0, "localhost", 8080, cancellationToken);

        // No listener at all: one connection, as a stream.
        await using Stream stream = await client.OpenTcpStreamAsync("db.internal", 5432, cancellationToken);
        // end-doc
    }
}

// Interop test harness: starts a real SSH peer in a container through the podman or docker CLI.
// No package dependencies. Uses only commands and flags that podman and docker share.
//
//   string image = await SshPeerContainer.BuildImageAsync("zorg-ssh-openssh-10:test", "images/openssh-10");
//   await using var peer = await SshPeerContainer.StartAsync(image);
//   connect to peer.Host:peer.Port; peer.Banner is e.g. "SSH-2.0-OpenSSH_10.6"
//
// Set ZORG_SSH_CONTAINER_CLI to a program name or full path to force the CLI.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Diagnostics;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Zorg.Ssh.InteropTests;

public sealed class ContainerCliNotFoundException(string message) : Exception(message);

public sealed class ContainerStartException(string message) : Exception(message);

/// <summary>Finds and runs the container CLI.</summary>
public static class ContainerCli
{
    public const string OverrideVariable = "ZORG_SSH_CONTAINER_CLI";

    private static readonly Lazy<string> Resolved = new(Resolve);

    /// <summary>Full path or name of the CLI. Throws <see cref="ContainerCliNotFoundException"/> if none works.</summary>
    public static string Path => Resolved.Value;

    /// <summary>
    /// A local run may skip when this is false. CI must not: call <see cref="Path"/> there, so a missing
    /// peer is a failure.
    /// </summary>
    public static bool IsAvailable
    {
        get
        {
            try
            {
                _ = Resolved.Value;
                return true;
            }
            catch (ContainerCliNotFoundException)
            {
                return false;
            }
        }
    }

    private static string Resolve()
    {
        string? forced = Environment.GetEnvironmentVariable(OverrideVariable);
        if (!string.IsNullOrWhiteSpace(forced))
        {
            // An explicit choice that doesn't work is an error; don't fall back to another engine.
            return EngineResponds(forced, out string forcedError)
                ? forced
                : throw new ContainerCliNotFoundException($"{OverrideVariable}={forced} doesn't work: {forcedError}");
        }

        var tried = new StringBuilder();
        foreach (string candidate in Candidates())
        {
            if (EngineResponds(candidate, out string error))
            {
                return candidate;
            }

            tried.AppendLine($"  {candidate}: {error}");
        }

        throw new ContainerCliNotFoundException($"No working podman or docker. Tried:\n{tried}");
    }

    // docker first: Ubuntu runners have both, and docker is the CI target.
    private static IEnumerable<string> Candidates()
    {
        string exe = OperatingSystem.IsWindows() ? ".exe" : "";
        string[] directories = (Environment.GetEnvironmentVariable("PATH") ?? "")
            .Split(System.IO.Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries);

        foreach (string name in new[] { "docker", "podman" })
        {
            foreach (string directory in directories)
            {
                string file = System.IO.Path.Combine(directory, name + exe);
                if (File.Exists(file))
                {
                    yield return file;
                }
            }
        }

        if (OperatingSystem.IsWindows())
        {
            string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string known = System.IO.Path.Combine(local, "Programs", "Podman", "podman.exe");
            if (File.Exists(known))
            {
                yield return known;
            }
        }
    }

    // `ps` needs a live engine on both CLIs, so an installed CLI with a stopped engine doesn't count.
    private static bool EngineResponds(string cli, out string error)
    {
        try
        {
            CliResult result = RunCoreAsync(cli, ["ps", "-q"], TimeSpan.FromSeconds(20), CancellationToken.None)
                .GetAwaiter().GetResult();
            error = result.ExitCode == 0 ? "" : $"exit {result.ExitCode}: {result.Error}";
            return result.ExitCode == 0;
        }
        catch (Exception e) when (e is Win32Exception or TimeoutException)
        {
            error = e.Message;
            return false;
        }
    }

    internal static async Task<string> RunAsync(
        TimeSpan timeout, CancellationToken cancellationToken, params string[] arguments)
    {
        CliResult result = await RunCoreAsync(Path, arguments, timeout, cancellationToken);
        return result.ExitCode == 0
            ? result.Output
            : throw new ContainerStartException(
                $"{System.IO.Path.GetFileName(Path)} {string.Join(' ', arguments)} exited {result.ExitCode}:\n{result.Error}");
    }

    internal static Task<CliResult> TryRunAsync(
        TimeSpan timeout, CancellationToken cancellationToken, params string[] arguments) =>
        RunCoreAsync(Path, arguments, timeout, cancellationToken);

    private static async Task<CliResult> RunCoreAsync(
        string cli, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var start = new ProcessStartInfo(cli)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (string argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using Process process = Process.Start(start)!;
        process.StandardInput.Close();
        Task<string> output = process.StandardOutput.ReadToEndAsync(CancellationToken.None);
        Task<string> error = process.StandardError.ReadToEndAsync(CancellationToken.None);

        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        limit.CancelAfter(timeout);
        try
        {
            await process.WaitForExitAsync(limit.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            cancellationToken.ThrowIfCancellationRequested();
            throw new TimeoutException($"{cli} {string.Join(' ', arguments)} took over {timeout}.");
        }

        return new CliResult(process.ExitCode, (await output).Trim(), (await error).Trim());
    }

    internal readonly record struct CliResult(int ExitCode, string Output, string Error);
}

/// <summary>A running SSH server in a container, ready to accept SSH connections.</summary>
public sealed class SshPeerContainer : IAsyncDisposable
{
    private const string OwnerLabel = "zorg.ssh.interop.owner";
    private const int MaxRunAttempts = 3;
    private const string NoBanner = "No SSH banner";

    private static readonly TimeSpan CliTimeout = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan BuildTimeout = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan AttemptTimeout = TimeSpan.FromSeconds(2);

    private static readonly ConcurrentDictionary<string, Lazy<Task>> Builds = new();
    private static readonly Lazy<Task> Sweep = new(RemoveOrphansAsync);

    private int _disposed;

    private SshPeerContainer(string id, string host, int port, string banner)
    {
        Id = id;
        Host = host;
        Port = port;
        Banner = banner;
    }

    public string Id { get; }

    public string Host { get; }

    public int Port { get; }

    /// <summary>The server's identification line, without CR LF.</summary>
    public string Banner { get; }

    /// <summary>Builds an image once per process. The engine's layer cache makes a repeat build cheap.</summary>
    public static async Task<string> BuildImageAsync(
        string tag, string contextDirectory, CancellationToken cancellationToken = default)
    {
        // On Podman the default rootless network ran at about 100 KB/s on the development machine, which made a build that
        // downloads look hung. Host networking in the build only is the same fix scripts/test-linux.sh uses. Docker's
        // default builder doesn't take it without an entitlement, so it isn't passed there.
        string[] network = System.IO.Path.GetFileNameWithoutExtension(ContainerCli.Path).Equals("podman", StringComparison.OrdinalIgnoreCase)
            ? ["--network", "host"]
            : [];
        Lazy<Task> build = Builds.GetOrAdd(tag, _ => new Lazy<Task>(() =>
            ContainerCli.RunAsync(BuildTimeout, CancellationToken.None, ["build", .. network, "-t", tag, contextDirectory])));
        await build.Value.WaitAsync(cancellationToken);
        return tag;
    }

    /// <summary>
    /// Starts a container and returns once it has sent an SSH banner. Port 22 in the container is
    /// published on a random loopback port, so test credentials aren't reachable from the network.
    /// </summary>
    public static async Task<SshPeerContainer> StartAsync(
        string image,
        IReadOnlyList<string>? command = null,
        TimeSpan? readyTimeout = null,
        CancellationToken cancellationToken = default)
    {
        await Sweep.Value;

        // Podman's published port sometimes accepts but never reaches the container: sshd logs no connection at all,
        // however long the probe goes on. A new container gets a new port. One that exits is a real failure, and isn't retried.
        for (int attempt = 1; ; attempt++)
        {
            string id = await RunContainerAsync(image, command, cancellationToken);

            try
            {
                int port = await GetPublishedPortAsync(id, cancellationToken);

                const string Host = "127.0.0.1";
                TimeSpan timeout = readyTimeout ?? TimeSpan.FromSeconds(20);
                string banner = await WaitForBannerAsync(id, Host, port, timeout, cancellationToken);
                return new SshPeerContainer(id, Host, port, banner);
            }
            catch (ContainerStartException e) when (attempt < MaxRunAttempts && e.Message.StartsWith(NoBanner, StringComparison.Ordinal))
            {
                await RemoveAsync(id);
            }
            catch
            {
                await RemoveAsync(id);
                throw;
            }
        }
    }

    public Task<string> GetLogsAsync(CancellationToken cancellationToken = default) =>
        ReadLogsAsync(Id, cancellationToken);

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            await RemoveAsync(Id);
        }
    }

    // Parallel starts on podman can very occasionally be given a random port that is already taken.
    // A failed `run` can leave a created container, so each attempt has a name to remove it by.
    private static async Task<string> RunContainerAsync(
        string image, IReadOnlyList<string>? command, CancellationToken cancellationToken)
    {
        for (int attempt = 1; ; attempt++)
        {
            string name = $"zorg-ssh-{Guid.NewGuid():N}";

            // --stop-timeout 0: podman's `rm -f` otherwise waits 10 s on a PID 1 that ignores SIGTERM,
            // which the Python servers do (measured 10.7 s against 0.5 s).
            string[] run =
            [
                "run", "-d", "--name", name, "--stop-timeout", "0",
                "--label", $"{OwnerLabel}={Environment.ProcessId}",
                "-p", "127.0.0.1::22",

                // Docker lets a container's normal users bind any port (it sets this to 0), and Podman leaves the
                // kernel's 1024. The tests that a privileged port is refused need the kernel's rule, on both.
                "--sysctl", "net.ipv4.ip_unprivileged_port_start=1024",
                image,
                .. command ?? [],
            ];

            try
            {
                string output = await ContainerCli.RunAsync(CliTimeout, cancellationToken, run);
                return output.Split('\n')[^1].Trim();
            }
            catch (Exception e)
            {
                await RemoveAsync(name);
                if (attempt == MaxRunAttempts || !e.Message.Contains("address already in use", StringComparison.OrdinalIgnoreCase))
                {
                    throw;
                }
            }
        }
    }

    private static async Task<int> GetPublishedPortAsync(string id, CancellationToken cancellationToken)
    {
        // docker can print one line per address family; podman prints one line.
        // A container that has already exited has no mapping: podman prints nothing, docker fails.
        ContainerCli.CliResult mapping = await ContainerCli.TryRunAsync(CliTimeout, cancellationToken, "port", id, "22/tcp");
        string first = mapping.Output.Split('\n')[0].Trim();
        if (mapping.ExitCode == 0 && int.TryParse(first[(first.LastIndexOf(':') + 1)..], out int port))
        {
            return port;
        }

        ContainerState state = await InspectAsync(id, cancellationToken);
        throw new ContainerStartException(state.Running
            ? $"Container {Short(id)} has no published port 22: {mapping.Output} {mapping.Error}"
            : await DescribeExitAsync(id, state, cancellationToken));
    }

    private static async Task<string> DescribeExitAsync(string id, ContainerState state, CancellationToken cancellationToken) =>
        $"Container {Short(id)} exited with code {state.ExitCode} before sending a banner.\n" +
        await ReadLogsAsync(id, cancellationToken);

    // A forwarded port accepts before sshd is up and then drops the connection,
    // so only an SSH identification line counts as ready.
    private static async Task<string> WaitForBannerAsync(
        string id, string host, int port, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var clock = Stopwatch.StartNew();
        var delay = TimeSpan.FromMilliseconds(50);
        string lastFailure = "no attempt made";

        while (clock.Elapsed < timeout)
        {
            try
            {
                string? banner = await TryReadBannerAsync(host, port, cancellationToken);
                if (banner is not null)
                {
                    return banner;
                }

                lastFailure = "connection closed before a banner";
            }
            catch (Exception e) when (e is SocketException or IOException or OperationCanceledException
                                      && !cancellationToken.IsCancellationRequested)
            {
                lastFailure = e.Message;
            }

            // Fail now rather than at the timeout if the server has died.
            ContainerState state = await InspectAsync(id, cancellationToken);
            if (!state.Running)
            {
                throw new ContainerStartException(await DescribeExitAsync(id, state, cancellationToken));
            }

            await Task.Delay(delay, cancellationToken);
            delay = TimeSpan.FromMilliseconds(Math.Min(delay.TotalMilliseconds * 2, 500));
        }

        throw new ContainerStartException(
            $"{NoBanner} from container {Short(id)} on {host}:{port} after {timeout}. Last: {lastFailure}\n" +
            await ReadLogsAsync(id, cancellationToken));
    }

    private static async Task<string?> TryReadBannerAsync(string host, int port, CancellationToken cancellationToken)
    {
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        limit.CancelAfter(AttemptTimeout);

        using var client = new TcpClient();
        await client.ConnectAsync(host, port, limit.Token);
        NetworkStream stream = client.GetStream();

        // RFC 4253 section 4.2 lets a server send other lines first.
        var line = new StringBuilder();
        var buffer = new byte[256];
        while (true)
        {
            int read = await stream.ReadAsync(buffer, limit.Token);
            if (read == 0)
            {
                return null;
            }

            for (int i = 0; i < read; i++)
            {
                if (buffer[i] != (byte)'\n')
                {
                    line.Append((char)buffer[i]);
                    continue;
                }

                string text = line.ToString().TrimEnd('\r');
                if (text.StartsWith("SSH-", StringComparison.Ordinal))
                {
                    return text;
                }

                line.Clear();
            }
        }
    }

    private static async Task<ContainerState> InspectAsync(string id, CancellationToken cancellationToken)
    {
        string output = await ContainerCli.RunAsync(
            CliTimeout, cancellationToken, "inspect", "--format", "{{.State.Running}} {{.State.ExitCode}}", id);
        string[] parts = output.Split(' ');
        return new ContainerState(parts[0] == "true", parts[1]);
    }

    private static async Task<string> ReadLogsAsync(string id, CancellationToken cancellationToken)
    {
        // A server may log to either stream.
        ContainerCli.CliResult result = await ContainerCli.TryRunAsync(CliTimeout, cancellationToken, "logs", id);
        return $"{result.Output}\n{result.Error}".Trim();
    }

    // Must run even when the test was cancelled, so it takes no caller token.
    private static Task RemoveAsync(string id) =>
        ContainerCli.TryRunAsync(CliTimeout, CancellationToken.None, "rm", "-f", id);

    // There is no reaper process. A killed test run leaves its containers behind, so the next run
    // removes any whose owner process has gone.
    private static async Task RemoveOrphansAsync()
    {
        string listing = await ContainerCli.RunAsync(
            CliTimeout, CancellationToken.None, "ps", "-aq", "--filter", $"label={OwnerLabel}");

        foreach (string id in listing.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            ContainerCli.CliResult owner = await ContainerCli.TryRunAsync(
                CliTimeout,
                CancellationToken.None,
                "inspect",
                "--format",
                "{{index .Config.Labels \"" + OwnerLabel + "\"}}",
                id);
            if (owner.ExitCode == 0 && int.TryParse(owner.Output, out int pid) && !IsAlive(pid))
            {
                await RemoveAsync(id);
            }
        }
    }

    private static bool IsAlive(int pid)
    {
        try
        {
            using Process process = Process.GetProcessById(pid);
            return !process.HasExited;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static string Short(string id) => id.Length > 12 ? id[..12] : id;

    private readonly record struct ContainerState(bool Running, string ExitCode);
}

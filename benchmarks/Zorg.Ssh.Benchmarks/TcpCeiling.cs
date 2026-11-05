using System;
using System.Diagnostics;
using System.Globalization;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Zorg.Ssh.InteropTests;

namespace Zorg.Ssh.Benchmarks;

/// <summary>
/// Plain TCP through the same published container port, with no SSH at all. No SFTP library can beat this path, so
/// it shows whether a transfer result says anything about the library. Run it with <c>--ceiling</c>.
/// </summary>
internal static class TcpCeiling
{
    private const int Runs = 5;
    private const long Bytes = 1024L * 1024 * 1024;

    // nc serves one connection and exits, and the harness's readiness probe takes the first.
    private const string SendLoop = "while :; do (echo SSH-2.0-ceiling; head -c 1073741824 /dev/zero) | nc -l -p 22; done";

    // nc drops its connection when its stdin ends, so stdin stays open for the whole transfer. That rules out a loop
    // like the one above, so each run gets its own container, without the harness and its probe.
    private const string ReceiveOnce = "sleep 600 | nc -l -p 22 > /dev/null";

    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(60);

    public static async Task RunAsync()
    {
        string image = await Peer.BuildImageAsync();
        await using (SshPeerContainer sender = await SshPeerContainer.StartAsync(image, ["sh", "-c", SendLoop]))
        {
            for (int i = 0; i < Runs; i++)
            {
                await Task.Delay(1000);
                await MeasureAsync("Container to client", () => ReadAllAsync(sender.Host, sender.Port));
            }
        }

        for (int i = 0; i < Runs; i++)
        {
            string id = await StartReceiverAsync(image);
            try
            {
                string mapping = await ContainerCli.RunAsync(Limit, CancellationToken.None, "port", id, "22/tcp");
                int port = int.Parse(mapping.Split('\n')[0].Trim().Split(':')[^1], CultureInfo.InvariantCulture);
                await Task.Delay(1000);
                await MeasureAsync("Client to container", () => WriteAllAsync("127.0.0.1", port));
            }
            finally
            {
                await ContainerCli.TryRunAsync(Limit, CancellationToken.None, "rm", "-f", id);
            }
        }
    }

    private static async Task<string> StartReceiverAsync(string image)
    {
        string output = await ContainerCli.RunAsync(
            Limit, CancellationToken.None, "run", "-d", "--stop-timeout", "0", "-p", "127.0.0.1::22", image, "sh", "-c", ReceiveOnce);
        return output.Split('\n')[^1].Trim();
    }

    private static async Task MeasureAsync(string name, Func<Task<long>> run)
    {
        Stopwatch clock = Stopwatch.StartNew();
        long bytes = await run();
        double perSecond = bytes / clock.Elapsed.TotalSeconds / (1024 * 1024);
        Console.WriteLine(string.Create(CultureInfo.InvariantCulture, $"{name}: {bytes} bytes, {perSecond:F0} MiB/s"));
    }

    private static async Task<long> ReadAllAsync(string host, int port)
    {
        using CancellationTokenSource limit = new(Limit);
        using TcpClient client = new() { NoDelay = true };
        await client.ConnectAsync(host, port);
        NetworkStream stream = client.GetStream();
        byte[] buffer = new byte[256 * 1024];
        long total = 0;

        // nc leaves the socket open at the end of its input, so the count ends this, not end of stream.
        while (total < Bytes)
        {
            int read = await stream.ReadAsync(buffer, limit.Token);
            if (read == 0)
            {
                throw new InvalidOperationException($"The sender stopped after {total} bytes.");
            }

            total += read;
        }

        return total;
    }

    private static async Task<long> WriteAllAsync(string host, int port)
    {
        using CancellationTokenSource limit = new(Limit);
        using TcpClient client = new() { NoDelay = true };
        await client.ConnectAsync(host, port);
        NetworkStream stream = client.GetStream();
        byte[] buffer = new byte[256 * 1024];
        long total = 0;
        while (total < Bytes)
        {
            await stream.WriteAsync(buffer, limit.Token);
            total += buffer.Length;
        }

        return total;
    }
}

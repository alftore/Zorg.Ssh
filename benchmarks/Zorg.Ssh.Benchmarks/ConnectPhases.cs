using System;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using SshNetClient = Renci.SshNet.SshClient;
using TmdsClient = Tmds.Ssh.SshClient;

namespace Zorg.Ssh.Benchmarks;

/// <summary>
/// Splits <see cref="ConnectBenchmarks"/> into its two halves, to show where the time goes: logging in, and closing.
/// It's a plain stopwatch, not a BenchmarkDotNet run. Run it with <c>--phases</c>.
/// </summary>
internal static class ConnectPhases
{
    private const int Warmup = 5;
    private const int Runs = 30;

    public static async Task RunAsync()
    {
        await using Peer peer = await Peer.StartAsync();

        await MeasureAsync("Zorg.Ssh", async () =>
        {
            long start = Stopwatch.GetTimestamp();
            SshClient client = await SshClient.ConnectAsync(peer.ZorgOptions());
            TimeSpan login = Stopwatch.GetElapsedTime(start);

            start = Stopwatch.GetTimestamp();
            await client.DisposeAsync();
            return (login, Stopwatch.GetElapsedTime(start));
        });

        await MeasureAsync("SSH.NET", async () =>
        {
            SshNetClient client = peer.SshNetClient();
            long start = Stopwatch.GetTimestamp();
            await client.ConnectAsync(default);
            TimeSpan login = Stopwatch.GetElapsedTime(start);

            start = Stopwatch.GetTimestamp();
            client.Dispose();
            return (login, Stopwatch.GetElapsedTime(start));
        });

        await MeasureAsync("Tmds.Ssh", async () =>
        {
            TmdsClient client = peer.TmdsClient();
            long start = Stopwatch.GetTimestamp();
            await client.ConnectAsync();
            TimeSpan login = Stopwatch.GetElapsedTime(start);

            start = Stopwatch.GetTimestamp();
            client.Dispose();
            return (login, Stopwatch.GetElapsedTime(start));
        });
    }

    private static async Task MeasureAsync(string name, Func<Task<(TimeSpan Login, TimeSpan Close)>> run)
    {
        for (int i = 0; i < Warmup; i++)
        {
            await run();
        }

        (TimeSpan Login, TimeSpan Close)[] results = new (TimeSpan, TimeSpan)[Runs];
        for (int i = 0; i < Runs; i++)
        {
            results[i] = await run();
        }

        double login = Median(results.Select(r => r.Login));
        double close = Median(results.Select(r => r.Close));
        Console.WriteLine(string.Create(CultureInfo.InvariantCulture, $"{name}: login {login:F1} ms, close {close:F1} ms (medians of {Runs})"));
    }

    private static double Median(System.Collections.Generic.IEnumerable<TimeSpan> values) =>
        values.Select(v => v.TotalMilliseconds).Order().ElementAt(Runs / 2);
}

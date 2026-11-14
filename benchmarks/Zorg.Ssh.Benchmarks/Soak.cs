// The console and CSV writes are a few lines per sample, so they stay synchronous.
#pragma warning disable CA1849
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Zorg.Ssh.Sftp;

namespace Zorg.Ssh.Benchmarks;

/// <summary>
/// A soak run: one in-process server on 127.0.0.1 and a mix of client operations from several workers for a long time,
/// with a resource sample at every interval. The point is that memory, handles and threads stay flat on both ends, so the
/// run ends with a least-squares line per metric and a PASS or FAIL against the tolerances below. Run it with
/// <c>--soak</c>. Options: <c>--minutes N</c> (10), <c>--interval S</c> (sample seconds, 30), <c>--concurrency N</c>
/// (workers, 8), <c>--out path.csv</c> (a file in the temp directory), <c>--warmup-minutes N</c> (2, or 20% of the run if
/// that is shorter), <c>--quiet-every N</c> (a quiet sample every N samples, 4; 0 turns them off), <c>--only kinds</c> (a comma-separated list of operation kinds to run, all by default). On Windows each quiet sample also counts handles by type. Exit code: 0 pass, 1 a metric or a check failed, 2 an exception that should not happen.
/// </summary>
internal sealed class Soak : IDisposable
{
    // Tolerances for the slope of each metric after warmup, per hour. Documented in docs/benchmarks.md.
    private const double HeapSlopeMiBPerHour = 2;
    private const double PrivateSlopeMiBPerHour = 20;
    private const double CountSlopePerHour = 5;

    // The verdict needs this many quiet samples after warmup. Quiet samples are taken with the workers parked and nothing open.
    private const int MinQuietSamples = 5;
    private static readonly TimeSpan QuietWait = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan QuietSettle = TimeSpan.FromSeconds(2);

    private const string User = "soak";
    private const string KeyUser = "soakkey";
    private const string Password = "soak-password";

    private static readonly string[] Kinds =
        ["connect", "reuse", "stream", "sftp_small", "sftp_large", "list", "forward", "bad_login", "abrupt", "cancel"];

    private static readonly int[] Weights = [20, 8, 10, 10, 3, 8, 10, 8, 6, 8];

    private static string HandleTypeChanges(Dictionary<string, int> from, Dictionary<string, int> to)
    {
        IEnumerable<string> changes = from.Keys.Union(to.Keys, StringComparer.Ordinal)
            .Select(type => (type, delta: to.GetValueOrDefault(type) - from.GetValueOrDefault(type)))
            .Where(c => c.delta != 0)
            .OrderBy(c => c.type, StringComparer.Ordinal)
            .Select(c => c.type + " " + c.delta.ToString("+0;-0", CultureInfo.InvariantCulture));
        string text = string.Join(", ", changes);
        return text.Length == 0 ? "none" : text;
    }

    private static readonly Metric[] Metrics =
    [
        new("heap_after_gc", "managed heap after a full blocking GC", true, HeapSlopeMiBPerHour),
        new("gen2", "gen 2 size after that GC", true, null),
        new("loh", "large object heap size after that GC", true, null),
        new("working_set", "working set", true, null),
        new("private_bytes", "private bytes", true, PrivateSlopeMiBPerHour),
        new("handles", "process handle count", false, CountSlopePerHour),
        new("fds", "/proc/self/fd entries (Linux)", false, CountSlopePerHour),
        new("threads", "OS threads", false, CountSlopePerHour),
        new("pool_threads", "ThreadPool.ThreadCount", false, CountSlopePerHour),
        new("live_connections", "client connections the harness holds open", false, null),
        new("server_sessions", "session handlers running on the server", false, null),
    ];

    private readonly double _minutes;
    private readonly double _intervalSeconds;
    private readonly int _concurrency;
    private readonly string _outPath;
    private readonly double _warmupMinutes;
    private readonly int _quietEvery;

    private readonly CancellationTokenSource _stop = new();
    private readonly CancellationTokenSource _hard = new();
    private readonly long[] _ops = new long[Kinds.Length];
    private readonly ConcurrentDictionary<string, Distinct> _distinct = new();
    private readonly ConcurrentQueue<string> _stale = new();
    private readonly List<Sample> _samples = [];
    private readonly List<Sample> _quiet = [];

    private string _root = "";
    private SshHostKey? _hostKey;
    private string _clientKey = "";
    private int _port;
    private int _echoPort;
    private long _expected;
    private long _portExhaustion;
    private long _sessionLimit;
    private int _thinkMs = 50;
    private long _unexpected;
    private int _live;
    private int _serverSessions;
    private int _maxLive;
    private long _serial;
    private volatile TaskCompletionSource? _gate;
    private int _parked;
    private int _quietTimeouts;
    private readonly List<(double Elapsed, Dictionary<string, int> Types)> _handleTypes = [];

    private Soak(double minutes, double intervalSeconds, int concurrency, string outPath, double warmupMinutes, int quietEvery)
    {
        _minutes = minutes;
        _intervalSeconds = intervalSeconds;
        _concurrency = concurrency;
        _outPath = outPath;
        _warmupMinutes = warmupMinutes;
        _quietEvery = quietEvery;
    }

    public static async Task<int> RunAsync(string[] args)
    {
        double minutes = Number(args, "--minutes", 10);
        double interval = Number(args, "--interval", 30);
        int concurrency = (int)Number(args, "--concurrency", 8);
        double warmup = Number(args, "--warmup-minutes", Math.Min(2, minutes * 0.2));
        int quietEvery = (int)Number(args, "--quiet-every", 4);
        if (Text(args, "--only") is { } only)
        {
            HashSet<string> keep = [.. only.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)];
            if (!keep.IsSubsetOf(Kinds))
            {
                Console.Error.WriteLine("Soak: --only takes a comma-separated list of: " + string.Join(", ", Kinds) + ".");
                return 2;
            }

            for (int i = 0; i < Kinds.Length; i++)
            {
                if (!keep.Contains(Kinds[i]))
                {
                    Weights[i] = 0;
                }
            }
        }
        string? outPath = Text(args, "--out");
        outPath ??= Path.Combine(Path.GetTempPath(), string.Create(CultureInfo.InvariantCulture, $"zorg-soak-{DateTime.UtcNow:yyyyMMdd-HHmmss}.csv"));
        if (minutes <= 0 || interval <= 0 || concurrency < 1 || warmup < 0 || quietEvery < 0)
        {
            Console.Error.WriteLine("Soak: --minutes and --interval must be above 0, --concurrency at least 1, --warmup-minutes and --quiet-every not negative.");
            return 3;
        }

        using Soak soak = new(minutes, interval, concurrency, outPath, warmup, quietEvery) { _thinkMs = (int)Number(args, "--think-ms", 50) };
        return await soak.ExecuteAsync();
    }

    public void Dispose()
    {
        _stop.Dispose();
        _hard.Dispose();
        _hostKey?.Dispose();
    }

    private static string F(double value, string format = "F1") => value.ToString(format, CultureInfo.InvariantCulture);

    private static double Mib(double bytes) => bytes / (1024 * 1024);

    private static double Number(string[] args, string name, double fallback)
    {
        string? text = Text(args, name);
        return text is null ? fallback : double.Parse(text, CultureInfo.InvariantCulture);
    }

    private static string? Text(string[] args, string name)
    {
        int index = Array.IndexOf(args, name);
        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }

    private static bool Refusal(Exception e) => e is SshException and not SshHostKeyException;

    private static string TopFrame(Exception e)
    {
        string? line = e.StackTrace?.Split('\n', 2)[0].Trim();
        return line ?? "no stack";
    }

    private async Task<int> ExecuteAsync()
    {
        _root = Directory.CreateTempSubdirectory("zorg-soak-sftp-").FullName;
        _hostKey = SshHostKey.GenerateEd25519();
        using (ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            _clientKey = key.ExportPkcs8PrivateKeyPem();
        }

        TaskScheduler.UnobservedTaskException += OnUnobserved;
        ConsoleCancelEventHandler cancel = (_, e) =>
        {
            e.Cancel = true;
            Console.WriteLine("Ctrl+C: stopping after the operations in flight.");
            _stop.Cancel();
        };
        Console.CancelKeyPress += cancel;
        await using EchoListener echo = new();
        _echoPort = echo.Port;
        try
        {
            await using SshServer server = await SshServer.StartAsync(new SshServerOptions
            {
                Address = IPAddress.Loopback,
                Port = 0,
                HostKeys = [_hostKey],
                MaxConnections = (_concurrency * 4) + 16,
                MaxUnauthenticatedConnections = (_concurrency * 2) + 8,
                MaxUnauthenticatedPerAddress = (_concurrency * 2) + 8,
                PasswordHandler = (request, _) => ValueTask.FromResult(
                    request.UserName == User && request.Password == Password ? SshAuthDecision.Accept : SshAuthDecision.Reject),
                PublicKeyHandler = (request, _) => ValueTask.FromResult(
                    request.UserName == KeyUser ? SshAuthDecision.Accept : SshAuthDecision.Reject),
                DirectTcpHandler = (request, _) => ValueTask.FromResult(
                    request.Host == "127.0.0.1" && request.Port == _echoPort ? SshForwardDecision.Allow : SshForwardDecision.Deny),
                SessionHandler = HandleSessionAsync,
            });
            _port = server.LocalEndPoint.Port;
            return await RunWorkloadAsync();
        }
        finally
        {
            Console.CancelKeyPress -= cancel;
            TaskScheduler.UnobservedTaskException -= OnUnobserved;
            try
            {
                Directory.Delete(_root, recursive: true);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                Console.Error.WriteLine("Soak: could not delete " + _root + ": " + e.Message);
            }
        }
    }

    private async Task<int> RunWorkloadAsync()
    {
        string os = $"{Environment.OSVersion} ({System.Runtime.InteropServices.RuntimeInformation.RuntimeIdentifier}), {Environment.ProcessorCount} logical CPUs, server GC {GCSettings.IsServerGC}, .NET {Environment.Version}";
        Console.WriteLine($"Soak: {F(_minutes)} min, sample every {F(_intervalSeconds, "F0")} s, {_concurrency} workers, warmup {F(_warmupMinutes)} min, quiet sample every {_quietEvery} samples, server 127.0.0.1:{_port}, SFTP root {_root}");
        Console.WriteLine("Soak: " + os);
        Console.WriteLine("Soak: verdict on quiet samples only (workers parked, no connection or session open, full GC), at least " + MinQuietSamples + " after warmup; run samples are info.");
        Console.WriteLine("Soak: tolerances (slope of quiet samples after warmup, per hour): heap after GC " + F(HeapSlopeMiBPerHour) + " MiB, private bytes " + F(PrivateSlopeMiBPerHour) + " MiB, handles, fds, threads and pool threads " + F(CountSlopePerHour, "F0") + " each; live connections at most " + _concurrency + " and 0 at the end; no unexpected exception.");
        Console.WriteLine("Soak: CSV " + _outPath);

        using StreamWriter csv = new(_outPath, append: false, new UTF8Encoding(false)) { AutoFlush = true };
        csv.WriteLine("elapsed_s,phase,ops_total," + string.Join(',', Kinds.Select(k => "ops_" + k)) + ",expected_failures,unexpected_errors," +
            string.Join(',', Metrics.Select(m => m.Name + (m.IsBytes ? "_bytes" : string.Empty))) + ",allocated_bytes");

        Stopwatch clock = Stopwatch.StartNew();
        Task[] workers = [.. Enumerable.Range(0, _concurrency).Select(id => Task.Run(() => WorkerAsync(id)))];

        TimeSpan duration = TimeSpan.FromMinutes(_minutes);
        TimeSpan interval = TimeSpan.FromSeconds(_intervalSeconds);
        for (int k = 0; !_stop.IsCancellationRequested; k++)
        {
            RecordSample("run", clock, csv);
            if (_quietEvery > 0 && (k + 1) % _quietEvery == 0 && clock.Elapsed < duration)
            {
                await TryQuietSampleAsync(clock, csv);
            }

            TimeSpan next = TimeSpan.FromTicks(interval.Ticks * (k + 1));
            TimeSpan wait = (next < duration ? next : duration) - clock.Elapsed;
            if (clock.Elapsed >= duration)
            {
                break;
            }

            try
            {
                await Task.Delay(wait > TimeSpan.Zero ? wait : TimeSpan.Zero, _stop.Token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        _stop.Cancel();
        Task all = Task.WhenAll(workers);
        if (await Task.WhenAny(all, Task.Delay(TimeSpan.FromSeconds(60))) != all)
        {
            Console.Error.WriteLine("Soak: workers still busy 60 s after the stop; cancelling their operations.");
            _hard.Cancel();
        }

        await all;
        for (int i = 0; i < 100 && Volatile.Read(ref _serverSessions) != 0; i++)
        {
            await Task.Delay(100);
        }

        Sample final = RecordSample("final", clock, csv);
        return Report(final);
    }

    private async Task TryQuietSampleAsync(Stopwatch clock, StreamWriter csv)
    {
        TaskCompletionSource gate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        _gate = gate;
        try
        {
            Stopwatch wait = Stopwatch.StartNew();
            while (!Idle())
            {
                if (wait.Elapsed > QuietWait)
                {
                    _quietTimeouts++;
                    Console.WriteLine($"[{F(clock.Elapsed.TotalSeconds, "F0"),6}s quiet] skipped: not idle after {F(QuietWait.TotalSeconds, "F0")} s (parked {Volatile.Read(ref _parked)} of {_concurrency}, live {Volatile.Read(ref _live)}, srv {Volatile.Read(ref _serverSessions)}).");
                    return;
                }

                await Task.Delay(50, _stop.Token);
            }

            await Task.Delay(QuietSettle, _stop.Token);
            if (!Idle())
            {
                _quietTimeouts++;
                Console.WriteLine($"[{F(clock.Elapsed.TotalSeconds, "F0"),6}s quiet] skipped: something opened again during the settle.");
                return;
            }

            RecordSample("quiet", clock, csv);
        }
        catch (OperationCanceledException)
        {
            // Stopping: the final sample follows.
        }
        finally
        {
            _gate = null;
            gate.TrySetResult();
        }
    }

    private bool Idle() =>
        Volatile.Read(ref _parked) == _concurrency && Volatile.Read(ref _live) == 0 && Volatile.Read(ref _serverSessions) == 0;

    // Workers call this between operations. The wait is not work: it is outside the operation and the think time.
    private async Task PassGateAsync()
    {
        TaskCompletionSource? gate = _gate;
        if (gate is null)
        {
            return;
        }

        Interlocked.Increment(ref _parked);
        try
        {
            await gate.Task.WaitAsync(_stop.Token);
        }
        catch (OperationCanceledException)
        {
            // Stopping.
        }
        finally
        {
            Interlocked.Decrement(ref _parked);
        }
    }

    private Sample RecordSample(string phase, Stopwatch clock, StreamWriter csv)
    {
        GC.Collect(2, GCCollectionMode.Forced, blocking: true, compacting: true);
        GC.WaitForPendingFinalizers();
        GC.Collect(2, GCCollectionMode.Forced, blocking: true, compacting: true);
        long heap = GC.GetTotalMemory(forceFullCollection: false);
        GCMemoryInfo info = GC.GetGCMemoryInfo(GCKind.FullBlocking);
        long gen2 = info.GenerationInfo[2].SizeAfterBytes;
        long loh = info.GenerationInfo[3].SizeAfterBytes;

        long workingSet;
        long privateBytes;
        long handles;
        long threads;
        using (Process process = Process.GetCurrentProcess())
        {
            workingSet = process.WorkingSet64;
            privateBytes = process.PrivateMemorySize64;
            handles = process.HandleCount;
            threads = process.Threads.Count;
        }

        long fds = -1;
        if (OperatingSystem.IsLinux())
        {
            try
            {
                fds = Directory.GetFileSystemEntries("/proc/self/fd").Length;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                fds = -1;
            }
        }

        long[] opsNow = [.. _ops.Select((_, i) => Volatile.Read(ref _ops[i]))];
        Sample sample = new(
            clock.Elapsed.TotalSeconds,
            phase,
            opsNow,
            Volatile.Read(ref _expected),
            Volatile.Read(ref _unexpected),
            [heap, gen2, loh, workingSet, privateBytes, handles, fds, threads, ThreadPool.ThreadCount, Volatile.Read(ref _live), Volatile.Read(ref _serverSessions)],
            GC.GetTotalAllocatedBytes(precise: false));
        if (phase == "run")
        {
            _samples.Add(sample);
        }
        else if (phase == "quiet")
        {
            _quiet.Add(sample);
            if (HandleTypes.Count() is { } types)
            {
                _handleTypes.Add((sample.Elapsed, types));
                (double _, Dictionary<string, int> baseline) = _handleTypes.Find(t => t.Elapsed >= _warmupMinutes * 60);
                if (baseline is not null && baseline != types)
                {
                    Console.WriteLine("         handle types against the first quiet sample after warmup: " + HandleTypeChanges(baseline, types));
                }
            }
        }

        csv.WriteLine(F(sample.Elapsed, "F1") + "," + phase + "," + opsNow.Sum().ToString(CultureInfo.InvariantCulture) + "," +
            string.Join(',', opsNow) + "," + sample.Expected.ToString(CultureInfo.InvariantCulture) + "," + sample.Unexpected.ToString(CultureInfo.InvariantCulture) + "," +
            string.Join(',', sample.Values) + "," + sample.Allocated.ToString(CultureInfo.InvariantCulture));
        Console.WriteLine(
            $"[{F(sample.Elapsed, "F0"),6}s {phase,-5}] ops {opsNow.Sum()} (refused as designed {sample.Expected}, unexpected {sample.Unexpected}) heap {F(Mib(heap))} MiB gen2 {F(Mib(gen2))} loh {F(Mib(loh))} ws {F(Mib(workingSet), "F0")} private {F(Mib(privateBytes), "F0")} handles {handles} fds {fds} threads {threads} pool {ThreadPool.ThreadCount} live {_live} srv {_serverSessions} alloc {F(Mib(sample.Allocated), "F0")} MiB");
        return sample;
    }

    private static bool PrintFit(List<Sample> fit, double spanMinutes, bool judge)
    {
        bool failed = false;
        Console.WriteLine($"{"metric",-18} {"start",12} {"end",12} {"change",12} {"slope/hour",12} {"R2",5} {"tolerance",10}  verdict");
        double[] hours = [.. fit.Select(s => s.Elapsed / 3600)];
        for (int m = 0; m < Metrics.Length; m++)
        {
            Metric metric = Metrics[m];
            double[] ys = [.. fit.Select(s => s.Values[m] / (metric.IsBytes ? 1024.0 * 1024 : 1))];
            if (ys.All(y => y < 0) || (metric.Name == "handles" && ys.All(y => y == 0)))
            {
                Console.WriteLine($"{metric.Name,-18} {"n/a on this OS",12}");
                continue;
            }

            (double slope, double r2) = Regression.Fit(hours, ys);
            string unit = metric.IsBytes ? " MiB" : string.Empty;
            string verdict = "info";
            if (judge && metric.Tolerance is double tolerance)
            {
                bool ok = slope < tolerance;
                verdict = ok ? "PASS" : spanMinutes < 10 ? "short run" : "FAIL";
                failed |= !ok && spanMinutes >= 10;
            }

            Console.WriteLine($"{metric.Name,-18} {F(ys[0]),12} {F(ys[^1]),12} {F(ys[^1] - ys[0]),12} {F(slope),12} {F(r2, "F2"),5} {(metric.Tolerance is double t ? "< " + F(t) + unit : "-"),10}  {verdict}  ({metric.Description})");
        }

        return failed;
    }

    private int Report(Sample final)
    {
        Console.WriteLine();
        Console.WriteLine("Operations completed: " + string.Join(", ", Kinds.Select((k, i) => k + " " + Volatile.Read(ref _ops[i]))));
        Console.WriteLine($"Refused or cancelled as designed: {_expected}. Unexpected exceptions: {_unexpected}.");
        if (_sessionLimit > 0)
        {
            Console.WriteLine($"Note: {_sessionLimit} reuse operations were refused at the session limit (reason 4): the server frees a slot a moment after the client sees a channel close (not counted as errors).");
        }

        if (_portExhaustion > 0)
        {
            Console.WriteLine($"Note: {_portExhaustion} connects failed at the TCP level, from ephemeral port exhaustion or a dropped SYN (not counted as errors). Raise --think-ms or lower --concurrency.");
        }

        bool failed = false;
        double warmupSeconds = _warmupMinutes * 60;
        List<(double Elapsed, Dictionary<string, int> Types)> typed = [.. _handleTypes.Where(t => t.Elapsed >= warmupSeconds)];
        if (typed.Count > 1)
        {
            Console.WriteLine();
            Console.WriteLine($"Handles by type at quiet points after warmup ({typed.Count} samples): type, first, last, min, max");
            foreach (string type in typed.SelectMany(t => t.Types.Keys).Distinct(StringComparer.Ordinal).OrderBy(t => t, StringComparer.Ordinal))
            {
                int[] v = [.. typed.Select(t => t.Types.GetValueOrDefault(type))];
                Console.WriteLine($"  {type,-24} {v[0],6} {v[^1],6} {v.Min(),6} {v.Max(),6}{(v[^1] != v[0] ? "   change " + (v[^1] - v[0]).ToString("+0;-0", CultureInfo.InvariantCulture) : string.Empty)}");
            }
        }
        Console.WriteLine();
        Console.WriteLine($"Quiet samples: {_quiet.Count} taken, {_quietTimeouts} skipped because the process never went idle within {F(QuietWait.TotalSeconds, "F0")} s (a connection or session that never ends is worth a look).");
        List<Sample> fit = [.. _quiet.Where(s => s.Elapsed >= warmupSeconds)];
        double spanMinutes = fit.Count > 1 ? (fit[^1].Elapsed - fit[0].Elapsed) / 60 : 0;
        Console.WriteLine($"Verdict fit: {fit.Count} quiet samples after {F(_warmupMinutes)} min of warmup ({F(spanMinutes)} min).");
        if (fit.Count < MinQuietSamples)
        {
            Console.WriteLine($"Too few quiet samples (need {MinQuietSamples} after warmup): no verdict on slopes. Run longer, sample more often, or lower --quiet-every.");
        }
        else
        {
            if (spanMinutes < 10)
            {
                Console.WriteLine("Note: under 10 minutes of fit window, the per-hour slopes extrapolate noise (a GC, a buffer in flight). A slope over its tolerance is shown as 'short run' and doesn't fail the run: read these as a smoke test, not a verdict.");
            }

            failed |= PrintFit(fit, spanMinutes, judge: true);
            foreach (string name in new[] { "handles", "fds" })
            {
                int m = Array.FindIndex(Metrics, x => x.Name == name);
                long[] v = [.. fit.Select(s => s.Values[m])];
                if (v.Any(x => x >= 0) && !(name == "handles" && v.All(x => x == 0)))
                {
                    Console.WriteLine($"{name} at quiet points: min {v.Min()}, max {v.Max()}, first {v[0]}, last {v[^1]}.");
                }
            }
        }

        List<Sample> runFit = [.. _samples.Where(s => s.Elapsed >= warmupSeconds)];
        Console.WriteLine();
        if (runFit.Count < 3)
        {
            Console.WriteLine($"Run samples after warmup: {runFit.Count}, too few for an info fit.");
        }
        else
        {
            double runSpan = (runFit[^1].Elapsed - runFit[0].Elapsed) / 60;
            Console.WriteLine($"Run samples (taken with work in flight, so they swing with the connections open; info only): {runFit.Count} samples, {F(runSpan)} min.");
            PrintFit(runFit, runSpan, judge: false);
        }

        int liveIndex = Array.FindIndex(Metrics, m => m.Name == "live_connections");
        int sessionIndex = Array.FindIndex(Metrics, m => m.Name == "server_sessions");
        int maxLive = Math.Max(Volatile.Read(ref _maxLive), _samples.Count == 0 ? 0 : (int)_samples.Max(s => s.Values[liveIndex]));
        bool liveOk = maxLive <= _concurrency;
        bool endLive = final.Values[liveIndex] == 0;
        bool endSessions = final.Values[sessionIndex] == 0;
        Console.WriteLine($"Most connections open at once: {maxLive} (limit {_concurrency}) {(liveOk ? "PASS" : "FAIL")}. Open at the end: {final.Values[liveIndex]} {(endLive ? "PASS" : "FAIL")}. Server sessions at the end: {final.Values[sessionIndex]} {(endSessions ? "PASS" : "FAIL")}.");
        failed |= !liveOk || !endLive || !endSessions;
        Console.WriteLine($"After the workers stopped: heap {F(Mib(final.Values[0]))} MiB, private {F(Mib(final.Values[4]))} MiB, threads {final.Values[7]}, handles {final.Values[5]}.");

        if (_unexpected > 0)
        {
            Console.Error.WriteLine();
            Console.Error.WriteLine($"Unexpected exceptions: {_unexpected} in {_distinct.Count} distinct places.");
            foreach (Distinct d in _distinct.Values.OrderByDescending(d => d.Count))
            {
                Console.Error.WriteLine($"--- {d.Count} x in {d.Context}");
                Console.Error.WriteLine(d.Text);
            }

            Console.WriteLine("RESULT: UNEXPECTED EXCEPTIONS (exit 2)");
            return 2;
        }

        Console.WriteLine(failed ? "RESULT: FAIL (exit 1)" : "RESULT: PASS (exit 0)");
        return failed ? 1 : 0;
    }

    private void OnUnobserved(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        e.SetObserved();
        Record("unobserved task", e.Exception.Flatten());
    }

    private void Record(string context, Exception e)
    {
        Interlocked.Increment(ref _unexpected);
        string key = e.GetType().FullName + " @ " + TopFrame(e);
        bool first = false;
        _distinct.AddOrUpdate(
            key,
            _ =>
            {
                first = true;
                return new Distinct(context, e.ToString(), 1);
            },
            (_, d) => d with { Count = d.Count + 1 });
        if (first)
        {
            Console.Error.WriteLine($"UNEXPECTED in {context}: {e.GetType().FullName}: {e.Message}");
        }
    }

    // ---- The server side -------------------------------------------------------------------------------------------

    private async Task<int> HandleSessionAsync(SshServerSession session, CancellationToken ct)
    {
        Interlocked.Increment(ref _serverSessions);
        try
        {
            if (session is { Kind: SshSessionKind.Subsystem, Command: "sftp" })
            {
                return await SftpServer.ServeAsync(session, new SftpServerOptions { RootDirectory = _root }, ct);
            }

            if (session.Kind != SshSessionKind.Exec || session.Command is null)
            {
                return 127;
            }

            string[] parts = session.Command.Split(' ', 2);
            switch (parts[0])
            {
                case "echo":
                    await session.Output.WriteAsync(Encoding.UTF8.GetBytes("reply: " + (parts.Length > 1 ? parts[1] : string.Empty) + "\n"), ct);
                    return 0;
                case "count":
                {
                    long total = 0;
                    byte[] buffer = new byte[32 * 1024];
                    int read;
                    while ((read = await session.Input.ReadAsync(buffer, ct)) > 0)
                    {
                        total += read;
                    }

                    await session.Output.WriteAsync(Encoding.UTF8.GetBytes(total.ToString(CultureInfo.InvariantCulture) + "\n"), ct);
                    return 0;
                }

                case "stream":
                {
                    // Copy stdin to stdout, and put a few bytes on stderr as it goes, so the client has to read both.
                    long total = 0;
                    long lastMark = 0;
                    byte[] buffer = new byte[32 * 1024];
                    int read;
                    while ((read = await session.Input.ReadAsync(buffer, ct)) > 0)
                    {
                        await session.Output.WriteAsync(buffer.AsMemory(0, read), ct);
                        total += read;
                        if (total - lastMark >= 128 * 1024)
                        {
                            lastMark = total;
                            await session.Error.WriteAsync("."u8.ToArray(), ct);
                        }
                    }

                    await session.Error.WriteAsync(Encoding.UTF8.GetBytes("done " + total.ToString(CultureInfo.InvariantCulture) + "\n"), ct);
                    return 0;
                }

                case "flood":
                {
                    byte[] block = new byte[64 * 1024];
                    while (true)
                    {
                        await session.Output.WriteAsync(block, ct);
                    }
                }

                case "hang":
                    await Task.Delay(Timeout.Infinite, ct);
                    return 0;
                default:
                    return 127;
            }
        }
        catch (Exception e) when (e is OperationCanceledException or IOException or SshException or ObjectDisposedException)
        {
            // The client went away or was cut off, which is what several operations do on purpose.
            return 1;
        }
#pragma warning disable CA1031 // The harness must count any other type from the library's streams.
        catch (Exception e)
#pragma warning restore CA1031
        {
            Record("server session handler", e);
            return 1;
        }
        finally
        {
            Interlocked.Decrement(ref _serverSessions);
        }
    }

    // ---- The client side -------------------------------------------------------------------------------------------

    private sealed class TrackedClient(SshClient client, Soak owner) : IAsyncDisposable
    {
        private int _disposed;

        public SshClient Client { get; } = client;

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                try
                {
                    await Client.DisposeAsync();
                }
                finally
                {
                    Interlocked.Decrement(ref owner._live);
                }
            }
        }
    }

    private async Task<TrackedClient> ConnectAsync(CancellationToken ct, bool key = false, int? port = null, string password = Password)
    {
        SshClient client = await SshClient.ConnectAsync(
            new SshClientOptions
            {
                Host = "127.0.0.1",
                Port = port ?? _port,
                UserName = key ? KeyUser : User,
                Credentials = [key ? SshCredential.FromPrivateKey(_clientKey) : SshCredential.FromPassword(password)],
                HostKeyPolicy = HostKeyPolicy.Fingerprint(_hostKey!.Sha256Fingerprint),
            },
            ct);
        int now = Interlocked.Increment(ref _live);
        int seen;
        while (now > (seen = Volatile.Read(ref _maxLive)) && Interlocked.CompareExchange(ref _maxLive, now, seen) != seen)
        {
        }

        return new TrackedClient(client, this);
    }

    private async Task WorkerAsync(int id)
    {
        Random rng = new(unchecked((Environment.TickCount * 31) + id));
        int totalWeight = Weights.Sum();
        while (!_stop.IsCancellationRequested)
        {
            await PassGateAsync();
            if (_stop.IsCancellationRequested)
            {
                break;
            }

            int pick = rng.Next(totalWeight);
            int kind = 0;
            while (pick >= Weights[kind])
            {
                pick -= Weights[kind];
                kind++;
            }

            await RunOneAsync(kind, id, rng);
            if (_thinkMs > 0)
            {
                try
                {
                    await Task.Delay(rng.Next(_thinkMs * 2), _stop.Token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }
    }

#pragma warning disable CA1031 // Every exception from an operation is classified below.
    private async Task RunOneAsync(int kind, int worker, Random rng)
    {
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(_hard.Token);
        timeout.CancelAfter(TimeSpan.FromSeconds(kind == 4 ? 180 : 90));
        CancellationToken ct = timeout.Token;
        long serial = Interlocked.Increment(ref _serial);
        string dir = string.Create(CultureInfo.InvariantCulture, $"w{worker}-{serial}");
        try
        {
            await (kind switch
            {
                0 => ConnectLoginAsync(rng, ct),
                1 => ReuseAsync(rng, ct),
                2 => StreamAsync(rng, ct),
                3 => SftpSmallAsync(dir, rng, 50, ct),
                4 => SftpLargeAsync(dir, rng, ct),
                5 => SftpSmallAsync(dir, rng, 20, ct, list: true),
                6 => ForwardAsync(rng, ct),
                7 => BadLoginAsync(ct),
                8 => AbruptAsync(ct),
                _ => CancelAsync(dir, rng, ct),
            });

            Interlocked.Increment(ref _ops[kind]);
        }
        catch (Exception e)
        {
            if (_hard.IsCancellationRequested && e is OperationCanceledException or SshException)
            {
                return;
            }

            if (timeout.IsCancellationRequested)
            {
                Record(Kinds[kind] + " (no result within its time limit: a hang)", e);
                return;
            }

            if (e is SshConnectionException { InnerException: SocketException { SocketErrorCode: SocketError.AddressAlreadyInUse or SocketError.NoBufferSpaceAvailable or SocketError.TimedOut } }
                || (kind == 6 && e is SocketException { SocketErrorCode: SocketError.AddressAlreadyInUse or SocketError.NoBufferSpaceAvailable }))
            {
                // The machine ran out of ephemeral ports (Windows keeps closed loopback connections in TIME_WAIT for two minutes), or a SYN was dropped.
                // That is the harness's rate, not the library: count it, and say so in the report.
                Interlocked.Increment(ref _portExhaustion);
                return;
            }

            if (kind == 1 && e is SshException { InnerException: null } && e.Message.Contains("(reason 4)", StringComparison.Ordinal))
            {
                // The server frees a session slot once the session's handler has ended, a moment after the client sees the channel close. A
                // connection reused as hard as this one can run into the limit of 10 for that moment. Counted and reported, not hidden.
                Interlocked.Increment(ref _sessionLimit);
                return;
            }

            bool designed = kind switch
            {
                7 => e is SshAuthenticationException,
                8 => Refusal(e),
                9 => e is OperationCanceledException,
                _ => false,
            };
            if (designed)
            {
                Interlocked.Increment(ref _ops[kind]);
                Interlocked.Increment(ref _expected);
            }
            else
            {
                Record(Kinds[kind], e);
            }
        }
        finally
        {
            Cleanup(dir);
        }
    }
#pragma warning restore CA1031

    private void Cleanup(string dir)
    {
        string path = Path.Combine(_root, dir);
        if (Directory.Exists(path))
        {
            try
            {
                Directory.Delete(path, recursive: true);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                // The server may still be closing a file after a cancelled transfer. Try again later.
                if (_stale.Count < 256)
                {
                    _stale.Enqueue(path);
                }
            }
        }

        for (int i = 0; i < 4 && _stale.TryDequeue(out string? old); i++)
        {
            try
            {
                if (Directory.Exists(old))
                {
                    Directory.Delete(old, recursive: true);
                }
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                _stale.Enqueue(old);
            }
        }
    }

    private static async Task ExpectEchoAsync(SshClient client, string text, CancellationToken ct)
    {
        SshCommandResult result = await client.ExecuteAsync("echo " + text, ct);
        if (result.ExitCode != 0 || result.StandardOutput != "reply: " + text + "\n")
        {
            throw new InvalidOperationException("The echo command came back wrong: exit " + result.ExitCode + ", output '" + result.StandardOutput + "'.");
        }
    }

    private async Task ConnectLoginAsync(Random rng, CancellationToken ct)
    {
        await using TrackedClient tc = await ConnectAsync(ct, key: rng.Next(4) == 0);
        await ExpectEchoAsync(tc.Client, "hello" + rng.Next(), ct);
    }

    private async Task ReuseAsync(Random rng, CancellationToken ct)
    {
        await using TrackedClient tc = await ConnectAsync(ct);
        for (int round = 0; round < 10; round++)
        {
            await Task.WhenAll(Enumerable.Range(0, 4).Select(i => ExpectEchoAsync(tc.Client, "r" + round + "-" + i + "-" + rng.Next(), ct)));
        }
    }

    private async Task StreamAsync(Random rng, CancellationToken ct)
    {
        const int Length = 1 << 20;
        await using TrackedClient tc = await ConnectAsync(ct);
        await using SshProcess process = await tc.Client.StartProcessAsync("stream", null, ct);
        using PatternStream source = new(Length, (ulong)rng.NextInt64());
        using HashSinkStream output = new();
        using HashSinkStream error = new();
        Task write = Task.Run(
            async () =>
            {
                await source.CopyToAsync(process.StandardInput, 16 * 1024, ct);
                await process.StandardInput.DisposeAsync();
            },
            ct);
        Task readOut = process.StandardOutput.CopyToAsync(output, ct);
        Task readErr = process.StandardError.CopyToAsync(error, ct);
        await Task.WhenAll(write, readOut, readErr);
        await process.WaitForExitAsync(ct);
        if (process.ExitCode != 0 || output.Written != Length || !output.Digest().AsSpan().SequenceEqual(source.Digest()) || error.Written == 0)
        {
            throw new InvalidOperationException($"The streamed command came back wrong: exit {process.ExitCode}, {output.Written} bytes out, {error.Written} on stderr.");
        }
    }

    private async Task SftpSmallAsync(string dir, Random rng, int files, CancellationToken ct, bool list = false)
    {
        await using TrackedClient tc = await ConnectAsync(ct);
        await using SftpClient sftp = await tc.Client.OpenSftpAsync(ct);
        string remote = "/" + dir;
        await sftp.CreateDirectoryAsync(remote, recursive: false, ct);
        Dictionary<string, byte[]> expected = [];
        for (int i = 0; i < files; i++)
        {
            byte[] data = new byte[rng.Next(1024, 16 * 1024 + 1)];
            rng.NextBytes(data);
            string path = string.Create(CultureInfo.InvariantCulture, $"{remote}/f{i:D3}.dat");
            expected[path] = data;
            if (i % 2 == 0)
            {
                await sftp.WriteAllBytesAsync(path, data, ct);
            }
            else
            {
                using MemoryStream source = new(data);
                await sftp.UploadFileAsync(source, path, ct);
            }
        }

        if (list)
        {
            int count = 0;
            await foreach (SftpEntry entry in sftp.ListDirectoryAsync(remote, ct))
            {
                if (entry.Name is "." or "..")
                {
                    continue;
                }

                if (!entry.IsSafeName)
                {
                    throw new InvalidOperationException("The listing held an unsafe name.");
                }

                if (entry.Name.EndsWith(".dat", StringComparison.Ordinal))
                {
                    count++;
                }
            }

            if (count != files)
            {
                throw new InvalidOperationException($"The listing held {count} of {files} files.");
            }
        }

        int n = 0;
        foreach ((string path, byte[] data) in expected)
        {
            byte[] back;
            if (n++ % 2 == 0)
            {
                back = await sftp.ReadAllBytesAsync(path, ct);
            }
            else
            {
                using MemoryStream sink = new();
                await sftp.DownloadFileAsync(path, sink, ct);
                back = sink.ToArray();
            }

            if (!back.AsSpan().SequenceEqual(data))
            {
                throw new InvalidOperationException("A small file came back different: " + path);
            }

            await sftp.DeleteFileAsync(path, ct);
        }

        await sftp.DeleteDirectoryAsync(remote, ct);
    }

    private async Task SftpLargeAsync(string dir, Random rng, CancellationToken ct)
    {
        long length = rng.NextInt64(8L << 20, (32L << 20) + 1);
        await using TrackedClient tc = await ConnectAsync(ct);
        await using SftpClient sftp = await tc.Client.OpenSftpAsync(ct);
        string remote = "/" + dir;
        await sftp.CreateDirectoryAsync(remote, recursive: false, ct);
        string path = remote + "/big.bin";
        using (PatternStream source = new(length, (ulong)rng.NextInt64()))
        {
            await sftp.UploadFileAsync(source, path, ct);
            using HashSinkStream sink = new();
            await sftp.DownloadFileAsync(path, sink, ct);
            if (sink.Written != length || !sink.Digest().AsSpan().SequenceEqual(source.Digest()))
            {
                throw new InvalidOperationException($"The large file came back different: {sink.Written} of {length} bytes.");
            }
        }

        await sftp.DeleteFileAsync(path, ct);
        await sftp.DeleteDirectoryAsync(remote, ct);
    }

    private async Task ForwardAsync(Random rng, CancellationToken ct)
    {
        byte[] payload = new byte[64 * 1024];
        rng.NextBytes(payload);
        await using TrackedClient tc = await ConnectAsync(ct);
        await using SshLocalForward forward = await tc.Client.ForwardLocalPortAsync("127.0.0.1", _echoPort, new IPEndPoint(IPAddress.Loopback, 0), ct);
        using TcpClient tcp = new();
        await tcp.ConnectAsync(forward.LocalEndPoint, ct);
        NetworkStream stream = tcp.GetStream();
        byte[] back = new byte[payload.Length];
        Task write = Task.Run(async () => await stream.WriteAsync(payload, ct), ct);
        await stream.ReadExactlyAsync(back, ct);
        await write;
        if (!back.AsSpan().SequenceEqual(payload))
        {
            throw new InvalidOperationException("The forwarded echo came back different.");
        }
    }

    private async Task BadLoginAsync(CancellationToken ct)
    {
        TrackedClient tc = await ConnectAsync(ct, password: "not-the-password");
        await tc.DisposeAsync();
        throw new InvalidOperationException("A wrong password was accepted.");
    }

    private async Task AbruptAsync(CancellationToken ct)
    {
        await using KillableRelay relay = new(_port);
        await using TrackedClient tc = await ConnectAsync(ct, port: relay.Port);
        await using SshProcess process = await tc.Client.StartProcessAsync("flood", null, ct);
        byte[] buffer = new byte[16 * 1024];
        long read = 0;
        while (read < 256 * 1024)
        {
            int n = await process.StandardOutput.ReadAsync(buffer, ct);
            if (n == 0)
            {
                throw new InvalidOperationException("The flood ended by itself.");
            }

            read += n;
        }

        relay.Kill();
        // The connection is gone: reading on or waiting for the exit has to say so with an SshException.
        while (await process.StandardOutput.ReadAsync(buffer, ct) > 0)
        {
        }

        await process.WaitForExitAsync(ct);
        throw new InvalidOperationException("The connection was cut and the client did not report an SshException.");
    }

    private async Task CancelAsync(string dir, Random rng, CancellationToken ct)
    {
        using CancellationTokenSource inner = CancellationTokenSource.CreateLinkedTokenSource(ct);
        switch (rng.Next(3))
        {
            case 0:
            {
                // Cancel somewhere in the connect and login.
                inner.CancelAfter(TimeSpan.FromMilliseconds(rng.Next(1, 12)));
                await using TrackedClient tc = await ConnectAsync(inner.Token);
                await ExpectEchoAsync(tc.Client, "late", inner.Token);
                return;
            }

            case 1:
            {
                // Cancel a command that never ends.
                await using TrackedClient tc = await ConnectAsync(ct);
                inner.CancelAfter(TimeSpan.FromMilliseconds(rng.Next(50, 400)));
                await tc.Client.ExecuteAsync("hang", inner.Token);
                throw new InvalidOperationException("A command that never ends returned.");
            }

            default:
            {
                // Cancel a large upload.
                await using TrackedClient tc = await ConnectAsync(ct);
                await using SftpClient sftp = await tc.Client.OpenSftpAsync(ct);
                await sftp.CreateDirectoryAsync("/" + dir, recursive: false, ct);
                inner.CancelAfter(TimeSpan.FromMilliseconds(rng.Next(30, 300)));
                using PatternStream source = new(256L << 20, (ulong)rng.NextInt64());
                await sftp.UploadFileAsync(source, "/" + dir + "/big.bin", inner.Token);
                return;
            }
        }
    }

    private sealed record Metric(string Name, string Description, bool IsBytes, double? Tolerance);

    private sealed record Distinct(string Context, string Text, int Count);

    private sealed record Sample(double Elapsed, string Phase, long[] Ops, long Expected, long Unexpected, long[] Values, long Allocated);
}

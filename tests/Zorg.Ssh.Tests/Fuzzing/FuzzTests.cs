#pragma warning disable CA1031 // The harness catches everything on purpose: an exception of any type is a finding.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Zorg.Ssh.Tests.Fuzzing;

/// <summary>
/// Seeded fuzzing of every decoder that reads bytes or text from a peer or a file. A normal pass runs a short, fixed run of
/// each target and adds a few seconds. Set <c>ZORG_FUZZ_MINUTES</c> for a long run (each target gets that long, all at once),
/// and <c>ZORG_FUZZ_SEED</c> with <c>ZORG_FUZZ_TARGET</c> to replay the input a failure message names. CONTRIBUTING.md has the details.
/// </summary>
public sealed class FuzzTests
{
    private static readonly Lock LongGate = new();
    private static Dictionary<string, FuzzReport>? _longRun;

    public static TheoryData<string> TargetNames() => [.. FuzzTargets.All.Select(target => target.Name)];

    [Theory]
    [MemberData(nameof(TargetNames))]
    public void Hostile_input_causes_only_the_documented_exception_no_hang_and_no_big_allocation(string name)
    {
        FuzzTarget target = FuzzTargets.Named(name);
        if (FuzzSettings.TargetFilter is { } filter && !name.Contains(filter, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        FuzzReport report;
        if (FuzzSettings.ReplaySeed is { } replay)
        {
            report = FuzzRunner.Run(target, new FuzzRunOptions(FuzzSettings.DefaultRunSeed, 0, null, replay, FuzzSettings.InputLimit));
        }
        else if (FuzzSettings.LongRun is not null)
        {
            report = LongReport(name);
        }
        else
        {
            report = FuzzRunner.Run(target, new FuzzRunOptions(FuzzSettings.DefaultRunSeed, target.ShortIterations, null, null, FuzzSettings.InputLimit));
        }

        Console.WriteLine(report.Summary());
        if (Environment.GetEnvironmentVariable("ZORG_FUZZ_VERBOSE") is { Length: > 0 })
        {
            foreach (KeyValuePair<string, int> stage in report.Reached.OrderByDescending(r => r.Value).Take(16))
            {
                Console.WriteLine($"    reached {stage.Value,7}  {stage.Key}");
            }

            foreach (KeyValuePair<string, int> reason in report.Reasons.OrderByDescending(r => r.Value).Take(12))
            {
                Console.WriteLine($"    {reason.Value,7}  {reason.Key}");
            }
        }

        Assert.True(report.Findings.Count == 0, report.Describe());

        if (FuzzSettings.ReplaySeed is null && FuzzSettings.LongRun is null)
        {
            // Depth: a target whose inputs all die at the first check proves nothing.
            Assert.True(report.AcceptedShare >= target.MinAcceptedShare, $"{report.Summary()}{Environment.NewLine}Too few inputs got all the way through ({report.AcceptedShare:P2}, wanted {target.MinAcceptedShare:P2}). The target has gone shallow.");
            Assert.True(report.Reached.Count >= target.MinReachedStages, $"{report.Summary()}{Environment.NewLine}Only {report.Reached.Count} different stages were reached, wanted {target.MinReachedStages}. Reached: {string.Join("; ", report.Reached.Keys)}");
            Assert.True(report.DistinctReasons >= target.MinRefusalReasons, $"{report.Summary()}{Environment.NewLine}Only {report.DistinctReasons} different refusal reasons were seen, wanted {target.MinRefusalReasons}. Reasons: {string.Join("; ", report.Reasons.Keys)}");
        }
    }

    [Theory]
    [MemberData(nameof(TargetNames))]
    public void Every_unmutated_seed_is_accepted_or_refused_with_an_allowed_exception(string name)
    {
        FuzzTarget target = FuzzTargets.Named(name);
        int accepted = 0;
        foreach (FuzzSeed seed in target.Corpus)
        {
            try
            {
                FuzzOutcome outcome = target.Execute(seed.Data);
                Assert.NotEqual(FuzzOutcome.Skipped, outcome);
                if (outcome == FuzzOutcome.Accepted)
                {
                    accepted++;
                }
            }
            catch (Exception exception) when (target.Allowed.Any(type => type.IsInstanceOfType(exception)))
            {
                // A seed may be a deliberate refusal, such as SOCKS4 or a legacy encrypted key.
            }
        }

        Assert.True(accepted * 2 >= target.Corpus.Count, $"{name}: only {accepted} of {target.Corpus.Count} seeds are accepted. The corpus is meant to be mostly well formed, so that a small mutation lands deep.");
    }

    [Fact]
    public void An_input_is_decided_by_its_seed_alone()
    {
        foreach (FuzzTarget target in FuzzTargets.All)
        {
            for (ulong seed = 1; seed <= 40; seed++)
            {
                Assert.Equal(FuzzRunner.InputFor(target, seed), FuzzRunner.InputFor(target, seed));
            }

            // Different seeds must give different inputs, or the run is repeating itself.
            int distinct = Enumerable.Range(1, 200).Select(i => Convert.ToBase64String(FuzzRunner.InputFor(target, FuzzRunner.InputSeed(target, FuzzSettings.DefaultRunSeed, i)))).Distinct(StringComparer.Ordinal).Count();
            Assert.True(distinct > 150, $"{target.Name}: only {distinct} different inputs in 200");
        }
    }

    [Fact]
    public void A_normal_pass_uses_a_fixed_run_seed_and_a_failure_names_the_target_and_seed()
    {
        FuzzTarget broken = new()
        {
            Name = "always throws",
            Corpus = [FuzzSeed.Binary("a", [1, 2, 3, 4])],
            Execute = static _ => throw new InvalidOperationException("boom"),
            Allowed = [typeof(FormatException)],
        };
        FuzzReport report = FuzzRunner.Run(broken, new FuzzRunOptions(FuzzSettings.DefaultRunSeed, 5, null, null, TimeSpan.FromSeconds(5)));
        FuzzFinding finding = Assert.Single(report.Findings);
        string text = finding.Describe();
        Assert.Contains("target=always throws", text, StringComparison.Ordinal);
        Assert.Contains($"seed={FuzzRunner.InputSeed(broken, FuzzSettings.DefaultRunSeed, 0)}", text, StringComparison.Ordinal);
        Assert.Contains("ZORG_FUZZ_SEED=", text, StringComparison.Ordinal);

        // And replaying that seed finds the same thing.
        FuzzReport again = FuzzRunner.Run(broken, new FuzzRunOptions(0, 0, null, finding.Seed, TimeSpan.FromSeconds(5)));
        Assert.Equal(finding.Seed, Assert.Single(again.Findings).Seed);
    }

    private static FuzzReport LongReport(string name)
    {
        lock (LongGate)
        {
            _longRun ??= RunAllLong();
        }

        return _longRun[name];
    }

    /// <summary>Gives every target its own thread for the whole time, so <c>ZORG_FUZZ_MINUTES</c> is the wall clock for the lot.</summary>
    private static Dictionary<string, FuzzReport> RunAllLong()
    {
        TimeSpan span = FuzzSettings.LongRun!.Value;
        ulong runSeed = FuzzSettings.LongRunSeed;
        List<FuzzTarget> targets = [.. FuzzTargets.All.Where(t => FuzzSettings.TargetFilter is not { } filter || t.Name.Contains(filter, StringComparison.OrdinalIgnoreCase))];
        Console.WriteLine($"Long fuzz run: {targets.Count} targets for {span.TotalMinutes:0.##} minutes each, run seed {runSeed}, {Environment.ProcessorCount} processors.");
        Dictionary<string, FuzzReport> results = [];
        List<Task> tasks = [];
        foreach (FuzzTarget target in targets)
        {
            tasks.Add(Task.Factory.StartNew(
                () =>
                {
                    FuzzReport report = FuzzRunner.Run(target, new FuzzRunOptions(runSeed, 0, span, null, FuzzSettings.InputLimit, WriteMarker: true));
                    lock (results)
                    {
                        results[target.Name] = report;
                    }
                },
                CancellationToken.None,
                TaskCreationOptions.LongRunning,
                TaskScheduler.Default));
        }

        Task.WaitAll([.. tasks]);
        StringBuilder text = new();
        text.AppendLine(CultureInfo.InvariantCulture, $"Long fuzz run, run seed {runSeed}, {span.TotalMinutes:0.##} minutes per target, started {DateTime.UtcNow:O}");
        foreach (FuzzReport report in results.Values.OrderBy(r => r.Target, StringComparer.Ordinal))
        {
            text.AppendLine(report.Summary());
            foreach (KeyValuePair<string, int> reason in report.Reasons.OrderByDescending(r => r.Value).Take(6))
            {
                text.AppendLine(CultureInfo.InvariantCulture, $"    {reason.Value,9}  {reason.Key}");
            }
        }

        string path = Environment.GetEnvironmentVariable("ZORG_FUZZ_REPORT") is { Length: > 0 } custom ? custom : Path.Combine(Path.GetTempPath(), "zorg-fuzz-report.txt");
        File.WriteAllText(path, text.ToString());
        Console.WriteLine(text.ToString());
        return results;
    }
}

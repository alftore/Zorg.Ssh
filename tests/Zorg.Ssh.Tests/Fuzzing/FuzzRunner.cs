#pragma warning disable CA1031 // The harness catches everything on purpose: an exception of any type is a finding.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;

namespace Zorg.Ssh.Tests.Fuzzing;

/// <summary>How far one input got. A target says so, and the report turns it into a share, to show the inputs aren't all stopped at the first byte.</summary>
internal enum FuzzOutcome
{
    /// <summary>The decoder refused the input with an allowed exception.</summary>
    Rejected,

    /// <summary>The decoder accepted it: every layer parsed.</summary>
    Accepted,

    /// <summary>The target chose not to run it, for example a config with an Include line.</summary>
    Skipped,
}

/// <summary>One decoder under test and everything the runner needs to attack it.</summary>
internal sealed class FuzzTarget
{
    public required string Name { get; init; }

    public required IReadOnlyList<FuzzSeed> Corpus { get; init; }

    /// <summary>Runs the decoder on one input, in this thread, to the end. It must throw only what the decoder documents.</summary>
    public required Func<byte[], FuzzOutcome> Execute { get; init; }

    /// <summary>Gets the exception types the decoder is allowed to throw. A type here also allows its subtypes.</summary>
    public required IReadOnlyList<Type> Allowed { get; init; }

    /// <summary>Gets how many inputs a normal pass runs.</summary>
    public int ShortIterations { get; init; } = 1500;

    /// <summary>Gets the allocation allowed for any input, whatever its size.</summary>
    public long AllocationSlack { get; init; } = 512 * 1024;

    /// <summary>Gets the allocation allowed for each byte of input on top of the slack. A small input that costs more than this is a finding.</summary>
    public int AllocationPerByte { get; init; } = 64;

    /// <summary>Gets words of the target's format, which the text mutator tries in place of tokens.</summary>
    public IReadOnlyList<string> Tokens { get; init; } = [];

    /// <summary>Gets offsets of length fields that the corpus builder knows, by seed name.</summary>
    public IReadOnlyDictionary<string, int[]> KnownLengthOffsets { get; init; } = new Dictionary<string, int[]>();

    /// <summary>Gets the least share of inputs that must be accepted, in a normal pass. It guards against a target that has gone shallow.</summary>
    public double MinAcceptedShare { get; init; } = 0.01;

    /// <summary>Gets the fewest different refusal reasons a normal pass must see.</summary>
    public int MinRefusalReasons { get; init; } = 3;

    /// <summary>Gets the fewest different stages (see <see cref="FuzzNotes"/>) a normal pass must reach. Zero means the target reports none.</summary>
    public int MinReachedStages { get; init; }

    public long AllocationBudget(int inputBytes) => AllocationSlack + ((long)AllocationPerByte * inputBytes);

    public override string ToString() => Name;
}

/// <summary>
/// How a target says which stage an input reached, such as "certificate parsed" or "status 2 from the server". The runner counts
/// them, and a normal pass checks that enough different stages were seen. This is the evidence that inputs get past the first check.
/// </summary>
internal static class FuzzNotes
{
    [ThreadStatic]
    private static List<string>? _notes;

    public static void Reached(string stage) => (_notes ??= []).Add(stage);

    internal static List<string> Drain()
    {
        List<string> notes = _notes ?? [];
        _notes = null;
        return notes;
    }
}

internal enum FuzzFindingKind
{
    Exception,
    Hang,
    Allocation,
    Harness,
}

internal sealed record FuzzFinding(FuzzFindingKind Kind, string Target, ulong Seed, string Detail, byte[] Input, bool IsText)
{
    public string Describe()
    {
        StringBuilder text = new();
        text.Append(CultureInfo.InvariantCulture, $"FUZZ FINDING ({Kind}) target={Target} seed={Seed}").AppendLine();
        text.AppendLine(Detail);
        text.AppendLine(Seed == 0
            ? "seed 0 means one of the target's own unmutated corpus inputs (see FuzzCorpus.cs), not a mutated one: it needs no replay."
            : string.Create(CultureInfo.InvariantCulture, $"replay: ZORG_FUZZ_SEED={Seed} ZORG_FUZZ_TARGET=\"{Target}\""));
        text.Append(CultureInfo.InvariantCulture, $"input ({Input.Length} bytes): ").AppendLine(Input.Length <= 4096 ? Convert.ToBase64String(Input) : Convert.ToBase64String(Input.AsSpan(0, 4096)) + "...");
        if (IsText)
        {
            text.Append("as text: \"").Append(FuzzText.Escape(FuzzText.Decode(Input), 2000)).AppendLine("\"");
        }

        return text.ToString();
    }
}

/// <summary>What one run of one target saw.</summary>
internal sealed class FuzzReport(string target)
{
    private const int MaxReasons = 300;

    private readonly Dictionary<string, int> _reasons = new(StringComparer.Ordinal);

    public string Target { get; } = target;

    public List<FuzzFinding> Findings { get; } = [];

    public int Iterations { get; set; }

    public int Accepted { get; set; }

    public int Rejected { get; set; }

    public int Skipped { get; set; }

    public long MaxAllocated { get; set; }

    /// <summary>Gets the largest allocation seen as a multiple of the budget for its input, as a share. 1.0 means right at the limit.</summary>
    public double MaxBudgetShare { get; set; }

    /// <summary>Gets the size of the input that came closest to its allocation budget.</summary>
    public int MaxBudgetShareInput { get; set; }

    public int LargestInput { get; set; }

    public double SlowestMilliseconds { get; set; }

    public TimeSpan Elapsed { get; set; }

    public int DistinctReasons => _reasons.Count;

    /// <summary>Gets how often each stage a target reported was reached, which shows how deep the inputs get.</summary>
    public Dictionary<string, int> Reached { get; } = new(StringComparer.Ordinal);

    public IReadOnlyDictionary<string, int> Reasons => _reasons;

    public double AcceptedShare => Iterations == 0 ? 0 : (double)Accepted / Iterations;

    public void CountReason(string reason)
    {
        if (_reasons.Count >= MaxReasons && !_reasons.ContainsKey(reason))
        {
            reason = "(other)";
        }

        _reasons[reason] = _reasons.GetValueOrDefault(reason) + 1;
    }

    public string Summary() =>
        string.Create(CultureInfo.InvariantCulture, $"{Target}: {Iterations} inputs in {Elapsed.TotalSeconds:F1}s, accepted {AcceptedShare:P1}, refused {Rejected} for {DistinctReasons} different reasons, skipped {Skipped}, reached {Reached.Count} stages, " +
            $"largest input {LargestInput} bytes, most allocated {MaxAllocated} bytes ({MaxBudgetShare:P0} of the budget, for an input of {MaxBudgetShareInput} bytes), slowest {SlowestMilliseconds:F0} ms, findings {Findings.Count}");

    public string Describe()
    {
        StringBuilder text = new();
        text.AppendLine(Summary());
        foreach (FuzzFinding finding in Findings)
        {
            text.AppendLine(finding.Describe());
        }

        return text.ToString();
    }
}

/// <summary>How to run a target: a number of inputs, or until a deadline, or a single seed.</summary>
internal sealed record FuzzRunOptions(ulong RunSeed, int Iterations, TimeSpan? Duration, ulong? ReplaySeed, TimeSpan InputLimit, bool WriteMarker = false, int MaxFindings = 5);

/// <summary>
/// Runs a target over mutated inputs and checks the three things guarantee 3 promises: no exception outside the decoder's
/// documented types, no input that runs past a time limit, and no small input that allocates a lot. Each input comes from one
/// 64-bit seed, so a finding prints a number that rebuilds it.
/// </summary>
internal static class FuzzRunner
{
    /// <summary>Gets the seed of input number <paramref name="index"/> in a run.</summary>
    public static ulong InputSeed(FuzzTarget target, ulong runSeed, long index) => FuzzRandom.Mix(runSeed ^ FuzzRandom.Hash(target.Name), (ulong)index);

    /// <summary>Builds the input for a seed. The seed alone decides it.</summary>
    public static byte[] InputFor(FuzzTarget target, ulong seed) =>
        FuzzMutator.Next(new FuzzRandom(seed), target.Corpus, target.Tokens, target.KnownLengthOffsets);

    public static FuzzReport Run(FuzzTarget target, FuzzRunOptions options)
    {
        FuzzReport report = new(target.Name);
        Stopwatch clock = Stopwatch.StartNew();

        // A hung input can't be interrupted from outside, so the work runs on its own thread and this thread watches the clock.
        Progress progress = new();
        Thread worker = new(() => Loop(target, options, report, progress, clock)) { IsBackground = true, Name = "fuzz " + target.Name };
        worker.Start();
        while (!worker.Join(20))
        {
            long started = Volatile.Read(ref progress.StartedTicks);
            if (started != 0 && Stopwatch.GetElapsedTime(started).TotalMilliseconds > options.InputLimit.TotalMilliseconds)
            {
                byte[] input = Volatile.Read(ref progress.Input) ?? [];
                ulong seed = Volatile.Read(ref progress.Seed);
                lock (report)
                {
                    report.Findings.Add(new FuzzFinding(
                        FuzzFindingKind.Hang,
                        target.Name,
                        seed,
                        $"The input ran for more than {options.InputLimit.TotalSeconds:0.#} s and was abandoned. A hostile peer could hold a connection or a thread for ever with it.",
                        input,
                        IsText(target)));
                }

                progress.Abandoned = true;
                break;
            }
        }

        report.Elapsed = clock.Elapsed;
        return report;
    }

    private static void Loop(FuzzTarget target, FuzzRunOptions options, FuzzReport report, Progress progress, Stopwatch clock)
    {
        FileStream? marker = options.WriteMarker ? OpenMarker(target) : null;
        try
        {
            Warm(target, progress);
            HashSet<string> signatures = [];
            long index = 0;
            while (!progress.Abandoned)
            {
                ulong seed;
                if (options.ReplaySeed is { } replay)
                {
                    if (index > 0)
                    {
                        break;
                    }

                    seed = replay;
                }
                else
                {
                    if (options.Duration is { } span ? clock.Elapsed >= span : index >= options.Iterations)
                    {
                        break;
                    }

                    seed = InputSeed(target, options.RunSeed, index);
                }

                index++;
                Volatile.Write(ref progress.Seed, seed);
                byte[] input = InputFor(target, seed);
                if (marker is not null)
                {
                    marker.Position = 0;
                    marker.Write(BitConverter.GetBytes(seed));
                }

                RunOne(target, options, report, progress, signatures, seed, input);
                if (report.Findings.Count >= options.MaxFindings)
                {
                    break;
                }
            }
        }
        catch (Exception exception)
        {
            // A bug in the harness must show up as a failing test with its seed, not as a crashed test process.
            lock (report)
            {
                report.Findings.Add(new FuzzFinding(FuzzFindingKind.Harness, target.Name, Volatile.Read(ref progress.Seed), "The fuzz harness itself threw, which is a bug in the tests:" + Environment.NewLine + Trim(exception.ToString()), Volatile.Read(ref progress.Input) ?? [], IsText(target)));
            }
        }
        finally
        {
            string? markerPath = marker?.Name;
            marker?.Dispose();
            if (markerPath is not null)
            {
                // Kept only if the process dies in the middle of an input, which is what it is for.
                try
                {
                    File.Delete(markerPath);
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    // A leftover 8 byte file in the temp directory is harmless.
                }
            }
        }
    }

    private static void RunOne(FuzzTarget target, FuzzRunOptions options, FuzzReport report, Progress progress, HashSet<string> signatures, ulong seed, byte[] input)
    {
        Volatile.Write(ref progress.Input, input);
        Volatile.Write(ref progress.Seed, seed);
        Volatile.Write(ref progress.StartedTicks, Stopwatch.GetTimestamp());
        long allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        Stopwatch watch = Stopwatch.StartNew();
        FuzzOutcome outcome = FuzzOutcome.Accepted;
        Exception? thrown = null;
        try
        {
            outcome = target.Execute(input);
        }
        catch (Exception exception)
        {
            thrown = exception;
        }

        watch.Stop();
        long allocated = GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;
        Volatile.Write(ref progress.StartedTicks, 0);
        if (progress.Abandoned)
        {
            return;
        }

        List<string> notes = FuzzNotes.Drain();
        lock (report)
        {
            foreach (string note in notes)
            {
                report.Reached[note] = report.Reached.GetValueOrDefault(note) + 1;
            }

            report.Iterations++;
            report.LargestInput = Math.Max(report.LargestInput, input.Length);
            report.SlowestMilliseconds = Math.Max(report.SlowestMilliseconds, watch.Elapsed.TotalMilliseconds);
            report.MaxAllocated = Math.Max(report.MaxAllocated, allocated);
            long budget = target.AllocationBudget(input.Length);
            if ((double)allocated / budget > report.MaxBudgetShare)
            {
                report.MaxBudgetShare = (double)allocated / budget;
                report.MaxBudgetShareInput = input.Length;
            }

            if (thrown is not null)
            {
                if (target.Allowed.Any(type => type.IsInstanceOfType(thrown)))
                {
                    report.Rejected++;
                    report.CountReason(Reason(thrown));
                }
                else
                {
                    AddFinding(report, options, signatures, FuzzFindingKind.Exception, target, seed, input, $"{thrown.GetType().FullName} is not one of the allowed types ({string.Join(", ", target.Allowed.Select(t => t.Name))}).{Environment.NewLine}{Trim(thrown.ToString())}", Signature(thrown));
                }
            }
            else if (outcome == FuzzOutcome.Accepted)
            {
                report.Accepted++;
            }
            else if (outcome == FuzzOutcome.Skipped)
            {
                report.Skipped++;
            }
            else
            {
                report.Rejected++;
                report.CountReason("(refused without an exception)");
            }

            if (allocated > budget)
            {
                AddFinding(report, options, signatures, FuzzFindingKind.Allocation, target, seed, input, $"The input is {input.Length} bytes and the call allocated {allocated} bytes, over the budget of {budget} bytes. Guarantee 3: a small input must not cost unbounded memory.", "allocation");
            }
        }
    }

    private static void AddFinding(FuzzReport report, FuzzRunOptions options, HashSet<string> signatures, FuzzFindingKind kind, FuzzTarget target, ulong seed, byte[] input, string detail, string signature)
    {
        if (report.Findings.Count < options.MaxFindings && signatures.Add(kind + signature))
        {
            report.Findings.Add(new FuzzFinding(kind, target.Name, seed, detail, input, IsText(target)));
        }
    }

    private static bool IsText(FuzzTarget target) => target.Corpus.Count > 0 && target.Corpus[0].IsText;

    /// <summary>Runs the unmutated corpus once, so JIT work and one-time setup are not counted as allocation by the first real input.</summary>
    private static void Warm(FuzzTarget target, Progress progress)
    {
        foreach (FuzzSeed seed in target.Corpus)
        {
            // The watchdog covers this too: a seed that hangs is a hang, and seed 0 in the message means "the unmutated corpus".
            Volatile.Write(ref progress.Input, seed.Data);
            Volatile.Write(ref progress.Seed, 0);
            Volatile.Write(ref progress.StartedTicks, Stopwatch.GetTimestamp());
            try
            {
                target.Execute(seed.Data);
            }
            catch (Exception)
            {
                // A seed that throws is reported by the corpus tests. Here it only had to run.
            }
            finally
            {
                Volatile.Write(ref progress.StartedTicks, 0);
            }
        }

        FuzzNotes.Drain();
    }

    private static string Signature(Exception exception)
    {
        string frame = (exception.StackTrace ?? string.Empty).Split('\n').FirstOrDefault(line => line.Contains("Zorg.Ssh", StringComparison.Ordinal) && !line.Contains("Zorg.Ssh.Tests", StringComparison.Ordinal))?.Trim() ?? string.Empty;
        return exception.GetType().FullName + "|" + frame;
    }

    private static string Reason(Exception exception)
    {
        string message = exception.Message;
        StringBuilder normalised = new();
        foreach (char c in message)
        {
            if (normalised.Length >= 90)
            {
                break;
            }

            normalised.Append(char.IsAsciiDigit(c) ? '#' : c);
        }

        return exception.GetType().Name + ": " + normalised;
    }

    private static string Trim(string text)
    {
        string[] lines = text.Split('\n');
        return string.Join('\n', lines.Take(18).Select(line => line.TrimEnd('\r')));
    }

    private static FileStream? OpenMarker(FuzzTarget target)
    {
        // For a crash that no handler can see, such as a stack overflow: the seed being run is in this file.
        string path = Path.Combine(Path.GetTempPath(), $"zorg-fuzz-last-seed-{Environment.ProcessId}-{target.Name.Replace(' ', '_').Replace('/', '_')}.bin");
        try
        {
            return new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.ReadWrite, bufferSize: 1);
        }
        catch (IOException)
        {
            return null;
        }
    }

    private sealed class Progress
    {
        public long StartedTicks;
        public byte[]? Input;
        public ulong Seed;
        public volatile bool Abandoned;
    }
}

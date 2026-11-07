using System;
using System.Globalization;

namespace Zorg.Ssh.Tests.Fuzzing;

/// <summary>
/// A small deterministic generator (SplitMix64). <see cref="Random"/> takes a 32-bit seed and its output is a runtime detail,
/// but a fuzz failure has to be replayable from one number on any machine, so the generator is written out here.
/// </summary>
internal sealed class FuzzRandom(ulong seed)
{
    private ulong _state = seed;

    /// <summary>Mixes two numbers into one, so each input of a run gets its own seed.</summary>
    public static ulong Mix(ulong a, ulong b)
    {
        ulong z = a + (b * 0x9E3779B97F4A7C15UL) + 0x9E3779B97F4A7C15UL;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBUL;
        return z ^ (z >> 31);
    }

    /// <summary>A stable hash of a name, so a target's seeds don't depend on how many targets there are.</summary>
    public static ulong Hash(string text)
    {
        ulong hash = 14695981039346656037UL;
        foreach (char c in text)
        {
            hash = (hash ^ c) * 1099511628211UL;
        }

        return hash;
    }

    public ulong NextUInt64()
    {
        _state += 0x9E3779B97F4A7C15UL;
        ulong z = _state;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBUL;
        return z ^ (z >> 31);
    }

    /// <summary>Returns a number in [0, <paramref name="exclusiveMax"/>). A zero or negative bound gives 0.</summary>
    public int Next(int exclusiveMax) => exclusiveMax <= 0 ? 0 : (int)(NextUInt64() % (ulong)exclusiveMax);

    /// <summary>Returns true <paramref name="percent"/> times in 100.</summary>
    public bool Chance(int percent) => Next(100) < percent;

    public T Pick<T>(ReadOnlySpan<T> items) => items[Next(items.Length)];

    public byte NextByte() => (byte)NextUInt64();
}

/// <summary>
/// Reads the environment. <c>ZORG_FUZZ_MINUTES</c> asks for a long run, <c>ZORG_FUZZ_SEED</c> replays one input,
/// <c>ZORG_FUZZ_TARGET</c> limits a run to targets whose name contains the text, and <c>ZORG_FUZZ_INPUT_SECONDS</c>
/// changes the per-input time limit. With none of them set, a run is short and its seeds are fixed.
/// </summary>
internal static class FuzzSettings
{
    /// <summary>The run seed of a normal pass. Fixed, so a normal pass is the same on every machine.</summary>
    public const ulong DefaultRunSeed = 0x5A0A_2026_1107UL;

    public static TimeSpan? LongRun => double.TryParse(Environment.GetEnvironmentVariable("ZORG_FUZZ_MINUTES"), NumberStyles.Float, CultureInfo.InvariantCulture, out double minutes) && minutes > 0
        ? TimeSpan.FromMinutes(minutes)
        : null;

    /// <summary>Gets the seed of the single input to replay, or null.</summary>
    public static ulong? ReplaySeed => ulong.TryParse(Environment.GetEnvironmentVariable("ZORG_FUZZ_SEED"), NumberStyles.None, CultureInfo.InvariantCulture, out ulong seed) ? seed : null;

    public static string? TargetFilter => Environment.GetEnvironmentVariable("ZORG_FUZZ_TARGET") is { Length: > 0 } filter ? filter : null;

    /// <summary>Gets the longest one input may run before it counts as a hang.</summary>
    public static TimeSpan InputLimit => double.TryParse(Environment.GetEnvironmentVariable("ZORG_FUZZ_INPUT_SECONDS"), NumberStyles.Float, CultureInfo.InvariantCulture, out double seconds) && seconds > 0
        ? TimeSpan.FromSeconds(seconds)
        : TimeSpan.FromSeconds(5);

    /// <summary>
    /// Gets the run seed of a long run. It comes from the clock, so that two long runs cover different inputs. The seed
    /// of each input is still printed in full, and that is what replays.
    /// </summary>
    public static ulong LongRunSeed { get; } = (ulong)DateTime.UtcNow.Ticks;
}

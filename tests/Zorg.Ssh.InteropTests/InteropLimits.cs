using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using Xunit;
using Xunit.v3;

[assembly: Zorg.Ssh.InteropTests.InteropClassDeadline]

namespace Zorg.Ssh.InteropTests;

/// <summary>
/// The overall time limits of the interop tests. These tests wait on containers, on Podman's published ports and on
/// peers that may misbehave, and every step in them has its own timeout. These limits are the backstop under those, so
/// that a peer which hangs, or a step that has no timeout, fails the test instead of hanging the run.
/// </summary>
/// <remarks>
/// Two bounds. A test has <see cref="TestMilliseconds"/>: xunit fails it when the time is up, whatever it is waiting on,
/// and cancels <c>TestContext.Current.CancellationToken</c>. A test class has <see cref="Class"/>: the first test that
/// starts after that much time since the class began fails at once, so a class takes at most
/// <see cref="Class"/> plus one test's limit. <see cref="InteropFactAttribute"/> and <see cref="InteropTheoryAttribute"/>
/// carry the first, <see cref="InteropClassDeadlineAttribute"/> enforces the second, and
/// <c>InteropLimitsTests</c> fails if a test is declared without them.
/// </remarks>
internal static class InteropLimits
{
    /// <summary>The most one test may take. The slowest test measured takes well under a minute on this machine, and the Podman stalls the tests work around last tens of seconds.</summary>
    public const int TestMilliseconds = 5 * 60 * 1000;

    /// <summary>The most one test class may run before its remaining tests are failed.</summary>
    public static readonly TimeSpan Class = TimeSpan.FromMinutes(20);
}

/// <summary>A <see cref="FactAttribute"/> with the interop time limit.</summary>
[AttributeUsage(AttributeTargets.Method)]
public sealed class InteropFactAttribute : FactAttribute
{
    public InteropFactAttribute([CallerFilePath] string? sourceFilePath = null, [CallerLineNumber] int sourceLineNumber = -1)
        : base(sourceFilePath, sourceLineNumber) => Timeout = InteropLimits.TestMilliseconds;
}

/// <summary>A <see cref="TheoryAttribute"/> with the interop time limit.</summary>
[AttributeUsage(AttributeTargets.Method)]
public sealed class InteropTheoryAttribute : TheoryAttribute
{
    public InteropTheoryAttribute([CallerFilePath] string? sourceFilePath = null, [CallerLineNumber] int sourceLineNumber = -1)
        : base(sourceFilePath, sourceLineNumber) => Timeout = InteropLimits.TestMilliseconds;
}

/// <summary>Fails a test that starts after its class has already used up <see cref="InteropLimits.Class"/>.</summary>
[AttributeUsage(AttributeTargets.Assembly)]
public sealed class InteropClassDeadlineAttribute : BeforeAfterTestAttribute
{
    private static readonly ConcurrentDictionary<Type, long> Started = new();

    internal static TimeSpan Limit { get; set; } = InteropLimits.Class;

    public override void Before(MethodInfo methodUnderTest, IXunitTest test)
    {
        Type type = methodUnderTest.DeclaringType!;
        long start = Started.GetOrAdd(type, static _ => Stopwatch.GetTimestamp());
        TimeSpan used = Stopwatch.GetElapsedTime(start);
        if (used > Limit)
        {
            throw new TimeoutException(
                $"{type.Name} has run for {used.TotalMinutes:F1} minutes, over its limit of {Limit.TotalMinutes:F0}. "
                + "This test was not run. Something in the class is slow or hung: look at the tests before this one.");
        }
    }
}

public class InteropLimitsTests
{
    [InteropFact]
    public void Every_interop_test_has_a_time_limit()
    {
        MethodInfo[] methods =
        [
            .. typeof(InteropLimitsTests).Assembly.GetTypes()
                .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
                .Where(m => m.GetCustomAttributes<FactAttribute>().Any()),
        ];

        Assert.True(methods.Length > 100, $"Only {methods.Length} tests found.");
        string[] unbounded =
        [
            .. methods
                .Where(m => m.GetCustomAttributes<FactAttribute>().Any(a => a.Timeout <= 0 || a.Timeout > InteropLimits.TestMilliseconds))
                .Select(m => $"{m.DeclaringType!.Name}.{m.Name}"),
        ];
        Assert.True(unbounded.Length == 0, "These tests have no time limit, or one over " + InteropLimits.TestMilliseconds + " ms: " + string.Join(", ", unbounded)
            + ". Use [InteropFact] or [InteropTheory].");

        Assert.Contains(typeof(InteropLimitsTests).Assembly.GetCustomAttributes<InteropClassDeadlineAttribute>(), _ => true);
    }
}

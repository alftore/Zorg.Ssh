using System;
using System.Runtime.InteropServices;
using Xunit;

namespace Zorg.Ssh.Tests;

/// <summary>
/// The library targets net10.0, but an app on a newer .NET runs it on that runtime. CI runs this suite again with
/// DOTNET_ROLL_FORWARD=LatestMajor and sets ZORG_EXPECT_DOTNET_MAJOR, so a job that quietly fell back to the older
/// runtime fails here instead of passing on the wrong one.
/// </summary>
public sealed class RuntimeVersionTests
{
    [Fact]
    public void The_suite_runs_on_the_expected_runtime()
    {
        string? expected = Environment.GetEnvironmentVariable("ZORG_EXPECT_DOTNET_MAJOR");
        if (string.IsNullOrEmpty(expected))
        {
            return;
        }

        Assert.True(int.TryParse(expected, out int major), $"ZORG_EXPECT_DOTNET_MAJOR isn't a number: {expected}");
        Assert.True(
            Environment.Version.Major == major,
            $"Expected .NET {major}, but the suite runs on {RuntimeInformation.FrameworkDescription}.");
    }
}

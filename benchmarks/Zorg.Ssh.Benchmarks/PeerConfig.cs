using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Engines;
using BenchmarkDotNet.Environments;
using BenchmarkDotNet.Jobs;

namespace Zorg.Ssh.Benchmarks;

/// <summary>
/// Settings for the benchmarks that talk to the container. One operation takes milliseconds to seconds and the noise
/// is in the network, so this uses the Monitoring strategy: fixed iterations, no pilot, no overhead subtraction.
/// </summary>
public class PeerConfig : ManualConfig
{
    /// <summary>The project BenchmarkDotNet generates inherits the repo's rules, which its code doesn't meet.</summary>
    internal static readonly Argument[] GeneratedProject =
    [
        new MsBuildArgument("/p:TreatWarningsAsErrors=false"),
        new MsBuildArgument("/p:MSBuildTreatWarningsAsErrors=false"),
        new MsBuildArgument("/p:RunAnalyzers=false"),
        new MsBuildArgument("/p:EnforceCodeStyleInBuild=false"),
    ];

    public PeerConfig()
        : this(warmupCount: 3, iterationCount: 15)
    {
    }

    protected PeerConfig(int warmupCount, int iterationCount)
    {
        AddJob(Job.Default
            .WithStrategy(RunStrategy.Monitoring)
            .WithLaunchCount(1)
            .WithWarmupCount(warmupCount)
            .WithIterationCount(iterationCount)
            .WithPowerPlan(PowerPlan.UserPowerPlan)
            .WithArguments(GeneratedProject));
        AddDiagnoser(MemoryDiagnoser.Default);
        AddLogicalGroupRules(BenchmarkLogicalGroupRule.ByCategory, BenchmarkLogicalGroupRule.ByParams);
    }
}

/// <summary>Fewer iterations for the large transfers, which take seconds each.</summary>
public sealed class TransferConfig : PeerConfig
{
    public TransferConfig()
        : base(warmupCount: 2, iterationCount: 8)
    {
    }
}

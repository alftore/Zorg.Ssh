using BenchmarkDotNet.Running;
using Zorg.Ssh.Benchmarks;

if (args is ["--ceiling"])
{
    await TcpCeiling.RunAsync();
    return;
}

if (args is ["--phases"])
{
    await ConnectPhases.RunAsync();
    return;
}

BenchmarkSwitcher.FromAssembly(typeof(CipherBenchmarks).Assembly).Run(args);

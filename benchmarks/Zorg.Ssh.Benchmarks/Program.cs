using System;
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

if (args is ["--sftp-server", ..])
{
    await SftpServerSmallFiles.RunAsync(args);
    return;
}

if (args is ["--soak", ..])
{
    Environment.ExitCode = await Soak.RunAsync(args);
    return;
}

BenchmarkSwitcher.FromAssembly(typeof(CipherBenchmarks).Assembly).Run(args);

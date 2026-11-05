using System;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using Tmds.Ssh;
using SshNetClient = Renci.SshNet.SshClient;
using SshNetCommand = Renci.SshNet.SshCommand;
using TmdsClient = Tmds.Ssh.SshClient;

namespace Zorg.Ssh.Benchmarks;

/// <summary>One command on a connection that's already open: open a channel, run, read the output, close.</summary>
[Config(typeof(PeerConfig))]
public class ExecBenchmarks
{
    private const int Commands = 20;
    private const string Command = "echo ok";

    private Peer _peer = null!;
    private SshClient? _zorg;
    private SshNetClient? _sshNet;
    private TmdsClient? _tmds;

    [GlobalSetup(Target = nameof(Zorg))]
    public async Task SetupZorg()
    {
        _peer = await Peer.StartAsync();
        _zorg = await SshClient.ConnectAsync(_peer.ZorgOptions());
        Check((await _zorg.ExecuteAsync(Command)).StandardOutput);
    }

    [GlobalSetup(Target = nameof(SshNet))]
    public async Task SetupSshNet()
    {
        _peer = await Peer.StartAsync();
        _sshNet = _peer.SshNetClient();
        await _sshNet.ConnectAsync(default);
        Check(_sshNet.RunCommand(Command).Result);
    }

    [GlobalSetup(Target = nameof(Tmds))]
    public async Task SetupTmds()
    {
        _peer = await Peer.StartAsync();
        _tmds = _peer.TmdsClient();
        await _tmds.ConnectAsync();
        using RemoteProcess process = await _tmds.ExecuteAsync(Command);
        (string output, _) = await process.ReadToEndAsStringAsync();
        Check(output);
    }

    [GlobalCleanup]
    public async Task Cleanup()
    {
        if (_zorg is not null)
        {
            await _zorg.DisposeAsync();
        }

        _sshNet?.Dispose();
        _tmds?.Dispose();
        await _peer.DisposeAsync();
    }

    [Benchmark(Baseline = true, OperationsPerInvoke = Commands)]
    public async Task<int> Zorg()
    {
        int total = 0;
        for (int i = 0; i < Commands; i++)
        {
            SshCommandResult result = await _zorg!.ExecuteAsync(Command);
            total += result.StandardOutput.Length;
        }

        return total;
    }

    [Benchmark(OperationsPerInvoke = Commands)]
    public async Task<int> SshNet()
    {
        int total = 0;
        for (int i = 0; i < Commands; i++)
        {
            using SshNetCommand command = _sshNet!.CreateCommand(Command);
            await command.ExecuteAsync();
            total += command.Result.Length;
        }

        return total;
    }

    [Benchmark(OperationsPerInvoke = Commands)]
    public async Task<int> Tmds()
    {
        int total = 0;
        for (int i = 0; i < Commands; i++)
        {
            using RemoteProcess process = await _tmds!.ExecuteAsync(Command);
            (string output, _) = await process.ReadToEndAsStringAsync();
            total += output.Length;
        }

        return total;
    }

    private static void Check(string output)
    {
        if (output != "ok\n")
        {
            throw new InvalidOperationException($"Expected the command's output, got '{output}'.");
        }
    }
}

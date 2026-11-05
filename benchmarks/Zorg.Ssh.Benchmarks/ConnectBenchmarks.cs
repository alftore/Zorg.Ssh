using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using SshNetClient = Renci.SshNet.SshClient;
using TmdsClient = Tmds.Ssh.SshClient;

namespace Zorg.Ssh.Benchmarks;

/// <summary>
/// A whole login: TCP connect, version exchange, key exchange, password login, then disconnect, because every
/// connection has to be closed to keep the server's process count flat. The server's forked process is part of it.
/// </summary>
[Config(typeof(PeerConfig))]
public class ConnectBenchmarks
{
    private const int Logins = 5;

    private Peer _peer = null!;

    [Params("curve25519-sha256", "mlkem768x25519-sha256")]
    public string Kex { get; set; } = Peer.DefaultKex;

    [GlobalSetup]
    public async Task Setup() => _peer = await Peer.StartAsync(kex: Kex);

    [GlobalCleanup]
    public async Task Cleanup() => await _peer.DisposeAsync();

    [Benchmark(Baseline = true, OperationsPerInvoke = Logins)]
    public async Task Zorg()
    {
        for (int i = 0; i < Logins; i++)
        {
            await using SshClient client = await SshClient.ConnectAsync(_peer.ZorgOptions());
        }
    }

    [Benchmark(OperationsPerInvoke = Logins)]
    public async Task SshNet()
    {
        for (int i = 0; i < Logins; i++)
        {
            using SshNetClient client = _peer.SshNetClient();
            await client.ConnectAsync(default);
        }
    }

    [Benchmark(OperationsPerInvoke = Logins)]
    public async Task Tmds()
    {
        for (int i = 0; i < Logins; i++)
        {
            using TmdsClient client = _peer.TmdsClient();
            await client.ConnectAsync();
        }
    }
}

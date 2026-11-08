using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Tests.Transport;

namespace Zorg.Ssh.Tests.Server;

/// <summary>
/// Guarantee 3: finite-field Diffie-Hellman costs a server two modular exponentiations before anyone has logged in,
/// so a server bounds how many run at once, across every connection and address. Elliptic-curve exchanges and
/// rekeys after login are not bounded.
/// </summary>
public sealed class PreAuthDiffieHellmanBoundTests : IDisposable
{
    private static readonly SshAlgorithms DhOnly = SshAlgorithms.LegacyUnsafe with { KeyExchange = ["diffie-hellman-group14-sha256"] };

    private readonly SshHostKey _hostKey = SshHostKey.GenerateEd25519();
    private readonly ManualResetEventSlim _release = new();
    private int _entered;
    private int _active;
    private int _maxActive;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose()
    {
        _release.Set();
        _release.Dispose();
        _hostKey.Dispose();
    }

    private SshServer NewServer(int concurrency, SshAlgorithms algorithms, bool block = true, TimeSpan? grace = null) => SshServer.Create(new SshServerOptions
    {
        HostKeys = [_hostKey],
        PasswordHandler = static (_, _) => ValueTask.FromResult(SshAuthDecision.Accept),
        SessionHandler = static (_, _) => Task.FromResult(0),
        Algorithms = algorithms,
        LoginGraceTime = grace ?? TimeSpan.FromSeconds(30),
        PreAuthCostlyKexConcurrency = concurrency,
        CostlyKexComputing = () =>
        {
            Interlocked.Increment(ref _entered);
            int now = Interlocked.Increment(ref _active);
            int seen;
            while (now > (seen = Volatile.Read(ref _maxActive)) && Interlocked.CompareExchange(ref _maxActive, now, seen) != seen)
            {
            }

            if (block)
            {
                _release.Wait(TimeSpan.FromSeconds(60));
            }

            Interlocked.Decrement(ref _active);
        },
    });

    private SshClientOptions ClientOptions(SshAlgorithms algorithms) => new()
    {
        Host = "in-memory",
        UserName = "alice",
        Credentials = [SshCredential.FromPassword("pw")],
        HostKeyPolicy = HostKeyPolicy.Fingerprint(_hostKey.Sha256Fingerprint),
        Algorithms = algorithms,
    };

    private Task<SshClient> ConnectAsync(SshServer server, SshAlgorithms algorithms)
    {
        (Stream clientSide, Stream serverSide) = DuplexStream.CreatePair();
        _ = server.ServeStreamAsync(serverSide, Ct);
        return SshClient.ConnectOverStreamAsync(clientSide, ClientOptions(algorithms), Ct);
    }

    private async Task WaitForAsync(Func<bool> condition)
    {
        DateTime end = DateTime.UtcNow.AddSeconds(20);
        while (!condition())
        {
            Assert.True(DateTime.UtcNow < end, "Timed out waiting.");
            await Task.Delay(10, Ct);
        }
    }

    [Fact]
    public async Task Only_as_many_computations_run_at_once_as_the_bound_allows_and_the_rest_wait_then_finish()
    {
        await using SshServer server = NewServer(concurrency: 2, DhOnly);
        Task<SshClient>[] connects = [.. Enumerable.Range(0, 6).Select(_ => ConnectAsync(server, DhOnly))];

        await WaitForAsync(() => Volatile.Read(ref _entered) >= 2);
        // Give the other four every chance to get in.
        await Task.Delay(500, Ct);
        Assert.Equal(2, Volatile.Read(ref _entered));
        Assert.All(connects, c => Assert.False(c.IsCompleted));

        _release.Set();
        SshClient[] clients = await Task.WhenAll(connects).WaitAsync(TimeSpan.FromSeconds(60), Ct);
        foreach (SshClient client in clients)
        {
            Assert.Equal(0, (await client.ExecuteAsync("x", Ct)).ExitCode);
            await client.DisposeAsync();
        }

        Assert.Equal(6, Volatile.Read(ref _entered));
        Assert.Equal(2, Volatile.Read(ref _maxActive));
    }

    [Fact]
    public async Task A_connection_still_waiting_when_its_login_grace_time_ends_fails_with_an_SshException()
    {
        await using SshServer server = NewServer(concurrency: 1, DhOnly, grace: TimeSpan.FromSeconds(2));
        Task<SshClient> holder = ConnectAsync(server, DhOnly);
        await WaitForAsync(() => Volatile.Read(ref _entered) == 1);

        Task<SshClient> waiting = ConnectAsync(server, DhOnly);
        SshException ex = await Assert.ThrowsAnyAsync<SshException>(() => waiting).WaitAsync(TimeSpan.FromSeconds(30), Ct);

        // It never got a slot, so it never did the work.
        Assert.Equal(1, Volatile.Read(ref _entered));
        Assert.NotNull(ex);

        // The one holding the slot is still blocked; letting go lets it end, and its slot comes back.
        _release.Set();
        await Assert.ThrowsAnyAsync<SshException>(() => holder).WaitAsync(TimeSpan.FromSeconds(30), Ct);
    }

    [Fact]
    public async Task A_slot_is_given_back_when_the_computation_ends_so_the_next_connection_gets_it()
    {
        await using SshServer server = NewServer(concurrency: 1, DhOnly, block: false);
        for (int i = 0; i < 3; i++)
        {
            await using SshClient client = await ConnectAsync(server, DhOnly).WaitAsync(TimeSpan.FromSeconds(30), Ct);
            Assert.Equal(0, (await client.ExecuteAsync("x", Ct)).ExitCode);
        }

        Assert.Equal(3, Volatile.Read(ref _entered));
        Assert.Equal(1, Volatile.Read(ref _maxActive));
    }

    [Fact]
    public async Task Elliptic_curve_exchanges_are_not_held_back_by_a_full_bound()
    {
        // A client on the default list negotiates curve25519, which never takes a slot, while Diffie-Hellman holds the only one.
        SshAlgorithms modern = SshAlgorithms.Default;
        await using SshServer both = NewServer(concurrency: 1, SshAlgorithms.LegacyUnsafe with { KeyExchange = ["diffie-hellman-group14-sha256", "curve25519-sha256"] });
        Task<SshClient> stuck = ConnectAsync(both, DhOnly);
        await WaitForAsync(() => Volatile.Read(ref _entered) >= 1);

        // Another client of the same server that offers only curve25519 gets straight through.
        await using SshClient client = await ConnectAsync(both, modern).WaitAsync(TimeSpan.FromSeconds(30), Ct);
        Assert.Equal(0, (await client.ExecuteAsync("x", Ct)).ExitCode);
        Assert.Equal(1, Volatile.Read(ref _entered));

        _release.Set();
        await (await stuck.WaitAsync(TimeSpan.FromSeconds(30), Ct)).DisposeAsync();
    }

    [Fact]
    public async Task A_rekey_after_login_does_not_take_a_slot()
    {
        await using SshServer server = NewServer(concurrency: 1, DhOnly, block: false);
        await using SshClient client = await ConnectAsync(server, DhOnly).WaitAsync(TimeSpan.FromSeconds(30), Ct);
        Assert.Equal(1, Volatile.Read(ref _entered));
        int before = client.CompletedKeyExchanges;

        client.RequestRekey();
        Assert.Equal(0, (await client.ExecuteAsync("x", Ct)).ExitCode);
        await WaitForAsync(() => client.CompletedKeyExchanges > before);

        // The exchange ran on the server again, but not through the bound.
        Assert.Equal(1, Volatile.Read(ref _entered));
    }
}

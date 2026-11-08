using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Zorg.Ssh.Tests.Server;

/// <summary>The server's accept loop when accepting fails.</summary>
public sealed class AcceptLoopTests : IDisposable
{
    private readonly SshHostKey _hostKey = SshHostKey.GenerateEd25519();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => _hostKey.Dispose();

    // C4: an accept that failed at once on every call, as when the process is out of file descriptors, was retried
    // straight away, so the loop spun a core until the failure cleared.
    [Fact]
    public async Task A_lasting_accept_failure_is_retried_with_a_growing_delay()
    {
        int attempts = 0;
        SshServer server = await SshServer.StartAsync(
            new SshServerOptions
            {
                Address = IPAddress.Loopback,
                HostKeys = [_hostKey],
                PasswordHandler = static (_, _) => ValueTask.FromResult(SshAuthDecision.Reject),
                SessionHandler = static (_, _) => Task.FromResult(0),
                AcceptOverride = _ =>
                {
                    Interlocked.Increment(ref attempts);
                    return ValueTask.FromException<Socket>(new SocketException((int)SocketError.TooManyOpenSockets));
                },
            },
            Ct);

        try
        {
            // 10, 20, 40, 80, 160 and 320 ms: about seven attempts in the first 650 ms, where a spin makes many thousands.
            await Task.Delay(TimeSpan.FromMilliseconds(650), Ct);
            Assert.InRange(Volatile.Read(ref attempts), 2, 20);
        }
        finally
        {
            // The delay is cancelled with the server, so stopping doesn't wait it out.
            Stopwatch stopping = Stopwatch.StartNew();
            await server.DisposeAsync();
            Assert.True(stopping.Elapsed < TimeSpan.FromSeconds(5), $"Stopping took {stopping.Elapsed}.");
        }
    }

    [Fact]
    public void The_accept_retry_delay_doubles_up_to_a_second()
    {
        Assert.Equal(TimeSpan.FromMilliseconds(10), SshServer.AcceptRetryDelay(1));
        Assert.Equal(TimeSpan.FromMilliseconds(20), SshServer.AcceptRetryDelay(2));
        Assert.Equal(TimeSpan.FromMilliseconds(640), SshServer.AcceptRetryDelay(7));
        Assert.Equal(TimeSpan.FromSeconds(1), SshServer.AcceptRetryDelay(8));
        Assert.Equal(TimeSpan.FromSeconds(1), SshServer.AcceptRetryDelay(int.MaxValue));
    }
}

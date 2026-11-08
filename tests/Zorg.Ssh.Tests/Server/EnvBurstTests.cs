using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Tests.Transport;

namespace Zorg.Ssh.Tests.Server;

/// <summary>A client's burst of requests before its command starts, against the real server.</summary>
public sealed class EnvBurstTests : IDisposable
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(20);

    private readonly SshHostKey _hostKey = SshHostKey.GenerateEd25519();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => _hostKey.Dispose();

    // C2: the client sends pty-req, every env and exec without waiting for a reply. The server's request loop starts on
    // another task, so the whole burst can arrive first, and a queue of 16 disconnected the client now and then.
    [Fact]
    public async Task A_burst_of_env_requests_before_exec_starts_the_session()
    {
        const int Variables = 60;
        Dictionary<string, string> environment = new(StringComparer.Ordinal);
        for (int i = 0; i < Variables; i++)
        {
            environment[$"LC_VAR{i}"] = "en_GB.UTF-8";
        }

        await using SshServer server = SshServer.Create(new SshServerOptions
        {
            HostKeys = [_hostKey],
            PasswordHandler = static (_, _) => ValueTask.FromResult(SshAuthDecision.Accept),
            SessionHandler = static (session, _) => Task.FromResult(session.Environment.Count),
        });

        for (int round = 0; round < 10; round++)
        {
            (Stream clientSide, Stream serverSide) = DuplexStream.CreatePair();
            Task serving = server.ServeStreamAsync(serverSide, Ct);
            await using (SshClient client = await SshClient.ConnectOverStreamAsync(clientSide, new SshClientOptions
            {
                Host = "in-memory",
                UserName = "alice",
                Credentials = [SshCredential.FromPassword("pw")],
                HostKeyPolicy = HostKeyPolicy.Fingerprint(_hostKey.Sha256Fingerprint),
            }, Ct))
            {
                SshProcessOptions options = new()
                {
                    Environment = environment,
                    Pty = new SshPtyOptions { Terminal = "xterm" },
                };
                await using SshProcess process = await client.StartProcessAsync("x", options, Ct).WaitAsync(Limit, Ct);
                await process.WaitForExitAsync(Ct).WaitAsync(Limit, Ct);
                Assert.Equal(Variables, process.ExitCode);
            }

            try
            {
                await serving.WaitAsync(Limit, Ct);
            }
            catch (SshException)
            {
                // The client closed, which is how this connection ends.
            }
        }
    }
}

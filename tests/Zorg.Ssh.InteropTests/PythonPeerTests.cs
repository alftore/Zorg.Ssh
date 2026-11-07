using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Zorg.Ssh.InteropTests;

/// <summary>Two independent SSH stacks, neither sharing code with OpenSSH.</summary>
public class PythonPeerTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [InteropTheory]
    [InlineData("server_asyncssh.py", "asyncssh ")]
    [InlineData("server_paramiko.py", "paramiko ")]
    public async Task Login_and_exec_work_against_python_servers(string script, string expectedOutput)
    {
        PeerTools.RequireContainers();
        string image = await SshPeerContainer.BuildImageAsync("zorg-ssh-test/python-ssh", Path.Combine(PeerTools.PeersPath, "python-ssh"), Ct);
        await using SshPeerContainer container = await SshPeerContainer.StartAsync(image, ["python", "-u", $"/app/{script}"], cancellationToken: Ct);
        await using SshClient client = await SshClient.ConnectAsync(
            new SshClientOptions
            {
                Host = container.Host,
                Port = container.Port,
                UserName = "zorg",
                Credentials = [SshCredential.FromPassword("zorg-test")],
                HostKeyPolicy = HostKeyPolicy.AcceptAnyUnsafe(),
            },
            Ct);

        SshCommandResult result = await client.ExecuteAsync("anything", Ct);
        Assert.StartsWith(expectedOutput, result.StandardOutput);
        Assert.Equal(0, result.ExitCode);
    }
}

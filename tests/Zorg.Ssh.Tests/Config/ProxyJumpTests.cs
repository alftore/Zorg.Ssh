using System.IO;
using Xunit;

namespace Zorg.Ssh.Tests.Config;

public sealed class ProxyJumpTests
{
    private static SshConfig Write(string text)
    {
        string path = Path.GetTempFileName();
        File.WriteAllText(path, text);
        try
        {
            return SshConfig.Load(path);
        }
        finally
        {
            File.Delete(path);
        }
    }

    // A host that must go through a bastion must never quietly connect straight to the target.
    [Fact]
    public void A_host_with_ProxyJump_is_refused_rather_than_connected_directly()
    {
        SshConfig config = Write("Host web\n  HostName 10.0.0.5\n  ProxyJump bastion\n");
        SshConfigException ex = Assert.Throws<SshConfigException>(
            () => SshClientOptions.FromConfig("web", config, HostKeyPolicy.AcceptAnyUnsafe()));
        Assert.Contains("ProxyJump", ex.Message);
    }

    [Fact]
    public void ProxyJump_none_is_a_direct_connection()
    {
        SshConfig config = Write("Host web\n  HostName 10.0.0.5\n  User alice\n  ProxyJump none\n");
        Assert.Equal("10.0.0.5", SshClientOptions.FromConfig("web", config, HostKeyPolicy.AcceptAnyUnsafe()).Host);
    }
}

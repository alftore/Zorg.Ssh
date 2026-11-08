using System;
using System.IO;
using Xunit;
using Zorg.Ssh.Tests.Crypto;

namespace Zorg.Ssh.Tests.Config;

/// <summary>A6: with no home directory, '~/' must fail, not turn into a path relative to the working directory.</summary>
public sealed class EmptyHomeTests : IDisposable
{
    private readonly TempDirectory _directory = new();

    public void Dispose() => _directory.Dispose();

    [Theory]
    [InlineData("~/.ssh/known_hosts")]
    [InlineData("~\\.ssh\\id_ed25519")]
    public void A6_ExpandHome_throws_without_a_home_directory(string path)
    {
        NotSupportedException ex = Assert.Throws<NotSupportedException>(() => SshCredential.ExpandHome(path, string.Empty));
        Assert.Contains("home directory", ex.Message);
    }

    [Fact]
    public void A6_ExpandHome_keeps_working_with_a_home_and_for_other_paths()
    {
        Assert.Equal(Path.Combine(_directory.Path, ".ssh/known_hosts"), SshCredential.ExpandHome("~/.ssh/known_hosts", _directory.Path));
        Assert.Equal("/etc/ssh/known_hosts", SshCredential.ExpandHome("/etc/ssh/known_hosts", string.Empty));
        Assert.Equal("relative/known_hosts", SshCredential.ExpandHome("relative/known_hosts", string.Empty));
    }

    [Fact]
    public void A6_a_config_without_a_home_refuses_the_default_files_and_tilde_paths()
    {
        SshConfig config = SshConfig.Parse("Host web\n  HostName web.example.com\n", string.Empty, null);
        Assert.Throws<SshConfigException>(() => config.Resolve("web"));
        Assert.Throws<SshConfigException>(() => SshConfig.Load(null, string.Empty, null));
        SshConfig tilde = SshConfig.Parse("Host web\n  UserKnownHostsFile ~/.ssh/kh\n  IdentityFile ~/.ssh/id\n", string.Empty, null);
        Assert.Throws<SshConfigException>(() => tilde.Resolve("web"));
    }

    [Fact]
    public void A6_a_config_without_a_home_still_works_with_absolute_paths()
    {
        string known = Path.Combine(_directory.Path, "known_hosts");
        string identity = Path.Combine(_directory.Path, "id");
        SshConfig config = SshConfig.Parse($"Host web\n  UserKnownHostsFile \"{known}\"\n  IdentityFile \"{identity}\"\n", string.Empty, null);
        SshHostConfig host = config.Resolve("web");
        Assert.Equal([known], host.UserKnownHostsFiles);
        Assert.Equal([identity], host.IdentityFiles);
    }
}

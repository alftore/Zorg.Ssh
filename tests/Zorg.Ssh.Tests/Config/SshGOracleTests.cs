using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Xunit;
using Zorg.Ssh.Tests.Crypto;

namespace Zorg.Ssh.Tests.Config;

/// <summary>
/// Real <c>ssh -G</c> as the oracle: it reads the same file and prints what it decided. Only literal paths are compared,
/// as it prints <c>IdentityFile</c> tokens and tildes unexpanded.
/// </summary>
public sealed class SshGOracleTests : IDisposable
{
    private const string Config = """
        # A file that uses the awkward parts of the syntax.
        Host FOO
          User upper
        Host foo Bar
          HostName %h.example.com
          User first
          User second
          Port=2222
          IdentityFile "/keys/with space"
          IdentityFile /keys/plain # a comment
          IdentityFile /keys/plain
          UserKnownHostsFile /kh/one /kh/two
          UserKnownHostsFile /kh/three
          StrictHostKeyChecking accept-new
          IdentitiesOnly=yes
        Host bar
          User = 'q u'#c
          Port 33
        Host neg* !negative
          User positive
        Host odd
          User a#b
          HostName x\ y
          StrictHostKeyChecking off
        Host pct
          User %h
          HostName 10.0.0.1
          ProxyJump j1
          StrictHostKeyChecking no
          IdentitiesOnly no
        Host Mixed
          HostName MiXeD.Example.com
        Host wild?.example.com *.test
          Port 4444
        Match host matched
          User from-match
        Host *
          User fallback
          Port 2020
        """;

    private readonly TempDirectory _directory = new();

    public void Dispose() => _directory.Dispose();

    private static Dictionary<string, List<string>> RunSshG(string file, string alias)
    {
        (int exitCode, string output) = OpenSshTools.Run(OpenSshTools.Require("ssh"), ["-G", "-F", file, alias]);
        Assert.True(exitCode == 0, output);
        Dictionary<string, List<string>> values = [];
        foreach (string line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            string[] pair = line.TrimEnd('\r').Split(' ', 2);
            if (!values.TryGetValue(pair[0], out List<string>? list))
            {
                values[pair[0]] = list = [];
            }

            list.Add(pair.Length > 1 ? pair[1] : string.Empty);
        }

        return values;
    }

    [Theory]
    [InlineData("foo")]
    [InlineData("Bar")]
    [InlineData("FOO")]
    [InlineData("bar")]
    [InlineData("negate")]
    [InlineData("negative")]
    [InlineData("odd")]
    [InlineData("pct")]
    [InlineData("wild1.example.com")]
    [InlineData("a.test")]
    [InlineData("unmatched")]
    [InlineData("matched-not")]
    [InlineData("Mixed")]
    public void The_parser_agrees_with_ssh(string alias)
    {
        string file = Path.Combine(_directory.Path, "config");
        File.WriteAllText(file, Config.Replace("\r\n", "\n", StringComparison.Ordinal));

        Dictionary<string, List<string>> ssh = RunSshG(file, alias);
        SshHostConfig mine = SshConfig.Load(file, _directory.Path, null).Resolve(alias);

        Assert.Equal(ssh["hostname"].Single(), mine.HostName);
        Assert.Equal(ssh["port"].Single(), mine.Port.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Assert.Equal(ssh["user"].Single(), mine.User);
        Assert.Equal(ssh["identitiesonly"].Single() == "yes", mine.IdentitiesOnly);
        Assert.Equal(
            ssh["stricthostkeychecking"].Single() switch
            {
                "false" or "no" => SshStrictHostKeyChecking.No,
                "accept-new" => SshStrictHostKeyChecking.AcceptNew,
                _ => SshStrictHostKeyChecking.Yes,
            },
            mine.StrictHostKeyChecking);
        Assert.Equal(ssh.TryGetValue("proxyjump", out List<string>? jump) ? jump.Single() : null, mine.ProxyJump);

        if (ssh["identityfile"].All(f => f.StartsWith("/keys", StringComparison.Ordinal)))
        {
            Assert.Equal(ssh["identityfile"], mine.IdentityFiles);
        }

        string knownHosts = ssh["userknownhostsfile"].Single();
        if (knownHosts.StartsWith("/kh", StringComparison.Ordinal))
        {
            Assert.Equal(knownHosts, string.Join(' ', mine.UserKnownHostsFiles));
        }
    }

    [Fact]
    public void Include_agrees_with_ssh()
    {
        string extra = Path.Combine(_directory.Path, "extra.conf");
        File.WriteAllText(extra, "Port 1234\nHost other\n User inner\n");

        // Git for Windows' ssh is an MSYS program, so it needs the path in its own form to see it as absolute.
        string posix = extra.Replace('\\', '/');
        if (OperatingSystem.IsWindows())
        {
            posix = "/" + char.ToLowerInvariant(posix[0]) + posix[2..];
        }

        string sshFile = Path.Combine(_directory.Path, "config-ssh");
        string file = Path.Combine(_directory.Path, "config");
        File.WriteAllText(sshFile, $"Host web\n Include \"{posix}\"\n User after\n");
        File.WriteAllText(file, $"Host web\n Include \"{extra.Replace('\\', '/')}\"\n User after\n");

        foreach (string alias in new[] { "web", "other" })
        {
            Dictionary<string, List<string>> ssh = RunSshG(sshFile, alias);
            SshHostConfig mine = SshConfig.Load(file, _directory.Path, null).Resolve(alias);
            Assert.Equal(ssh["port"].Single(), mine.Port.ToString(System.Globalization.CultureInfo.InvariantCulture));
            Assert.Equal(ssh["user"].Single(), mine.User);
        }
    }
}

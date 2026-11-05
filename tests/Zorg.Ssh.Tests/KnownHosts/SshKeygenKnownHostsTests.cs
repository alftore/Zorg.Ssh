using System;
using System.IO;
using Xunit;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.KnownHosts;
using Zorg.Ssh.Tests.Crypto;

namespace Zorg.Ssh.Tests.KnownHosts;

/// <summary>
/// Real <c>ssh-keygen</c> on both sides: it hashes files for this code to read, finds lines this code wrote, and acts
/// as the oracle for what a pattern matches. A missing tool skips locally and fails in CI.
/// </summary>
public class SshKeygenKnownHostsTests
{
    private static readonly SshPublicKey Key = NewKey();

    // ssh-keygen -F takes the lookup name as ssh forms it, so a port goes in the bracket form.
    public static TheoryData<string, string, int> PatternCases => new()
    {
        { "example.com", "example.com", 22 },
        { "example.com", "example.org", 22 },
        { "Example.COM", "example.com", 22 },
        { "a.example,b.example", "b.example", 22 },
        { "a.example,b.example", "c.example", 22 },
        { "*.example.com", "a.b.example.com", 22 },
        { "*.example.com", "example.com", 22 },
        { "*.EXAMPLE.com", "a.example.com", 22 },
        { "host?.example", "host1.example", 22 },
        { "host?.example", "host12.example", 22 },
        { "host?.example", "host.example", 22 },
        { "*", "anything.example", 22 },
        { "*", "anything.example", 2222 },
        { "a*b*c", "axxbyyc", 22 },
        { "a*b*c", "axxbyy", 22 },
        { "**", "anything", 22 },
        { "?*", "x", 22 },
        { "*.example.com,!bad.example.com", "good.example.com", 22 },
        { "*.example.com,!bad.example.com", "bad.example.com", 22 },
        { "!bad.example.com,*.example.com", "bad.example.com", 22 },
        { "!bad.example.com", "good.example.com", 22 },
        { "!*.bad.example,*.example", "x.bad.example", 22 },
        { "[example.com]:2222", "example.com", 2222 },
        { "[example.com]:2222", "example.com", 22 },
        { "[example.com]:2222", "example.com", 2223 },
        { "example.com", "example.com", 2222 },
        { "[example.com]:22", "example.com", 22 },
        { "[*.example.com]:2222", "a.example.com", 2222 },
        { "[example.com]:*", "example.com", 2222 },
        { "[example.com]:22?2", "example.com", 2222 },
        { "::1", "::1", 22 },
        { "[::1]:2222", "::1", 2222 },
        { "a,,b", "b", 22 },
        { "192.0.2.*", "192.0.2.7", 22 },
    };

    [Theory]
    [MemberData(nameof(PatternCases))]
    public void Patterns_match_exactly_what_ssh_keygen_matches(string patterns, string host, int port)
    {
        string keygen = OpenSshTools.Require("ssh-keygen");
        using TempDirectory directory = new();
        string path = Path.Combine(directory.Path, "known_hosts");
        string text = $"{patterns} {Key.KeyType} {Convert.ToBase64String(Key.Blob.Span)}\n";
        File.WriteAllText(path, text);

        string name = port == 22 ? host : $"[{host}]:{port}";
        (int exitCode, string output) = OpenSshTools.Run(keygen, ["-F", name, "-f", path]);
        bool foundByOpenSsh = exitCode == 0 && output.Contains(Key.KeyType, StringComparison.Ordinal);

        KnownHostStatus status = KnownHostsFile.Parse(text).Lookup(host, port, Key);
        Assert.Equal(foundByOpenSsh ? KnownHostStatus.Trusted : KnownHostStatus.Unknown, status);
    }

    [Fact]
    public void Files_hashed_by_ssh_keygen_are_read()
    {
        string keygen = OpenSshTools.Require("ssh-keygen");
        using TempDirectory directory = new();
        string path = Path.Combine(directory.Path, "known_hosts");
        string blob = Convert.ToBase64String(Key.Blob.Span);
        File.WriteAllText(path, $"a.example,192.0.2.1 {Key.KeyType} {blob}\n[b.example]:2222 {Key.KeyType} {blob}\n");

        (int exitCode, string output) = OpenSshTools.Run(keygen, ["-H", "-f", path]);
        Assert.True(exitCode == 0, output);

        string hashed = File.ReadAllText(path);
        Assert.DoesNotContain("example", hashed, StringComparison.Ordinal);
        Assert.StartsWith("|1|", hashed, StringComparison.Ordinal);

        KnownHostsFile file = KnownHostsFile.Parse(hashed);
        Assert.Equal(3, file.Entries.Count); // ssh-keygen writes one line for each name in a list.
        Assert.All(file.Entries, static entry => Assert.True(entry.IsHashed));
        Assert.Equal(KnownHostStatus.Trusted, file.Lookup("a.example", 22, Key));
        Assert.Equal(KnownHostStatus.Trusted, file.Lookup("192.0.2.1", 22, Key));
        Assert.Equal(KnownHostStatus.Trusted, file.Lookup("b.example", 2222, Key));
        Assert.Equal(KnownHostStatus.Unknown, file.Lookup("b.example", 22, Key));
        Assert.Equal(KnownHostStatus.Unknown, file.Lookup("c.example", 22, Key));
    }

    [Theory]
    [InlineData("example.com", 22, "example.com")]
    [InlineData("example.com", 2222, "[example.com]:2222")]
    [InlineData("192.0.2.1", 22, "192.0.2.1")]
    [InlineData("::1", 2222, "[::1]:2222")]
    public void Ssh_keygen_finds_hashed_lines_written_here(string host, int port, string lookupName)
    {
        string keygen = OpenSshTools.Require("ssh-keygen");
        using TempDirectory directory = new();
        string path = Path.Combine(directory.Path, "known_hosts");
        KnownHostsFile.Append(path, host, port, Key);

        (int exitCode, string output) = OpenSshTools.Run(keygen, ["-F", lookupName, "-f", path]);
        Assert.True(exitCode == 0, output);
        Assert.Contains(Convert.ToBase64String(Key.Blob.Span), output, StringComparison.Ordinal);

        (exitCode, _) = OpenSshTools.Run(keygen, ["-F", "not-" + lookupName.TrimStart('['), "-f", path]);
        Assert.NotEqual(0, exitCode);
    }

    [Fact]
    public void Ssh_keygen_finds_plain_lines_written_here()
    {
        string keygen = OpenSshTools.Require("ssh-keygen");
        using TempDirectory directory = new();
        string path = Path.Combine(directory.Path, "known_hosts");
        KnownHostsFile.Append(path, "example.com", 2222, Key, hashed: false);

        (int exitCode, string output) = OpenSshTools.Run(keygen, ["-F", "[example.com]:2222", "-f", path]);
        Assert.True(exitCode == 0, output);
    }

    // A hashed lookup on the ssh-keygen side, against the same file this code reads.
    [Fact]
    public void Ssh_keygen_and_this_code_agree_on_a_markers_file()
    {
        string keygen = OpenSshTools.Require("ssh-keygen");
        using TempDirectory directory = new();
        string path = Path.Combine(directory.Path, "known_hosts");
        string blob = Convert.ToBase64String(Key.Blob.Span);
        string text = $"@revoked revoked.example {Key.KeyType} {blob}\n@cert-authority ca.example {Key.KeyType} {blob}\n";
        File.WriteAllText(path, text);

        (int exitCode, string output) = OpenSshTools.Run(keygen, ["-F", "revoked.example", "-f", path]);
        Assert.True(exitCode == 0, output);
        Assert.Contains("@revoked", output, StringComparison.Ordinal);

        (exitCode, output) = OpenSshTools.Run(keygen, ["-F", "ca.example", "-f", path]);
        Assert.True(exitCode == 0, output);
        Assert.Contains("@cert-authority", output, StringComparison.Ordinal);

        KnownHostsFile file = KnownHostsFile.Parse(text);
        Assert.Equal(KnownHostStatus.Revoked, file.Lookup("revoked.example", 22, Key));
        Assert.Equal(KnownHostStatus.Unknown, file.Lookup("ca.example", 22, Key));
    }

    private static SshPublicKey NewKey()
    {
        using SshPrivateKey key = SshPrivateKey.GenerateEd25519();
        return key.PublicKey;
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Tests.Crypto;

namespace Zorg.Ssh.Tests.Config;

/// <summary>
/// M5 review T2 to T5 and K9: what <see cref="SshClientOptions.FromConfig"/> does with settings that decide trust. The
/// rule is that anything it can't honour fails closed with a <see cref="SshConfigException"/> that says what to do.
/// </summary>
public sealed class ConfigTrustTests : IDisposable
{
    private static readonly SshPublicKey Key = NewKey();

    private readonly TempDirectory _directory = new();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static string NullDevice => OperatingSystem.IsWindows() ? "NUL" : "/dev/null";

    public void Dispose() => _directory.Dispose();

    private SshConfig Config(string text) => SshConfig.Parse(text, _directory.Path, null);

    private string KnownHostsPath(string name = "known_hosts") => Path.Combine(_directory.Path, name);

    private static SshPublicKey NewKey()
    {
        using SshPrivateKey key = SshPrivateKey.GenerateEd25519();
        return key.PublicKey;
    }

    private static string Line(string marker, string host, SshPublicKey key) =>
        $"{marker} {host} {key.KeyType} {Convert.ToBase64String(key.Blob.Span)}\n".TrimStart();

    private static SshConfigException Refused(Func<SshClientOptions> act) => Assert.Throws<SshConfigException>(act);

    // T2

    [Fact]
    public void T2_accept_new_with_a_null_device_known_hosts_file_is_refused()
    {
        SshConfig config = Config($"Host *\n  StrictHostKeyChecking accept-new\n  UserKnownHostsFile {NullDevice}\n");

        SshConfigException ex = Refused(() => SshClientOptions.FromConfig("web", config));
        Assert.Contains("accept-new", ex.Message);
        Assert.Contains("isn't a regular file", ex.Message);
    }

    [Fact]
    public void T2_accept_new_with_a_directory_as_known_hosts_file_is_refused()
    {
        SshConfig config = Config($"StrictHostKeyChecking accept-new\nUserKnownHostsFile {_directory.Path}\n");

        Assert.Contains("isn't a regular file", Refused(() => SshClientOptions.FromConfig("web", config)).Message);
    }

    [Fact]
    public void T2_accept_new_with_a_file_that_does_not_exist_yet_is_fine()
    {
        SshConfig config = Config($"StrictHostKeyChecking accept-new\nUserKnownHostsFile {KnownHostsPath()}\n");

        Assert.NotNull(SshClientOptions.FromConfig("web", config, acceptNewHostKeysUnsafe: true).HostKeyPolicy);
    }

    [Fact]
    public void Accept_new_needs_the_callers_opt_in()
    {
        SshConfig config = Config($"StrictHostKeyChecking accept-new\nUserKnownHostsFile {KnownHostsPath()}\n");

        SshConfigException ex = Refused(() => SshClientOptions.FromConfig("web", config));
        Assert.Contains("accept-new", ex.Message, StringComparison.Ordinal);
        Assert.Contains("acceptNewHostKeysUnsafe: true", ex.Message, StringComparison.Ordinal);

        // A policy of the caller's own replaces what the config says, so it needs no opt-in.
        Assert.NotNull(SshClientOptions.FromConfig("web", config, HostKeyPolicy.KnownHostsFile(KnownHostsPath())));
    }

    [Fact]
    public async Task Accept_new_with_the_opt_in_records_a_new_host_and_strict_checking_never_does()
    {
        string path = KnownHostsPath("tofu");
        SshConfig tofu = Config($"StrictHostKeyChecking accept-new\nUserKnownHostsFile {path}\n");
        Assert.True(await SshClientOptions.FromConfig("web", tofu, acceptNewHostKeysUnsafe: true).HostKeyPolicy.CheckAsync("web", 22, Key, Ct));
        Assert.Single(await File.ReadAllLinesAsync(path, Ct));

        string strictPath = KnownHostsPath("strict");
        SshConfig strict = Config($"StrictHostKeyChecking yes\nUserKnownHostsFile {strictPath}\n");
        HostKeyPolicy policy = SshClientOptions.FromConfig("web", strict, acceptNewHostKeysUnsafe: true).HostKeyPolicy;
        await Assert.ThrowsAsync<SshHostKeyException>(async () => await policy.CheckAsync("web", 22, Key, Ct));
        Assert.False(File.Exists(strictPath));
    }

    [Fact]
    public void T2_a_null_device_with_strict_checking_is_fine_because_nothing_is_recorded()
    {
        SshConfig config = Config($"StrictHostKeyChecking yes\nUserKnownHostsFile {NullDevice}\n");

        Assert.NotNull(SshClientOptions.FromConfig("web", config).HostKeyPolicy);
    }

    // The same policy built by hand: the device takes the write and keeps nothing, so nothing is trusted.
    [Fact]
    public async Task T2_a_policy_that_records_into_a_null_device_refuses_the_key()
    {
        HostKeyPolicy policy = HostKeyPolicy.KnownHostsFileAcceptNewUnsafe(NullDevice);

        await Assert.ThrowsAsync<SshHostKeyException>(async () => await policy.CheckAsync("web", 22, Key, Ct));
    }

    // T3

    [Fact]
    public void T3_a_match_block_that_tightens_host_key_checking_is_refused()
    {
        SshConfig config = Config("Match host prod\n  StrictHostKeyChecking yes\n  UserKnownHostsFile ~/.ssh/prod_hosts\nHost *\n  StrictHostKeyChecking accept-new\n");

        SshConfigException ex = Refused(() => SshClientOptions.FromConfig("prod", config));
        Assert.Contains("Match", ex.Message);
        Assert.Contains("StrictHostKeyChecking", ex.Message);
        Assert.Contains("UserKnownHostsFile", ex.Message);
        Assert.Contains("isn't supported", ex.Message);
    }

    [Fact]
    public void T3_a_match_block_inside_an_included_file_counts_too()
    {
        File.WriteAllText(KnownHostsPath("more.conf"), "ProxyJump bastion\n");
        SshConfig config = Config($"Match all\n  Include {KnownHostsPath("more.conf").Replace('\\', '/')}\n");

        Assert.Contains("ProxyJump", Refused(() => SshClientOptions.FromConfig("web", config)).Message);
    }

    [Fact]
    public void T3_other_keywords_in_a_match_block_are_still_ignored_with_a_note()
    {
        SshConfig config = Config("Match host web\n  ForwardAgent yes\n  User nobody\n");

        Assert.NotNull(SshClientOptions.FromConfig("web", config).HostKeyPolicy);
    }

    [Fact]
    public void T3_a_match_block_under_a_host_block_that_does_not_apply_does_not_matter()
    {
        // Include conditions carry over to what the included file sets, and here they don't match this alias.
        File.WriteAllText(KnownHostsPath("inner.conf"), "Match all\n  StrictHostKeyChecking yes\n");
        SshConfig config = Config($"Host other\n  Include {KnownHostsPath("inner.conf").Replace('\\', '/')}\n");

        Assert.NotNull(SshClientOptions.FromConfig("web", config).HostKeyPolicy);
    }

    // T4

    [Fact]
    public void T4_ProxyCommand_is_refused_like_ProxyJump()
    {
        SshConfig config = Config("Host web\n  HostName web.internal\n  ProxyCommand ssh -W %h:%p bastion\n");

        SshConfigException ex = Refused(() => SshClientOptions.FromConfig("web", config));
        Assert.Contains("ProxyCommand", ex.Message);
    }

    [Fact]
    public void T4_ProxyCommand_none_is_a_direct_connection()
    {
        SshConfig config = Config("ProxyCommand none\n");

        Assert.NotNull(SshClientOptions.FromConfig("web", config).HostKeyPolicy);
    }

    // T5

    [Theory]
    [InlineData("RevokedHostKeys /etc/ssh/revoked", "RevokedHostKeys")]
    [InlineData("KnownHostsCommand /usr/bin/lookup %H", "KnownHostsCommand")]
    [InlineData("HostKeyAlias other.example", "HostKeyAlias")]
    public void T5_keywords_that_change_who_is_trusted_are_refused(string line, string keyword)
    {
        SshConfig config = Config($"Host web\n  {line}\n");

        Assert.Contains(keyword, Refused(() => SshClientOptions.FromConfig("web", config)).Message);

        // With the caller's own policy the config's known_hosts keywords play no part.
        Assert.NotNull(SshClientOptions.FromConfig("web", config, HostKeyPolicy.Fingerprint("SHA256:x")));
    }

    [Fact]
    public void T5_KnownHostsCommand_none_is_fine()
    {
        Assert.NotNull(SshClientOptions.FromConfig("web", Config("KnownHostsCommand none\n")).HostKeyPolicy);
    }

    [Fact]
    public void T5_the_global_known_hosts_files_default_as_in_OpenSSH()
    {
        SshHostConfig host = Config(string.Empty).Resolve("web");

        string[] expected = OperatingSystem.IsWindows()
            ? [Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ssh", "ssh_known_hosts")]
            : ["/etc/ssh/ssh_known_hosts", "/etc/ssh/ssh_known_hosts2"];
        Assert.Equal(expected, host.GlobalKnownHostsFiles);
        Assert.Empty(Config("GlobalKnownHostsFile none\n").Resolve("web").GlobalKnownHostsFiles);
    }

    [Fact]
    public async Task T5_a_revoked_line_in_the_global_known_hosts_file_beats_the_users_trusted_line()
    {
        string user = KnownHostsPath("user");
        string global = KnownHostsPath("global");
        await File.WriteAllTextAsync(user, Line(string.Empty, "web", Key), Ct);
        await File.WriteAllTextAsync(global, Line("@revoked", "*", Key), Ct);
        SshConfig config = Config($"UserKnownHostsFile {user.Replace('\\', '/')}\nGlobalKnownHostsFile {global.Replace('\\', '/')}\n");

        SshClientOptions options = SshClientOptions.FromConfig("web", config);

        SshHostKeyException ex = await Assert.ThrowsAsync<SshHostKeyException>(async () => await options.HostKeyPolicy.CheckAsync("web", 22, Key, Ct));
        Assert.Contains("revoked", ex.Message);
    }

    [Fact]
    public async Task T5_the_KnownHostsFile_policy_takes_global_files_and_records_only_in_its_own()
    {
        string user = KnownHostsPath("user");
        string global = KnownHostsPath("global");
        await File.WriteAllTextAsync(global, Line(string.Empty, "other", NewKey()), Ct);
        HostKeyPolicy policy = HostKeyPolicy.KnownHostsFileAcceptNewUnsafe(user, globalPaths: [global]);
        string before = await File.ReadAllTextAsync(global, Ct);

        Assert.True(await policy.CheckAsync("web", 22, Key, Ct));

        Assert.Equal(before, await File.ReadAllTextAsync(global, Ct));
        Assert.Contains("ssh-ed25519", await File.ReadAllTextAsync(user, Ct), StringComparison.Ordinal);

        // And a key trusted only in the global file is trusted.
        await File.WriteAllTextAsync(global, Line(string.Empty, "web2", Key), Ct);
        Assert.True(await HostKeyPolicy.KnownHostsFile(KnownHostsPath("none"), globalPaths: [global]).CheckAsync("web2", 22, Key, Ct));
    }

    [Fact]
    public void T5_keywords_that_are_not_honoured_are_warned_about_by_name()
    {
        RecordingLogger logger = new();
        using ILoggerFactory factory = new RecordingFactory(logger);
        SshConfig config = Config("IdentityAgent /run/agent.sock\nCertificateFile /k/c.pub\nHostKeyAlgorithms ssh-ed25519\nCASignatureAlgorithms ssh-ed25519\n");

        SshClientOptions.FromConfig("web", config, loggerFactory: factory);

        foreach (string keyword in new[] { "IdentityAgent", "CertificateFile", "HostKeyAlgorithms", "CASignatureAlgorithms" })
        {
            Assert.Contains(logger.Messages, m => m.Contains(keyword, StringComparison.Ordinal));
        }
    }

    [Fact]
    public void T5_IdentityAgent_none_means_no_agent()
    {
        Assert.DoesNotContain(SshClientOptions.FromConfig("web", Config("IdentityAgent none\n")).Credentials, c => c is AgentCredential);
        Assert.Contains(SshClientOptions.FromConfig("web", Config(string.Empty)).Credentials, c => c is AgentCredential);
    }

    // K9

    [Fact]
    public void K9_ServerAliveInterval_zero_turns_keepalive_off()
    {
        SshClientOptions options = SshClientOptions.FromConfig("web", Config("ServerAliveInterval 0\n"));

        Assert.Equal(TimeSpan.Zero, options.KeepAliveInterval);
    }

    [Fact]
    public void K9_keepalive_and_timeout_settings_are_mapped()
    {
        SshClientOptions options = SshClientOptions.FromConfig("web", Config("ServerAliveInterval 15\nServerAliveCountMax 5\nConnectTimeout 12\n"));

        Assert.Equal(TimeSpan.FromSeconds(15), options.KeepAliveInterval);
        Assert.Equal(5, options.KeepAliveCountMax);
        Assert.Equal(TimeSpan.FromSeconds(12), options.ConnectTimeout);
    }

    [Fact]
    public void K9_library_defaults_stay_when_the_config_is_silent_and_for_ConnectTimeout_zero()
    {
        SshClientOptions options = SshClientOptions.FromConfig("web", Config("ConnectTimeout 0\n"));
        SshClientOptions plain = SshClientOptions.FromConfig("web", Config(string.Empty));

        Assert.Equal(TimeSpan.FromMinutes(5), plain.KeepAliveInterval);
        Assert.Equal(3, plain.KeepAliveCountMax);
        Assert.Equal(TimeSpan.FromSeconds(30), plain.ConnectTimeout);
        Assert.Equal(TimeSpan.FromSeconds(30), options.ConnectTimeout);
    }

    [Theory]
    [InlineData("ServerAliveInterval soon")]
    [InlineData("ServerAliveInterval -1")]
    [InlineData("ServerAliveInterval 90000")]
    [InlineData("ServerAliveCountMax 0")]
    [InlineData("ServerAliveCountMax 5000")]
    [InlineData("ConnectTimeout 1m")]
    public void K9_a_bad_value_is_a_config_error(string line)
    {
        SshConfigException ex = Assert.Throws<SshConfigException>(() => Config(line + "\n"));
        Assert.Contains("line 1", ex.Message);
    }

    private sealed class RecordingFactory(RecordingLogger logger) : ILoggerFactory
    {
        public void AddProvider(ILoggerProvider provider)
        {
        }

        public ILogger CreateLogger(string categoryName) => logger;

        public void Dispose()
        {
        }
    }

    private sealed class RecordingLogger : ILogger
    {
        public List<string> Messages { get; } = [];

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => NullLogger.Instance.BeginScope(state);

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Messages.Add(formatter(state, exception));
    }
}

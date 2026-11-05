using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Zorg.Ssh.Tests.Crypto;

namespace Zorg.Ssh.Tests.Config;

/// <summary>The config parser, with a made-up home directory so the real one plays no part.</summary>
public sealed class SshConfigTests : IDisposable
{
    private readonly TempDirectory _directory = new();

    private string Home => _directory.Path;

    public void Dispose() => _directory.Dispose();

    private SshHostConfig Resolve(string text, string alias, ILogger? logger = null) =>
        SshConfig.Parse(text, Home, logger).Resolve(alias);

    private string Write(string relative, string text)
    {
        string path = Path.Combine(Home, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, text);
        return path;
    }

    [Fact]
    public void An_empty_config_gives_the_defaults()
    {
        SshHostConfig host = Resolve(string.Empty, "web");
        Assert.Equal("web", host.HostName);
        Assert.Equal(22, host.Port);
        Assert.Equal(Environment.UserName, host.User);
        Assert.False(host.IdentitiesOnly);
        Assert.Equal(SshStrictHostKeyChecking.Yes, host.StrictHostKeyChecking);
        Assert.Equal(Path.Combine(Home, ".ssh", "known_hosts"), host.UserKnownHostsFiles[0]);
        Assert.Contains(Path.Combine(Home, ".ssh", "id_ed25519"), host.IdentityFiles);
        Assert.Null(host.ProxyJump);
    }

    [Fact]
    public void The_first_value_wins()
    {
        SshHostConfig host = Resolve("Host web\n Port 1\nHost *\n Port 2\n User u\nHost web\n User v\n", "web");
        Assert.Equal(1, host.Port);
        Assert.Equal("u", host.User);
    }

    [Fact]
    public void Identity_files_add_up_without_repeats()
    {
        SshHostConfig host = Resolve("IdentityFile /a\nIdentityFile /b\nIdentityFile /a\n", "web");
        Assert.Equal(["/a", "/b"], host.IdentityFiles);
    }

    [Fact]
    public void Identity_none_means_no_defaults()
    {
        Assert.Empty(Resolve("IdentityFile none\n", "web").IdentityFiles);
    }

    [Theory]
    [InlineData("web", "web", true)]
    [InlineData("WEB", "web", false)]
    [InlineData("*.example.com", "a.example.com", true)]
    [InlineData("web?", "web1", true)]
    [InlineData("web?", "web", false)]
    [InlineData("a b web", "web", true)]
    [InlineData("* !web", "web", false)]
    [InlineData("!web *", "web", false)]
    [InlineData("* !web", "other", true)]
    [InlineData("!web", "other", false)]
    public void Host_patterns(string patterns, string alias, bool matches)
    {
        Assert.Equal(matches, Resolve($"Host {patterns}\n Port 9\n", alias).Port == 9);
    }

    [Theory]
    [InlineData("Port=33")]
    [InlineData("Port = 33")]
    [InlineData("Port\t33")]
    [InlineData("  port   33  ")]
    [InlineData("PORT 33 # a comment")]
    [InlineData("\"Port\" 33")]
    [InlineData("Port \"33\"")]
    public void Separators_and_case_do_not_matter(string line)
    {
        Assert.Equal(33, Resolve(line + "\r\n", "web").Port);
    }

    [Theory]
    [InlineData("IdentityFile \"/a b\"", "/a b")]
    [InlineData("IdentityFile '/a b'", "/a b")]
    [InlineData(@"IdentityFile /a\ b", "/a b")]
    [InlineData(@"IdentityFile C:\keys\id", @"C:\keys\id")]
    [InlineData("IdentityFile /a#b", "/a#b")]
    [InlineData("IdentityFile \"/a#b\" # note", "/a#b")]
    public void Quoting(string line, string expected)
    {
        Assert.Equal([expected], Resolve(line + "\n", "web").IdentityFiles);
    }

    [Fact]
    public void Comments_and_blank_lines_are_skipped()
    {
        Assert.Equal(5, Resolve("# Port 4\n\n   \n  # Host x\nPort 5\n", "web").Port);
    }

    [Fact]
    public void A_byte_order_mark_is_skipped()
    {
        Assert.Equal(5, Resolve("\uFEFFPort 5\n", "web").Port);
    }

    [Fact]
    public void Unknown_keywords_are_ignored_even_when_malformed()
    {
        Assert.Equal(5, Resolve("ForwardAgent yes\nSomeFutureThing \"unclosed\nPort 5\n", "web").Port);
    }

    [Fact]
    public void Tokens_expand()
    {
        SshHostConfig host = Resolve(
            "Host web\n HostName %h.example.com\n User alice\n Port 2200\n IdentityFile /k/%h-%p-%r-%u-%%\n UserKnownHostsFile %d/kh\n",
            "web");
        Assert.Equal("web.example.com", host.HostName);
        Assert.Equal([$"/k/web.example.com-2200-alice-{Environment.UserName}-%"], host.IdentityFiles);
        Assert.Equal([Path.Combine(Home, "kh").Replace('\\', Path.DirectorySeparatorChar)], host.UserKnownHostsFiles.Select(p => p.Replace('/', Path.DirectorySeparatorChar)));
    }

    // ssh 10.6 expands this and older versions don't, so the ssh -G oracle can't cover it on every machine.
    [Fact]
    public void Tokens_expand_in_the_user_as_in_recent_ssh()
    {
        Assert.Equal("web", Resolve("User %h\n", "web").User);
    }

    [Fact]
    public void Tilde_means_the_home_directory()
    {
        SshHostConfig host = Resolve("IdentityFile ~/id\nUserKnownHostsFile ~/kh\n", "web");
        Assert.Equal([Path.Combine(Home, "id")], host.IdentityFiles);
        Assert.Equal([Path.Combine(Home, "kh")], host.UserKnownHostsFiles);
    }

    [Theory]
    [InlineData("IdentityFile /k/%C")]
    [InlineData("IdentityFile /k/%")]
    [InlineData("HostName %p.example.com")]
    public void An_unsupported_token_is_an_error_not_a_wrong_value(string line)
    {
        Assert.Throws<SshConfigException>(() => Resolve(line + "\n", "web"));
    }

    [Fact]
    public void Known_hosts_take_several_values_from_the_first_line_only()
    {
        Assert.Equal(["/a", "/b"], Resolve("UserKnownHostsFile /a /b\nUserKnownHostsFile /c\n", "web").UserKnownHostsFiles);
        Assert.Empty(Resolve("UserKnownHostsFile none\n", "web").UserKnownHostsFiles);
    }

    [Theory]
    [InlineData("yes", SshStrictHostKeyChecking.Yes)]
    [InlineData("true", SshStrictHostKeyChecking.Yes)]
    [InlineData("ask", SshStrictHostKeyChecking.Yes)]
    [InlineData("accept-new", SshStrictHostKeyChecking.AcceptNew)]
    [InlineData("no", SshStrictHostKeyChecking.No)]
    [InlineData("off", SshStrictHostKeyChecking.No)]
    [InlineData("false", SshStrictHostKeyChecking.No)]
    public void Strict_host_key_checking_values(string value, SshStrictHostKeyChecking expected)
    {
        Assert.Equal(expected, Resolve($"StrictHostKeyChecking {value}\n", "web").StrictHostKeyChecking);
    }

    [Theory]
    [InlineData("Port")]
    [InlineData("Port 0")]
    [InlineData("Port 65536")]
    [InlineData("Port abc")]
    [InlineData("Port -1")]
    [InlineData("Port 22 23")]
    [InlineData("Port 99999999999999999999")]
    [InlineData("User \"unclosed")]
    [InlineData("User \"\"")]
    [InlineData("IdentitiesOnly maybe")]
    [InlineData("StrictHostKeyChecking perhaps")]
    [InlineData("Host")]
    public void A_bad_value_for_a_known_keyword_says_where(string line)
    {
        SshConfigException failure = Assert.Throws<SshConfigException>(() => SshConfig.Parse($"# first\n{line}\n", Home, null));
        Assert.Contains("line 2", failure.Message);
    }

    [Fact]
    public void A_match_block_is_skipped_whole_and_noted()
    {
        RecordingLogger logger = new();
        SshHostConfig host = Resolve("Match host web\n Port 1\n User nobody\n Include /nonexistent\nHost web\n Port 2\n", "web", logger);
        Assert.Equal(2, host.Port);
        Assert.NotEqual("nobody", host.User);
        Assert.Contains(logger.Messages, m => m.Contains("Match", StringComparison.Ordinal) && m.Contains("line 1", StringComparison.Ordinal));
    }

    [Fact]
    public void A_bad_value_in_a_match_block_does_not_matter()
    {
        Assert.Equal(22, Resolve("Match all\n Port nonsense\n", "web").Port);
    }

    [Fact]
    public void Include_reads_relative_to_dot_ssh_and_in_place()
    {
        Write(".ssh/extra", "Port 7\n");
        Assert.Equal(7, Resolve("Include extra\nPort 8\n", "web").Port);
        Assert.Equal(8, Resolve("Port 8\nInclude extra\n", "web").Port);
    }

    [Fact]
    public void Include_under_a_host_applies_only_to_that_host()
    {
        Write(".ssh/extra", "Port 7\n");
        const string Text = "Host web\n Include extra\nHost *\n User u\n";
        Assert.Equal(7, Resolve(Text, "web").Port);
        Assert.Equal(22, Resolve(Text, "db").Port);
    }

    [Fact]
    public void A_host_line_in_an_include_does_not_leak_out()
    {
        Write(".ssh/extra", "Host other\n Port 7\n");
        const string Text = "Host web\n Include extra\n User u\n";
        Assert.Equal("u", Resolve(Text, "web").User);
        Assert.Equal(22, Resolve(Text, "other").Port); // The enclosing Host web still applies inside the file.
    }

    [Fact]
    public void Include_globs_sort_by_name()
    {
        Write(".ssh/conf.d/b.conf", "Port 2\n");
        Write(".ssh/conf.d/a.conf", "Port 1\n");
        Write(".ssh/conf.d/c.txt", "Port 3\n");
        Assert.Equal(1, Resolve("Include conf.d/*.conf\n", "web").Port);
    }

    [Fact]
    public void An_include_that_finds_nothing_is_fine()
    {
        Assert.Equal(22, Resolve("Include missing\nInclude nothing/*\n", "web").Port);
    }

    [Fact]
    public void A_file_that_includes_itself_stops_at_the_depth_cap()
    {
        string path = Write(".ssh/loop", "Include loop\n");
        SshConfigException failure = Assert.Throws<SshConfigException>(() => SshConfig.Load(path, Home, null));
        Assert.Contains("nested", failure.Message);
    }

    [Fact]
    public void Fan_out_stops_at_the_file_cap()
    {
        // Two includes per level would be 2^16 reads without a limit on files.
        for (int i = 0; i < 16; i++)
        {
            Write($".ssh/level{i}", $"Include level{i + 1}\nInclude level{i + 1}\n");
        }

        Write(".ssh/level16", "Port 1\n");
        string path = Path.Combine(Home, ".ssh", "level0");
        SshConfigException failure = Assert.Throws<SshConfigException>(() => SshConfig.Load(path, Home, null));
        Assert.Contains("limit", failure.Message);
    }

    [Fact]
    public void A_file_over_the_size_cap_is_refused()
    {
        string path = Write("big", new string('#', SshConfig.MaxFileLength + 1));
        Assert.Contains("over the limit", Assert.Throws<SshConfigException>(() => SshConfig.Load(path, Home, null)).Message);
        Assert.Throws<SshConfigException>(() => SshConfig.Parse(new string('#', SshConfig.MaxFileLength + 1), Home, null));
    }

    [Fact]
    public void A_line_over_the_limit_is_refused()
    {
        Assert.Throws<SshConfigException>(() => SshConfig.Parse(new string('#', 100_000), Home, null));
    }

    [Fact]
    public void A_pattern_built_to_be_slow_still_finishes()
    {
        string pattern = string.Concat(Enumerable.Repeat("*a", 2000)) + "b";
        Assert.Equal(22, Resolve($"Host {pattern}\n Port 9\n", new string('a', 2000)).Port);
    }

    [Fact]
    public void A_named_file_must_exist_but_the_default_need_not()
    {
        Assert.Throws<SshConfigException>(() => SshConfig.Load(Path.Combine(Home, "missing"), Home, null));
        Assert.Equal("web", SshConfig.Load(null, Home, null).Resolve("web").HostName);
    }

    [Fact]
    public void Options_come_from_the_config()
    {
        string key = Write("id_test", "not read until login");
        SshConfig config = SshConfig.Parse($"Host web\n HostName web.example.com\n Port 2222\n User alice\n IdentityFile {key}\n IdentityFile /missing/key\n IdentitiesOnly yes\n", Home, null);

        SshClientOptions options = SshClientOptions.FromConfig("web", config);

        Assert.Equal("web.example.com", options.Host);
        Assert.Equal(2222, options.Port);
        Assert.Equal("alice", options.UserName);
        Assert.IsType<PrivateKeyCredential>(Assert.Single(options.Credentials));
        Assert.IsType<KnownHostsPolicy>(options.HostKeyPolicy);
    }

    [Fact]
    public void The_agent_comes_first_unless_identities_only_is_set()
    {
        SshClientOptions options = SshClientOptions.FromConfig("web", SshConfig.Parse("IdentityFile none\n", Home, null));
        Assert.True(Assert.IsType<AgentCredential>(Assert.Single(options.Credentials)).IsOptional);
    }

    [Fact]
    public void Extra_credentials_go_last()
    {
        SshCredential extra = SshCredential.FromPassword("p");
        SshClientOptions options = SshClientOptions.FromConfig("web", SshConfig.Parse("IdentityFile none\nIdentitiesOnly yes\n", Home, null), credentials: [extra]);
        Assert.Same(extra, Assert.Single(options.Credentials));
    }

    // The point of the rule: a config file alone must never turn off host key checking.
    [Theory]
    [InlineData("no")]
    [InlineData("off")]
    [InlineData("false")]
    public void Strict_checking_off_in_a_file_is_refused(string value)
    {
        SshConfig config = SshConfig.Parse($"StrictHostKeyChecking {value}\n", Home, null);
        SshConfigException failure = Assert.Throws<SshConfigException>(() => SshClientOptions.FromConfig("web", config));
        Assert.Contains("AcceptAnyUnsafe", failure.Message);
    }

    [Fact]
    public void Strict_checking_off_works_only_with_the_callers_policy()
    {
        HostKeyPolicy policy = HostKeyPolicy.AcceptAnyUnsafe();
        SshConfig config = SshConfig.Parse("StrictHostKeyChecking no\n", Home, null);
        Assert.Same(policy, SshClientOptions.FromConfig("web", config, policy).HostKeyPolicy);
    }

    [Fact]
    public void A_policy_from_the_caller_beats_the_file()
    {
        HostKeyPolicy policy = HostKeyPolicy.Fingerprint("SHA256:abc");
        SshConfig config = SshConfig.Parse("StrictHostKeyChecking accept-new\n", Home, null);
        Assert.Same(policy, SshClientOptions.FromConfig("web", config, policy).HostKeyPolicy);
    }

    [Fact]
    public void Proxy_jump_is_reported_and_logged()
    {
        RecordingLogger logger = new();
        SshConfig config = SshConfig.Parse("ProxyJump bastion\n", Home, null);
        Assert.Equal("bastion", config.Resolve("web").ProxyJump);
        SshClientOptions.FromConfig("web", config, loggerFactory: new RecordingFactory(logger));
        Assert.Contains(logger.Messages, m => m.Contains("ProxyJump", StringComparison.Ordinal));
        Assert.Null(SshConfig.Parse("ProxyJump none\n", Home, null).Resolve("web").ProxyJump);
    }

    private sealed class RecordingFactory(ILogger logger) : ILoggerFactory
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

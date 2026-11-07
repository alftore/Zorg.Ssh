using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Zorg.Ssh.KnownHosts;

namespace Zorg.Ssh;

/// <summary>What a config file says about checking host keys.</summary>
/// <example>
/// <code>
/// if (config.Resolve("web").StrictHostKeyChecking == SshStrictHostKeyChecking.No) { ... }
/// </code>
/// </example>
public enum SshStrictHostKeyChecking
{
    /// <summary>Refuse a host that isn't known. A library can't ask anyone, so <c>ask</c> means this as well.</summary>
    Yes,

    /// <summary><c>accept-new</c>: record a host seen for the first time, and refuse a changed key.</summary>
    AcceptNew,

    /// <summary><c>no</c>: the file asks for no check. A config file can't turn the check off by itself: see <see cref="SshClientOptions.FromConfig"/>.</summary>
    No,
}

/// <summary>What a config file says about one host, with tokens expanded and defaults filled in.</summary>
/// <example>
/// <code>
/// SshHostConfig host = SshConfig.Load().Resolve("web");
/// Console.WriteLine($"{host.User}@{host.HostName}:{host.Port}");
/// </code>
/// </example>
public sealed record SshHostConfig
{
    internal SshHostConfig()
    {
    }

    /// <summary>Gets the name or address to connect to.</summary>
    public required string HostName { get; init; }

    /// <summary>Gets the port.</summary>
    public required int Port { get; init; }

    /// <summary>Gets the user to log in as.</summary>
    public required string User { get; init; }

    /// <summary>Gets the private key files, in order. They may not exist.</summary>
    public required IReadOnlyList<string> IdentityFiles { get; init; }

    /// <summary>Gets whether to use only these files, and not the agent.</summary>
    public required bool IdentitiesOnly { get; init; }

    /// <summary>Gets the known_hosts files, in order. Empty means <c>none</c>.</summary>
    public required IReadOnlyList<string> UserKnownHostsFiles { get; init; }

    /// <summary>Gets the host key setting.</summary>
    public required SshStrictHostKeyChecking StrictHostKeyChecking { get; init; }

    /// <summary>Gets the <c>ProxyJump</c> value, if any. <see cref="SshClientOptions.FromConfig"/> refuses a host that has one.</summary>
    public string? ProxyJump { get; init; }

    /// <summary>Gets the files <c>GlobalKnownHostsFile</c> names, or OpenSSH's defaults. They're read and never written.</summary>
    internal IReadOnlyList<string> GlobalKnownHostsFiles { get; init; } = [];

    /// <summary>Gets the <c>ProxyCommand</c> value, if any and not <c>none</c>.</summary>
    internal string? ProxyCommand { get; init; }

    /// <summary>Gets the keywords set that decide who is trusted and that this library doesn't honour: they make <see cref="SshClientOptions.FromConfig"/> refuse.</summary>
    internal IReadOnlyList<string> UnhonouredTrustKeywords { get; init; } = [];

    /// <summary>Gets the security-relevant keywords that a <c>Match</c> block sets and that could apply to this host.</summary>
    internal IReadOnlyList<string> MatchTrustKeywords { get; init; } = [];

    /// <summary>Gets keywords that are set and ignored, and that a reader might expect to be honoured. They're warned about.</summary>
    internal IReadOnlyList<string> IgnoredKeywords { get; init; } = [];

    /// <summary>Gets whether <c>IdentityAgent none</c> says not to use an agent.</summary>
    internal bool AgentDisabled { get; init; }

    /// <summary>Gets <c>ServerAliveInterval</c> in seconds, if set. Zero turns keepalive off.</summary>
    internal int? ServerAliveInterval { get; init; }

    /// <summary>Gets <c>ServerAliveCountMax</c>, if set.</summary>
    internal int? ServerAliveCountMax { get; init; }

    /// <summary>Gets <c>ConnectTimeout</c> in seconds, if set. Zero means the library's own limit.</summary>
    internal int? ConnectTimeout { get; init; }
}

/// <summary>
/// A subset of OpenSSH's <c>ssh_config(5)</c>: <c>Host</c>, <c>Include</c>, <c>HostName</c>, <c>Port</c>, <c>User</c>,
/// <c>IdentityFile</c>, <c>IdentitiesOnly</c>, <c>UserKnownHostsFile</c>, <c>GlobalKnownHostsFile</c>,
/// <c>StrictHostKeyChecking</c>, <c>ProxyJump</c>, <c>ServerAliveInterval</c>, <c>ServerAliveCountMax</c> and
/// <c>ConnectTimeout</c>. Other keywords are ignored, except that <see cref="SshClientOptions.FromConfig"/> refuses a
/// host that sets one that decides trust or the network path and that it can't honour (<c>ProxyCommand</c>,
/// <c>RevokedHostKeys</c>, <c>KnownHostsCommand</c>, <c>HostKeyAlias</c>). <c>Match</c> blocks are never evaluated: one
/// that sets a keyword which decides trust, such as <c>StrictHostKeyChecking</c>, makes <c>FromConfig</c> throw, and
/// anything else in a <c>Match</c> block is skipped with a logged note. As in <c>ssh</c>, the first value found for a
/// keyword wins, except that <c>IdentityFile</c> adds up.
/// </summary>
/// <example>
/// <code>
/// SshClientOptions options = SshClientOptions.FromConfig("web", SshConfig.Load());
/// await using SshClient client = await SshClient.ConnectAsync(options, cancellationToken);
/// </code>
/// </example>
public sealed partial class SshConfig
{
    /// <summary>The largest config file accepted, in bytes.</summary>
    internal const int MaxFileLength = 1 << 20;

    private const int MaxLineLength = 16 * 1024;
    private const int MaxIncludeDepth = 16; // The same limit as ssh.
    private const int MaxFiles = 256;
    private const int MaxDirectives = 64 * 1024;
    private const int MaxIdentityFiles = 100; // The same limit as ssh.

    private static readonly string[] DefaultIdentityNames = ["id_rsa", "id_ecdsa", "id_ed25519"];

    /// <summary>Keywords that decide who is trusted, where a connection goes or how it logs in. A Match block that sets one can't be ignored.</summary>
    private static readonly HashSet<string> TrustKeywords = new(StringComparer.Ordinal)
    {
        "STRICTHOSTKEYCHECKING", "USERKNOWNHOSTSFILE", "GLOBALKNOWNHOSTSFILE", "HOSTKEYALIAS", "REVOKEDHOSTKEYS",
        "KNOWNHOSTSCOMMAND", "PROXYCOMMAND", "PROXYJUMP", "HOSTKEYALGORITHMS", "CASIGNATUREALGORITHMS", "HOSTNAME",
        "PORT", "IDENTITIESONLY", "IDENTITYFILE", "IDENTITYAGENT", "CERTIFICATEFILE", "PUBKEYAUTHENTICATION",
        "VERIFYHOSTKEYDNS", "CHECKHOSTIP", "UPDATEHOSTKEYS", "HOSTBASEDAUTHENTICATION",
    };

    /// <summary>Keywords that are noted and not honoured. Setting one still compiles, but a reader would expect it to count.</summary>
    private static readonly HashSet<string> WarnedKeywords = new(StringComparer.Ordinal)
    {
        "IDENTITYAGENT", "CERTIFICATEFILE", "HOSTKEYALGORITHMS", "CASIGNATUREALGORITHMS", "PUBKEYAUTHENTICATION",
    };

    /// <summary>Keywords that decide who is trusted and that are not honoured: a host that sets one is refused by FromConfig.</summary>
    private static readonly HashSet<string> RefusedKeywords = new(StringComparer.Ordinal)
    {
        "REVOKEDHOSTKEYS", "KNOWNHOSTSCOMMAND", "HOSTKEYALIAS",
    };

    private readonly List<Directive> _directives = [];
    private readonly List<Directive> _matchDirectives = [];
    private readonly string _home;
    private readonly ILogger _logger;
    private int _files;

    private SshConfig(string home, ILogger? logger)
    {
        _home = home;
        _logger = logger ?? NullLogger.Instance;
    }

    private static string UserHome => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    /// <summary>Reads a config file and the files it includes.</summary>
    /// <param name="path">The file. The default is <c>~/.ssh/config</c>, and it's fine for that one not to exist. A file you name must exist.</param>
    /// <param name="logger">Receives notes about what was skipped.</param>
    /// <returns>The config.</returns>
    /// <exception cref="SshConfigException">A file can't be read, or a keyword this class handles has a bad value.</exception>
    /// <example>
    /// <code>
    /// SshConfig config = SshConfig.Load("~/.ssh/config.work");
    /// </code>
    /// </example>
    public static SshConfig Load(string? path = null, ILogger? logger = null) => Load(path, UserHome, logger);

    /// <summary>Reads config text. <c>Include</c> paths that aren't absolute are relative to <c>~/.ssh</c>.</summary>
    /// <param name="text">The text of a config file.</param>
    /// <param name="logger">Receives notes about what was skipped.</param>
    /// <returns>The config.</returns>
    /// <exception cref="SshConfigException">A keyword this class handles has a bad value.</exception>
    /// <example>
    /// <code>
    /// SshConfig config = SshConfig.Parse("Host web\n  HostName web.example.com\n  User alice\n");
    /// </code>
    /// </example>
    public static SshConfig Parse(string text, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(text);
        return Parse(text, UserHome, logger);
    }

    /// <summary>Works out the settings for a host.</summary>
    /// <param name="hostAlias">The name as you'd give it to <c>ssh</c>, which is what <c>Host</c> lines match.</param>
    /// <returns>The settings.</returns>
    /// <exception cref="SshConfigException">A value uses a token that isn't supported.</exception>
    /// <example>
    /// <code>
    /// SshHostConfig host = config.Resolve("web");
    /// </code>
    /// </example>
    public SshHostConfig Resolve(string hostAlias)
    {
        ArgumentException.ThrowIfNullOrEmpty(hostAlias);
        Dictionary<string, Directive> first = new(StringComparer.Ordinal);
        List<Directive> identities = [];
        foreach (Directive directive in _directives)
        {
            if (!directive.Conditions.All(patterns => HostLineMatches(patterns, hostAlias)))
            {
                continue;
            }

            if (directive.Keyword == "IDENTITYFILE")
            {
                identities.Add(directive);
            }
            else
            {
                first.TryAdd(directive.Keyword, directive);
            }
        }

        string Value(string keyword) => first.TryGetValue(keyword, out Directive? d) ? d.Arguments[0] : string.Empty;

        string localUser = Environment.UserName;
        string hostName = LowerAscii(first.TryGetValue("HOSTNAME", out Directive? hostDirective)
            ? ExpandTokens(hostDirective.Arguments[0], hostDirective.Source, c => c == 'h' ? hostAlias : null)
            : hostAlias);
        int port = first.ContainsKey("PORT") ? int.Parse(Value("PORT"), CultureInfo.InvariantCulture) : 22;
        string user = first.TryGetValue("USER", out Directive? userDirective)
            ? ExpandTokens(userDirective.Arguments[0], userDirective.Source, c => c switch
            {
                'd' => _home,
                'h' => hostName,
                'p' => port.ToString(CultureInfo.InvariantCulture),
                'u' => localUser,
                _ => null,
            })
            : localUser;

        string? Token(char c) => c switch
        {
            'd' => _home,
            'h' => hostName,
            'p' => port.ToString(CultureInfo.InvariantCulture),
            'r' => user,
            'u' => localUser,
            _ => null,
        };

        string ExpandPath(string value, string source) => ExpandTilde(ExpandTokens(value, source, Token));

        List<string> identityFiles = [];
        bool noDefaults = false;
        foreach (Directive directive in identities)
        {
            if (directive.Arguments[0].Equals("none", StringComparison.OrdinalIgnoreCase))
            {
                noDefaults = true;
                continue;
            }

            string path = ExpandPath(directive.Arguments[0], directive.Source);
            if (!identityFiles.Contains(path) && identityFiles.Count < MaxIdentityFiles)
            {
                identityFiles.Add(path);
            }
        }

        if (identityFiles.Count == 0 && !noDefaults)
        {
            identityFiles.AddRange(DefaultIdentityNames.Select(name => Path.Combine(_home, ".ssh", name)));
        }

        string[] knownHosts;
        if (!first.TryGetValue("USERKNOWNHOSTSFILE", out Directive? knownHostsDirective))
        {
            knownHosts = [Path.Combine(_home, ".ssh", "known_hosts"), Path.Combine(_home, ".ssh", "known_hosts2")];
        }
        else if (knownHostsDirective.Arguments is ["none"])
        {
            knownHosts = [];
        }
        else
        {
            knownHosts = [.. knownHostsDirective.Arguments.Select(a => ExpandPath(a, knownHostsDirective.Source))];
        }

        string[] globalKnownHosts;
        if (!first.TryGetValue("GLOBALKNOWNHOSTSFILE", out Directive? globalDirective))
        {
            globalKnownHosts = DefaultGlobalKnownHostsFiles();
        }
        else if (globalDirective.Arguments is [var only] && only.Equals("none", StringComparison.OrdinalIgnoreCase))
        {
            globalKnownHosts = [];
        }
        else
        {
            globalKnownHosts = [.. globalDirective.Arguments.Select(a => ExpandPath(a, globalDirective.Source))];
        }

        bool IsSetAndNotNone(string keyword) =>
            first.TryGetValue(keyword, out Directive? d) && !(d.Arguments is [var v] && v.Equals("none", StringComparison.OrdinalIgnoreCase));

        // ssh lets the first value win even when it is "none", which switches the keyword off.
        // "none" switches KnownHostsCommand off. For the other two it would be a file name or an alias.
        bool agentDisabled = first.TryGetValue("IDENTITYAGENT", out Directive? agent)
            && agent.Arguments is [var agentValue] && agentValue.Equals("none", StringComparison.OrdinalIgnoreCase);
        string[] refused = [.. RefusedKeywords
            .Where(k => k == "KNOWNHOSTSCOMMAND" ? IsSetAndNotNone(k) : first.ContainsKey(k))
            .Order(StringComparer.Ordinal)
            .Select(KeywordName)];
        string[] ignored = [.. WarnedKeywords
            .Where(k => first.ContainsKey(k) && !(k == "IDENTITYAGENT" && agentDisabled))
            .Order(StringComparer.Ordinal)
            .Select(KeywordName)];
        string[] matched = [.. _matchDirectives
            .Where(d => d.Conditions.All(patterns => HostLineMatches(patterns, hostAlias)))
            .Select(d => KeywordName(d.Keyword))
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)];

        return new SshHostConfig
        {
            HostName = hostName,
            Port = port,
            User = user,
            IdentityFiles = identityFiles,
            IdentitiesOnly = first.ContainsKey("IDENTITIESONLY") && IsYes(Value("IDENTITIESONLY")),
            UserKnownHostsFiles = knownHosts,
            StrictHostKeyChecking = first.ContainsKey("STRICTHOSTKEYCHECKING") ? ParseStrict(Value("STRICTHOSTKEYCHECKING")) : SshStrictHostKeyChecking.Yes,
            ProxyJump = first.ContainsKey("PROXYJUMP") && !Value("PROXYJUMP").Equals("none", StringComparison.OrdinalIgnoreCase) ? Value("PROXYJUMP") : null,
            GlobalKnownHostsFiles = globalKnownHosts,
            ProxyCommand = IsSetAndNotNone("PROXYCOMMAND") ? first["PROXYCOMMAND"].Arguments[0] : null,
            UnhonouredTrustKeywords = refused,
            MatchTrustKeywords = matched,
            IgnoredKeywords = ignored,
            AgentDisabled = agentDisabled,
            ServerAliveInterval = IntValue("SERVERALIVEINTERVAL"),
            ServerAliveCountMax = IntValue("SERVERALIVECOUNTMAX"),
            ConnectTimeout = IntValue("CONNECTTIMEOUT"),
        };

        int? IntValue(string keyword) => first.ContainsKey(keyword) ? int.Parse(Value(keyword), CultureInfo.InvariantCulture) : null;
    }

    /// <summary>Gets the name as users write it, for messages.</summary>
    private static string KeywordName(string keyword) => keyword switch
    {
        "STRICTHOSTKEYCHECKING" => "StrictHostKeyChecking",
        "USERKNOWNHOSTSFILE" => "UserKnownHostsFile",
        "GLOBALKNOWNHOSTSFILE" => "GlobalKnownHostsFile",
        "HOSTKEYALIAS" => "HostKeyAlias",
        "REVOKEDHOSTKEYS" => "RevokedHostKeys",
        "KNOWNHOSTSCOMMAND" => "KnownHostsCommand",
        "PROXYCOMMAND" => "ProxyCommand",
        "PROXYJUMP" => "ProxyJump",
        "HOSTKEYALGORITHMS" => "HostKeyAlgorithms",
        "CASIGNATUREALGORITHMS" => "CASignatureAlgorithms",
        "HOSTNAME" => "HostName",
        "PORT" => "Port",
        "IDENTITIESONLY" => "IdentitiesOnly",
        "IDENTITYFILE" => "IdentityFile",
        "IDENTITYAGENT" => "IdentityAgent",
        "CERTIFICATEFILE" => "CertificateFile",
        "PUBKEYAUTHENTICATION" => "PubkeyAuthentication",
        "VERIFYHOSTKEYDNS" => "VerifyHostKeyDNS",
        "CHECKHOSTIP" => "CheckHostIP",
        "UPDATEHOSTKEYS" => "UpdateHostKeys",
        "HOSTBASEDAUTHENTICATION" => "HostbasedAuthentication",
        _ => keyword,
    };

    /// <summary>OpenSSH's default <c>GlobalKnownHostsFile</c>: where an administrator puts <c>@revoked</c> and <c>@cert-authority</c> lines.</summary>
    private static string[] DefaultGlobalKnownHostsFiles() => OperatingSystem.IsWindows()
        ? [Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ssh", "ssh_known_hosts")]
        : ["/etc/ssh/ssh_known_hosts", "/etc/ssh/ssh_known_hosts2"];

    /// <summary>Reads a file, with the home directory given, so tests needn't touch the real one.</summary>
    internal static SshConfig Load(string? path, string home, ILogger? logger)
    {
        SshConfig config = new(home, logger);
        string file = config.ExpandTilde(path ?? "~/.ssh/config");
        if (path is null && !File.Exists(file))
        {
            return config;
        }

        config.ReadFile(file, [], depth: 0);
        return config;
    }

    /// <summary>Reads text, with the home directory given, so tests needn't touch the real one.</summary>
    internal static SshConfig Parse(string text, string home, ILogger? logger)
    {
        SshConfig config = new(home, logger);
        config.ReadText(text, "config text", [], depth: 0);
        return config;
    }

    /// <summary>Matches one <c>Host</c> line. Unlike known_hosts, case counts. A matching negated pattern rules the host out.</summary>
    private static bool HostLineMatches(string[] patterns, string alias)
    {
        bool matched = false;
        foreach (string pattern in patterns)
        {
            bool negated = pattern.StartsWith('!');
            if (KnownHostsEntry.MatchesGlob(negated ? pattern.AsSpan(1) : pattern, alias, ignoreCase: false))
            {
                if (negated)
                {
                    return false;
                }

                matched = true;
            }
        }

        return matched;
    }

    /// <summary>As <c>ssh</c> treats a host name once the config has been matched.</summary>
    private static string LowerAscii(string name) => string.Create(name.Length, name, static (span, source) =>
    {
        for (int i = 0; i < span.Length; i++)
        {
            span[i] = KnownHostsEntry.Fold(source[i]);
        }
    });

    private static bool IsYes(string value) => value.ToUpperInvariant() is "YES" or "TRUE";

    private static SshStrictHostKeyChecking ParseStrict(string value) => value.ToUpperInvariant() switch
    {
        "NO" or "FALSE" or "OFF" => SshStrictHostKeyChecking.No,
        "ACCEPT-NEW" => SshStrictHostKeyChecking.AcceptNew,
        _ => SshStrictHostKeyChecking.Yes,
    };

    private static string ExpandTokens(string value, string source, Func<char, string?> token)
    {
        if (!value.Contains('%', StringComparison.Ordinal))
        {
            return value;
        }

        StringBuilder result = new(value.Length);
        for (int i = 0; i < value.Length; i++)
        {
            if (value[i] != '%')
            {
                result.Append(value[i]);
                continue;
            }

            if (++i == value.Length)
            {
                throw new SshConfigException($"{source}: \"{value}\" ends with a lone %. Write %% for a percent sign.");
            }

            string? replacement = value[i] == '%' ? "%" : token(value[i]);
            result.Append(replacement ?? throw new SshConfigException($"{source}: the token %{value[i]} in \"{value}\" isn't supported here. Write the value out in full."));
        }

        return result.ToString();
    }

    /// <summary>Splits arguments as <c>ssh</c> does: quotes group, a backslash escapes quotes, backslashes and spaces, and <c>#</c> at the start of a word ends the line.</summary>
    private static List<string> SplitArguments(ReadOnlySpan<char> text, string source)
    {
        List<string> arguments = [];
        StringBuilder word = new();
        int i = 0;
        while (true)
        {
            while (i < text.Length && text[i] is ' ' or '\t')
            {
                i++;
            }

            if (i == text.Length || text[i] == '#')
            {
                return arguments;
            }

            word.Clear();
            char quote = '\0';
            for (; i < text.Length; i++)
            {
                char c = text[i];
                char next = i + 1 < text.Length ? text[i + 1] : '\0';
                if (c == '\\' && (next is '\'' or '"' or '\\' || (quote == '\0' && next == ' ')))
                {
                    word.Append(next);
                    i++;
                }
                else if (quote == '\0' && c is ' ' or '\t')
                {
                    break;
                }
                else if (quote == '\0' && c is '"' or '\'')
                {
                    quote = c;
                }
                else if (c == quote)
                {
                    quote = '\0';
                }
                else
                {
                    word.Append(c);
                }
            }

            if (quote != '\0')
            {
                throw new SshConfigException($"{source}: a quote isn't closed.");
            }

            arguments.Add(word.ToString());
        }
    }

    /// <summary>Takes the keyword from a line, along with whitespace and one <c>=</c> after it.</summary>
    private static ReadOnlySpan<char> TakeKeyword(ReadOnlySpan<char> line, out ReadOnlySpan<char> rest)
    {
        ReadOnlySpan<char> keyword;
        if (line[0] == '"')
        {
            int close = line[1..].IndexOf('"');
            keyword = close < 0 ? line[1..] : line.Slice(1, close);
            rest = close < 0 ? default : line[(close + 2)..];
        }
        else
        {
            int end = line.IndexOfAny(" \t=");
            keyword = end < 0 ? line : line[..end];
            rest = end < 0 ? default : line[end..];
        }

        rest = rest.TrimStart(" \t");
        if (!rest.IsEmpty && rest[0] == '=')
        {
            rest = rest[1..].TrimStart(" \t");
        }

        return keyword;
    }

    private static void Validate(string keyword, List<string> arguments, string source)
    {
        if (arguments.Count == 0 || arguments[0].Length == 0)
        {
            throw new SshConfigException($"{source}: {keyword} has no value.");
        }

        if (keyword != "USERKNOWNHOSTSFILE" && arguments.Count > 1)
        {
            throw new SshConfigException($"{source}: {keyword} takes one value, and this line has {arguments.Count}.");
        }

        string value = arguments[0];
        switch (keyword)
        {
            case "PORT" when !int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int port) || port is < 1 or > 65535:
                throw new SshConfigException($"{source}: \"{value}\" isn't a port number.");
            case "SERVERALIVEINTERVAL" when !int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int interval) || interval > 86400:
                throw new SshConfigException($"{source}: \"{value}\" isn't a number of seconds from 0 to 86400 for ServerAliveInterval. Use 0 to turn keepalive off.");
            case "SERVERALIVECOUNTMAX" when !int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int countMax) || countMax is < 1 or > 1000:
                throw new SshConfigException($"{source}: \"{value}\" isn't a count from 1 to 1000 for ServerAliveCountMax.");
            case "CONNECTTIMEOUT" when !int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int timeout) || timeout > 86400:
                throw new SshConfigException($"{source}: \"{value}\" isn't a number of seconds from 0 to 86400 for ConnectTimeout. Write whole seconds.");
            case "IDENTITIESONLY" when value.ToUpperInvariant() is not ("YES" or "NO" or "TRUE" or "FALSE"):
                throw new SshConfigException($"{source}: IdentitiesOnly must be yes or no.");
            case "STRICTHOSTKEYCHECKING" when value.ToUpperInvariant() is not ("YES" or "NO" or "TRUE" or "FALSE" or "OFF" or "ASK" or "ACCEPT-NEW"):
                throw new SshConfigException($"{source}: StrictHostKeyChecking must be yes, no, ask or accept-new.");
        }
    }

    private void ReadFile(string path, IReadOnlyList<string[]> conditions, int depth, bool matchContext = false)
    {
        if (depth > MaxIncludeDepth)
        {
            throw new SshConfigException($"Includes are nested more than {MaxIncludeDepth} deep at {path}. Check for a file that includes itself.");
        }

        if (++_files > MaxFiles)
        {
            throw new SshConfigException($"The config reads more than {MaxFiles} files, which is the limit. Check its Include lines.");
        }

        string text;
        try
        {
            // Regular files only, and read with a limit: an Include can name a FIFO or /dev/zero.
            text = Encoding.UTF8.GetString(LocalFile.ReadAllBytes(path, MaxFileLength));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or ArgumentException)
        {
            throw new SshConfigException($"Couldn't read the config file {path}: {ex.Message}", ex);
        }

        ReadText(text, path, conditions, depth, matchContext);
    }

    private void ReadText(string text, string name, IReadOnlyList<string[]> outer, int depth, bool matchContext = false)
    {
        if (text.Length > MaxFileLength)
        {
            throw new SshConfigException($"{name} is over the limit of {MaxFileLength} characters, so it wasn't read.");
        }

        IReadOnlyList<string[]> conditions = outer;
        bool inMatch = matchContext;
        int lineNumber = 0;
        const char ByteOrderMark = (char)0xFEFF;
        ReadOnlySpan<char> body = text.AsSpan().TrimStart(ByteOrderMark);
        foreach (Range range in body.Split('\n'))
        {
            ReadOnlySpan<char> line = body[range];
            lineNumber++;
            string source = $"{name} line {lineNumber}";
            if (line.Length > MaxLineLength)
            {
                throw new SshConfigException($"{source}: the line is over the limit of {MaxLineLength} characters.");
            }

            line = line.Trim(" \t\r\f");
            if (line.IsEmpty || line[0] == '#')
            {
                continue;
            }

            string keyword = TakeKeyword(line, out ReadOnlySpan<char> rest).ToString().ToUpperInvariant();
            switch (keyword)
            {
                case "HOST":
                    List<string> patterns = SplitArguments(rest, source);
                    if (patterns.Count == 0)
                    {
                        throw new SshConfigException($"{source}: Host has no patterns.");
                    }

                    conditions = [.. outer, [.. patterns]];
                    inMatch = matchContext;
                    break;
                case "MATCH":
                    // Never evaluated. The block could apply to this host, and what it sets decides below whether that matters.
                    ConfigLog.MatchIgnored(_logger, name, lineNumber);
                    conditions = outer;
                    inMatch = true;
                    break;
                case "INCLUDE":
                    // Inside a Match block the file is read as part of it, so a trust keyword in it is noticed too.
                    foreach (string pattern in SplitArguments(rest, source))
                    {
                        foreach (string file in ExpandInclude(pattern, source))
                        {
                            ReadFile(file, conditions, depth + 1, inMatch);
                        }
                    }

                    break;
                default:
                    if (inMatch)
                    {
                        if (TrustKeywords.Contains(keyword))
                        {
                            AddDirective(_matchDirectives, new Directive(keyword, ArgumentsOrWhole(rest, source), conditions, source));
                        }
                    }
                    else if (keyword is "HOSTNAME" or "PORT" or "USER" or "IDENTITYFILE" or "IDENTITIESONLY"
                        or "USERKNOWNHOSTSFILE" or "STRICTHOSTKEYCHECKING" or "PROXYJUMP"
                        or "SERVERALIVEINTERVAL" or "SERVERALIVECOUNTMAX" or "CONNECTTIMEOUT")
                    {
                        List<string> arguments = SplitArguments(rest, source);
                        Validate(keyword, arguments, source);
                        AddDirective(_directives, new Directive(keyword, arguments, conditions, source));
                    }
                    else if (keyword == "PROXYCOMMAND")
                    {
                        // The value is the rest of the line, quotes and all.
                        AddDirective(_directives, new Directive(keyword, [rest.Trim(" \t").ToString()], conditions, source));
                    }
                    else if (keyword is "GLOBALKNOWNHOSTSFILE" or "REVOKEDHOSTKEYS" or "KNOWNHOSTSCOMMAND" or "HOSTKEYALIAS"
                        or "IDENTITYAGENT" or "CERTIFICATEFILE" or "HOSTKEYALGORITHMS" or "CASIGNATUREALGORITHMS" or "PUBKEYAUTHENTICATION")
                    {
                        // Noted, not validated: FromConfig refuses or warns by what they say. A line that can't be split still counts as set.
                        List<string> noted = ArgumentsOrWhole(rest, source);
                        if (keyword == "GLOBALKNOWNHOSTSFILE" && noted[0].Length == 0)
                        {
                            throw new SshConfigException($"{source}: GlobalKnownHostsFile has no value. Name a file, or write none.");
                        }

                        AddDirective(_directives, new Directive(keyword, noted, conditions, source));
                    }

                    break;
            }
        }
    }

    private static List<string> ArgumentsOrWhole(ReadOnlySpan<char> rest, string source)
    {
        try
        {
            List<string> arguments = SplitArguments(rest, source);
            return arguments.Count == 0 ? [string.Empty] : arguments;
        }
        catch (SshConfigException)
        {
            return [rest.ToString()];
        }
    }

    private static void AddDirective(List<Directive> list, Directive directive)
    {
        if (list.Count == MaxDirectives)
        {
            throw new SshConfigException($"{directive.Source}: the config has more than {MaxDirectives} settings, which is the limit.");
        }

        list.Add(directive);
    }

    /// <summary>Turns an <c>Include</c> argument into files, sorted as <c>glob(3)</c> sorts them. No match is fine. There's no host yet, so only host-free tokens work.</summary>
    private List<string> ExpandInclude(string pattern, string source)
    {
        string expanded = ExpandTilde(ExpandTokens(pattern, source, c => c switch
        {
            'd' => _home,
            'u' => Environment.UserName,
            _ => null,
        }));
        if (!Path.IsPathRooted(expanded))
        {
            expanded = Path.Combine(_home, ".ssh", expanded);
        }

        if (expanded.AsSpan().IndexOfAny('*', '?') < 0)
        {
            return File.Exists(expanded) ? [expanded] : [];
        }

        int separator = expanded.AsSpan().LastIndexOfAny('/', '\\');
        string directory = expanded[..(separator + 1)];
        string namePattern = expanded[(separator + 1)..];
        if (directory.AsSpan().IndexOfAny('*', '?') >= 0)
        {
            throw new SshConfigException($"{source}: wildcards in Include are only supported in the file name.");
        }

        try
        {
            if (!Directory.Exists(directory))
            {
                return [];
            }

            List<string> files = [];
            foreach (string file in Directory.EnumerateFiles(directory))
            {
                if (KnownHostsEntry.MatchesGlob(namePattern, Path.GetFileName(file), ignoreCase: false))
                {
                    if (files.Count == MaxFiles)
                    {
                        throw new SshConfigException($"{source}: Include matches more than {MaxFiles} files, which is the limit.");
                    }

                    files.Add(file);
                }
            }

            files.Sort(StringComparer.Ordinal);
            return files;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new SshConfigException($"{source}: couldn't list {directory}: {ex.Message}", ex);
        }
    }

    private string ExpandTilde(string path) =>
        path.StartsWith("~/", StringComparison.Ordinal) || path.StartsWith("~\\", StringComparison.Ordinal)
            ? Path.Combine(_home, path[2..])
            : path;

    /// <summary>One setting, and the <c>Host</c> lines that must all match for it to apply: its own, and those around its <c>Include</c>.</summary>
    private sealed record Directive(string Keyword, List<string> Arguments, IReadOnlyList<string[]> Conditions, string Source);
}

/// <summary>Notes from reading a config file. They hold file names and line numbers, not values.</summary>
internal static partial class ConfigLog
{
    [LoggerMessage(Level = LogLevel.Information, Message = "Ignoring the Match block at {File} line {Line}: Match isn't supported")]
    public static partial void MatchIgnored(ILogger logger, string file, int line);

    [LoggerMessage(Level = LogLevel.Warning, Message = "The config sets {Keyword} for this host, and Zorg.Ssh doesn't honour it, so it has no effect")]
    public static partial void KeywordIgnored(ILogger logger, string keyword);
}

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
/// <param name="HostName">The name or address to connect to.</param>
/// <param name="Port">The port.</param>
/// <param name="User">The user to log in as.</param>
/// <param name="IdentityFiles">The private key files, in order. They may not exist.</param>
/// <param name="IdentitiesOnly">Whether to use only these files, and not the agent.</param>
/// <param name="UserKnownHostsFiles">The known_hosts files, in order. Empty means <c>none</c>.</param>
/// <param name="StrictHostKeyChecking">The host key setting.</param>
/// <param name="ProxyJump">The <c>ProxyJump</c> value, if any. It's reported but isn't acted on.</param>
/// <example>
/// <code>
/// SshHostConfig host = SshConfig.Load().Resolve("web");
/// Console.WriteLine($"{host.User}@{host.HostName}:{host.Port}");
/// </code>
/// </example>
public sealed record SshHostConfig(
    string HostName,
    int Port,
    string User,
    IReadOnlyList<string> IdentityFiles,
    bool IdentitiesOnly,
    IReadOnlyList<string> UserKnownHostsFiles,
    SshStrictHostKeyChecking StrictHostKeyChecking,
    string? ProxyJump);

/// <summary>
/// A subset of OpenSSH's <c>ssh_config(5)</c>: <c>Host</c>, <c>Include</c>, <c>HostName</c>, <c>Port</c>, <c>User</c>,
/// <c>IdentityFile</c>, <c>IdentitiesOnly</c>, <c>UserKnownHostsFile</c>, <c>StrictHostKeyChecking</c> and
/// <c>ProxyJump</c>. Other keywords are ignored. <c>Match</c> blocks are skipped whole, with a logged note. As in
/// <c>ssh</c>, the first value found for a keyword wins, except that <c>IdentityFile</c> adds up.
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
    public const int MaxFileLength = 1 << 20;

    private const int MaxLineLength = 16 * 1024;
    private const int MaxIncludeDepth = 16; // The same limit as ssh.
    private const int MaxFiles = 256;
    private const int MaxDirectives = 64 * 1024;
    private const int MaxIdentityFiles = 100; // The same limit as ssh.

    private static readonly string[] DefaultIdentityNames = ["id_rsa", "id_ecdsa", "id_ed25519"];

    private readonly List<Directive> _directives = [];
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

        return new SshHostConfig(
            hostName,
            port,
            user,
            identityFiles,
            first.ContainsKey("IDENTITIESONLY") && IsYes(Value("IDENTITIESONLY")),
            knownHosts,
            first.ContainsKey("STRICTHOSTKEYCHECKING") ? ParseStrict(Value("STRICTHOSTKEYCHECKING")) : SshStrictHostKeyChecking.Yes,
            first.ContainsKey("PROXYJUMP") && !Value("PROXYJUMP").Equals("none", StringComparison.OrdinalIgnoreCase) ? Value("PROXYJUMP") : null);
    }

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
            case "IDENTITIESONLY" when value.ToUpperInvariant() is not ("YES" or "NO" or "TRUE" or "FALSE"):
                throw new SshConfigException($"{source}: IdentitiesOnly must be yes or no.");
            case "STRICTHOSTKEYCHECKING" when value.ToUpperInvariant() is not ("YES" or "NO" or "TRUE" or "FALSE" or "OFF" or "ASK" or "ACCEPT-NEW"):
                throw new SshConfigException($"{source}: StrictHostKeyChecking must be yes, no, ask or accept-new.");
        }
    }

    private void ReadFile(string path, IReadOnlyList<string[]> conditions, int depth)
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
            using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (stream.Length > MaxFileLength)
            {
                throw new SshConfigException($"The config file {path} is over the limit of {MaxFileLength} bytes, so it wasn't read. Check that this is the right file.");
            }

            byte[] bytes = new byte[(int)stream.Length];
            int read = stream.ReadAtLeast(bytes, bytes.Length, throwOnEndOfStream: false);
            text = Encoding.UTF8.GetString(bytes, 0, read);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new SshConfigException($"Couldn't read the config file {path}: {ex.Message}", ex);
        }

        ReadText(text, path, conditions, depth);
    }

    private void ReadText(string text, string name, IReadOnlyList<string[]> outer, int depth)
    {
        if (text.Length > MaxFileLength)
        {
            throw new SshConfigException($"{name} is over the limit of {MaxFileLength} characters, so it wasn't read.");
        }

        IReadOnlyList<string[]> conditions = outer;
        bool inMatch = false;
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
                    inMatch = false;
                    break;
                case "MATCH":
                    ConfigLog.MatchIgnored(_logger, name, lineNumber);
                    inMatch = true;
                    break;
                case "INCLUDE" when !inMatch:
                    foreach (string pattern in SplitArguments(rest, source))
                    {
                        foreach (string file in ExpandInclude(pattern, source))
                        {
                            ReadFile(file, conditions, depth + 1);
                        }
                    }

                    break;
                case "HOSTNAME" or "PORT" or "USER" or "IDENTITYFILE" or "IDENTITIESONLY"
                    or "USERKNOWNHOSTSFILE" or "STRICTHOSTKEYCHECKING" or "PROXYJUMP" when !inMatch:
                    List<string> arguments = SplitArguments(rest, source);
                    Validate(keyword, arguments, source);
                    if (_directives.Count == MaxDirectives)
                    {
                        throw new SshConfigException($"{source}: the config has more than {MaxDirectives} settings, which is the limit.");
                    }

                    _directives.Add(new Directive(keyword, arguments, conditions, source));
                    break;
            }
        }
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

    [LoggerMessage(Level = LogLevel.Warning, Message = "Ignoring ProxyJump for {Host}: this build has no jump host support, so the connection goes direct")]
    public static partial void ProxyJumpIgnored(ILogger logger, string host);
}

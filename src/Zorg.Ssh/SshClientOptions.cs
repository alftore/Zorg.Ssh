using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Extensions.Logging;

namespace Zorg.Ssh;

/// <summary>What <see cref="SshClient.ConnectAsync"/> needs. Host, user name and host key policy are required, so that no connection is accidentally unverified.</summary>
/// <example>
/// <code>
/// SshClientOptions options = new()
/// {
///     Host = "example.com",
///     UserName = "alice",
///     Credentials = [SshCredential.FromPassword(password)],
///     HostKeyPolicy = HostKeyPolicy.Fingerprint(knownFingerprint),
/// };
/// </code>
/// </example>
public sealed class SshClientOptions
{
    /// <summary>Gets the host name or address to connect to.</summary>
    public required string Host { get; init; }

    /// <summary>Gets the port. The default is 22.</summary>
    public int Port { get; init; } = 22;

    /// <summary>Gets the user to log in as.</summary>
    public required string UserName { get; init; }

    /// <summary>Gets the credentials, tried in order.</summary>
    public IReadOnlyList<SshCredential> Credentials { get; init; } = [];

    /// <summary>Gets the check on the server's identity.</summary>
    public required HostKeyPolicy HostKeyPolicy { get; init; }

    /// <summary>Gets the algorithms to offer. The defaults are current and need no tuning.</summary>
    public SshAlgorithms Algorithms { get; init; } = SshAlgorithms.Default;

    /// <summary>Gets the time allowed to connect, exchange keys and log in. The default is 30 seconds.</summary>
    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Gets how long the connection can be silent before a probe goes out. The default is 30 seconds, and
    /// <see cref="TimeSpan.Zero"/> turns keepalive and the stalled-send check off. Otherwise it's 1 second to 1 day.
    /// Keepalive starts after login. Any packet from the server counts as an answer, so a busy connection sends no
    /// probes. If it stays silent for <see cref="KeepAliveCountMax"/> more intervals, or one write to it stays
    /// unfinished for this interval times <see cref="KeepAliveCountMax"/>, the connection fails with
    /// <see cref="SshConnectionException"/> and everything waiting on it wakes. A server that answers probes but grants no window is alive: a write waiting for window needs its own token.
    /// </summary>
    /// <example>
    /// <code>
    /// KeepAliveInterval = TimeSpan.FromSeconds(15),
    /// </code>
    /// </example>
    public TimeSpan KeepAliveInterval { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Gets how many intervals of silence after the probe end the connection. The default is 3, and it's 1 to 1000.
    /// With the defaults, a dead server is noticed after 2 minutes of silence, and a stalled send after 90 seconds or a little more.
    /// </summary>
    /// <example>
    /// <code>
    /// KeepAliveCountMax = 5,
    /// </code>
    /// </example>
    public int KeepAliveCountMax { get; init; } = 3;

    /// <summary>Gets the clock, for tests.</summary>
    internal TimeProvider TimeProvider { get; init; } = TimeProvider.System;

    /// <summary>Gets the most output <see cref="SshClient.ExecuteAsync"/> keeps, per stream, before it fails. The default is 64 MiB. Use <see cref="SshClient.StartProcessAsync"/> for more.</summary>
    public int MaxCommandOutputBytes { get; init; } = 64 * 1024 * 1024;

    /// <summary>
    /// Gets a connected client to reach this host through, as <c>ssh -J</c> does. Null, the default, connects directly.
    /// <see cref="Host"/> and <see cref="Port"/> are then as the jump host sees them, and <see cref="HostKeyPolicy"/>
    /// still checks this host: the jump host vouches for nothing. The caller keeps ownership of the jump host, and this
    /// connection ends with it. Chains work: the jump host can have its own jump host.
    /// </summary>
    /// <example>
    /// <code>
    /// await using SshClient bastion = await SshClient.ConnectAsync(bastionOptions, cancellationToken);
    /// await using SshClient inner = await SshClient.ConnectAsync(new SshClientOptions
    /// {
    ///     Host = "10.0.0.5",
    ///     UserName = "alice",
    ///     Credentials = [SshCredential.FromPassword(password)],
    ///     HostKeyPolicy = HostKeyPolicy.Fingerprint(innerFingerprint),
    ///     JumpHost = bastion,
    /// }, cancellationToken);
    /// </code>
    /// </example>
    public SshClient? JumpHost { get; init; }

    /// <summary>Gets the most connections each forward carries at once. The default is 64. Past this, a forward refuses new connections until one ends.</summary>
    public int MaxForwardedConnections { get; init; } = 64;

    /// <summary>
    /// Gets the time a client of <see cref="SshClient.ForwardDynamicPortAsync"/> has to finish its SOCKS handshake.
    /// The default is 10 seconds. Anyone local can connect to that port, so one that says nothing must not keep its slot.
    /// </summary>
    public TimeSpan SocksHandshakeTimeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>Gets a handler for the server's login banner. Its text is chosen by the server.</summary>
    public Action<string>? BannerHandler { get; init; }

    /// <summary>Gets the logger factory. Secrets are never logged.</summary>
    public ILoggerFactory? LoggerFactory { get; init; }

    /// <summary>
    /// Makes options from an OpenSSH config file, for the host as you'd name it to <c>ssh</c>. Credentials are the agent,
    /// unless <c>IdentitiesOnly</c> is set, then each identity file that exists, then <paramref name="credentials"/>.
    /// An agent that isn't there and an identity file that can't be used, such as an encrypted one, are passed over.
    /// <c>StrictHostKeyChecking no</c> throws <see cref="SshConfigException"/> unless
    /// <paramref name="hostKeyPolicy"/> is given, because a config file mustn't silently weaken security. The check
    /// can be dropped only by passing <see cref="HostKeyPolicy.AcceptAnyUnsafe"/> here.
    /// A host with <c>ProxyJump</c> throws <see cref="SshConfigException"/>: this method can't follow it, and going direct could bypass a required bastion.
    /// </summary>
    /// <param name="hostAlias">The host name or <c>Host</c> alias.</param>
    /// <param name="config">The config. The default is <c>~/.ssh/config</c>.</param>
    /// <param name="hostKeyPolicy">A policy to use in place of what the config says.</param>
    /// <param name="credentials">More credentials to try after those from the config, such as a key with a passphrase.</param>
    /// <param name="loggerFactory">The logger factory for the options, and for notes about the config.</param>
    /// <returns>The options.</returns>
    /// <exception cref="SshConfigException">The config can't be used.</exception>
    /// <example>
    /// <code>
    /// SshClientOptions options = SshClientOptions.FromConfig("web");
    /// await using SshClient client = await SshClient.ConnectAsync(options, cancellationToken);
    /// </code>
    /// </example>
    public static SshClientOptions FromConfig(
        string hostAlias,
        SshConfig? config = null,
        HostKeyPolicy? hostKeyPolicy = null,
        IReadOnlyList<SshCredential>? credentials = null,
        ILoggerFactory? loggerFactory = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(hostAlias);
        ILogger? logger = loggerFactory?.CreateLogger<SshConfig>();
        SshHostConfig host = (config ?? SshConfig.Load(logger: logger)).Resolve(hostAlias);
        if (host.ProxyJump is not null)
        {
            // Connecting directly could bypass the bastion the config requires, so it isn't a quiet fallback.
            throw new SshConfigException($"{hostAlias} uses ProxyJump, which FromConfig can't follow. Connect to the jump host yourself, then connect through it.");
        }

        if (hostKeyPolicy is null && host.StrictHostKeyChecking == SshStrictHostKeyChecking.No)
        {
            throw new SshConfigException($"The config says StrictHostKeyChecking no for {hostAlias}, which would remove protection against interception. A config file can't do that here. Change it to yes or accept-new, or pass HostKeyPolicy.AcceptAnyUnsafe() to FromConfig if you mean it.");
        }

        List<SshCredential> all = [];
        if (!host.IdentitiesOnly)
        {
            all.Add(new AgentCredential(
                ct => Agent.SshAgentEndpoint.ConnectAsync(null, ct),
                AgentCredential.DefaultMaxKeysOffered,
                isOptional: true));
        }

        all.AddRange(host.IdentityFiles.Where(File.Exists).Select(SshCredential.FromIdentityFile));
        all.AddRange(credentials ?? []);
        return new SshClientOptions
        {
            Host = host.HostName,
            Port = host.Port,
            UserName = host.User,
            Credentials = all,
            HostKeyPolicy = hostKeyPolicy ?? new KnownHostsPolicy(
                host.UserKnownHostsFiles,
                host.StrictHostKeyChecking == SshStrictHostKeyChecking.AcceptNew,
                TimeProvider.System),
            LoggerFactory = loggerFactory,
        };
    }
}

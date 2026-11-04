using System;
using System.Collections.Generic;
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

    /// <summary>Gets the time allowed to connect, exchange keys and log in. The default is 30 seconds.</summary>
    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Gets the most output <see cref="SshClient.ExecuteAsync"/> keeps, per stream, before it fails. The default is 64 MiB. Use <see cref="SshClient.StartProcessAsync"/> for more.</summary>
    public int MaxCommandOutputBytes { get; init; } = 64 * 1024 * 1024;

    /// <summary>Gets a handler for the server's login banner. Its text is chosen by the server.</summary>
    public Action<string>? BannerHandler { get; init; }

    /// <summary>Gets the logger factory. Secrets are never logged.</summary>
    public ILoggerFactory? LoggerFactory { get; init; }
}

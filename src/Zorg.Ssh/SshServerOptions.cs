using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Zorg.Ssh.Crypto;

namespace Zorg.Ssh;

/// <summary>A server's identity. Create one once and keep it: clients pin it. The caller disposes it after the server stops.</summary>
/// <example>
/// <code>
/// using SshHostKey key = SshHostKey.GenerateEd25519();
/// Console.WriteLine(key.Sha256Fingerprint);
/// </code>
/// </example>
public sealed class SshHostKey : IDisposable
{
    internal SshHostKey(SshPrivateKey key) => Key = key;

    /// <summary>Gets the fingerprint clients see, in OpenSSH form.</summary>
    public string Sha256Fingerprint => HostKeyPolicy.ComputeFingerprint(Key.PublicKey.Blob.Span);

    internal SshPrivateKey Key { get; }

    /// <summary>Creates a new random Ed25519 key, for tests. It can't be saved, so for a lasting identity make one with ssh-keygen and use <see cref="Load"/>.</summary>
    /// <returns>The key.</returns>
    /// <example>
    /// <code>
    /// using SshHostKey key = SshHostKey.GenerateEd25519();
    /// </code>
    /// </example>
    public static SshHostKey GenerateEd25519() => new(SshPrivateKey.GenerateEd25519());

    /// <summary>Loads a host key from the text of a private key file.</summary>
    /// <param name="keyText">The file's contents: OpenSSH, PKCS#1, SEC1 or PKCS#8 format.</param>
    /// <param name="passphrase">The passphrase, if the key is encrypted.</param>
    /// <returns>The key.</returns>
    /// <example>
    /// <code>
    /// using SshHostKey key = SshHostKey.Load(File.ReadAllText("/etc/myapp/ssh_host_ed25519_key"));
    /// </code>
    /// </example>
    public static SshHostKey Load(string keyText, string? passphrase = null) => new(Crypto.KeyFiles.SshKeyFile.Load(keyText, passphrase));

    /// <summary>Zeroes the key.</summary>
    public void Dispose() => Key.Dispose();
}

/// <summary>What an auth handler decided.</summary>
public enum SshAuthDecision
{
    /// <summary>This attempt failed.</summary>
    Reject,

    /// <summary>The user is logged in.</summary>
    Accept,
}

/// <summary>A login attempt with a password.</summary>
/// <param name="UserName">The user name. It's unverified, and chosen by the client.</param>
/// <param name="Password">The password.</param>
/// <example>
/// <code>
/// PasswordHandler = (request, ct) => users.CheckAsync(request.UserName, request.Password, ct),
/// </code>
/// </example>
public sealed record SshPasswordRequest(string UserName, string Password)
{
    /// <summary>Returns a description with the password left out, so logging a request can't leak it.</summary>
    /// <returns>The description.</returns>
    public override string ToString() => $"SshPasswordRequest {{ UserName = {UserName} }}";
}

/// <summary>
/// A login attempt with a public key. The handler runs before the signature is checked, so <see cref="SshAuthDecision.Accept"/>
/// only takes effect if the client proves it holds the key. OpenSSH certificates aren't supported on the server: one is
/// a failed attempt, and the handler never sees it.
/// </summary>
/// <param name="UserName">The user name. It's unverified, and chosen by the client.</param>
/// <param name="KeyType">The key type, for example <c>ssh-ed25519</c>.</param>
/// <param name="Sha256Fingerprint">The key's fingerprint in OpenSSH form.</param>
/// <example>
/// <code>
/// PublicKeyHandler = (request, ct) => ValueTask.FromResult(
///     allowed.Contains(request.Sha256Fingerprint) ? SshAuthDecision.Accept : SshAuthDecision.Reject),
/// </code>
/// </example>
public sealed record SshPublicKeyRequest(string UserName, string KeyType, string Sha256Fingerprint);

/// <summary>Who logged in.</summary>
/// <param name="UserName">The authenticated user.</param>
/// <param name="Methods">Every method that passed, in order.</param>
/// <param name="KeyFingerprint">The fingerprint of the key that was proven, if one was.</param>
/// <example>
/// <code>
/// if (!session.Principal.Methods.Contains("publickey"))
/// {
///     return 1;
/// }
/// </code>
/// </example>
public sealed record SshPrincipal(string UserName, IReadOnlyList<string> Methods, string? KeyFingerprint);

/// <summary>Why a session started.</summary>
public enum SshSessionKind
{
    /// <summary>The client asked to run <see cref="SshServerSession.Command"/>.</summary>
    Exec,

    /// <summary>The client asked for a shell.</summary>
    Shell,

    /// <summary>The client asked for the subsystem in <see cref="SshServerSession.Command"/>.</summary>
    Subsystem,
}

/// <summary>The terminal a client asked for.</summary>
/// <param name="Terminal">The terminal type.</param>
/// <param name="Columns">The width in characters.</param>
/// <param name="Rows">The height in characters.</param>
/// <example>
/// <code>
/// if (session.Pty is { } pty)
/// {
///     Console.WriteLine($"{pty.Columns}x{pty.Rows}");
/// }
/// </code>
/// </example>
public sealed record SshPtyRequest(string Terminal, int Columns, int Rows);

/// <summary>Everything a session handler needs. All of it comes from an authenticated client, but is still client-controlled.</summary>
/// <example>
/// <code>
/// SessionHandler = async (session, ct) =>
/// {
///     await session.Output.WriteAsync("hello\n"u8.ToArray(), ct);
///     return 0;
/// },
/// </code>
/// </example>
public sealed class SshServerSession
{
    internal SshServerSession(
        SshPrincipal principal,
        SshSessionKind kind,
        string? command,
        SshPtyRequest? pty,
        IReadOnlyDictionary<string, string> environment,
        Stream input,
        Stream output,
        Stream error)
    {
        Principal = principal;
        Kind = kind;
        Command = command;
        Pty = pty;
        Environment = environment;
        Input = input;
        Output = output;
        Error = error;
    }

    /// <summary>Gets who logged in.</summary>
    public SshPrincipal Principal { get; }

    /// <summary>Gets why the session started.</summary>
    public SshSessionKind Kind { get; }

    /// <summary>Gets the command line or subsystem name. Null for a shell. Never pass this to a shell without thinking about what it can do.</summary>
    public string? Command { get; }

    /// <summary>Gets the terminal the client asked for, if any.</summary>
    public SshPtyRequest? Pty { get; }

    /// <summary>Gets the environment the client asked for. Don't apply these blindly: variables like <c>LD_PRELOAD</c> are dangerous.</summary>
    public IReadOnlyDictionary<string, string> Environment { get; }

    /// <summary>Gets what the client sends.</summary>
    public Stream Input { get; }

    /// <summary>Gets the stream to the client's stdout.</summary>
    public Stream Output { get; }

    /// <summary>Gets the stream to the client's stderr.</summary>
    public Stream Error { get; }
}

/// <summary>What a <see cref="SshServerOptions.DirectTcpHandler"/> decided.</summary>
public enum SshForwardDecision
{
    /// <summary>The connection is refused.</summary>
    Deny,

    /// <summary>The server connects to the target, and carries the data.</summary>
    Allow,
}

/// <summary>A logged-in client asks the server to open a TCP connection for it.</summary>
/// <param name="Principal">Who asked.</param>
/// <param name="Host">The target host, chosen by the client. Names resolve on the server, so a rule on names alone can be dodged with an address.</param>
/// <param name="Port">The target port.</param>
/// <param name="OriginatorAddress">Where the client says the connection came from. It's unverified.</param>
/// <param name="OriginatorPort">The port the client says the connection came from. It's unverified.</param>
/// <example>
/// <code>
/// DirectTcpHandler = (request, ct) => ValueTask.FromResult(
///     request.Host == "db.internal" &amp;&amp; request.Port == 5432 ? SshForwardDecision.Allow : SshForwardDecision.Deny),
/// </code>
/// </example>
public sealed record SshDirectTcpRequest(SshPrincipal Principal, string Host, int Port, string OriginatorAddress, int OriginatorPort);

/// <summary>What <see cref="SshServer.StartAsync"/> needs. It listens on loopback unless told otherwise.</summary>
/// <example>
/// <code>
/// SshServerOptions options = new()
/// {
///     Port = 2222,
///     HostKeys = [hostKey],
///     PasswordHandler = (request, ct) => users.CheckAsync(request, ct),
///     SessionHandler = (session, ct) => RunAsync(session, ct),
/// };
/// </code>
/// </example>
public sealed class SshServerOptions
{
    /// <summary>Gets the address to listen on. The default is loopback, so exposing a server is a deliberate choice.</summary>
    public IPAddress Address { get; init; } = IPAddress.Loopback;

    /// <summary>Gets the port. Zero, the default, picks a free one: read it from <see cref="SshServer.LocalEndPoint"/>.</summary>
    public int Port { get; init; }

    /// <summary>Gets the host keys. At least one is required.</summary>
    public required IReadOnlyList<SshHostKey> HostKeys { get; init; }

    /// <summary>Gets the password check. Without it, password login isn't offered.</summary>
    public Func<SshPasswordRequest, CancellationToken, ValueTask<SshAuthDecision>>? PasswordHandler { get; init; }

    /// <summary>Gets the public key check. Without it, publickey login isn't offered.</summary>
    public Func<SshPublicKeyRequest, CancellationToken, ValueTask<SshAuthDecision>>? PublicKeyHandler { get; init; }

    /// <summary>Gets the code that serves a session, which returns the exit code. It runs once per exec, shell or subsystem request.</summary>
    public required Func<SshServerSession, CancellationToken, Task<int>> SessionHandler { get; init; }

    /// <summary>
    /// Gets the decision on each direct-tcpip channel: a client asking the server to connect somewhere, as with
    /// <c>ssh -L</c>. Null, the default, refuses them all. On <see cref="SshForwardDecision.Allow"/> the server itself
    /// makes the connection, so this is what stands between a logged-in user and the server's own network. Decide on
    /// the target, not just the user. A handler that throws, or takes longer than <see cref="LoginGraceTime"/>, has
    /// denied. Each connection counts towards <see cref="MaxSessionsPerConnection"/>.
    /// The server doesn't offer remote forwarding: it refuses every <c>tcpip-forward</c> request.
    /// </summary>
    public Func<SshDirectTcpRequest, CancellationToken, ValueTask<SshForwardDecision>>? DirectTcpHandler { get; init; }

    /// <summary>
    /// Gets the methods that must all pass, for example <c>["publickey", "password"]</c> for two-factor login.
    /// Null, the default, means any one offered method is enough. The server enforces this, whatever handlers return.
    /// </summary>
    public IReadOnlyList<string>? RequiredAuthMethods { get; init; }

    /// <summary>Gets how long <see cref="SshServer.DisposeAsync"/> waits for handlers that ignore cancellation. The default is 10 seconds.</summary>
    public TimeSpan ShutdownTimeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>Gets the algorithms to offer. The defaults are current and need no tuning.</summary>
    public SshAlgorithms Algorithms { get; init; } = SshAlgorithms.Default;

    /// <summary>Gets a text sent to clients before login.</summary>
    public string? Banner { get; init; }

    /// <summary>Gets the most connections at once. The default is 100.</summary>
    public int MaxConnections { get; init; } = 100;

    /// <summary>Gets the most connections not yet logged in. The default is 20. It stops idle connections crowding out real users.</summary>
    public int MaxUnauthenticatedConnections { get; init; } = 20;

    /// <summary>Gets the time allowed to log in. The default is 30 seconds.</summary>
    public TimeSpan LoginGraceTime { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Gets the failed login attempts allowed per connection. The default is 6.</summary>
    public int MaxAuthAttempts { get; init; } = 6;

    /// <summary>Gets the most sessions per connection, counting direct-tcpip connections. The default is 10.</summary>
    public int MaxSessionsPerConnection { get; init; } = 10;

    /// <summary>Gets the logger factory. Passwords and keys are never logged.</summary>
    public ILoggerFactory? LoggerFactory { get; init; }
}

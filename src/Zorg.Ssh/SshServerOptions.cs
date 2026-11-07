using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
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
/// <example>
/// <code>
/// PasswordHandler = (request, ct) => users.CheckAsync(request.UserName, request.Password, ct),
/// </code>
/// </example>
public sealed record SshPasswordRequest
{
    /// <summary>Gets the user name. It's unverified, and chosen by the client.</summary>
    public required string UserName { get; init; }

    /// <summary>Gets the password.</summary>
    public required string Password { get; init; }

    /// <summary>Gets the client's address and port, or null for a connection given to <see cref="SshServer.ServeStreamAsync"/>.</summary>
    public IPEndPoint? RemoteEndPoint { get; init; }

    /// <summary>Returns a description with the password left out, so logging a request can't leak it.</summary>
    /// <returns>The description.</returns>
    public override string ToString() => $"SshPasswordRequest {{ UserName = {UserName}, RemoteEndPoint = {RemoteEndPoint} }}";
}

/// <summary>
/// A login attempt with a public key. The handler runs before the signature is checked, so <see cref="SshAuthDecision.Accept"/>
/// only takes effect if the client proves it holds the key. OpenSSH certificates aren't supported on the server: one is
/// a failed attempt, and the handler never sees it.
/// </summary>
/// <example>
/// <code>
/// PublicKeyHandler = (request, ct) => ValueTask.FromResult(
///     allowed.Contains(request.Sha256Fingerprint) ? SshAuthDecision.Accept : SshAuthDecision.Reject),
/// </code>
/// </example>
public sealed record SshPublicKeyRequest
{
    /// <summary>Gets the user name. It's unverified, and chosen by the client.</summary>
    public required string UserName { get; init; }

    /// <summary>Gets the key type, for example <c>ssh-ed25519</c>.</summary>
    public required string KeyType { get; init; }

    /// <summary>Gets the key's fingerprint in OpenSSH form.</summary>
    public required string Sha256Fingerprint { get; init; }

    /// <summary>Gets the client's address and port, or null for a connection given to <see cref="SshServer.ServeStreamAsync"/>.</summary>
    public IPEndPoint? RemoteEndPoint { get; init; }
}

/// <summary>Who logged in.</summary>
/// <example>
/// <code>
/// if (!session.Principal.Methods.Contains("publickey"))
/// {
///     return 1;
/// }
/// </code>
/// </example>
public sealed record SshPrincipal
{
    /// <summary>Gets the authenticated user.</summary>
    public required string UserName { get; init; }

    /// <summary>Gets every method that passed, in order.</summary>
    public required IReadOnlyList<string> Methods { get; init; }

    /// <summary>
    /// Gets the fingerprint of every key the client proved it holds during login, in the order it proved them.
    /// It is empty if no key was used. A key counts once, however often it was offered, and a login can prove
    /// only a few. A key listed here may belong to a step that <see cref="Methods"/> doesn't count, because a
    /// method passes once however many keys the client proves.
    /// </summary>
    /// <example>
    /// <code>
    /// if (!session.Principal.KeyFingerprints.Contains(adminFingerprint))
    /// {
    ///     return 1;
    /// }
    /// </code>
    /// </example>
    public IReadOnlyList<string> KeyFingerprints { get; init; } = [];
}

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
/// <example>
/// <code>
/// if (session.Pty is { } pty)
/// {
///     Console.WriteLine($"{pty.Columns}x{pty.Rows}");
/// }
/// </code>
/// </example>
public sealed record SshPtyRequest
{
    /// <summary>Gets the terminal type.</summary>
    public required string Terminal { get; init; }

    /// <summary>Gets the width in characters.</summary>
    public required int Columns { get; init; }

    /// <summary>Gets the height in characters.</summary>
    public required int Rows { get; init; }
}

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
        Stream error,
        IPEndPoint? remoteEndPoint)
    {
        Principal = principal;
        RemoteEndPoint = remoteEndPoint;
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

    /// <summary>Gets the client's address and port, or null for a connection given to <see cref="SshServer.ServeStreamAsync"/>.</summary>
    public IPEndPoint? RemoteEndPoint { get; }

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
/// <example>
/// <code>
/// DirectTcpHandler = (request, ct) => ValueTask.FromResult(
///     request.Host == "db.internal" &amp;&amp; request.Port == 5432 ? SshForwardDecision.Allow : SshForwardDecision.Deny),
/// </code>
/// </example>
public sealed record SshDirectTcpRequest
{
    /// <summary>Gets who asked.</summary>
    public required SshPrincipal Principal { get; init; }

    /// <summary>Gets the target host, chosen by the client. Names resolve on the server, so a rule on names alone can be dodged with an address.</summary>
    public required string Host { get; init; }

    /// <summary>Gets the target port.</summary>
    public required int Port { get; init; }

    /// <summary>Gets where the client says the connection came from. It's unverified.</summary>
    public required string OriginatorAddress { get; init; }

    /// <summary>Gets the port the client says the connection came from. It's unverified.</summary>
    public required int OriginatorPort { get; init; }
}

/// <summary>
/// What <see cref="SshServer.StartAsync"/> needs. It listens on loopback unless told otherwise. Use <c>with</c> to
/// change a copy. <see cref="ToString"/> shows only the address and port, so logging options can't leak a key.
/// </summary>
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
public sealed record SshServerOptions
{
    /// <summary>Gets the address to listen on. The default is loopback, so exposing a server is a deliberate choice.</summary>
    public IPAddress Address { get; init; } = IPAddress.Loopback;

    /// <summary>Gets the port. Zero, the default, picks a free one: read it from <see cref="SshServer.LocalEndPoint"/>.</summary>
    public int Port { get; init; }

    /// <summary>Gets the host keys. At least one is required.</summary>
    public required IReadOnlyList<SshHostKey> HostKeys { get; init; }

    /// <summary>Gets the password check. Without it, password login isn't offered. One that throws has rejected the attempt, and the failure is logged.</summary>
    public Func<SshPasswordRequest, CancellationToken, ValueTask<SshAuthDecision>>? PasswordHandler { get; init; }

    /// <summary>Gets the public key check. Without it, publickey login isn't offered. One that throws has rejected the attempt, and the failure is logged.</summary>
    public Func<SshPublicKeyRequest, CancellationToken, ValueTask<SshAuthDecision>>? PublicKeyHandler { get; init; }

    /// <summary>
    /// Gets the code that serves a session, which returns the exit code. It runs once per exec, shell or subsystem
    /// request. One that throws ends the session with exit code 1, and the failure is logged.
    /// </summary>
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

    /// <summary>
    /// Gets the most connections not yet logged in that one source address may hold. The default is 5. Without it,
    /// one address could hold every <see cref="MaxUnauthenticatedConnections"/> slot and lock everyone else out.
    /// An IPv4-mapped IPv6 address counts as its IPv4 address, and IPv6 addresses count together by /64 prefix,
    /// because one host commonly owns a whole /64. A connection given to <see cref="SshServer.ServeStreamAsync"/>
    /// has no address, so it isn't counted here. Must be at least 1.
    /// </summary>
    /// <example>
    /// <code>
    /// SshServerOptions options = new()
    /// {
    ///     HostKeys = [hostKey],
    ///     PasswordHandler = handler,
    ///     SessionHandler = RunSessionAsync,
    ///     MaxUnauthenticatedPerAddress = 3,
    /// };
    /// </code>
    /// </example>
    public int MaxUnauthenticatedPerAddress { get; init; } = 5;

    /// <summary>
    /// Gets how long a logged-in connection may have no open channel before the server closes it, like OpenSSH's
    /// <c>UnusedConnectionTimeout</c>. Null, the default, means never. Opening a channel resets it, and the clock
    /// restarts when the last channel closes, except for a channel the server refused, such as a denied direct-tcpip
    /// open: refused opens can't keep a connection alive. A channel that arrives after the server has decided the
    /// connection is idle is refused too. Keepalive traffic doesn't count as activity. Must be above zero.
    /// </summary>
    /// <example>
    /// <code>
    /// SshServerOptions options = new()
    /// {
    ///     HostKeys = [hostKey],
    ///     PasswordHandler = handler,
    ///     SessionHandler = RunSessionAsync,
    ///     IdleTimeout = TimeSpan.FromMinutes(10),
    /// };
    /// </code>
    /// </example>
    public TimeSpan? IdleTimeout { get; init; }

    /// <summary>Gets the time allowed to log in. The default is 30 seconds.</summary>
    public TimeSpan LoginGraceTime { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Gets how long the connection can be silent before a probe goes out. The default is 5 minutes, and
    /// <see cref="TimeSpan.Zero"/> turns keepalive and the stalled-send check off. Otherwise it's 1 second to 1 day.
    /// Keepalive starts after login. Any packet from the client counts as an answer, so a busy connection sends no
    /// probes. If it stays silent for <see cref="KeepAliveCountMax"/> more intervals, or one write to it stays
    /// unfinished for this interval times <see cref="KeepAliveCountMax"/>, the connection fails with
    /// <see cref="SshConnectionException"/> and everything waiting on it wakes. A client that answers probes but grants no window is alive: a handler writing to it needs its token.
    /// </summary>
    /// <example>
    /// <code>
    /// KeepAliveInterval = TimeSpan.FromSeconds(15),
    /// </code>
    /// </example>
    public TimeSpan KeepAliveInterval { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets how many intervals of silence after the probe end the connection. The default is 3, and it's 1 to 1000.
    /// With the defaults, a dead client is noticed after 20 minutes of silence, and a stalled send after 15 minutes or a little more.
    /// </summary>
    /// <example>
    /// <code>
    /// KeepAliveCountMax = 5,
    /// </code>
    /// </example>
    public int KeepAliveCountMax { get; init; } = 3;

    /// <summary>Gets the clock, for tests.</summary>
    internal TimeProvider TimeProvider { get; init; } = TimeProvider.System;

    /// <summary>Gets a hook that sees each connection once it is authenticated and running. For tests that count what a connection holds; it changes nothing.</summary>
    internal Action<Connection.SshConnection>? ConnectionStarted { get; init; }

    /// <summary>Gets the failed login attempts allowed per connection. The default is 6.</summary>
    public int MaxAuthAttempts { get; init; } = 6;

    /// <summary>Gets the most sessions per connection, counting direct-tcpip connections. The default is 10.</summary>
    public int MaxSessionsPerConnection { get; init; } = 10;

    /// <summary>Gets the logger factory. Passwords and keys are never logged.</summary>
    public ILoggerFactory? LoggerFactory { get; init; }

    /// <summary>Prints the address and port only. Guarantee 4: host keys and handlers never reach a string.</summary>
    private bool PrintMembers(StringBuilder builder)
    {
        builder.Append("Address = ").Append(Address).Append(", Port = ").Append(Port);
        return true;
    }
}

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Zorg.Ssh.Auth;
using Zorg.Ssh.Connection;
using Zorg.Ssh.Forwarding;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Transport;

namespace Zorg.Ssh;

/// <summary>An SSH server. Start with <see cref="StartAsync"/>, and dispose it to stop.</summary>
/// <example>
/// <code>
/// await using SshServer server = await SshServer.StartAsync(new SshServerOptions
/// {
///     Port = 2222,
///     HostKeys = [hostKey],
///     PasswordHandler = (request, ct) => users.CheckAsync(request, ct),
///     SessionHandler = async (session, ct) =>
///     {
///         await session.Output.WriteAsync("hello\n"u8.ToArray(), ct);
///         return 0;
///     },
/// }, cancellationToken);
/// </code>
/// </example>
public sealed partial class SshServer : IAsyncDisposable
{
    private const int MaxEnvironmentEntries = 64;
    private const int MaxEnvironmentName = 256;
    private const int MaxEnvironmentValue = 8 * 1024;
    private const int MaxForwardHost = 255;

    private readonly SshServerOptions _options;
    private readonly ILogger _logger;
    private readonly TcpListener _listener;
    // Never disposed: a handler that ignored cancellation can outlive the server, and still hold a token from it.
#pragma warning disable CA2213
    private readonly CancellationTokenSource _stop = new();
#pragma warning restore CA2213
    private readonly ConcurrentDictionary<Task, bool> _connections = new();
    private readonly TransportOptions _transportOptions;
    private int _connectionCount;
    private readonly PerAddressLimiter _perAddress;
    private readonly TimeProvider _idleTime;
    private int _unauthenticatedCount;
    private int _disposed;
    private Task? _acceptLoop;

    private SshServer(SshServerOptions options, TcpListener listener, TimeProvider idleTime)
    {
        _options = options;
        _idleTime = idleTime;
        _perAddress = new PerAddressLimiter(options.MaxUnauthenticatedPerAddress);
        _listener = listener;
        _logger = options.LoggerFactory?.CreateLogger<SshServer>() ?? NullLogger<SshServer>.Instance;
        _transportOptions = new TransportOptions
        {
            Role = SshRole.Server,
            HostKeys = [.. options.HostKeys.Select(k => k.Key)],
            HandshakeTimeout = options.LoginGraceTime,
            KeepAliveInterval = options.KeepAliveInterval,
            KeepAliveCountMax = options.KeepAliveCountMax,
            TimeProvider = options.TimeProvider,
            KexAlgorithms = options.Algorithms.ServerKeyExchange,
            KeyExchangeExtension = options.Algorithms.KeyExchangeExtension,
            HostKeyAlgorithms = options.Algorithms.HostKeys,
            ServerSignatureAlgorithms = options.Algorithms.ServerSignatureAlgorithms,
            Ciphers = options.Algorithms.Ciphers,
            Macs = options.Algorithms.Macs,
            Logger = _logger,
        };
    }

    /// <summary>Gets how many source addresses have a counted unauthenticated connection. For tests: it must return to zero.</summary>
    internal int UnauthenticatedAddressCount => _perAddress.Entries;

    /// <summary>Gets the address and port the server listens on.</summary>
    public IPEndPoint LocalEndPoint => (IPEndPoint)_listener.LocalEndpoint;

    /// <summary>Starts listening.</summary>
    /// <param name="options">The host keys, handlers and limits.</param>
    /// <param name="cancellationToken">Cancels the start. It doesn't stop a started server: dispose it for that.</param>
    /// <returns>The running server.</returns>
    /// <example>
    /// <code>
    /// await using SshServer server = await SshServer.StartAsync(options, cancellationToken);
    /// Console.WriteLine(server.LocalEndPoint);
    /// </code>
    /// </example>
    public static Task<SshServer> StartAsync(SshServerOptions options, CancellationToken cancellationToken = default)
        => StartWithClockAsync(options, TimeProvider.System, cancellationToken);

    /// <summary>Starts listening with a time source for the idle timeout, so tests don't have to sleep.</summary>
    internal static Task<SshServer> StartWithClockAsync(SshServerOptions options, TimeProvider idleTime, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        cancellationToken.ThrowIfCancellationRequested();
        if (options.HostKeys.Count == 0)
        {
            throw new ArgumentException("A server needs at least one host key.", nameof(options));
        }

        options.Algorithms.Validate();
        TransportOptions.ValidateKeepAlive(options.KeepAliveInterval, options.KeepAliveCountMax);
        if (options.PasswordHandler is null && options.PublicKeyHandler is null)
        {
            throw new ArgumentException("Set PasswordHandler or PublicKeyHandler, or nobody can log in.", nameof(options));
        }

        if (options.MaxUnauthenticatedPerAddress < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.MaxUnauthenticatedPerAddress, "MaxUnauthenticatedPerAddress must be at least 1, or nobody can log in.");
        }

        if (options.IdleTimeout is { } idle && idle <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(options), idle, "IdleTimeout must be above zero. Leave it null for no idle timeout.");
        }

        TcpListener listener = new(options.Address, options.Port);
        listener.Start();
        SshServer server = new(options, listener, idleTime);
        server._acceptLoop = Task.Run(server.AcceptLoopAsync, CancellationToken.None);
        return Task.FromResult(server);
    }

    /// <summary>
    /// Serves a connection you've accepted yourself, such as one arriving through a tunnel. It counts towards
    /// the same limits as a listened-for connection. The server owns the stream from here on.
    /// </summary>
    /// <param name="stream">The connected stream.</param>
    /// <param name="cancellationToken">Closes the connection.</param>
    /// <returns>A task that completes when the connection ends. It doesn't fail because of the client.</returns>
    /// <exception cref="SshConnectionException">The server is at a connection limit.</exception>
    /// <example>
    /// <code>
    /// await server.ServeStreamAsync(tunnelStream, cancellationToken);
    /// </code>
    /// </example>
    public async Task ServeStreamAsync(Stream stream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (Volatile.Read(ref _disposed) != 0 || !TryReserve())
        {
            await stream.DisposeAsync().ConfigureAwait(false);
            LogLimitReached(_logger);
            throw new SshConnectionException("The server is at its connection limit. Raise MaxConnections or MaxUnauthenticatedConnections, or try later.");
        }

        using CancellationTokenRegistration closeOnCancel = cancellationToken.Register(static s => ((Stream)s!).Dispose(), stream);
        await Track(stream).ConfigureAwait(false);
    }

    /// <summary>Stops listening, closes every connection, and waits for handlers to end.</summary>
    /// <returns>A task that completes when everything has stopped.</returns>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        await _stop.CancelAsync().ConfigureAwait(false);
        _listener.Stop();
        if (_acceptLoop is not null)
        {
            await _acceptLoop.ConfigureAwait(false);
        }

        try
        {
            await Task.WhenAll(_connections.Keys).WaitAsync(_options.ShutdownTimeout).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            // A handler is ignoring its token. It keeps running, but it can't hold the caller for ever.
            LogShutdownTimedOut(_logger);
        }

        _listener.Dispose();
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "Refused a connection: limit reached")]
    private static partial void LogLimitReached(ILogger logger);

    [LoggerMessage(Level = LogLevel.Information, Message = "Closed a connection with no open channel for {IdleTimeout}")]
    private static partial void LogIdleClosed(ILogger logger, TimeSpan idleTimeout);

    [LoggerMessage(Level = LogLevel.Warning, Message = "A session handler ignored cancellation during shutdown")]
    private static partial void LogShutdownTimedOut(ILogger logger);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Connection ended")]
    private static partial void LogConnectionEnded(ILogger logger, Exception exception);

    [LoggerMessage(Level = LogLevel.Error, Message = "A session handler failed")]
    private static partial void LogHandlerFailed(ILogger logger, Exception exception);

    private static string ParseString(byte[] data)
    {
        SshReader reader = new(data);
        return reader.ReadUtf8String();
    }

    private static (string Name, string Value) ParseEnvironment(byte[] data)
    {
        SshReader reader = new(data);
        return (reader.ReadUtf8String(), reader.ReadUtf8String());
    }

    private static SshPtyRequest ParsePty(byte[] data)
    {
        SshReader reader = new(data);
        string terminal = reader.ReadUtf8String();
        int columns = (int)Math.Min(reader.ReadUInt32(), 65535);
        int rows = (int)Math.Min(reader.ReadUInt32(), 65535);
        return new SshPtyRequest { Terminal = terminal, Columns = columns, Rows = rows };
    }

    /// <summary>Reads a direct-tcpip open. Returns null for one that names no real target, which the handler never sees.</summary>
    private static SshDirectTcpRequest? ParseDirectTcp(byte[] extra, SshPrincipal principal)
    {
        try
        {
            SshReader reader = new(extra);
            string host = reader.ReadUtf8String();
            uint port = reader.ReadUInt32();
            string origin = reader.ReadUtf8String();
            uint originPort = reader.ReadUInt32();
            if (host.Length is 0 or > MaxForwardHost || port is 0 or > 65535 || host.Any(char.IsControl))
            {
                return null;
            }

            return new SshDirectTcpRequest
            {
                Principal = principal,
                Host = host,
                Port = (int)port,
                OriginatorAddress = PeerText.Clean(origin, MaxForwardHost),
                OriginatorPort = (int)Math.Min(originPort, 65535),
            };
        }
        catch (SshProtocolException)
        {
            return null;
        }
    }

    private async Task AcceptLoopAsync()
    {
        while (true)
        {
            Socket socket;
            try
            {
                socket = await _listener.AcceptSocketAsync(_stop.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException or InvalidOperationException)
            {
                if (_stop.IsCancellationRequested)
                {
                    return;
                }

                continue;
            }

            if (!TryConfigure(socket) || SourceEndPoint(socket) is not { } remote)
            {
                socket.Dispose();
                continue;
            }

            IPAddress address = remote.Address;

            // S6: refused before a single byte is read, so a flood costs almost nothing.
            if (!TryReserve(address))
            {
                LogLimitReached(_logger);
                socket.Dispose();
                continue;
            }

            try
            {
#pragma warning disable CA2000 // The connection owns the stream, and closes it on every path.
                _ = Track(new NetworkStream(socket, ownsSocket: true), remote);
#pragma warning restore CA2000
            }
            catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
            {
                // The socket died before the connection took it over, so nothing else will give the counts back.
                Interlocked.Decrement(ref _connectionCount);
                ReleaseUnauthenticated(address);
                socket.Dispose();
            }
        }
    }

    private static bool TryConfigure(Socket socket)
    {
        try
        {
            socket.NoDelay = true;

            // So a client that vanishes without a word is noticed eventually.
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            return true;
        }
        catch (SocketException)
        {
            return false;
        }
    }

    /// <summary>Reads the peer's address and port, or null if the socket has already gone.</summary>
    private static IPEndPoint? SourceEndPoint(Socket socket)
    {
        try
        {
            return socket.RemoteEndPoint as IPEndPoint;
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
        {
            return null;
        }
    }

    /// <summary>
    /// Takes a connection slot, an unauthenticated slot and, when the source is known, a per-address count. It
    /// takes all or nothing. A stream has no address, so it isn't counted per address.
    /// </summary>
    private bool TryReserve(IPAddress? address = null)
    {
        if (Interlocked.Increment(ref _connectionCount) > _options.MaxConnections)
        {
            Interlocked.Decrement(ref _connectionCount);
            return false;
        }

        if (Interlocked.Increment(ref _unauthenticatedCount) > _options.MaxUnauthenticatedConnections)
        {
            Interlocked.Decrement(ref _unauthenticatedCount);
            Interlocked.Decrement(ref _connectionCount);
            return false;
        }

        if (address is not null && !_perAddress.TryAcquire(address))
        {
            Interlocked.Decrement(ref _unauthenticatedCount);
            Interlocked.Decrement(ref _connectionCount);
            return false;
        }

        return true;
    }

    /// <summary>Gives back the unauthenticated slot and the per-address count. Each connection calls this exactly once.</summary>
    private void ReleaseUnauthenticated(IPAddress? address)
    {
        Interlocked.Decrement(ref _unauthenticatedCount);
        if (address is not null)
        {
            _perAddress.Release(address);
        }
    }

    private Task Track(Stream stream, IPEndPoint? remote = null)
    {
        Task connection = Task.Run(() => ServeAsync(stream, remote), CancellationToken.None);
        _connections.TryAdd(connection, true);
        _ = connection.ContinueWith(
            finished => _connections.TryRemove(finished, out _),
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
        return connection;
    }

    private async Task ServeAsync(Stream stream, IPEndPoint? remote)
    {
        IPAddress? address = remote?.Address;
        bool authenticated = false;
        SshTransport? transport = null;
        try
        {
            using CancellationTokenSource grace = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
            grace.CancelAfter(_options.LoginGraceTime);

#pragma warning disable CA2000 // The finally block or the connection owns the transport.
            transport = await SshTransport.StartAsync(stream, _transportOptions, grace.Token).ConfigureAwait(false);
#pragma warning restore CA2000

            ServerAuthenticator authenticator = new(transport, BuildAuthOptions(remote));
            AuthenticatedUser user = await authenticator.AuthenticateAsync(grace.Token).ConfigureAwait(false);
            authenticated = true;
            ReleaseUnauthenticated(address);

            SshPrincipal principal = new()
            {
                UserName = user.Name,
                Methods = user.Methods,
                KeyFingerprints = [.. user.ProvenKeys.Select(static k => HostKeyPolicy.ComputeFingerprint(k.Blob.Span))],
            };

            SshConnection connection = new(transport, _options.MaxSessionsPerConnection)
            {
                AcceptIncomingChannels = true,
                AcceptDirectTcp = _options.DirectTcpHandler is not null,
            };
            transport = null;
            await using (connection.ConfigureAwait(false))
            {
                connection.Start();
                _options.ConnectionStarted?.Invoke(connection);
                await ServeChannelsAsync(connection, principal, remote).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is SshException or OperationCanceledException or IOException)
        {
            LogConnectionEnded(_logger, ex);
        }
        finally
        {
            if (transport is not null)
            {
                await transport.DisposeAsync().ConfigureAwait(false);
            }
            else if (!authenticated)
            {
                await stream.DisposeAsync().ConfigureAwait(false);
            }

            if (!authenticated)
            {
                ReleaseUnauthenticated(address);
            }

            Interlocked.Decrement(ref _connectionCount);
        }
    }

    private ServerAuthOptions BuildAuthOptions(IPEndPoint? remote)
    {
        SshServerOptions options = _options;
        return new ServerAuthOptions
        {
            Banner = options.Banner,
            MaxAttempts = options.MaxAuthAttempts,
            RequiredMethods = options.RequiredAuthMethods,
            AllowRsaSha1 = options.Algorithms.AllowsRsaSha1,
            Password = options.PasswordHandler is { } password
                ? (user, secret, ct) => CheckAsync(() => password(new SshPasswordRequest { UserName = user, Password = secret, RemoteEndPoint = remote }, ct))
                : null,
            PublicKey = options.PublicKeyHandler is { } key
                ? (user, publicKey, ct) => CheckAsync(() => key(
                    new SshPublicKeyRequest
                    {
                        UserName = user,
                        KeyType = publicKey.KeyType,
                        Sha256Fingerprint = HostKeyPolicy.ComputeFingerprint(publicKey.Blob.Span),
                        RemoteEndPoint = remote,
                    },
                    ct))
                : null,
        };
    }

    /// <summary>Runs an auth handler. One that throws has said no, and the client learns nothing more.</summary>
    private async ValueTask<AuthDecision> CheckAsync(Func<ValueTask<SshAuthDecision>> handler)
    {
        try
        {
            return (AuthDecision)await handler().ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
#pragma warning disable CA1031 // Application code can throw anything, and it must not end the server's loop.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            LogHandlerFailed(_logger, ex);
            return AuthDecision.Reject;
        }
    }

    private async Task ServeChannelsAsync(SshConnection connection, SshPrincipal principal, IPEndPoint? remote)
    {
        List<Task> sessions = [];
        IdleMonitor? idle = _options.IdleTimeout is { } timeout ? new IdleMonitor(timeout, _idleTime) : null;

        // Ends the accept loop below, either because the server is stopping or because the connection sat idle.
        using CancellationTokenSource ended = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
#pragma warning disable CA2025 // The finally block below awaits the watcher before the source is disposed.
        Task watcher = CloseWhenIdleAsync(idle, ended);
#pragma warning restore CA2025
        try
        {
            try
            {
                await foreach (IncomingChannelOpen open in connection.IncomingChannels.ReadAllAsync(ended.Token).ConfigureAwait(false))
                {
                    if (idle is not null && !idle.ChannelOpened())
                    {
                        // The idle decision was made first. The connection is closing, so this open isn't served.
                        sessions.Add(Task.Run(() => RefuseAfterIdleAsync(connection, open), CancellationToken.None));
                        continue;
                    }

                    sessions.Add(open.Channel is { } channel
                        ? Task.Run(() => RunCountedAsync(idle, async () =>
                        {
                            await ServeSessionAsync(connection, channel, principal, remote).ConfigureAwait(false);
                            return true;
                        }), CancellationToken.None)
                        : Task.Run(() => RunCountedAsync(idle, () => ServeDirectTcpAsync(connection, open, principal)), CancellationToken.None));
                    sessions.RemoveAll(static s => s.IsCompleted);
                }
            }
            catch (OperationCanceledException)
            {
                // The server is stopping, or the connection was idle.
            }

            await Task.WhenAll(sessions).ConfigureAwait(false);
        }
        finally
        {
            await ended.CancelAsync().ConfigureAwait(false);
            await watcher.ConfigureAwait(false);
        }
    }

    /// <summary>Runs one channel's work and tells the idle clock when it ends, however it ends.</summary>
    /// <remarks>The work returns false if the channel was refused, which doesn't restart the idle clock.</remarks>
    private static async Task RunCountedAsync(IdleMonitor? idle, Func<Task<bool>> work)
    {
        bool served = false;
        try
        {
            served = await work().ConfigureAwait(false);
        }
        finally
        {
            idle?.ChannelClosed(restartClock: served);
        }
    }

    /// <summary>Ends an open that arrived after the connection was judged idle: a session is closed, a direct-tcpip open refused.</summary>
    private async Task RefuseAfterIdleAsync(SshConnection connection, IncomingChannelOpen open)
    {
        try
        {
            if (open.Channel is { } channel)
            {
                await channel.DisposeAsync().ConfigureAwait(false);
            }
            else
            {
                await connection.RefuseIncomingAsync(open, SshConnection.OpenFailureResourceShortage, "connection closing", _stop.Token).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is SshException or OperationCanceledException or IOException or ObjectDisposedException)
        {
            LogConnectionEnded(_logger, ex);
        }
        finally
        {
            connection.ReleaseIncomingSession();
        }
    }

    private async Task CloseWhenIdleAsync(IdleMonitor? idle, CancellationTokenSource ended)
    {
        if (idle is null)
        {
            return;
        }

        try
        {
            await idle.WaitForIdleAsync(ended.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        LogIdleClosed(_logger, _options.IdleTimeout!.Value);

        // The connection is disposed after this, which sends the DISCONNECT.
        await ended.CancelAsync().ConfigureAwait(false);
    }

    /// <summary>
    /// Owns one direct-tcpip connection from start to end, like <see cref="ServeSessionAsync"/>. The client hears
    /// the answer only after the handler and the connect, so a refusal is a refused channel, not a closed one.
    /// Returns whether the open was accepted: a refused one is no use of the connection, so it doesn't restart the idle clock.
    /// </summary>
    private async Task<bool> ServeDirectTcpAsync(SshConnection connection, IncomingChannelOpen open, SshPrincipal principal)
    {
        bool accepted = false;
        try
        {
            (Socket? target, int refusal) = await ConnectDirectTcpAsync(open, principal).ConfigureAwait(false);
            if (target is null)
            {
                await connection.RefuseIncomingAsync(open, refusal, "refused", _stop.Token).ConfigureAwait(false);
                return false;
            }

            SshChannel channel;
            try
            {
                channel = await connection.AcceptIncomingAsync(open, _stop.Token).ConfigureAwait(false);
            }
            catch
            {
                target.Dispose();
                throw;
            }

            accepted = true;
            await TcpRelay.RunAsync(channel, target, _stop.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SshException or OperationCanceledException or IOException or SocketException or ObjectDisposedException)
        {
            LogConnectionEnded(_logger, ex);
        }
        finally
        {
            connection.ReleaseIncomingSession();
        }

        return accepted;
    }

    /// <summary>Asks the handler, and connects if it said yes. Without a socket, the second value is the reason to refuse with.</summary>
    private async Task<(Socket? Target, int Refusal)> ConnectDirectTcpAsync(IncomingChannelOpen open, SshPrincipal principal)
    {
        if (ParseDirectTcp(open.Extra, principal) is not { } request)
        {
            return (null, SshConnection.OpenFailureProhibited);
        }

        // Both steps can take as long as they like otherwise, and the client's slot goes with them.
        using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
        limit.CancelAfter(_options.LoginGraceTime);
        try
        {
            SshForwardDecision decision = await _options.DirectTcpHandler!(request, limit.Token).AsTask().WaitAsync(limit.Token).ConfigureAwait(false);
            if (decision != SshForwardDecision.Allow)
            {
                return (null, SshConnection.OpenFailureProhibited);
            }
        }
        catch (OperationCanceledException)
        {
            return (null, SshConnection.OpenFailureProhibited);
        }
#pragma warning disable CA1031 // S4: application code can throw anything, and the peer learns nothing from it.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            LogHandlerFailed(_logger, ex);
            return (null, SshConnection.OpenFailureProhibited);
        }

        try
        {
            return (await TcpRelay.ConnectAsync(request.Host, request.Port, limit.Token).ConfigureAwait(false), 0);
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ArgumentException)
        {
            LogConnectionEnded(_logger, ex);
            return (null, SshConnection.OpenFailureConnectFailed);
        }
    }

    /// <summary>
    /// Owns one session from start to end. The channel, the handler and the session slot all live and die here,
    /// so none of them can outlast the others: the slot is only freed once the handler has really ended.
    /// </summary>
    private async Task ServeSessionAsync(SshConnection connection, SshChannel channel, SshPrincipal principal, IPEndPoint? remote)
    {
        using CancellationTokenSource session = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
        Task? running = null;
        try
        {
            running = await ServeRequestsAsync(channel, principal, remote, session).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SshException or OperationCanceledException)
        {
            LogConnectionEnded(_logger, ex);
        }
        finally
        {
            // The request stream only ends when the client has closed or gone, so this tells the handler to stop.
            await session.CancelAsync().ConfigureAwait(false);
            if (running is not null)
            {
                await running.ConfigureAwait(false);
            }

            await channel.DisposeAsync().ConfigureAwait(false);
            connection.ReleaseIncomingSession();
        }
    }

    /// <summary>Handles requests until the channel closes. Returns the running handler, if one was started.</summary>
    private async Task<Task?> ServeRequestsAsync(SshChannel channel, SshPrincipal principal, IPEndPoint? remote, CancellationTokenSource session)
    {
        Dictionary<string, string> environment = new(StringComparer.Ordinal);
        SshPtyRequest? pty = null;
        Task? running = null;
        CancellationToken token = session.Token;
        try
        {
            await foreach (IncomingChannelRequest request in channel.Requests.ReadAllAsync(token).ConfigureAwait(false))
            {
                bool ok;
                SshServerSession? start = null;
                try
                {
                    switch (request.Type)
                    {
                        case "env" when running is null:
                            (string name, string value) = ParseEnvironment(request.Data);
                            ok = environment.Count < MaxEnvironmentEntries
                                && name.Length <= MaxEnvironmentName
                                && value.Length <= MaxEnvironmentValue;
                            if (ok)
                            {
                                environment[name] = value;
                            }

                            break;
                        case "pty-req" when running is null:
                            pty = ParsePty(request.Data);
                            ok = true;
                            break;
                        case "window-change":
                            ok = true;
                            break;
                        case "exec" or "shell" or "subsystem" when running is null:
                            SshSessionKind kind = request.Type switch
                            {
                                "exec" => SshSessionKind.Exec,
                                "shell" => SshSessionKind.Shell,
                                _ => SshSessionKind.Subsystem,
                            };
                            string? command = kind == SshSessionKind.Shell ? null : ParseString(request.Data);
                            start = new(principal, kind, command, pty, environment, channel.Output, channel.Input, channel.ErrorInput, remote);
                            ok = true;
                            break;
                        default:
                            ok = false;
                            break;
                    }
                }
                catch (SshProtocolException)
                {
                    // A malformed request fails that request. It's a client bug, not a reason to abandon a handler.
                    ok = false;
                }

                if (request.WantReply)
                {
                    await channel.ReplyAsync(ok, token).ConfigureAwait(false);
                }

                // Only after the reply: the handler's output must not reach the client ahead of it.
                if (start is not null)
                {
                    running = RunHandlerAsync(channel, start, session);
                }
            }
        }
        catch (Exception ex) when (running is not null && ex is SshException or OperationCanceledException)
        {
            LogConnectionEnded(_logger, ex);
        }

        return running;
    }

    private async Task RunHandlerAsync(SshChannel channel, SshServerSession session, CancellationTokenSource lifetime)
    {
        // The handler runs on its own, so a slow start can't hold up the request loop.
        await Task.Yield();
        CancellationToken token = lifetime.Token;
        int exitCode;
        try
        {
            exitCode = await _options.SessionHandler(session, token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            return;
        }
#pragma warning disable CA1031 // S4: handler failures end the session, and the peer learns nothing from them.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            LogHandlerFailed(_logger, ex);
            exitCode = 1;
        }

        try
        {
            SshRequestWriter status = new();
            status.UInt32(unchecked((uint)exitCode));
            await channel.SendEofAsync(token).ConfigureAwait(false);
            await channel.SendRequestNoReplyAsync("exit-status", status.ToArray(), token).ConfigureAwait(false);
            await channel.CloseAsync(token).ConfigureAwait(false);

            // A client that never answers our CLOSE can't keep this session's slot.
            lifetime.CancelAfter(_options.LoginGraceTime);
        }
        catch (Exception ex) when (ex is SshException or OperationCanceledException or ObjectDisposedException)
        {
            LogConnectionEnded(_logger, ex);
        }
    }
}

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
    private int _unauthenticatedCount;
    private int _disposed;
    private Task? _acceptLoop;

    private SshServer(SshServerOptions options, TcpListener listener)
    {
        _options = options;
        _listener = listener;
        _logger = options.LoggerFactory?.CreateLogger<SshServer>() ?? NullLogger<SshServer>.Instance;
        _transportOptions = new TransportOptions
        {
            Role = SshRole.Server,
            HostKeys = [.. options.HostKeys.Select(k => k.Key)],
            HandshakeTimeout = options.LoginGraceTime,
            KexAlgorithms = options.Algorithms.KeyExchange,
            HostKeyAlgorithms = options.Algorithms.HostKeys,
            Ciphers = options.Algorithms.Ciphers,
            Macs = options.Algorithms.Macs,
            Logger = _logger,
        };
    }

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
    {
        ArgumentNullException.ThrowIfNull(options);
        cancellationToken.ThrowIfCancellationRequested();
        if (options.HostKeys.Count == 0)
        {
            throw new ArgumentException("A server needs at least one host key.", nameof(options));
        }

        options.Algorithms.Validate();
        if (options.PasswordHandler is null && options.PublicKeyHandler is null)
        {
            throw new ArgumentException("Set PasswordHandler or PublicKeyHandler, or nobody can log in.", nameof(options));
        }

        TcpListener listener = new(options.Address, options.Port);
        listener.Start();
        SshServer server = new(options, listener);
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
        return new SshPtyRequest(terminal, (int)Math.Min(reader.ReadUInt32(), 65535), (int)Math.Min(reader.ReadUInt32(), 65535));
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

            if (!TryConfigure(socket))
            {
                continue;
            }

            // S6: refused before a single byte is read, so a flood costs almost nothing.
            if (!TryReserve())
            {
                LogLimitReached(_logger);
                socket.Dispose();
                continue;
            }

#pragma warning disable CA2000 // The connection owns the stream, and closes it on every path.
            _ = Track(new NetworkStream(socket, ownsSocket: true));
#pragma warning restore CA2000
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
            socket.Dispose();
            return false;
        }
    }

    private bool TryReserve()
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

        return true;
    }

    private Task Track(Stream stream)
    {
        Task connection = Task.Run(() => ServeAsync(stream), CancellationToken.None);
        _connections.TryAdd(connection, true);
        _ = connection.ContinueWith(
            finished => _connections.TryRemove(finished, out _),
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
        return connection;
    }

    private async Task ServeAsync(Stream stream)
    {
        bool authenticated = false;
        SshTransport? transport = null;
        try
        {
            using CancellationTokenSource grace = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
            grace.CancelAfter(_options.LoginGraceTime);

#pragma warning disable CA2000 // The finally block or the connection owns the transport.
            transport = await SshTransport.StartAsync(stream, _transportOptions, grace.Token).ConfigureAwait(false);
#pragma warning restore CA2000

            ServerAuthenticator authenticator = new(transport, BuildAuthOptions());
            AuthenticatedUser user = await authenticator.AuthenticateAsync(grace.Token).ConfigureAwait(false);
            authenticated = true;
            Interlocked.Decrement(ref _unauthenticatedCount);

            SshPrincipal principal = new(
                user.Name,
                user.Methods,
                user.Key is null ? null : HostKeyPolicy.ComputeFingerprint(user.Key.Blob.Span));

            SshConnection connection = new(transport, _options.MaxSessionsPerConnection) { AcceptIncomingChannels = true };
            transport = null;
            await using (connection.ConfigureAwait(false))
            {
                connection.Start();
                await ServeChannelsAsync(connection, principal).ConfigureAwait(false);
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
                Interlocked.Decrement(ref _unauthenticatedCount);
            }

            Interlocked.Decrement(ref _connectionCount);
        }
    }

    private ServerAuthOptions BuildAuthOptions()
    {
        SshServerOptions options = _options;
        return new ServerAuthOptions
        {
            Banner = options.Banner,
            MaxAttempts = options.MaxAuthAttempts,
            RequiredMethods = options.RequiredAuthMethods,
            Password = options.PasswordHandler is { } password
                ? (user, secret, ct) => CheckAsync(() => password(new SshPasswordRequest(user, secret), ct))
                : null,
            PublicKey = options.PublicKeyHandler is { } key
                ? (user, publicKey, ct) => CheckAsync(() => key(
                    new SshPublicKeyRequest(user, publicKey.KeyType, HostKeyPolicy.ComputeFingerprint(publicKey.Blob.Span)),
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

    private async Task ServeChannelsAsync(SshConnection connection, SshPrincipal principal)
    {
        List<Task> sessions = [];
        try
        {
            await foreach (IncomingChannelOpen open in connection.IncomingChannels.ReadAllAsync(_stop.Token).ConfigureAwait(false))
            {
                sessions.Add(Task.Run(() => ServeSessionAsync(connection, open.Channel, principal), CancellationToken.None));
                sessions.RemoveAll(static s => s.IsCompleted);
            }
        }
        catch (OperationCanceledException)
        {
            // The server is stopping.
        }

        await Task.WhenAll(sessions).ConfigureAwait(false);
    }

    /// <summary>
    /// Owns one session from start to end. The channel, the handler and the session slot all live and die here,
    /// so none of them can outlast the others: the slot is only freed once the handler has really ended.
    /// </summary>
    private async Task ServeSessionAsync(SshConnection connection, SshChannel channel, SshPrincipal principal)
    {
        using CancellationTokenSource session = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
        Task? running = null;
        try
        {
            running = await ServeRequestsAsync(channel, principal, session).ConfigureAwait(false);
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
    private async Task<Task?> ServeRequestsAsync(SshChannel channel, SshPrincipal principal, CancellationTokenSource session)
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
                            start = new(principal, kind, command, pty, environment, channel.Output, channel.Input, channel.ErrorInput);
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

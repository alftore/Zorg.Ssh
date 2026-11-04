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

    private readonly SshServerOptions _options;
    private readonly ILogger _logger;
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _stop = new();
    private readonly ConcurrentDictionary<Task, bool> _connections = new();
    private readonly TransportOptions _transportOptions;
    private int _connectionCount;
    private int _unauthenticatedCount;
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

    /// <summary>Stops listening, closes every connection, and waits for handlers to end.</summary>
    /// <returns>A task that completes when everything has stopped.</returns>
    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync().ConfigureAwait(false);
        _listener.Stop();
        if (_acceptLoop is not null)
        {
            await _acceptLoop.ConfigureAwait(false);
        }

        await Task.WhenAll(_connections.Keys).ConfigureAwait(false);
        _listener.Dispose();
        _stop.Dispose();
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "Refused a connection: limit reached")]
    private static partial void LogLimitReached(ILogger logger);

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
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                if (_stop.IsCancellationRequested)
                {
                    return;
                }

                continue;
            }

            // S6: refused before a single byte is read, so a flood costs almost nothing.
            if (Volatile.Read(ref _connectionCount) >= _options.MaxConnections
                || Volatile.Read(ref _unauthenticatedCount) >= _options.MaxUnauthenticatedConnections)
            {
                LogLimitReached(_logger);
                socket.Dispose();
                continue;
            }

            socket.NoDelay = true;
            Interlocked.Increment(ref _connectionCount);
            Interlocked.Increment(ref _unauthenticatedCount);
#pragma warning disable CA2025 // ServeAsync owns the socket and disposes it; nothing here does.
            Task connection = Task.Run(() => ServeAsync(socket), CancellationToken.None);
#pragma warning restore CA2025
            _connections.TryAdd(connection, true);
            _ = connection.ContinueWith(
                finished => _connections.TryRemove(finished, out _),
                CancellationToken.None,
                TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
        }
    }

    private async Task ServeAsync(Socket socket)
    {
        bool authenticated = false;
        SshTransport? transport = null;
        try
        {
            using CancellationTokenSource grace = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
            grace.CancelAfter(_options.LoginGraceTime);

#pragma warning disable CA2000 // The transport owns the stream, and the finally block or the connection owns the transport.
            NetworkStream stream = new(socket, ownsSocket: true);
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
                socket.Dispose();
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
            Password = options.PasswordHandler is { } password
                ? async (user, secret, ct) => (AuthDecision)await password(new SshPasswordRequest(user, secret), ct).ConfigureAwait(false)
                : null,
            PublicKey = options.PublicKeyHandler is { } key
                ? async (user, publicKey, ct) => (AuthDecision)await key(
                    new SshPublicKeyRequest(user, publicKey.KeyType, HostKeyPolicy.ComputeFingerprint(publicKey.Blob.Span)),
                    ct).ConfigureAwait(false)
                : null,
        };
    }

    private async Task ServeChannelsAsync(SshConnection connection, SshPrincipal principal)
    {
        List<Task> sessions = [];
        try
        {
            await foreach (IncomingChannelOpen open in connection.IncomingChannels.ReadAllAsync(_stop.Token).ConfigureAwait(false))
            {
                sessions.Add(Task.Run(() => ServeSessionAsync(open.Channel, principal), CancellationToken.None));
                sessions.RemoveAll(static s => s.IsCompleted);
            }
        }
        catch (OperationCanceledException)
        {
            // The server is stopping.
        }

        await Task.WhenAll(sessions).ConfigureAwait(false);
    }

    private async Task ServeSessionAsync(SshChannel channel, SshPrincipal principal)
    {
        await using (channel.ConfigureAwait(false))
        {
            try
            {
                Dictionary<string, string> environment = new(StringComparer.Ordinal);
                SshPtyRequest? pty = null;
                Task<int>? running = null;
                CancellationToken token = _stop.Token;

                await foreach (IncomingChannelRequest request in channel.Requests.ReadAllAsync(token).ConfigureAwait(false))
                {
                    bool ok;
                    switch (request.Type)
                    {
                        case "env":
                            (string name, string value) = ParseEnvironment(request.Data);
                            ok = environment.Count < MaxEnvironmentEntries;
                            if (ok)
                            {
                                environment[name] = value;
                            }

                            break;
                        case "pty-req":
                            pty = ParsePty(request.Data);
                            ok = running is null;
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
                            SshServerSession session = new(principal, kind, command, pty, environment, channel.Output, channel.Input, channel.ErrorInput);
                            running = RunHandlerAsync(channel, session, token);
                            ok = true;
                            break;
                        default:
                            ok = false;
                            break;
                    }

                    if (request.WantReply)
                    {
                        await channel.ReplyAsync(ok, token).ConfigureAwait(false);
                    }
                }

                if (running is not null)
                {
                    await running.ConfigureAwait(false);
                }
            }
            catch (Exception ex) when (ex is SshException or OperationCanceledException)
            {
                LogConnectionEnded(_logger, ex);
            }
        }
    }

    private async Task<int> RunHandlerAsync(SshChannel channel, SshServerSession session, CancellationToken cancellationToken)
    {
        // Yield first: the handler must not run before the reply to the request that started it.
        await Task.Yield();
        int exitCode;
        try
        {
            exitCode = await _options.SessionHandler(session, cancellationToken).ConfigureAwait(false);
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
            await channel.SendEofAsync(cancellationToken).ConfigureAwait(false);
            await channel.SendRequestNoReplyAsync("exit-status", status.ToArray(), cancellationToken).ConfigureAwait(false);
            await channel.CloseAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SshException or OperationCanceledException)
        {
            LogConnectionEnded(_logger, ex);
        }

        return exitCode;
    }
}

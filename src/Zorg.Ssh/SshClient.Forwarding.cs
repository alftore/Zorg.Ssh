using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Zorg.Ssh.Connection;
using Zorg.Ssh.Forwarding;

namespace Zorg.Ssh;

// Port forwarding (RFC 4254 section 7), and the tunnel a jump host goes through.
public sealed partial class SshClient
{
    private const string TcpIpForward = "tcpip-forward";
    private const string CancelTcpIpForward = "cancel-tcpip-forward";
    private const int MaxHostLength = 255;

    private static readonly TimeSpan ForwardCancelLimit = TimeSpan.FromSeconds(5);

    private readonly Lock _forwardsGate = new();
    private readonly HashSet<IAsyncDisposable> _forwards = [];
    private bool _forwardsClosed;

    /// <summary>
    /// Opens a TCP connection from the server to a host it can reach, and returns it as a stream. Nothing listens on
    /// this side. Disposing the stream closes the connection.
    /// </summary>
    /// <param name="host">The host to connect to. The server resolves the name, so it's as the server sees it.</param>
    /// <param name="port">The port to connect to.</param>
    /// <param name="cancellationToken">Cancels the open. It doesn't affect a stream that has opened.</param>
    /// <returns>A stream that reads and writes the connection. Reading returns 0 when the far side has finished.</returns>
    /// <exception cref="SshException">The server refused, or couldn't connect. Check that it allows TCP forwarding and that the target is listening.</exception>
    /// <example>
    /// <code>
    /// await using Stream stream = await client.OpenTcpStreamAsync("db.internal", 5432, cancellationToken);
    /// await stream.WriteAsync(request, cancellationToken);
    /// </code>
    /// </example>
    public async Task<Stream> OpenTcpStreamAsync(string host, int port, CancellationToken cancellationToken = default)
    {
        CheckTarget(host, port);
        SshChannel channel = await OpenDirectTcpAsync(host, port, IPAddress.Loopback.ToString(), 0, cancellationToken).ConfigureAwait(false);

        // Nothing reads it, and TCP has no such stream. Dropped data is credited, so it can't eat the window.
        await channel.ErrorOutput.DisposeAsync().ConfigureAwait(false);
#pragma warning disable CA2000 // The caller owns the stream, and through it the channel.
        return new ChannelStream(channel);
#pragma warning restore CA2000
    }

    /// <summary>
    /// Listens on a local port, and carries each connection through the server to one fixed target, as
    /// <c>ssh -L</c> does. At most <see cref="SshClientOptions.MaxForwardedConnections"/> run at once, and
    /// connections past that are closed.
    /// </summary>
    /// <param name="localEndPoint">
    /// The address and port to bind. Null binds a free port on loopback. Anyone who can reach this port can use the
    /// tunnel, with no login, so think before binding anything but loopback.
    /// </param>
    /// <param name="remoteHost">The target host, as the server sees it.</param>
    /// <param name="remotePort">The target port.</param>
    /// <param name="cancellationToken">Cancels the start. It doesn't stop a forward that has started: dispose it for that.</param>
    /// <returns>The running forward, with the port it bound.</returns>
    /// <exception cref="SshException">The port couldn't be bound.</exception>
    /// <example>
    /// <code>
    /// await using SshForward forward = await client.ForwardLocalPortAsync(null, "db.internal", 5432, cancellationToken);
    /// using TcpClient connection = new();
    /// await connection.ConnectAsync(forward.LocalEndPoint, cancellationToken);
    /// </code>
    /// </example>
    public Task<SshForward> ForwardLocalPortAsync(IPEndPoint? localEndPoint, string remoteHost, int remotePort, CancellationToken cancellationToken = default)
    {
        CheckTarget(remoteHost, remotePort);
        cancellationToken.ThrowIfCancellationRequested();
        return ListenAsync(localEndPoint, (socket, token) => ServeTunnelAsync(socket, remoteHost, remotePort, token));
    }

    /// <summary>
    /// Listens on a local port as a SOCKS5 proxy, and carries each connection through the server, as <c>ssh -D</c>
    /// does. It takes CONNECT with no authentication. SOCKS4 isn't supported. A client has
    /// <see cref="SshClientOptions.SocksHandshakeTimeout"/> to finish its handshake, and at most
    /// <see cref="SshClientOptions.MaxForwardedConnections"/> run at once.
    /// </summary>
    /// <param name="localEndPoint">
    /// The address and port to bind. Null binds a free port on loopback. There's no login, so binding anything but
    /// loopback gives whoever can reach it the server's view of the network.
    /// </param>
    /// <param name="cancellationToken">Cancels the start. It doesn't stop a forward that has started: dispose it for that.</param>
    /// <returns>The running forward, with the port it bound.</returns>
    /// <exception cref="SshException">The port couldn't be bound.</exception>
    /// <example>
    /// <code>
    /// await using SshForward proxy = await client.ForwardDynamicPortAsync(null, cancellationToken);
    /// using HttpClient http = new(new SocketsHttpHandler { Proxy = new WebProxy($"socks5://{proxy.LocalEndPoint}") });
    /// </code>
    /// </example>
    public Task<SshForward> ForwardDynamicPortAsync(IPEndPoint? localEndPoint = null, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ListenAsync(localEndPoint, ServeSocksAsync);
    }

    /// <summary>
    /// Asks the server to listen on a port, and connects each connection it gets to a target on this side, as
    /// <c>ssh -R</c> does. At most <see cref="SshClientOptions.MaxForwardedConnections"/> run at once, and the server
    /// is refused past that. The server can only reach this target through a port asked for here.
    /// </summary>
    /// <param name="remoteAddress">
    /// The address the server binds, for example <c>127.0.0.1</c>. The server has the last word: OpenSSH keeps to
    /// loopback unless <c>GatewayPorts</c> says otherwise.
    /// </param>
    /// <param name="remotePort">The port the server binds. Zero lets the server choose: read it from <see cref="SshRemoteForward.RemotePort"/>.</param>
    /// <param name="localHost">The target host, as this side sees it.</param>
    /// <param name="localPort">The target port.</param>
    /// <param name="cancellationToken">Stops waiting for the server. If the server then says yes, the port is released again.</param>
    /// <returns>The running forward, with the port the server bound.</returns>
    /// <exception cref="SshException">The server refused. Check that it allows TCP forwarding, and that the port is free.</exception>
    /// <example>
    /// <code>
    /// await using SshRemoteForward forward = await client.ForwardRemotePortAsync("127.0.0.1", 0, "localhost", 8080, cancellationToken);
    /// await client.ExecuteAsync($"curl http://127.0.0.1:{forward.RemotePort}/", cancellationToken);
    /// </code>
    /// </example>
    public async Task<SshRemoteForward> ForwardRemotePortAsync(string remoteAddress, int remotePort, string localHost, int localPort, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(remoteAddress);
        ArgumentOutOfRangeException.ThrowIfNegative(remotePort);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(remotePort, 65535);
        CheckTarget(localHost, localPort);
        if (remotePort != 0 && _remoteForwards.Contains(remoteAddress, remotePort))
        {
            throw new SshException($"Port {remotePort} on {remoteAddress} is already forwarded. Dispose that forward first.");
        }

#pragma warning disable CA2000 // The forward owns it, and the catch below disposes it if there's no forward.
        ForwardScope scope = new(_options.MaxForwardedConnections, _logger);
#pragma warning restore CA2000
        RemoteForwardEntry entry = new(remoteAddress, remotePort, scope, (open, token) => ServeForwardedAsync(open, localHost, localPort, token));
        try
        {
            byte[] request = Encode(w =>
            {
                w.String(remoteAddress);
                w.UInt32((uint)remotePort);
            });
            Task<byte[]?> reply = await _connection
                .StartGlobalRequestAsync(TcpIpForward, request, r => _remoteForwards.OnReply(entry, r), cancellationToken)
                .ConfigureAwait(false);
            byte[]? granted;
            try
            {
                granted = await reply.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // The answer is still on its way, and a yes would leave a port open that nobody owns.
                _remoteForwards.Abandon(entry);
                _ = CancelWhenGrantedAsync(reply, entry);
                throw;
            }

            if (granted is null)
            {
                throw new SshException($"The server refused to listen on port {remotePort} of {remoteAddress}. Check that it allows TCP forwarding, and that the port is free.");
            }

            if (entry.Conflict)
            {
                throw new SshException($"The server said it listens on port {entry.BoundPort}, which is already forwarded. Dispose that forward first.");
            }

            SshRemoteForward forward = new(entry, CloseRemoteForwardAsync);
            if (!TryAdopt(forward))
            {
                throw new SshConnectionException("The connection has ended. Connect again to continue.");
            }

            return forward;
        }
        catch
        {
            _remoteForwards.Remove(entry);
            await scope.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private static void CheckTarget(string host, int port)
    {
        ArgumentException.ThrowIfNullOrEmpty(host);
        ArgumentOutOfRangeException.ThrowIfLessThan(port, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, 65535);
        if (host.Length > MaxHostLength || host.Any(char.IsControl))
        {
            throw new ArgumentException("That isn't a host name: it's too long, or holds control characters.", nameof(host));
        }
    }

    private static byte[] EncodeForward(RemoteForwardEntry entry) => Encode(w =>
    {
        w.String(entry.Address);
        w.UInt32((uint)entry.BoundPort);
    });

    private async Task<SshForward> ListenAsync(IPEndPoint? localEndPoint, Func<Socket, CancellationToken, Task> serve)
    {
        IPEndPoint endPoint = localEndPoint ?? new IPEndPoint(IPAddress.Loopback, 0);
#pragma warning disable CA2000 // The forward owns both, and is disposed below if it's never handed out.
        TcpListener listener = new(endPoint);
        try
        {
            listener.Start();
        }
        catch (SocketException ex)
        {
            listener.Dispose();
            throw new SshException($"Couldn't listen on {endPoint}: {ex.Message}. Check that the address is local and the port is free.", ex);
        }

        SshForward forward = new(listener, new ForwardScope(_options.MaxForwardedConnections, _logger), Forget);
#pragma warning restore CA2000
        if (!TryAdopt(forward))
        {
            await forward.DisposeAsync().ConfigureAwait(false);
            throw new SshConnectionException("The connection has ended. Connect again to continue.");
        }

        forward.Start(serve);
        return forward;
    }

    /// <summary>Adds a forward to the ones this client closes. Returns false if the client has already ended.</summary>
    private bool TryAdopt(IAsyncDisposable forward)
    {
        lock (_forwardsGate)
        {
            if (_forwardsClosed)
            {
                return false;
            }

            _forwards.Add(forward);
            return true;
        }
    }

    private void Forget(IAsyncDisposable forward)
    {
        lock (_forwardsGate)
        {
            _forwards.Remove(forward);
        }
    }

    /// <summary>Closes every forward, in parallel, so that slow server replies can't add up.</summary>
    private async Task CloseForwardsAsync()
    {
        IAsyncDisposable[] forwards;
        lock (_forwardsGate)
        {
            _forwardsClosed = true;
            forwards = [.. _forwards];
        }

        await Task.WhenAll(forwards.Select(f => f.DisposeAsync().AsTask())).ConfigureAwait(false);
    }

    /// <summary>A listener for a connection that has gone would only hand out dead ends.</summary>
    private async Task CloseForwardsWhenEndedAsync()
    {
        await _connection.Ended.ConfigureAwait(false);
        await CloseForwardsAsync().ConfigureAwait(false);
    }

    private async Task<SshChannel> OpenDirectTcpAsync(string host, int port, string originAddress, int originPort, CancellationToken cancellationToken)
    {
        byte[] extra = Encode(w =>
        {
            w.String(host);
            w.UInt32((uint)port);
            w.String(originAddress);
            w.UInt32((uint)originPort);
        });
        try
        {
            return await _connection.OpenChannelAsync("direct-tcpip", cancellationToken, extra).ConfigureAwait(false);
        }
        catch (SshException ex) when (ex is not SshConnectionException)
        {
            throw new SshException($"Couldn't open a TCP connection to {host}:{port} through the server. Check that it allows TCP forwarding and that the target is listening. {ex.Message}", ex);
        }
    }

    private async Task<SshChannel> OpenForSocketAsync(Socket socket, string host, int port, CancellationToken cancellationToken)
    {
        using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        limit.CancelAfter(_options.ConnectTimeout);
        IPEndPoint? origin = socket.RemoteEndPoint as IPEndPoint;
        return await OpenDirectTcpAsync(host, port, origin?.Address.ToString() ?? IPAddress.Loopback.ToString(), origin?.Port ?? 0, limit.Token).ConfigureAwait(false);
    }

    private async Task ServeTunnelAsync(Socket socket, string host, int port, CancellationToken cancellationToken)
    {
        SshChannel channel;
        try
        {
            channel = await OpenForSocketAsync(socket, host, port, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            socket.Dispose();
            throw;
        }

        await TcpRelay.RunAsync(channel, socket, cancellationToken).ConfigureAwait(false);
    }

    private async Task ServeSocksAsync(Socket socket, CancellationToken cancellationToken)
    {
        SshChannel? channel = null;
        try
        {
            channel = await SocksConnectAsync(socket, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if (channel is null)
            {
                socket.Dispose();
            }
        }

        if (channel is not null)
        {
            await TcpRelay.RunAsync(channel, socket, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Runs the handshake and opens the channel. Returns null if the client was refused.</summary>
    private async Task<SshChannel?> SocksConnectAsync(Socket socket, CancellationToken cancellationToken)
    {
        using NetworkStream network = new(socket, ownsSocket: false);
        using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        limit.CancelAfter(_options.SocksHandshakeTimeout);
        if (await SocksHandshake.ReadRequestAsync(network, limit.Token).ConfigureAwait(false) is not { } target)
        {
            return null;
        }

        SshChannel channel;
        try
        {
            channel = await OpenForSocketAsync(socket, target.Host, target.Port, cancellationToken).ConfigureAwait(false);
        }
        catch (SshException)
        {
            await SendSocksReplyAsync(network, SocksHandshake.ReplyConnectionRefused, cancellationToken).ConfigureAwait(false);
            throw;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            await SendSocksReplyAsync(network, SocksHandshake.ReplyGeneralFailure, cancellationToken).ConfigureAwait(false);
            throw;
        }

        try
        {
            await SendSocksReplyAsync(network, SocksHandshake.ReplySucceeded, cancellationToken).ConfigureAwait(false);
            return channel;
        }
        catch
        {
            await channel.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>Sends a reply within the handshake's time limit: this client may have stopped reading.</summary>
    private async Task SendSocksReplyAsync(NetworkStream network, byte reply, CancellationToken cancellationToken)
    {
        using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        limit.CancelAfter(_options.SocksHandshakeTimeout);
        await SocksHandshake.SendReplyAsync(network, reply, limit.Token).ConfigureAwait(false);
    }

    /// <summary>
    /// Serves a connection the server opened. The target is connected first, so a dead target is refused
    /// properly, rather than being accepted and closed at once.
    /// </summary>
    private async Task ServeForwardedAsync(IncomingChannelOpen open, string host, int port, CancellationToken cancellationToken)
    {
        Socket socket;
        try
        {
            using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            limit.CancelAfter(_options.ConnectTimeout);
#pragma warning disable CA2000 // Disposed below if the channel fails, and owned by the relay after that.
            socket = await TcpRelay.ConnectAsync(host, port, limit.Token).ConfigureAwait(false);
#pragma warning restore CA2000
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ArgumentException)
        {
            await _connection.RefuseIncomingAsync(open, SshConnection.OpenFailureConnectFailed, "connect failed").ConfigureAwait(false);
            return;
        }

        SshChannel channel;
        try
        {
            channel = await _connection.AcceptIncomingAsync(open).ConfigureAwait(false);
        }
        catch
        {
            socket.Dispose();
            throw;
        }

        await TcpRelay.RunAsync(channel, socket, cancellationToken).ConfigureAwait(false);
    }

    private async Task CloseRemoteForwardAsync(SshRemoteForward forward)
    {
        // Out of the table first, so nothing new is accepted while the server is being told.
        RemoteForwardEntry entry = forward.Entry;
        _remoteForwards.Remove(entry);
        await entry.Scope.DisposeAsync().ConfigureAwait(false);
        Forget(forward);
        await SendForwardCancelAsync(entry).ConfigureAwait(false);
    }

    /// <summary>Releases a port the caller stopped waiting for, if the server turns out to have bound it.</summary>
    private async Task CancelWhenGrantedAsync(Task<byte[]?> reply, RemoteForwardEntry entry)
    {
        try
        {
            if (await reply.ConfigureAwait(false) is null)
            {
                return;
            }
        }
        catch (SshException)
        {
            // The connection has gone, and the port with it.
            return;
        }

        await SendForwardCancelAsync(entry).ConfigureAwait(false);
    }

    private async Task SendForwardCancelAsync(RemoteForwardEntry entry)
    {
        try
        {
            using CancellationTokenSource limit = new(ForwardCancelLimit);
            Task<byte[]?> reply = await _connection
                .StartGlobalRequestAsync(CancelTcpIpForward, EncodeForward(entry), null, limit.Token)
                .ConfigureAwait(false);
            await reply.WaitAsync(limit.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SshException or OperationCanceledException)
        {
            // The connection has gone, or the server isn't answering. Either way this side has let go of the port.
        }
    }
}

using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Zorg.Ssh.Forwarding;

namespace Zorg.Ssh;

/// <summary>
/// A local port that leads through an SSH connection. Disposing it stops the listener and closes every
/// connection still going through it. It also closes by itself when the SSH connection ends.
/// </summary>
/// <example>
/// <code>
/// await using SshForward forward = await client.ForwardLocalPortAsync(null, "db.internal", 5432, cancellationToken);
/// Console.WriteLine($"Connect to {forward.LocalEndPoint}");
/// </code>
/// </example>
public sealed class SshForward : IAsyncDisposable
{
    private static readonly TimeSpan AcceptRetryDelay = TimeSpan.FromMilliseconds(100);

    private readonly TcpListener _listener;
    private readonly ForwardScope _scope;
    private readonly Action<IAsyncDisposable> _onClosed;
    private Task? _acceptLoop;
    private int _disposed;

    internal SshForward(TcpListener listener, ForwardScope scope, Action<IAsyncDisposable> onClosed)
    {
        _listener = listener;
        _scope = scope;
        _onClosed = onClosed;
        LocalEndPoint = (IPEndPoint)listener.LocalEndpoint;
    }

    /// <summary>Gets the address and port that were bound, with the real port if port 0 was asked for.</summary>
    public IPEndPoint LocalEndPoint { get; }

    /// <summary>Gets how many connections are going through this forward right now.</summary>
    public int ActiveConnections => _scope.Active;

    /// <summary>Stops listening, closes every active connection, and waits for them to end.</summary>
    /// <returns>A task that completes when everything has stopped.</returns>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        await _scope.CancelAsync().ConfigureAwait(false);
        _listener.Stop();
        if (_acceptLoop is not null)
        {
            await _acceptLoop.ConfigureAwait(false);
        }

        await _scope.DisposeAsync().ConfigureAwait(false);
        _listener.Dispose();
        _onClosed(this);
    }

    /// <summary>Starts accepting. Every accepted socket passes to <paramref name="serve"/>, which owns it from then on.</summary>
    internal void Start(Func<Socket, CancellationToken, Task> serve) =>
        _acceptLoop = Task.Run(() => AcceptLoopAsync(serve), CancellationToken.None);

    private static async Task DelayAsync(CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(AcceptRetryDelay, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // The loop checks the token.
        }
    }

    private async Task AcceptLoopAsync(Func<Socket, CancellationToken, Task> serve)
    {
        CancellationToken token = _scope.Token;
        while (!token.IsCancellationRequested)
        {
            Socket socket;
            try
            {
                socket = await _listener.AcceptSocketAsync(token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or InvalidOperationException)
            {
                return;
            }
            catch (SocketException)
            {
                // Usually one connection that died in the queue. A lasting failure mustn't turn this into a spin.
                await DelayAsync(token).ConfigureAwait(false);
                continue;
            }

            // Past the cap the connection is closed at once, which costs nothing and tells the client plainly.
            if (!_scope.TryReserve())
            {
                socket.Dispose();
                continue;
            }

#pragma warning disable CA2025 // Nothing here disposes the socket: it now belongs to the task.
            _scope.Run(cancellation => ServeAsync(socket, serve, cancellation));
#pragma warning restore CA2025
        }
    }

    private static async Task ServeAsync(Socket socket, Func<Socket, CancellationToken, Task> serve, CancellationToken cancellationToken)
    {
        try
        {
            socket.NoDelay = true;
        }
        catch
        {
            socket.Dispose();
            throw;
        }

        await serve(socket, cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>
/// A port on the server that leads back to this side. Disposing it asks the server to stop listening, and
/// closes every connection still going through it. It also closes by itself when the SSH connection ends.
/// </summary>
/// <example>
/// <code>
/// await using SshRemoteForward forward = await client.ForwardRemotePortAsync("127.0.0.1", 0, "localhost", 8080, cancellationToken);
/// Console.WriteLine($"The server listens on port {forward.RemotePort}");
/// </code>
/// </example>
public sealed class SshRemoteForward : IAsyncDisposable
{
    private readonly Func<SshRemoteForward, Task> _close;
    private int _disposed;

    internal SshRemoteForward(RemoteForwardEntry entry, Func<SshRemoteForward, Task> close)
    {
        Entry = entry;
        _close = close;
    }

    /// <summary>Gets the address the server was asked to listen on.</summary>
    public string RemoteAddress => Entry.Address;

    /// <summary>Gets the port the server listens on, with the real port if port 0 was asked for.</summary>
    public int RemotePort => Entry.BoundPort;

    /// <summary>Gets how many connections are going through this forward right now.</summary>
    public int ActiveConnections => Entry.Scope.Active;

    internal RemoteForwardEntry Entry { get; }

    /// <summary>Asks the server to stop listening, closes every active connection, and waits for them to end.</summary>
    /// <returns>A task that completes when everything has stopped.</returns>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            await _close(this).ConfigureAwait(false);
        }
    }
}

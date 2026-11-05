using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Zorg.Ssh.Forwarding;

/// <summary>
/// Everything running for one forward: the cap on its connections, the token that ends them, and the wait for
/// them to finish. A connection takes a slot before any work starts on it and holds it until it has ended,
/// so a stalled peer can use up this forward's slots and nothing else.
/// </summary>
internal sealed partial class ForwardScope : IAsyncDisposable
{
    private static readonly TimeSpan StopTimeout = TimeSpan.FromSeconds(10);

    private readonly Lock _gate = new();
    private readonly HashSet<Task> _running = [];
    private readonly CancellationTokenSource _stop = new();
    private readonly int _maxConnections;
    private readonly ILogger _logger;
    private int _active;
    private bool _stopping;
    private int _disposed;

    public ForwardScope(int maxConnections, ILogger logger)
    {
        _maxConnections = maxConnections;
        _logger = logger;

        // Kept apart from the source, which is disposed while a late connection might still ask for the token.
        Token = _stop.Token;
    }

    /// <summary>Gets the token that fires when the forward closes.</summary>
    public CancellationToken Token { get; }

    /// <summary>Gets how many connections hold a slot.</summary>
    public int Active
    {
        get
        {
            lock (_gate)
            {
                return _active;
            }
        }
    }

    /// <summary>Takes a slot. It never waits, so the receive loop can call it. Follow it with <see cref="Run"/>.</summary>
    public bool TryReserve()
    {
        lock (_gate)
        {
            if (_stopping || _active >= _maxConnections)
            {
                return false;
            }

            _active++;
            return true;
        }
    }

    /// <summary>Runs one connection on the thread pool, and frees its slot when it ends. It returns at once.</summary>
    public void Run(Func<CancellationToken, Task> work)
    {
        Task running = Task.Run(() => RunCoreAsync(work), CancellationToken.None);
        lock (_gate)
        {
            _running.Add(running);
        }

        _ = running.ContinueWith(
            finished =>
            {
                lock (_gate)
                {
                    _running.Remove(finished);
                }
            },
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    /// <summary>Tells every connection to stop, without waiting for them.</summary>
    public async Task CancelAsync()
    {
        lock (_gate)
        {
            _stopping = true;
        }

        if (Volatile.Read(ref _disposed) == 0)
        {
            await _stop.CancelAsync().ConfigureAwait(false);
        }
    }

    /// <summary>Stops every connection and waits for them. Safe to call more than once.</summary>
    public async ValueTask DisposeAsync()
    {
        await CancelAsync().ConfigureAwait(false);
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        Task[] running;
        lock (_gate)
        {
            running = [.. _running];
        }

        try
        {
            await Task.WhenAll(running).WaitAsync(StopTimeout).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            // Each connection has its own limits on closing, so this is a backstop. It can't hold the caller for ever.
        }

        _stop.Dispose();
    }

    [LoggerMessage(Level = LogLevel.Debug, Message = "A forwarded connection ended early")]
    private static partial void LogEnded(ILogger logger, Exception exception);

    [LoggerMessage(Level = LogLevel.Error, Message = "A forwarded connection failed unexpectedly")]
    private static partial void LogFailed(ILogger logger, Exception exception);

    private async Task RunCoreAsync(Func<CancellationToken, Task> work)
    {
        try
        {
            await work(Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SshException or IOException or SocketException or OperationCanceledException or ObjectDisposedException)
        {
            LogEnded(_logger, ex);
        }
#pragma warning disable CA1031 // Nothing awaits this task, so a bug here would otherwise vanish.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            LogFailed(_logger, ex);
        }
        finally
        {
            lock (_gate)
            {
                _active--;
            }
        }
    }
}

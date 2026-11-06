using System;
using System.Threading;
using System.Threading.Tasks;

namespace Zorg.Ssh;

/// <summary>
/// Watches one authenticated server connection for <see cref="SshServerOptions.IdleTimeout"/>. It counts open
/// channels, and the clock runs only while there are none. It runs on its own task, never on the receive loop.
/// </summary>
internal sealed class IdleMonitor
{
    private static readonly TimeSpan LongestWait = TimeSpan.FromDays(1);

    private readonly object _lock = new();
    private readonly TimeSpan _timeout;
    private readonly TimeProvider _time;
    private int _open;
    private long _idleSince;
    private TaskCompletionSource _changed = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public IdleMonitor(TimeSpan timeout, TimeProvider time)
    {
        _timeout = timeout;
        _time = time;
        _idleSince = time.GetTimestamp();
    }

    /// <summary>A channel was opened. This stops the clock.</summary>
    public void ChannelOpened()
    {
        lock (_lock)
        {
            _open++;
            Signal();
        }
    }

    /// <summary>A channel ended. When it was the last, the clock restarts from now.</summary>
    public void ChannelClosed()
    {
        lock (_lock)
        {
            if (_open > 0 && --_open == 0)
            {
                _idleSince = _time.GetTimestamp();
            }

            Signal();
        }
    }

    /// <summary>Completes when the connection has had no channel for the whole timeout. Cancellation throws.</summary>
    public async Task WaitForIdleAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            Task changed;
            TimeSpan remaining;
            lock (_lock)
            {
                changed = _changed.Task;
                if (_open > 0)
                {
                    remaining = Timeout.InfiniteTimeSpan;
                }
                else
                {
                    remaining = _timeout - _time.GetElapsedTime(_idleSince);
                    if (remaining <= TimeSpan.Zero)
                    {
                        return;
                    }
                }
            }

            if (remaining == Timeout.InfiniteTimeSpan)
            {
                await changed.WaitAsync(cancellationToken).ConfigureAwait(false);
                continue;
            }

            using CancellationTokenSource wake = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            Task delay = Task.Delay(remaining < LongestWait ? remaining : LongestWait, _time, wake.Token);
            await Task.WhenAny(delay, changed).ConfigureAwait(false);
            await wake.CancelAsync().ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
        }
    }

    private void Signal()
    {
        _changed.TrySetResult();
        _changed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }
}

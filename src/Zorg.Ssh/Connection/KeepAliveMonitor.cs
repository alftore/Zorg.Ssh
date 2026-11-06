using System;
using System.Threading;
using System.Threading.Tasks;
using Zorg.Ssh.Transport;

namespace Zorg.Ssh.Connection;

/// <summary>
/// Notices a peer that went away, for one connection, so nothing waits on it for ever (guarantee 3). It runs on its
/// own task, never in the receive loop (T1), and only after auth (T11).
/// <para>
/// Silence: a whole interval with nothing received sends a probe, and any packet starts the count again. After the
/// probe, <see cref="TransportOptions.KeepAliveCountMax"/> more silent intervals end the connection. Misses are counted
/// by waking, not worked out from the clock, so a laptop that slept loses one interval and not the connection.
/// </para>
/// <para>
/// A key exchange holds back every other message, so no probe goes out, and a peer in one can't answer. Silence still
/// counts, because a rekey the peer abandoned is the same hang. A live one sends packets, and each of those resets the count.
/// </para>
/// <para>
/// Stall: a peer that keeps sending but stopped reading is never silent, so one socket write that doesn't finish within
/// interval times count ends the connection too. The check happens when this task wakes, so it can be up to an interval late.
/// </para>
/// </summary>
internal sealed class KeepAliveMonitor
{
    /// <summary>The request every SSH implementation answers, if only with a failure, which is the normal reply.</summary>
    public const string RequestName = "keepalive@openssh.com";

    private readonly SshConnection _connection;
    private readonly SshTransport _transport;
    private readonly TimeProvider _clock;
    private readonly TimeSpan _interval;
    private readonly int _countMax;
    private readonly TimeSpan _stallLimit;
    private int _probesSent;
    private int _probesAnswered;

    public KeepAliveMonitor(SshConnection connection)
    {
        _connection = connection;
        _transport = connection.Transport;
        _clock = _transport.Options.TimeProvider;
        _interval = _transport.Options.KeepAliveInterval;
        _countMax = _transport.Options.KeepAliveCountMax;
        _stallLimit = _interval * _countMax;
    }

    /// <summary>Gets how many probes have gone into the send queue.</summary>
    public int ProbesSent => Volatile.Read(ref _probesSent);

    /// <summary>Gets how many probes the peer has answered.</summary>
    public int ProbesAnswered => Volatile.Read(ref _probesAnswered);

    /// <summary>Runs until the connection ends. If it decides the peer has gone, that's what ends it.</summary>
    public async Task RunAsync(CancellationToken stop)
    {
        CancellationTokenSource? sendLimit = null;
        Task probe = Task.CompletedTask;
        long lastSeen = _transport.LastReceivedTimestamp;
        int silentIntervals = 0;
        TimeSpan wait = _interval;
        try
        {
            while (await SleepAsync(wait, stop).ConfigureAwait(false))
            {
                // A send still waiting after an interval gives up, so a full queue can't hold the request line.
                // Waking early is harmless: that means a packet came, and there's no need for the probe.
                if (!probe.IsCompleted)
                {
                    await sendLimit!.CancelAsync().ConfigureAwait(false);
                }

                if (_transport.WritePendingFor >= _stallLimit)
                {
                    _transport.Abort(new SshConnectionException("The peer stopped reading, so a send never finished. Connect again to continue."));
                    return;
                }

                long received = _transport.LastReceivedTimestamp;
                if (received != lastSeen)
                {
                    lastSeen = received;
                    silentIntervals = 0;
                }

                TimeSpan quiet = _clock.GetElapsedTime(received);
                if (quiet < _interval)
                {
                    wait = _interval - quiet;
                    continue;
                }

                wait = _interval;
                bool keyExchange = _transport.KeyExchangeRunning;
                if (++silentIntervals > _countMax)
                {
                    _transport.Abort(new SshConnectionException(keyExchange
                        ? "The peer went silent during a key exchange. Connect again to continue."
                        : "The peer stopped answering keepalives. Connect again to continue."));
                    return;
                }

                // At most one in the line, or a peer that never replies would grow it.
                if (probe.IsCompleted && !keyExchange)
                {
                    sendLimit?.Dispose();
                    sendLimit = new CancellationTokenSource();
                    probe = ProbeAsync(sendLimit.Token);
                }
            }
        }
        finally
        {
            sendLimit?.Dispose();
        }
    }

    /// <summary>Returns true after the full wait, and false if the connection ended first.</summary>
    private async Task<bool> SleepAsync(TimeSpan wait, CancellationToken stop)
    {
        Task sleep = _connection.Ended.WaitAsync(wait, _clock, stop);
        await sleep.ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
        return sleep.IsFaulted;
    }

    /// <summary>
    /// Goes through the connection's request line, because replies are matched by order: outside it, a probe's
    /// reply would answer a caller's request. Its failures don't matter here. Only silence ends a connection.
    /// </summary>
    private async Task ProbeAsync(CancellationToken sendLimit)
    {
        try
        {
            Task<byte[]?> reply = await _connection.StartGlobalRequestAsync(RequestName, [], null, sendLimit).ConfigureAwait(false);
            Interlocked.Increment(ref _probesSent);
            await reply.ConfigureAwait(false);
            Interlocked.Increment(ref _probesAnswered);
        }
        catch (Exception ex) when (ex is SshException or OperationCanceledException)
        {
            // Cancelled by the send limit, too many caller requests in the line, or the connection ended.
        }
    }
}

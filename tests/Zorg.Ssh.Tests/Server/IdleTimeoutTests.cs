using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Zorg.Ssh.Tests.Server;

/// <summary>R11: an authenticated connection with no open channel for <c>IdleTimeout</c> is closed.</summary>
public sealed class IdleTimeoutTests : IDisposable
{
    private static readonly TimeSpan Timeout10 = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(15);

    private readonly SshHostKey _hostKey = SshHostKey.GenerateEd25519();
    private readonly ManualTime _time = new();
    private readonly CapturingLoggerFactory _logs = new();
    private readonly TaskCompletionSource _started = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose()
    {
        _hostKey.Dispose();
        _logs.Dispose();
    }

    [Fact]
    public async Task A_connection_with_no_channel_is_closed_after_the_timeout()
    {
        await using SshServer server = await StartAsync(Timeout10);
        await using SshClient client = await ConnectAsync(server);
        await _time.WaitForTimerAsync(0);

        _time.Advance(Timeout10 - TimeSpan.FromSeconds(1));
        Assert.False(_logs.Contains("Closed a connection"));

        _time.Advance(TimeSpan.FromSeconds(1));
        await WaitForAsync(() => _logs.Contains("Closed a connection"));
        await Assert.ThrowsAnyAsync<SshException>(() => client.ExecuteAsync("x", Ct).WaitAsync(Limit, Ct));
    }

    [Fact]
    public async Task A_connection_with_an_open_channel_is_not_closed_however_long_it_waits()
    {
        await using SshServer server = await StartAsync(Timeout10);
        await using SshClient client = await ConnectAsync(server);
        await using SshProcess process = await client.StartProcessAsync("hold", null, Ct);
        await _started.Task.WaitAsync(Limit, Ct);

        _time.Advance(TimeSpan.FromDays(3));
        _release.SetResult();
        await process.WaitForExitAsync(Ct).WaitAsync(Limit, Ct);

        Assert.False(_logs.Contains("Closed a connection"));
        Assert.Equal(0, (await client.ExecuteAsync("again", Ct)).ExitCode);
    }

    [Fact]
    public async Task The_clock_restarts_when_the_last_channel_closes()
    {
        await using SshServer server = await StartAsync(Timeout10);
        await using SshClient client = await ConnectAsync(server);
        await _time.WaitForTimerAsync(0);

        // Nine idle minutes, then a channel that outlives the original deadline many times over.
        _time.Advance(TimeSpan.FromMinutes(9));
        int armed = _time.TimersCreated;
        await using SshProcess process = await client.StartProcessAsync("hold", null, Ct);
        await _started.Task.WaitAsync(Limit, Ct);
        _time.Advance(TimeSpan.FromMinutes(50));
        Assert.False(_logs.Contains("Closed a connection"));

        // The last channel closes. The clock starts again from here, so nine more minutes is not enough.
        _release.SetResult();
        await process.WaitForExitAsync(Ct).WaitAsync(Limit, Ct);
        await _time.WaitForTimerAsync(armed);
        _time.Advance(TimeSpan.FromMinutes(9));
        Assert.False(_logs.Contains("Closed a connection"));

        _time.Advance(TimeSpan.FromMinutes(1));
        await WaitForAsync(() => _logs.Contains("Closed a connection"));
    }

    // A refused open is no use of the connection: it must not restart the clock, or a client could hold an unused connection for ever.
    [Fact]
    public async Task A_refused_direct_tcpip_open_does_not_restart_the_idle_clock()
    {
        await using SshServer server = await StartAsync(Timeout10, denyDirectTcp: true);
        await using SshClient client = await ConnectAsync(server);
        await _time.WaitForTimerAsync(0);

        _time.Advance(TimeSpan.FromMinutes(9));
        await Assert.ThrowsAsync<SshException>(() => client.OpenTcpStreamAsync("127.0.0.1", 9, Ct));

        _time.Advance(TimeSpan.FromMinutes(1));
        await WaitForAsync(() => _logs.Contains("Closed a connection"));
    }

    // The idle decision and the count of opens are one step: an open after the decision is refused, not counted.
    [Fact]
    public async Task A_channel_opened_after_the_idle_decision_is_not_counted()
    {
        FixedTime time = new();
        IdleMonitor monitor = new(Timeout10, time);
        time.Now = Timeout10.Ticks;

        await monitor.WaitForIdleAsync(Ct).WaitAsync(Limit, Ct);

        Assert.False(monitor.ChannelOpened());
    }

    [Fact]
    public async Task A_channel_opened_before_the_idle_decision_keeps_the_connection()
    {
        FixedTime time = new();
        IdleMonitor monitor = new(Timeout10, time);
        time.Now = Timeout10.Ticks;

        Assert.True(monitor.ChannelOpened());
        Task waiting = monitor.WaitForIdleAsync(Ct);
        await Task.Delay(100, Ct);
        Assert.False(waiting.IsCompleted);

        // Closing without a restart leaves the old deadline, which has passed.
        monitor.ChannelClosed(restartClock: false);
        await waiting.WaitAsync(Limit, Ct);
        Assert.False(monitor.ChannelOpened());
    }

    /// <summary>A clock that is only read, never waited on.</summary>
    private sealed class FixedTime : TimeProvider
    {
        public long Now { get; set; }

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;

        public override long GetTimestamp() => Now;
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    public async Task A_timeout_of_zero_or_less_is_refused_at_start(int seconds)
    {
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => StartAsync(TimeSpan.FromSeconds(seconds)));
    }

    [Fact]
    public async Task No_timeout_means_an_idle_connection_stays_open()
    {
        await using SshServer server = await StartAsync(null);
        await using SshClient client = await ConnectAsync(server);

        _time.Advance(TimeSpan.FromDays(30));

        Assert.Equal(0, (await client.ExecuteAsync("x", Ct)).ExitCode);
        Assert.Equal(0, _time.TimersCreated);
    }

    private Task<SshServer> StartAsync(TimeSpan? idle, bool denyDirectTcp = false) => SshServer.StartWithClockAsync(
        new SshServerOptions
        {
            HostKeys = [_hostKey],
            PasswordHandler = (_, _) => ValueTask.FromResult(SshAuthDecision.Accept),
            SessionHandler = async (session, ct) =>
            {
                if (session.Command == "hold")
                {
                    _started.TrySetResult();
                    await _release.Task.WaitAsync(ct);
                }

                return 0;
            },
            IdleTimeout = idle,
            DirectTcpHandler = denyDirectTcp ? (_, _) => ValueTask.FromResult(SshForwardDecision.Deny) : null,
            LoggerFactory = _logs,
        },
        _time,
        Ct);

    private Task<SshClient> ConnectAsync(SshServer server) => SshClient.ConnectAsync(
        new SshClientOptions
        {
            Host = "127.0.0.1",
            Port = server.LocalEndPoint.Port,
            UserName = "alice",
            Credentials = [SshCredential.FromPassword("pw")],
            HostKeyPolicy = HostKeyPolicy.Fingerprint(_hostKey.Sha256Fingerprint),
        },
        Ct);

    private static async Task WaitForAsync(Func<bool> condition)
    {
        using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        limit.CancelAfter(Limit);
        while (!condition())
        {
            await Task.Delay(20, limit.Token);
        }
    }

    /// <summary>A clock that moves only when told, and fires the timers it passes.</summary>
    private sealed class ManualTime : TimeProvider
    {
        private readonly object _lock = new();
        private readonly List<FakeTimer> _timers = [];
        private long _now;
        private int _created;

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;

        public int TimersCreated => Volatile.Read(ref _created);

        public override long GetTimestamp() => Volatile.Read(ref _now);

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            FakeTimer timer = new(this, callback, state);
            lock (_lock)
            {
                _timers.Add(timer);
                _created++;
                timer.Change(dueTime, period);
            }

            return timer;
        }

        public void Advance(TimeSpan by)
        {
            List<FakeTimer> due;
            lock (_lock)
            {
                _now += by.Ticks;
                due = [.. _timers.Where(t => t.Due is { } d && d <= _now)];
                foreach (FakeTimer t in due)
                {
                    t.Due = null;
                }
            }

            foreach (FakeTimer t in due)
            {
                t.Fire();
            }
        }

        /// <summary>Waits until more than <paramref name="after"/> timers have been created.</summary>
        public async Task WaitForTimerAsync(int after)
        {
            using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(Ct);
            limit.CancelAfter(Limit);
            while (TimersCreated <= after)
            {
                await Task.Delay(10, limit.Token);
            }
        }

        private void Remove(FakeTimer timer)
        {
            lock (_lock)
            {
                _timers.Remove(timer);
            }
        }

        private sealed class FakeTimer(ManualTime owner, TimerCallback callback, object? state) : ITimer
        {
            public long? Due { get; set; }

            public bool Change(TimeSpan dueTime, TimeSpan period)
            {
                Due = dueTime == Timeout.InfiniteTimeSpan ? null : owner.GetTimestamp() + dueTime.Ticks;
                return true;
            }

            public void Fire() => callback(state);

            public void Dispose() => owner.Remove(this);

            public ValueTask DisposeAsync()
            {
                Dispose();
                return ValueTask.CompletedTask;
            }
        }
    }

    private sealed class CapturingLoggerFactory : ILoggerFactory
    {
        private readonly List<string> _messages = [];

        public bool Contains(string text)
        {
            lock (_messages)
            {
                return _messages.Any(m => m.Contains(text, StringComparison.Ordinal));
            }
        }

        public void AddProvider(ILoggerProvider provider)
        {
        }

        public ILogger CreateLogger(string categoryName) => new Capture(this);

        public void Dispose()
        {
        }

        private sealed class Capture(CapturingLoggerFactory owner) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state)
                where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            {
                lock (owner._messages)
                {
                    owner._messages.Add(formatter(state, exception));
                }
            }
        }
    }
}

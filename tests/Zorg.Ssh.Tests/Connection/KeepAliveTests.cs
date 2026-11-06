using System;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Connection;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Transport;

namespace Zorg.Ssh.Tests.Connection;

/// <summary>Keepalive and the stalled-send check on a connection, in both roles, on a manual clock.</summary>
public class KeepAliveTests
{
    private const string Silent = "stopped answering keepalives";
    private const string Stalled = "stopped reading";
    private const string SilentInKex = "silent during a key exchange";

    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(20);

    public static TheoryData<bool> Roles() => new(true, false);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static SshRole Role(bool asClient) => asClient ? SshRole.Client : SshRole.Server;

    [Theory]
    [MemberData(nameof(Roles))]
    public async Task A_silent_peer_gets_one_probe_and_ends_after_count_more_intervals(bool asClient)
    {
        await using KeepAliveRig rig = await KeepAliveRig.StartAsync(Role(asClient), Ct);

        await rig.IntervalsAsync(0.9);
        Assert.Equal(0, rig.RequestsSeen);

        await rig.IntervalsAsync(0.1);
        Assert.Equal(KeepAliveMonitor.RequestName, await rig.NextGlobalRequestAsync());

        await rig.IntervalsAsync(2.9);
        Assert.False(rig.Ended);

        await rig.IntervalsAsync(0.1);
        Assert.Contains(Silent, await rig.FailureAsync());
    }

    [Theory]
    [MemberData(nameof(Roles))]
    public async Task A_peer_that_answers_stays_connected(bool asClient)
    {
        await using KeepAliveRig rig = await KeepAliveRig.StartAsync(Role(asClient), Ct);
        rig.AutoAnswer = true;

        await rig.IntervalsAsync(20);

        Assert.False(rig.Ended);
        Assert.Equal(20, rig.Monitor.ProbesSent);
        Assert.Equal(20, rig.Monitor.ProbesAnswered);
    }

    [Fact]
    public async Task Any_packet_resets_the_count()
    {
        await using KeepAliveRig rig = await KeepAliveRig.StartAsync(SshRole.Client, Ct);

        await rig.IntervalsAsync(3.5);
        await rig.PeerSpeaksAsync();
        await rig.IntervalsAsync(3.9);
        Assert.False(rig.Ended);

        await rig.IntervalsAsync(0.1);
        Assert.Contains(Silent, await rig.FailureAsync());
    }

    [Fact]
    public async Task At_most_one_probe_is_outstanding_for_a_peer_that_never_replies()
    {
        await using KeepAliveRig rig = await KeepAliveRig.StartAsync(SshRole.Client, Ct, countMax: 100);

        for (int i = 0; i < 10; i++)
        {
            await rig.IntervalsAsync(5);
            await rig.PeerSpeaksAsync();
        }

        await rig.IntervalsAsync(2);
        Assert.False(rig.Ended);
        Assert.Equal(1, rig.Connection.PendingGlobalRequests);
        Assert.Equal(1, rig.Monitor.ProbesSent);
        Assert.Equal(1, rig.RequestsSeen);
    }

    [Fact]
    public async Task A_busy_link_sends_no_probes()
    {
        await using KeepAliveRig rig = await KeepAliveRig.StartAsync(SshRole.Client, Ct);

        for (int i = 0; i < 40; i++)
        {
            await rig.PeerSpeaksAsync();
            await rig.IntervalsAsync(0.9);
        }

        Assert.False(rig.Ended);
        Assert.Equal(0, rig.Monitor.ProbesSent);
        Assert.Equal(0, rig.RequestsSeen);
    }

    [Theory]
    [MemberData(nameof(Roles))]
    public async Task Zero_sends_nothing_and_ends_nothing(bool asClient)
    {
        await using KeepAliveRig rig = await KeepAliveRig.StartAsync(Role(asClient), Ct, interval: TimeSpan.Zero);
        rig.Link.Hold();
        ValueTask stuck = rig.Connection.SendAsync(new byte[] { MessageNumber.Ignore, 0, 0, 0, 0 }, Ct);
        await stuck;
        await rig.UntilAsync(() => rig.Link.WritesWaiting == 1);

        Assert.Equal(0, rig.Clock.ActiveTimers);
        await rig.ElapseAsync(TimeSpan.FromDays(30));

        Assert.Null(rig.Connection.KeepAlive);
        Assert.Equal(0, rig.Clock.ActiveTimers);
        Assert.False(rig.Ended);
        Assert.Equal(1, rig.Link.WritesWaiting);
        Assert.Equal(0, rig.RequestsSeen);
    }

    [Fact]
    public async Task A_callers_global_request_behind_a_probe_gets_its_own_reply()
    {
        await using KeepAliveRig rig = await KeepAliveRig.StartAsync(SshRole.Client, Ct);

        await rig.IntervalsAsync(1);
        Assert.Equal(KeepAliveMonitor.RequestName, await rig.NextGlobalRequestAsync());

        Task<byte[]?> reply = await rig.Connection.StartGlobalRequestAsync("tcpip-forward", [], null, Ct);
        Assert.Equal("tcpip-forward", await rig.NextGlobalRequestAsync());
        Assert.Equal(2, rig.Connection.PendingGlobalRequests);

        await rig.AnswerAsync(MessageNumber.RequestFailure);
        await rig.AnswerAsync(MessageNumber.RequestSuccess, 1, 2, 3);

        Assert.Equal([1, 2, 3], await reply.WaitAsync(Limit, Ct));
        await rig.UntilAsync(() => rig.Monitor.ProbesAnswered == 1);
    }

    [Fact]
    public async Task A_probe_behind_a_callers_global_request_leaves_its_reply_alone()
    {
        await using KeepAliveRig rig = await KeepAliveRig.StartAsync(SshRole.Client, Ct);

        Task<byte[]?> reply = await rig.Connection.StartGlobalRequestAsync("tcpip-forward", [], null, Ct);
        Assert.Equal("tcpip-forward", await rig.NextGlobalRequestAsync());

        await rig.IntervalsAsync(1);
        Assert.Equal(KeepAliveMonitor.RequestName, await rig.NextGlobalRequestAsync());

        await rig.AnswerAsync(MessageNumber.RequestSuccess, 9);
        await rig.AnswerAsync(MessageNumber.RequestFailure);

        Assert.Equal([9], await reply.WaitAsync(Limit, Ct));
        await rig.UntilAsync(() => rig.Monitor.ProbesAnswered == 1);
        Assert.Equal(0, rig.Connection.PendingGlobalRequests);
    }

    [Fact]
    public async Task A_stuck_probe_gives_up_the_request_line_after_an_interval()
    {
        await using KeepAliveRig rig = await KeepAliveRig.StartAsync(SshRole.Client, Ct, countMax: 10, queueCapacity: 2);
        rig.Link.Hold();

        // The send loop holds one packet at the link, and the queue holds the rest, so the probe can't get in.
        byte[] ignore = [MessageNumber.Ignore, 0, 0, 0, 0];
        await rig.Connection.SendAsync(ignore, Ct);
        await rig.UntilAsync(() => rig.Link.WritesWaiting == 1);
        await rig.Connection.SendAsync(ignore, Ct);
        await rig.Connection.SendAsync(ignore, Ct);

        await rig.IntervalsAsync(1);
        await rig.UntilAsync(() => rig.Connection.PendingGlobalRequests == 1);

        Task<Task<byte[]?>> caller = rig.Connection.StartGlobalRequestAsync("tcpip-forward", [], null, Ct);
        await rig.IntervalsAsync(1);

        rig.Link.Open();
        Assert.Equal("tcpip-forward", await rig.NextGlobalRequestAsync());

        Task<byte[]?> reply = await caller.WaitAsync(Limit, Ct);
        await rig.AnswerAsync(MessageNumber.RequestSuccess, 7);
        Assert.Equal([7], await reply.WaitAsync(Limit, Ct));
    }

    [Fact]
    public async Task A_full_request_line_stops_the_probe_but_not_the_count()
    {
        await using KeepAliveRig rig = await KeepAliveRig.StartAsync(SshRole.Client, Ct);
        for (int i = 0; i < 32; i++)
        {
            _ = await rig.Connection.StartGlobalRequestAsync("tcpip-forward", [], null, Ct);
        }

        await rig.IntervalsAsync(3.9);
        Assert.False(rig.Ended);
        Assert.Equal(0, rig.Monitor.ProbesSent);

        await rig.IntervalsAsync(0.1);
        Assert.Contains(Silent, await rig.FailureAsync());
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, false)]
    [InlineData(true, true)]
    [InlineData(false, true)]
    public async Task A_peer_that_sends_but_never_reads_ends_through_the_stall_check(bool asClient, bool ignoreCancellation)
    {
        await using KeepAliveRig rig = await KeepAliveRig.StartAsync(Role(asClient), Ct);
        rig.Link.Hold(ignoreCancellation);
        await rig.Connection.SendAsync(new byte[] { MessageNumber.Ignore, 0, 0, 0, 0 }, Ct);
        await rig.UntilAsync(() => rig.Link.WritesWaiting == 1);

        // Well under an interval between packets, so the miss count never moves.
        for (int i = 0; i < 40 && !rig.Ended; i++)
        {
            await rig.PeerSpeaksAsync();
            await rig.IntervalsAsync(0.4);

            if (i == 6)
            {
                Assert.False(rig.Ended, "The stall limit is three intervals.");
            }
        }

        Assert.Contains(Stalled, await rig.FailureAsync());
        Assert.Equal(0, rig.RequestsSeen);
    }

    [Fact]
    public async Task A_slow_reader_that_finishes_its_writes_is_not_a_stall()
    {
        await using KeepAliveRig rig = await KeepAliveRig.StartAsync(SshRole.Client, Ct);

        // Each write takes two intervals. Together they take far longer than the three the limit allows for one.
        for (int i = 0; i < 6; i++)
        {
            rig.Link.Hold();
            await rig.Connection.SendAsync(new byte[] { MessageNumber.Ignore, 0, 0, 0, 0 }, Ct);
            await rig.UntilAsync(() => rig.Link.WritesWaiting == 1);

            await rig.IntervalsAsync(0.8);
            await rig.PeerSpeaksAsync();
            await rig.IntervalsAsync(0.8);
            await rig.PeerSpeaksAsync();
            await rig.IntervalsAsync(0.4);
            await rig.PeerSpeaksAsync();

            rig.Link.Open();
            await rig.UntilAsync(() => rig.Connection.Transport.WritePendingFor == TimeSpan.Zero);
        }

        Assert.False(rig.Ended);
    }

    [Theory]
    [MemberData(nameof(Roles))]
    public async Task Everything_waiting_wakes_when_the_peer_dies(bool asClient)
    {
        await using KeepAliveRig rig = await KeepAliveRig.StartAsync(Role(asClient), Ct);
        SshChannel reading = await rig.OpenAsync(1, 1 << 20);
        SshChannel writing = await rig.OpenAsync(2, 0);

        // None of these has a token that can fire.
        Task<int> read = reading.Output.ReadAsync(new byte[16], CancellationToken.None).AsTask();
        Task write = writing.Input.WriteAsync(new byte[16], CancellationToken.None).AsTask();
        Task<SshChannel> open = rig.Connection.OpenChannelAsync("session", CancellationToken.None);
        Task<byte[]?> reply = await rig.Connection.StartGlobalRequestAsync("tcpip-forward", [], null, CancellationToken.None);

        await rig.IntervalsAsync(4);

        Assert.Contains(Silent, await rig.FailureAsync());
        SshConnectionException failure = await Assert.ThrowsAsync<SshConnectionException>(() => read.WaitAsync(Limit, Ct));
        Assert.Contains(Silent, failure.Message);
        await Assert.ThrowsAnyAsync<SshConnectionException>(() => write.WaitAsync(Limit, Ct));
        await Assert.ThrowsAnyAsync<SshConnectionException>(() => open.WaitAsync(Limit, Ct));
        await Assert.ThrowsAnyAsync<SshConnectionException>(() => reply.WaitAsync(Limit, Ct));
    }

    [Fact]
    public async Task A_peer_that_answers_but_grants_no_window_stays_connected()
    {
        await using KeepAliveRig rig = await KeepAliveRig.StartAsync(SshRole.Client, Ct);
        rig.AutoAnswer = true;
        SshChannel channel = await rig.OpenAsync(1, 0);

        using CancellationTokenSource writer = new();
        Task write = channel.Input.WriteAsync(new byte[16], writer.Token).AsTask();
        await rig.IntervalsAsync(20);

        Assert.False(rig.Ended);
        Assert.False(write.IsCompleted);

        await writer.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => write.WaitAsync(Limit, Ct));
    }

    [Theory]
    [MemberData(nameof(Roles))]
    public async Task A_rekey_abandoned_half_way_ends_on_silence_before_its_own_deadline(bool asClient)
    {
        await using KeepAliveRig rig = await KeepAliveRig.StartAsync(Role(asClient), Ct);

        // The peer sends its KEXINIT and nothing more, so the exchange is running with nobody on the other end.
        // The clock moves first, so that the timestamp shows the KEXINIT has arrived.
        await rig.IntervalsAsync(0.2);
        rig.PeerLink.DropAfter(1);
        int before = rig.Connection.Transport.CompletedKeyExchanges;
        rig.Connection.Transport.RequestRekey();
        await rig.UntilAsync(() => rig.Connection.Transport.LastReceivedTimestamp == rig.Clock.GetTimestamp());

        await rig.IntervalsAsync(3.9);
        Assert.False(rig.Ended);

        await rig.IntervalsAsync(0.1);
        Assert.Contains(SilentInKex, await rig.FailureAsync());
        Assert.Equal(before, rig.Connection.Transport.CompletedKeyExchanges);
        Assert.Equal(0, rig.RequestsSeen);
    }

    [Fact]
    public async Task A_slow_but_live_rekey_survives_several_times_the_limit()
    {
        await using KeepAliveRig rig = await KeepAliveRig.StartAsync(SshRole.Client, Ct);
        rig.AutoAnswer = true;
        await rig.IntervalsAsync(1);
        await rig.UntilAsync(() => rig.Monitor.ProbesAnswered == 1);

        // Every packet the peer sends in the exchange is held for three intervals, and four would end the connection.
        rig.PeerLink.Hold();
        int before = rig.Connection.Transport.CompletedKeyExchanges;
        rig.Connection.Transport.RequestRekey();
        for (int step = 0; step < 3; step++)
        {
            await rig.UntilAsync(() => rig.PeerLink.WritesWaiting == 1);
            await rig.IntervalsAsync(3);
            Assert.False(rig.Ended);
            Assert.Equal(1, rig.Monitor.ProbesSent);

            rig.PeerLink.ReleaseOne();
            if (step < 2)
            {
                await rig.UntilAsync(() => rig.Connection.Transport.LastReceivedTimestamp == rig.Clock.GetTimestamp());
            }
        }

        rig.PeerLink.Open();
        await rig.UntilAsync(() => rig.Connection.Transport.CompletedKeyExchanges == before + 1);

        await rig.IntervalsAsync(5);
        Assert.False(rig.Ended);
        Assert.True(rig.Monitor.ProbesAnswered > 1);
    }

    [Theory]
    [MemberData(nameof(Roles))]
    public async Task A_rekey_during_probing_loses_nothing(bool asClient)
    {
        await using KeepAliveRig rig = await KeepAliveRig.StartAsync(Role(asClient), Ct);
        rig.AutoAnswer = true;

        for (int i = 1; i <= 5; i++)
        {
            await rig.IntervalsAsync(1);
            int done = rig.Connection.Transport.CompletedKeyExchanges;
            rig.Connection.Transport.RequestRekey();
            await rig.UntilAsync(() => rig.Connection.Transport.CompletedKeyExchanges == done + 1);
        }

        await rig.IntervalsAsync(3);
        Assert.False(rig.Ended);
        Assert.True(rig.Monitor.ProbesAnswered >= 5, $"{rig.Monitor.ProbesAnswered} probes answered.");
    }

    [Fact]
    public async Task A_rekey_the_peer_starts_while_a_probe_is_out_gets_the_probe_answered()
    {
        await using KeepAliveRig rig = await KeepAliveRig.StartAsync(SshRole.Client, Ct);

        await rig.IntervalsAsync(1);
        Assert.Equal(KeepAliveMonitor.RequestName, await rig.NextGlobalRequestAsync());

        int done = rig.Peer.CompletedKeyExchanges;
        rig.Peer.RequestRekey();
        await rig.UntilAsync(() => rig.Peer.CompletedKeyExchanges == done + 1);
        await rig.AnswerAsync(MessageNumber.RequestFailure);
        await rig.UntilAsync(() => rig.Monitor.ProbesAnswered == 1);
        Assert.False(rig.Ended);
    }
}

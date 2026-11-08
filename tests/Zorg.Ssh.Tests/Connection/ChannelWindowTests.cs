using System;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Connection;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Tests.Connection;

/// <summary>
/// The windows of a channel: credit taken for a packet comes back if the packet is never queued, and data received and never
/// read is credited when its stream is dropped.
/// </summary>
public sealed class ChannelWindowTests
{
    private const uint Busy = 1;
    private const uint Subject = 2;

    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(30);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    // A write cancelled after reserving window, while waiting for room in the send queue, used to lose its credit.
    [Fact]
    public async Task A_write_cancelled_while_waiting_for_the_queue_gives_back_its_window()
    {
        await using ChannelRig rig = await ChannelRig.StartAsync(Ct);
        SshChannel busy = await rig.OpenAsync(Busy);
        SshChannel subject = await rig.OpenAsync(Subject, window: 2 * ChannelRig.PacketSize);
        (_, Task stuck) = await rig.FillQueueAsync(busy);

        using (CancellationTokenSource cancel = new(TimeSpan.FromMilliseconds(300)))
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => subject.WriteAsync(new byte[ChannelRig.PacketSize], cancel.Token).AsTask());
        }

        rig.Drain();
        await stuck.WaitAsync(Limit, Ct);

        // The peer granted two packets and received none from this channel, so two must go.
        await subject.WriteAsync(new byte[2 * ChannelRig.PacketSize], Ct).AsTask().WaitAsync(TimeSpan.FromSeconds(10), Ct);
    }

    // Same loss, for a write that waits on the channel's send lock, held by an earlier writer stuck on the queue.
    [Fact]
    public async Task A_write_cancelled_while_waiting_for_the_send_lock_gives_back_its_window()
    {
        await using ChannelRig rig = await ChannelRig.StartAsync(Ct);
        SshChannel busy = await rig.OpenAsync(Busy);
        SshChannel subject = await rig.OpenAsync(Subject, window: 4 * ChannelRig.PacketSize);
        (_, Task stuck) = await rig.FillQueueAsync(busy);

        // This one holds the send lock, waiting for room in the queue.
        Task holder = subject.WriteAsync(new byte[ChannelRig.PacketSize], Ct).AsTask();
        using (CancellationTokenSource cancel = new(TimeSpan.FromMilliseconds(300)))
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => subject.WriteAsync(new byte[ChannelRig.PacketSize], cancel.Token).AsTask());
        }

        rig.Drain();
        await stuck.WaitAsync(Limit, Ct);
        await holder.WaitAsync(Limit, Ct);

        // Four were granted and one was used, so three remain.
        await subject.WriteAsync(new byte[3 * ChannelRig.PacketSize], Ct).AsTask().WaitAsync(TimeSpan.FromSeconds(10), Ct);
    }

    // The reported failure: each cancelled write used to shrink the window until nothing could be written.
    [Fact]
    public async Task Many_cancelled_writes_do_not_drain_the_window()
    {
        await using ChannelRig rig = await ChannelRig.StartAsync(Ct);
        SshChannel busy = await rig.OpenAsync(Busy);
        SshChannel subject = await rig.OpenAsync(Subject, window: 4 * ChannelRig.PacketSize);
        (_, Task stuck) = await rig.FillQueueAsync(busy);

        for (int i = 0; i < 12; i++)
        {
            using CancellationTokenSource cancel = new(TimeSpan.FromMilliseconds(30));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => subject.WriteAsync(new byte[ChannelRig.PacketSize], cancel.Token).AsTask());
        }

        rig.Drain();
        await stuck.WaitAsync(Limit, Ct);
        await subject.WriteAsync(new byte[4 * ChannelRig.PacketSize], Ct).AsTask().WaitAsync(TimeSpan.FromSeconds(10), Ct);
    }

    // C1: disposing a read stream used to drop what it held without crediting it, so the window both streams share shrank for
    // good. With stderr unread and the window full, disposing ErrorOutput (the natural move) left stdout stalled for ever.
    [Fact]
    public async Task Disposing_a_read_stream_credits_the_data_it_held()
    {
        await using ChannelRig rig = await ChannelRig.StartAsync(Ct);
        SshChannel channel = await rig.OpenAsync(Busy);
        int packets = await FillHalfTheWindowAsync(rig, channel);

        await channel.ErrorOutput.DisposeAsync();

        // Half the window credited at once is enough for a WINDOW_ADJUST, and the window is whole again.
        Assert.Equal(MessageNumber.ChannelWindowAdjust, await rig.NextAsync(Busy));
        await WaitUntilAsync(() => channel.ReceiveWindowRemaining == SshChannel.DefaultWindow);

        // Data that arrives later is credited as it comes, and stdout still flows.
        await FillHalfTheWindowAsync(rig, channel, packets, waitForWindow: false);
        Assert.Equal(MessageNumber.ChannelWindowAdjust, await rig.NextAsync(Busy));
        await WaitUntilAsync(() => channel.ReceiveWindowRemaining == SshChannel.DefaultWindow);
        await rig.SendDataAsync(channel.LocalId, [42]);
        byte[] one = new byte[1];
        Assert.Equal(1, await channel.Output.ReadAsync(one, Ct).AsTask().WaitAsync(Limit, Ct));
    }

    // C1, the other way a stream completes its pipe: disposed under a read that is waiting, the read finishes it.
    [Fact]
    public async Task A_read_stream_disposed_during_a_read_credits_what_arrives_after()
    {
        await using ChannelRig rig = await ChannelRig.StartAsync(Ct);
        SshChannel channel = await rig.OpenAsync(Busy);
        Task<int> read = channel.ErrorOutput.ReadAsync(new byte[16], Ct).AsTask();
        Assert.False(read.IsCompleted);

        await channel.ErrorOutput.DisposeAsync();
        Assert.Equal(0, await read.WaitAsync(Limit, Ct));

        await FillHalfTheWindowAsync(rig, channel, waitForWindow: false);
        Assert.Equal(MessageNumber.ChannelWindowAdjust, await rig.NextAsync(Busy));
        await WaitUntilAsync(() => channel.ReceiveWindowRemaining == SshChannel.DefaultWindow);
    }

    /// <summary>Sends half the receive window as stderr, and waits until the channel has taken it all.</summary>
    private static async Task<int> FillHalfTheWindowAsync(ChannelRig rig, SshChannel channel, int? count = null, bool waitForWindow = true)
    {
        int packet = (int)SshChannel.MaxPacket;
        int packets = count ?? (int)(SshChannel.DefaultWindow / 2 / (uint)packet);
        for (int i = 0; i < packets; i++)
        {
            await rig.SendDataAsync(channel.LocalId, new byte[packet], extended: true);
        }

        if (waitForWindow)
        {
            await WaitUntilAsync(() => channel.ReceiveWindowRemaining == SshChannel.DefaultWindow - ((long)packets * packet));
        }

        return packets;
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        limit.CancelAfter(Limit);
        while (!condition())
        {
            await Task.Delay(10, limit.Token);
        }
    }
}

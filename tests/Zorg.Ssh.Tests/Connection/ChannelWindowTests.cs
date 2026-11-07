using System;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Connection;

namespace Zorg.Ssh.Tests.Connection;

/// <summary>The send window of a channel: credit taken for a packet comes back if the packet is never queued.</summary>
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
}

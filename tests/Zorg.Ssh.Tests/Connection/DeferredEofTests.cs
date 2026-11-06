using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Connection;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Tests.Transport;

namespace Zorg.Ssh.Tests.Connection;

/// <summary>
/// EOF behind a full send queue. The peer holds a process or a forwarded connection open until it hears EOF, so
/// running out of time to queue it can't lose it, and it still has to keep its place between the data and the CLOSE.
/// </summary>
public sealed class DeferredEofTests
{
    private const uint Busy = 1;
    private const uint Subject = 2;
    private const byte Data = MessageNumber.ChannelData;
    private const byte Eof = MessageNumber.ChannelEof;
    private const byte Close = MessageNumber.ChannelClose;

    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(30);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>Closes a channel's input. A peer that has stopped reading can't make this wait.</summary>
    private static void DisposeInputWithoutWaiting(SshChannel channel) =>
        Assert.True(channel.Input.DisposeAsync().AsTask().IsCompletedSuccessfully, "Disposing the input waited for the send queue.");

    private static byte[] Packets(int count) => new byte[count * ChannelRig.PacketSize];

    [Fact]
    public async Task Eof_behind_a_full_queue_reaches_the_peer_once_the_queue_drains()
    {
        await using ChannelRig rig = await ChannelRig.StartAsync(Ct);
        SshChannel busy = await rig.OpenAsync(Busy);
        SshChannel subject = await rig.OpenAsync(Subject);
        (_, Task stuck) = await rig.FillQueueAsync(busy);

        await subject.Input.DisposeAsync().AsTask().WaitAsync(Limit, Ct);
        rig.Drain();
        await stuck.WaitAsync(Limit, Ct);

        Assert.Equal(Eof, await rig.NextAsync(Subject));
        Assert.Empty(await rig.RestAsync(Subject));
    }

    [Fact]
    public async Task Disposing_the_input_never_waits_for_the_queue()
    {
        await using ChannelRig rig = await ChannelRig.StartAsync(Ct);
        SshChannel busy = await rig.OpenAsync(Busy);
        SshChannel subject = await rig.OpenAsync(Subject);
        (_, Task stuck) = await rig.FillQueueAsync(busy);

        DisposeInputWithoutWaiting(subject);

        rig.Drain();
        await stuck.WaitAsync(Limit, Ct);
    }

    [Fact]
    public async Task Data_eof_and_close_keep_their_order_behind_a_full_queue()
    {
        await using ChannelRig rig = await ChannelRig.StartAsync(Ct);
        SshChannel subject = await rig.OpenAsync(Subject);
        (int packets, Task stuck) = await rig.FillQueueAsync(subject);

        await subject.Input.DisposeAsync().AsTask().WaitAsync(Limit, Ct);
        using CancellationTokenSource limit = new();
        Task closing = subject.CloseAsync(limit.Token).AsTask();
        await limit.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => closing.WaitAsync(Limit, Ct));
        rig.Drain();
        await stuck.WaitAsync(Limit, Ct);

        List<byte> seen = await rig.ReadUntilAsync(Subject, Close);
        Assert.Equal([.. Enumerable.Repeat(Data, packets), Eof, Close], seen);
        Assert.Empty(await rig.RestAsync(Subject));
    }

    // CLOSE has to send the EOF it finds owed, and if it's cancelled there, the sender loop finishes both.
    [Fact]
    public async Task A_close_cancelled_while_sending_the_owed_eof_sends_both_once()
    {
        await using ChannelRig rig = await ChannelRig.StartAsync(Ct);
        SshChannel busy = await rig.OpenAsync(Busy);
        SshChannel holder = await rig.OpenAsync(3);
        SshChannel subject = await rig.OpenAsync(Subject);
        (_, Task stuck) = await rig.FillQueueAsync(busy);
        DisposeInputWithoutWaiting(holder);
        DisposeInputWithoutWaiting(subject);

        using CancellationTokenSource limit = new();
        Task closing = subject.CloseAsync(limit.Token).AsTask();
        Assert.False(closing.IsCompleted);
        await limit.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => closing.WaitAsync(Limit, Ct));
        rig.Drain();
        await stuck.WaitAsync(Limit, Ct);

        Assert.Equal([Eof, Close], await rig.ReadUntilAsync(Subject, Close));
        Assert.Empty(await rig.RestAsync(Subject));
    }

    // This is the relay's path: its token fires, and the far end must still hear that the socket ended.
    [Fact]
    public async Task A_cancelled_eof_is_still_sent_and_only_once()
    {
        await using ChannelRig rig = await ChannelRig.StartAsync(Ct);
        SshChannel busy = await rig.OpenAsync(Busy);
        SshChannel subject = await rig.OpenAsync(Subject);
        (_, Task stuck) = await rig.FillQueueAsync(busy);

        using CancellationTokenSource limit = new();
        Task sending = subject.SendEofAsync(limit.Token).AsTask();
        Assert.False(sending.IsCompleted);
        await limit.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sending.WaitAsync(Limit, Ct));
        await subject.SendEofAsync(CancellationToken.None);
        await subject.Input.DisposeAsync();
        rig.Drain();
        await stuck.WaitAsync(Limit, Ct);

        Assert.Equal(Eof, await rig.NextAsync(Subject));
        Assert.Empty(await rig.RestAsync(Subject));
    }

    // The data of a write that had already started comes first, even though it's waiting for window.
    [Fact]
    public async Task A_deferred_eof_waits_for_a_write_still_in_progress()
    {
        await using ChannelRig rig = await ChannelRig.StartAsync(Ct);
        SshChannel subject = await rig.OpenAsync(Subject, window: ChannelRig.PacketSize);

        Task writing = subject.WriteAsync(Packets(3), Ct).AsTask();
        Assert.Equal(Data, await rig.NextAsync(Subject));
        DisposeInputWithoutWaiting(subject);
        Assert.False(writing.IsCompleted);
        await rig.GrantWindowAsync(subject.LocalId, 2 * ChannelRig.PacketSize);

        await writing.WaitAsync(Limit, Ct);
        Assert.Equal([Data, Data, Eof], await rig.ReadUntilAsync(Subject, Eof));
        Assert.Empty(await rig.RestAsync(Subject));
    }

    [Fact]
    public async Task A_write_after_the_input_is_closed_is_refused()
    {
        await using ChannelRig rig = await ChannelRig.StartAsync(Ct);
        SshChannel busy = await rig.OpenAsync(Busy);
        SshChannel subject = await rig.OpenAsync(Subject);
        (_, Task stuck) = await rig.FillQueueAsync(busy);
        DisposeInputWithoutWaiting(subject);

        await Assert.ThrowsAnyAsync<SshException>(() => subject.WriteAsync(Packets(1), Ct).AsTask().WaitAsync(Limit, Ct));

        rig.Drain();
        await stuck.WaitAsync(Limit, Ct);
        Assert.Equal(Eof, await rig.NextAsync(Subject));
    }

    // EOF takes no window, so a peer that has run the window down still hears it.
    [Fact]
    public async Task Eof_needs_no_window_behind_a_full_queue()
    {
        await using ChannelRig rig = await ChannelRig.StartAsync(Ct);
        SshChannel busy = await rig.OpenAsync(Busy);
        SshChannel subject = await rig.OpenAsync(Subject, window: 0);
        (_, Task stuck) = await rig.FillQueueAsync(busy);

        DisposeInputWithoutWaiting(subject);
        rig.Drain();
        await stuck.WaitAsync(Limit, Ct);

        Assert.Equal(Eof, await rig.NextAsync(Subject));
    }

    // The peer has said it's done, so CLOSE alone answers it. Receiving this must not wait for the stuck queue either.
    [Fact]
    public async Task A_peer_close_while_eof_is_owed_sends_only_close()
    {
        await using ChannelRig rig = await ChannelRig.StartAsync(Ct);
        SshChannel busy = await rig.OpenAsync(Busy);
        SshChannel holder = await rig.OpenAsync(3);
        SshChannel subject = await rig.OpenAsync(Subject);
        (_, Task stuck) = await rig.FillQueueAsync(busy);
        DisposeInputWithoutWaiting(holder);
        DisposeInputWithoutWaiting(subject);

        await rig.SendAsync(Close, subject.LocalId);
        Assert.Equal(0, await subject.Output.ReadAsync(new byte[1], Ct).AsTask().WaitAsync(Limit, Ct));
        rig.Drain();
        await stuck.WaitAsync(Limit, Ct);

        Assert.Equal([Close], await rig.ReadUntilAsync(Subject, Close));
        Assert.Empty(await rig.RestAsync(Subject));
        await subject.Closed.WaitAsync(Limit, Ct);
    }

    [Fact]
    public async Task A_peer_close_during_a_zero_window_write_ends_it_with_no_eof()
    {
        await using ChannelRig rig = await ChannelRig.StartAsync(Ct);
        SshChannel subject = await rig.OpenAsync(Subject, window: ChannelRig.PacketSize);
        Task writing = subject.WriteAsync(Packets(2), Ct).AsTask();
        Assert.Equal(Data, await rig.NextAsync(Subject));
        DisposeInputWithoutWaiting(subject);

        await rig.SendAsync(Close, subject.LocalId);

        await Assert.ThrowsAnyAsync<SshException>(() => writing.WaitAsync(Limit, Ct));
        Assert.Equal([Close], await rig.ReadUntilAsync(Subject, Close));
        Assert.Empty(await rig.RestAsync(Subject));
    }

    // CLOSE can't wait for a write that may never get window, so the write fails, and EOF still comes first.
    [Fact]
    public async Task A_local_close_during_a_zero_window_write_sends_eof_then_close()
    {
        await using ChannelRig rig = await ChannelRig.StartAsync(Ct);
        SshChannel subject = await rig.OpenAsync(Subject, window: ChannelRig.PacketSize);
        Task writing = subject.WriteAsync(Packets(2), Ct).AsTask();
        Assert.Equal(Data, await rig.NextAsync(Subject));
        DisposeInputWithoutWaiting(subject);

        await subject.CloseAsync(Ct).AsTask().WaitAsync(Limit, Ct);

        Assert.Equal([Eof, Close], await rig.ReadUntilAsync(Subject, Close));
        await rig.GrantWindowAsync(subject.LocalId, ChannelRig.PacketSize);
        await Assert.ThrowsAnyAsync<SshException>(() => writing.WaitAsync(Limit, Ct));
        Assert.Empty(await rig.RestAsync(Subject));
    }

    [Fact]
    public async Task The_connection_failing_with_eof_owed_leaves_nothing_waiting()
    {
        await using ChannelRig rig = await ChannelRig.StartAsync(Ct);
        SshChannel busy = await rig.OpenAsync(Busy);
        SshChannel holder = await rig.OpenAsync(3);
        SshChannel subject = await rig.OpenAsync(Subject);
        SshChannel writer = await rig.OpenAsync(4, window: 0);
        (_, Task stuck) = await rig.FillQueueAsync(busy);
        DisposeInputWithoutWaiting(holder);
        Task zeroWindow = writer.WriteAsync(Packets(1), Ct).AsTask();
        DisposeInputWithoutWaiting(subject);
        DisposeInputWithoutWaiting(writer);
        Assert.True(subject.EofOwed);
        Assert.True(writer.EofOwed);

        await rig.KillPeerAsync();

        await rig.Connection.Ended.WaitAsync(Limit, Ct);
        await Assert.ThrowsAnyAsync<SshException>(() => stuck.WaitAsync(Limit, Ct));
        await Assert.ThrowsAnyAsync<SshException>(() => zeroWindow.WaitAsync(Limit, Ct));
        await subject.Closed.WaitAsync(Limit, Ct);
        await writer.Closed.WaitAsync(Limit, Ct);
        Assert.False(subject.EofOwed);
        Assert.False(writer.EofOwed);
        await subject.SendEofAsync(Ct).AsTask().WaitAsync(Limit, Ct);
        await subject.CloseAsync(Ct).AsTask().WaitAsync(Limit, Ct);
        await subject.DisposeAsync().AsTask().WaitAsync(Limit, Ct);
    }

    // Guarantee 3: however often the wait is given up, the sender loop holds a fixed number of entries for a channel.
    [Fact]
    public async Task A_peer_that_never_reads_grows_nothing_and_holds_up_no_disposal()
    {
        const int Channels = 8;
        ChannelRig rig = await ChannelRig.StartAsync(Ct);
        SshChannel busy = await rig.OpenAsync(Busy);
        SshChannel[] channels = await Task.WhenAll(Enumerable.Range(10, Channels).Select(i => rig.OpenAsync((uint)i)));
        (_, Task stuck) = await rig.FillQueueAsync(busy);

        using CancellationTokenSource cancelled = new();
        await cancelled.CancelAsync();
        foreach (SshChannel channel in channels)
        {
            DisposeInputWithoutWaiting(channel);
            for (int i = 0; i < 500; i++)
            {
                await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await channel.CloseAsync(cancelled.Token));
                await channel.SendEofAsync(cancelled.Token);
            }
        }

        // An EOF and a CLOSE each. The loop may have taken one out already.
        Assert.InRange(rig.Connection.DeferredCount, 1, 2 * Channels);

        await Task.WhenAll(channels.Select(c => c.DisposeAsync().AsTask())).WaitAsync(Limit, Ct);
        Assert.InRange(rig.Connection.DeferredCount, 1, 2 * Channels);
        await rig.DisposeAsync().AsTask().WaitAsync(Limit, Ct);
        await Assert.ThrowsAnyAsync<SshException>(() => stuck.WaitAsync(Limit, Ct));
    }

    // No schedule is forced here. What's checked is the shape of what reached the peer, whichever way each race went.
    [Fact]
    public async Task A_write_a_dispose_and_a_close_racing_keep_the_order()
    {
        await using ChannelRig rig = await ChannelRig.StartAsync(Ct);
        for (uint i = 0; i < 200; i++)
        {
            uint remote = 1000 + i;
            SshChannel channel = await rig.OpenAsync(remote);
            byte[] data = Packets(4);
            Task[] racing =
            [
                Task.Run(
                    async () =>
                    {
                        try
                        {
                            await channel.WriteAsync(data, Ct);
                        }
                        catch (SshException)
                        {
                            // Closed under it, which is one way this can go.
                        }
                    },
                    Ct),
                Task.Run(async () => await channel.Input.DisposeAsync(), Ct),
                Task.Run(async () => await channel.CloseAsync(Ct), Ct),
            ];
            await Task.WhenAll(racing).WaitAsync(Limit, Ct);

            List<byte> seen = await rig.ReadUntilAsync(remote, Close);
            await rig.SendAsync(Close, channel.LocalId);
            await channel.Closed.WaitAsync(Limit, Ct);

            seen.AddRange(await rig.RestAsync(remote));
            int eof = seen.IndexOf(Eof);
            Assert.Equal(seen.Count - 1, seen.IndexOf(Close));
            Assert.Equal(1, seen.Count(n => n == Close));
            Assert.InRange(seen.Count(n => n == Eof), 0, 1);
            Assert.True(eof == -1 || seen.Skip(eof + 1).All(n => n == Close), $"Something followed EOF: {string.Join(", ", seen)}.");
        }
    }

    // The whole way through the public API: a handler reading stdin ends, because EOF got through.
    [Fact]
    public async Task A_process_reading_stdin_ends_when_its_eof_was_behind_a_full_queue()
    {
        using SshHostKey key = SshHostKey.GenerateEd25519();
        TaskCompletionSource<long> total = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await using SshServer server = await SshServer.StartAsync(
            new SshServerOptions
            {
                HostKeys = [key],
                PasswordHandler = static (_, _) => ValueTask.FromResult(SshAuthDecision.Accept),
                SessionHandler = async (session, ct) =>
                {
                    byte[] buffer = new byte[4096];
                    long sum = 0;
                    int read;
                    while ((read = await session.Input.ReadAsync(buffer, ct)) != 0)
                    {
                        sum += read;
                    }

                    total.TrySetResult(sum);
                    return 0;
                },
            },
            Ct);
        (Stream clientSide, Stream serverSide) = DuplexStream.CreatePair();
        GatedStream gate = new(clientSide);
        Task serving = server.ServeStreamAsync(serverSide, Ct);
        SshClient client = await SshClient.ConnectOverStreamAsync(
            gate,
            new SshClientOptions
            {
                Host = "x",
                UserName = "alice",
                Credentials = [SshCredential.FromPassword("pw")],
                HostKeyPolicy = HostKeyPolicy.AcceptAnyUnsafe(),
            },
            Ct);

        SshProcess process = await client.StartProcessAsync("cat", null, Ct);
        await using (process)
        {
            gate.Shut();
            byte[] one = [42];
            await process.StandardInput.WriteAsync(one, Ct);
            await gate.Stuck.WaitAsync(Limit, Ct);

            long written = 1;
            Task? stuck = null;
            while (stuck is null)
            {
                ValueTask write = process.StandardInput.WriteAsync(one, Ct);
                written++;
                if (!write.IsCompleted)
                {
                    stuck = write.AsTask();
                }
                else
                {
                    await write;
                }
            }

            await process.StandardInput.DisposeAsync().AsTask().WaitAsync(Limit, Ct);
            gate.Open();
            await stuck.WaitAsync(Limit, Ct);

            Assert.Equal(written, await total.Task.WaitAsync(Limit, Ct));
            await process.WaitForExitAsync(Ct).WaitAsync(Limit, Ct);
            Assert.Equal(0, process.ExitCode);
        }

        await client.DisposeAsync();
        await serving.WaitAsync(Limit, Ct);
    }
}

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Connection;

namespace Zorg.Ssh.Tests.Connection;

/// <summary>
/// The queue of peer requests a server's channel holds for the application. It must take any burst a real client sends
/// before its shell starts, and still stop a peer that sends without end (guarantee 3).
/// </summary>
public sealed class ChannelRequestQueueTests
{
    private const uint Remote = 1;

    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(30);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    // C2: a queue of 16 ended the connection when OpenSSH sent pty-req, an env per SendEnv variable and shell in one burst,
    // whenever the server's request loop hadn't started yet. 'SendEnv *' can send far more than 64 variables.
    [Fact]
    public async Task A_burst_of_env_requests_before_the_application_reads_is_queued()
    {
        await using ChannelRig rig = await ChannelRig.StartAsync(Ct);
        SshChannel channel = await rig.OpenAsync(Remote);
        channel.QueueIncomingRequests = true;

        const int Burst = 300;
        await rig.SendRequestAsync(channel.LocalId, "pty-req", wantReply: false, Pty);
        for (int i = 0; i < Burst; i++)
        {
            await rig.SendRequestAsync(channel.LocalId, "env", wantReply: false, w =>
            {
                w.String($"LC_VAR{i}");
                w.String("en_GB.UTF-8");
            });
        }

        await rig.SendRequestAsync(channel.LocalId, "shell", wantReply: true);

        // Everything before the barrier has been handled, and the connection is still up.
        Assert.Empty(await rig.RestAsync(Remote));
        Assert.False(rig.Connection.Ended.IsCompleted);
        Assert.Equal(Burst + 2, channel.QueuedRequestCount);
        Assert.InRange(channel.QueuedRequestBytes, 1, SshChannel.MaxQueuedRequestBytes);

        // Taking a request gives back what it cost.
        List<string> types = [];
        while (channel.Requests.TryRead(out IncomingChannelRequest? request))
        {
            types.Add(request.Type);
        }

        Assert.Equal("pty-req", types[0]);
        Assert.Equal("shell", types[^1]);
        Assert.Equal(0, channel.QueuedRequestBytes);
    }

    // C2: the limit is on what the requests cost, so a peer that sends without the application reading is still stopped.
    [Fact]
    public async Task Requests_past_the_byte_limit_end_the_connection()
    {
        await using ChannelRig rig = await ChannelRig.StartAsync(Ct);
        SshChannel channel = await rig.OpenAsync(Remote);
        channel.QueueIncomingRequests = true;

        byte[] large = new byte[30_000];
        int sent = 0;
        while (!rig.Connection.Ended.IsCompleted && sent < 100)
        {
            try
            {
                await rig.SendRequestAsync(channel.LocalId, "x-large@example.com", wantReply: true, w => w.Bytes(large));
            }
            catch (SshException)
            {
                // The connection ended under this send.
                break;
            }

            sent++;
            Assert.InRange(channel.QueuedRequestBytes, 0, SshChannel.MaxQueuedRequestBytes);
        }

        SshException? reason = await rig.Connection.CloseReason.WaitAsync(Limit, Ct);
        SshProtocolException protocol = Assert.IsType<SshProtocolException>(reason);
        Assert.Contains("1 MiB", protocol.Message, StringComparison.Ordinal);
        Assert.InRange(sent, SshChannel.MaxQueuedRequestBytes / large.Length - 1, 100);
    }

    private static void Pty(Zorg.Ssh.Auth.SshRequestWriter w)
    {
        w.String("xterm-256color");
        w.UInt32(80);
        w.UInt32(24);
        w.UInt32(0);
        w.UInt32(0);
        w.String(string.Empty);
    }
}

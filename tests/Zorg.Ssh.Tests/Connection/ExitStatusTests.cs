using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Auth;
using Zorg.Ssh.Connection;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Tests.Connection;

/// <summary>exit-status and exit-signal (RFC 4254 section 6.10): a server sends them, about a session the client opened.</summary>
public sealed class ExitStatusTests
{
    private const uint Remote = 1;

    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(20);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task A_client_session_takes_exit_status_and_exit_signal()
    {
        await using ChannelRig rig = await ChannelRig.StartAsync(Ct);
        SshChannel channel = await rig.OpenAsync(Remote);

        await SendExitAsync(rig, channel);
        await UntilAsync(() => channel.ExitSignal is not null);

        Assert.Equal(7, channel.ExitCode);
        Assert.Equal("KILL", channel.ExitSignal);
        Assert.DoesNotContain(MessageNumber.ChannelFailure, await rig.RestAsync(Remote));
    }

    // C5: a server-side channel took a client's exit-status and exit-signal, and set ExitCode and ExitSignal from them, where
    // every other request it doesn't handle goes to the application and is refused there.
    [Fact]
    public async Task A_server_channel_queues_exit_status_from_the_client_instead_of_taking_it()
    {
        await using ChannelRig rig = await ChannelRig.StartAsync(Ct);
        SshChannel channel = await rig.OpenAsync(Remote);
        channel.QueueIncomingRequests = true;

        await SendExitAsync(rig, channel);
        Assert.Empty(await rig.RestAsync(Remote));

        Assert.Null(channel.ExitCode);
        Assert.Null(channel.ExitSignal);
        List<string> types = [];
        while (channel.Requests.TryRead(out IncomingChannelRequest? request))
        {
            types.Add(request.Type);
        }

        Assert.Equal(["exit-status", "exit-signal"], types);
    }

    // C5: and a channel that isn't a session has no exit status, so the request is refused like any other.
    [Fact]
    public async Task A_direct_tcpip_channel_refuses_exit_status()
    {
        await using ChannelRig rig = await ChannelRig.StartAsync(Ct);
        SshChannel channel = await rig.OpenAsync(Remote, type: "direct-tcpip");

        await SendExitAsync(rig, channel);

        Assert.Equal(MessageNumber.ChannelFailure, await rig.NextAsync(Remote));
        Assert.Equal(MessageNumber.ChannelFailure, await rig.NextAsync(Remote));
        Assert.Null(channel.ExitCode);
        Assert.Null(channel.ExitSignal);
    }

    private static async Task SendExitAsync(ChannelRig rig, SshChannel channel)
    {
        await rig.SendRequestAsync(channel.LocalId, "exit-status", wantReply: true, w => w.UInt32(7));
        await rig.SendRequestAsync(channel.LocalId, "exit-signal", wantReply: true, static (SshRequestWriter w) =>
        {
            w.String("KILL");
            w.Bool(false);
            w.String("msg");
            w.String(string.Empty);
        });
    }

    private static async Task UntilAsync(Func<bool> condition)
    {
        using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        limit.CancelAfter(Limit);
        while (!condition())
        {
            await Task.Delay(10, limit.Token);
        }
    }
}

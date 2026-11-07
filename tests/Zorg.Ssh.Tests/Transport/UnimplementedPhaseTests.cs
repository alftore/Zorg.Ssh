using System;
using System.Buffers.Binary;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Transport;
using static Zorg.Ssh.Tests.Transport.TransportHarness;

namespace Zorg.Ssh.Tests.Transport;

/// <summary>UNIMPLEMENTED can answer a global request, so the transport hands it on only in the Connected phase.</summary>
public sealed class UnimplementedPhaseTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static byte[] Unimplemented(uint sequence)
    {
        byte[] payload = new byte[5];
        payload[0] = MessageNumber.Unimplemented;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1), sequence);
        return payload;
    }

    [Theory]
    [InlineData((int)TransportPhase.InitialKex)]
    [InlineData((int)TransportPhase.AwaitService)]
    [InlineData((int)TransportPhase.Auth)]
    public async Task UNIMPLEMENTED_before_the_connection_is_up_reaches_no_handler(int phaseValue)
    {
        (SshTransport client, SshTransport server) = await ConnectAsync(ClientOptions(), ServerOptions(), Ct);
        await using (client)
        await using (server)
        {
            int calls = 0;
            server.UnimplementedHandler = _ => Interlocked.Increment(ref calls);
            server.SetPhase((TransportPhase)phaseValue);

            await client.SendAsync(Unimplemented(3), Ct);
            await client.SendAsync([MessageNumber.Disconnect, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0], Ct);
            await Assert.ThrowsAnyAsync<SshException>(async () => await server.ReceiveAsync(Ct));

            Assert.Equal(0, calls);
        }
    }

    [Fact]
    public async Task UNIMPLEMENTED_once_connected_reaches_the_handler()
    {
        (SshTransport client, SshTransport server) = await ConnectAsync(ClientOptions(), ServerOptions(), Ct);
        await using (client)
        await using (server)
        {
            MarkConnected(client, server);
            TaskCompletionSource<uint> seen = new(TaskCreationOptions.RunContinuationsAsynchronously);
            server.UnimplementedHandler = seen.SetResult;
            _ = server.ReceiveAsync(Ct).AsTask().ContinueWith(static t => _ = t.Exception, TaskScheduler.Default);

            await client.SendAsync(Unimplemented(7), Ct);

            Assert.Equal(7u, await seen.Task.WaitAsync(TimeSpan.FromSeconds(10), Ct));
        }
    }
}

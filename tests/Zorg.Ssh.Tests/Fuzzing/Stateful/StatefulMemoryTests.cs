using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Tests.Fuzzing.Stateful;

/// <summary>
/// Guarantee 3 across a long sequence on one connection. The fuzzer's inputs are short, so each is checked at its end. These tests run
/// thousands of messages of every kind that costs the SUT something on one connection, measure it at intervals while it is busy, and
/// insist that what it holds stays within its limits and does not grow.
/// </summary>
// Serial: the live heap is process-wide, and tests running beside this one would move it.
[Collection(Zorg.Ssh.Tests.Sftp.SftpSerialTests.Name)]
public sealed class StatefulMemoryTests
{
    private const int Rounds = 40;
    private const long AllowedGrowth = 24L * 1024 * 1024;

    // Not a finding: the guarantee the key exchange injection checks, pinned with fixed inputs. A channel open is queued behind the peer's KEXINIT, where policy
    // forbids every connection message. The rig throws "GUARANTEE 1 BREACH" if the SUT answers it, and the SUT must end the connection instead.
    [Fact]
    public void A_channel_open_sent_in_the_middle_of_the_peers_key_exchange_is_refused_by_both_roles_and_never_answered()
    {
        using ServerRig server = new(preAuth: false, Depth.Authenticated);
        server.Run(
            FuzzOpCodec.Encode(0, [FuzzOp.Send(Wire.ServiceRequest()), FuzzOp.Await(MessageNumber.ServiceAccept), FuzzOp.Send(Wire.AuthPassword(Wire.Secret)), FuzzOp.Await(MessageNumber.UserAuthSuccess), FuzzOp.Canary(0), FuzzOp.Canary(1)]),
            sftp: false);
        Assert.Contains("ended by", server.LastDescription, StringComparison.Ordinal);

        using ClientRig client = new(Depth.Authenticated);
        client.Run(FuzzOpCodec.Encode(0, [FuzzOp.Await(MessageNumber.ServiceRequest), FuzzOp.Send(Wire.ServiceAccept()), FuzzOp.Await(MessageNumber.UserAuthRequest), FuzzOp.Send(Wire.AuthFailure(false, "password")), FuzzOp.Await(MessageNumber.UserAuthRequest), FuzzOp.Send(Wire.AuthSuccess()), FuzzOp.Canary(0), FuzzOp.Canary(2)]));
    }

    [Fact]
    public void A_long_sequence_on_one_server_connection_holds_no_more_than_its_limits_and_its_memory_does_not_grow()
    {
        List<long> heap = [];
        List<string> broken = [];
        using ServerRig rig = new(preAuth: false) { PatientAwaits = true };
        rig.Probe = () =>
        {
            if (ServerRig.CheckBounds(rig.Connection, 10) is { } why)
            {
                broken.Add(why);
            }

            heap.Add(GC.GetTotalMemory(forceFullCollection: true));
            return Task.CompletedTask;
        };

        List<FuzzOp> ops =
        [
            FuzzOp.Send(Wire.ServiceRequest()),
            FuzzOp.Await(MessageNumber.ServiceAccept),
            FuzzOp.Send(Wire.AuthPassword(Wire.Secret)),
            FuzzOp.Await(MessageNumber.UserAuthSuccess),
            FuzzOp.Send(Wire.ChannelOpen("session", 100)),
            FuzzOp.Await(MessageNumber.ChannelOpenConfirmation),
            FuzzOp.Send(Wire.Exec(0, "run")),
            FuzzOp.Await(MessageNumber.ChannelSuccess),
            FuzzOp.Of(OpKind.Probe),
        ];
        for (int round = 0; round < Rounds; round++)
        {
            // Everything here is paced by a probe, which waits for the SUT to answer, so that the replies stay inside the control queue.
            ops.AddRange(Enumerable.Repeat(FuzzOp.Send(Wire.WindowAdjust(0, 1)), 60));
            ops.AddRange(Enumerable.Repeat(FuzzOp.Send(Wire.KeepAlive()), 60));
            ops.AddRange(Enumerable.Repeat(FuzzOp.Send(Wire.ChannelOpen("x11", 300)), 60));
            ops.AddRange(Enumerable.Repeat(FuzzOp.Data(0, new byte[200]), 20));
            ops.AddRange(Enumerable.Repeat(FuzzOp.Send(Wire.ChannelOpen("direct-tcpip", 301, Wire.DirectTcpExtra("10.1.1.1", 9))), 6));
            ops.AddRange(Enumerable.Repeat(FuzzOp.Send(Wire.TcpIpForward("0.0.0.0", 0)), 60));
            ops.Add(FuzzOp.Of(OpKind.Probe));
        }

        FuzzOutcome outcome = rig.Run(FuzzOpCodec.Encode(0, ops), sftp: false);
        Assert.Empty(broken);
        Assert.Equal(FuzzOutcome.Accepted, outcome);
        Assert.True(heap.Count > Rounds, $"Only {heap.Count} probes ran, so the connection did not survive the sequence. {rig.LastDescription}");
        long growth = heap[^1] - heap[1];
        Assert.True(growth < AllowedGrowth, $"The live heap grew by {growth} bytes over {Rounds} rounds on one connection: {string.Join(", ", heap.Where((_, i) => i % 8 == 0))}");
    }

    [Fact]
    public void A_long_sequence_on_one_client_connection_holds_no_more_than_its_limits_and_its_memory_does_not_grow()
    {
        List<long> heap = [];
        List<string> broken = [];
        using ClientRig rig = new() { PatientAwaits = true };
        rig.Probe = client =>
        {
            if (client is not null && ServerRig.CheckBounds(client.Connection, 256) is { } why)
            {
                broken.Add(why);
            }

            heap.Add(GC.GetTotalMemory(forceFullCollection: true));
            return Task.CompletedTask;
        };

        List<FuzzOp> ops =
        [
            FuzzOp.Await(MessageNumber.ServiceRequest),
            FuzzOp.Send(Wire.ServiceAccept()),
            FuzzOp.Await(MessageNumber.UserAuthRequest),
            FuzzOp.Send(Wire.AuthFailure(false, "password")),
            FuzzOp.Await(MessageNumber.UserAuthRequest),
            FuzzOp.Send(Wire.AuthSuccess()),

            // The app op gives the client's connect only a moment to finish, and on a loaded machine it can take longer. If it
            // hadn't, no channel would be opened and the rest would answer a channel that was never asked for. A probe waits for it.
            FuzzOp.Of(OpKind.Probe),
            FuzzOp.App(0),
            FuzzOp.Await(MessageNumber.ChannelOpen),
            FuzzOp.Send(Wire.ChannelOpenConfirmation(0, 100)),
            FuzzOp.Await(MessageNumber.ChannelRequest),
            FuzzOp.Send(Wire.ChannelSuccess(0)),
            FuzzOp.Of(OpKind.Probe),
        ];
        for (int round = 0; round < Rounds; round++)
        {
            ops.AddRange(Enumerable.Repeat(FuzzOp.Send(Wire.WindowAdjust(0, 1)), 60));
            ops.AddRange(Enumerable.Repeat(FuzzOp.Send(Wire.GlobalRequest("hostkeys-00@openssh.com", true)), 60));
            ops.AddRange(Enumerable.Repeat(FuzzOp.Send(Wire.ChannelOpen("x11", 300)), 60));
            ops.AddRange(Enumerable.Repeat(FuzzOp.Send(Wire.ChannelOpen("forwarded-tcpip", 301, Wire.ForwardedTcpExtra("127.0.0.1", 9))), 60));
            ops.AddRange(Enumerable.Repeat(FuzzOp.Send(Wire.ChannelData(0, new byte[300])), 20));
            ops.AddRange(Enumerable.Repeat(FuzzOp.Send(Wire.RequestSuccess()), 60));
            ops.Add(FuzzOp.Of(OpKind.Probe));
        }

        FuzzOutcome outcome = rig.Run(FuzzOpCodec.Encode(0, ops));
        Assert.Empty(broken);
        Assert.Equal(FuzzOutcome.Accepted, outcome);
        Assert.True(heap.Count > Rounds, $"Only {heap.Count} probes ran, so the connection did not survive the sequence. {rig.LastDescription}");
        long growth = heap[^1] - heap[1];
        Assert.True(growth < AllowedGrowth, $"The live heap grew by {growth} bytes over {Rounds} rounds on one connection: {string.Join(", ", heap.Where((_, i) => i % 8 == 0))}");
    }
}

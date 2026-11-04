using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Transport;
using static Zorg.Ssh.Tests.Transport.TransportHarness;

namespace Zorg.Ssh.Tests.Transport;

public class RekeyTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public static TheoryData<string, string?> AllCiphers() => TransportTests.AllCiphers();

    /// <summary>Reads until stopped, as the connection loop will: someone must always drive the receive path.</summary>
    private static async Task DrainAsync(SshTransport transport, Action<ReadOnlyMemory<byte>> onMessage, CancellationToken stop)
    {
        try
        {
            while (true)
            {
                onMessage(await transport.ReceiveAsync(stop));
            }
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested)
        {
        }
    }

    private static async Task WaitForAsync(Func<bool> condition)
    {
        using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        limit.CancelAfter(TimeSpan.FromSeconds(30));
        while (!condition())
        {
            await Task.Delay(5, limit.Token);
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task A_rekey_from_either_side_keeps_the_session_and_the_traffic(bool clientStarts)
    {
        (SshTransport client, SshTransport server) = await ConnectAsync(ClientOptions(), ServerOptions(), Ct);
        await using (client)
        await using (server)
        {
            MarkConnected(client, server);
            byte[] session = client.SessionId.ToArray();
            List<byte> toClient = [];
            List<byte> toServer = [];
            using CancellationTokenSource stop = CancellationTokenSource.CreateLinkedTokenSource(Ct);
            Task c = DrainAsync(client, m => toClient.Add(m.Span[1]), stop.Token);
            Task s = DrainAsync(server, m => toServer.Add(m.Span[1]), stop.Token);

            SshTransport starter = clientStarts ? client : server;
            for (int i = 0; i < 3; i++)
            {
                int done = starter.CompletedKeyExchanges;
                starter.RequestRekey();
                await client.SendAsync(new byte[] { MessageNumber.ChannelData, (byte)i }, Ct);
                await server.SendAsync(new byte[] { MessageNumber.ChannelData, (byte)(i + 100) }, Ct);
                await WaitForAsync(() => starter.CompletedKeyExchanges > done);
            }

            await WaitForAsync(() => toClient.Count == 3 && toServer.Count == 3);
            await stop.CancelAsync();
            await Task.WhenAll(c, s);

            Assert.Equal([100, 101, 102], toClient);
            Assert.Equal([0, 1, 2], toServer);
            Assert.Equal(4, client.CompletedKeyExchanges);
            Assert.Equal(4, server.CompletedKeyExchanges);
            Assert.Equal(session, client.SessionId.ToArray());
            Assert.Equal(session, server.SessionId.ToArray());
        }
    }

    [Theory]
    [MemberData(nameof(AllCiphers))]
    public async Task Many_automatic_rekeys_under_load_lose_nothing(string cipher, string? mac)
    {
        const int Packets = 3000;
        const long Limit = 512 * 1024;
        IReadOnlyList<string> macs = mac is null ? PacketCipherCatalog.DefaultMacs : [mac];
        (SshTransport client, SshTransport server) = await ConnectAsync(
            ClientOptions(ciphers: [cipher], macs: macs, kex: ["curve25519-sha256"], rekeyBytes: Limit),
            ServerOptions(ciphers: [cipher], macs: macs, kex: ["curve25519-sha256"], rekeyBytes: Limit),
            Ct);
        await using (client)
        await using (server)
        {
            MarkConnected(client, server);
            int atClient = 0;
            int atServer = 0;
            using CancellationTokenSource stop = CancellationTokenSource.CreateLinkedTokenSource(Ct);
            Task c = DrainAsync(client, m => Assert.Equal(atClient++, BitConverter.ToInt32(m.Span[1..5])), stop.Token);
            Task s = DrainAsync(server, m => Assert.Equal(atServer++, BitConverter.ToInt32(m.Span[1..5])), stop.Token);

            await Task.WhenAll(SendAll(client), SendAll(server));
            await WaitForAsync(() => Volatile.Read(ref atClient) == Packets && Volatile.Read(ref atServer) == Packets);
            await stop.CancelAsync();
            await Task.WhenAll(c, s);
            Assert.True(client.CompletedKeyExchanges > 5, $"Only {client.CompletedKeyExchanges} key exchanges ran.");
        }

        static async Task SendAll(SshTransport from)
        {
            byte[] payload = new byte[2000];
            payload[0] = MessageNumber.ChannelData;
            for (int i = 0; i < Packets; i++)
            {
                BitConverter.TryWriteBytes(payload.AsSpan(1), i);
                await from.SendAsync(payload, Ct);
            }
        }
    }
}

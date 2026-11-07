#pragma warning disable xUnit1069 // Tests reach the token through the Ct property, which the analyzer can't see.

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Sftp;

namespace Zorg.Ssh.Tests.Sftp;

/// <summary>What a hostile or broken server can do to the client. Each test has a time limit, because a hang is a failure.</summary>
[Collection(SftpSerialTests.Name)]
public class SftpHostileServerTests
{
    private const int Limit = 30_000;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static ValueTask Silent(FakeSftpServer server, FakeRequest request) => ValueTask.CompletedTask;

    /// <summary>Waits for the session to report its end through a fresh call.</summary>
    private static Task AssertEndedAsync(SftpClient client) =>
        Assert.ThrowsAnyAsync<SshException>(() => client.GetFullPathAsync(".", Ct));

    // libssh CVE-2026-59848: a response must match a request that's outstanding.
    [Fact(Timeout = Limit)]
    public async Task Libssh_CVE_2026_59848_a_response_with_an_unknown_id_ends_the_session()
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) => server.SendStatusAsync(request.Id + 1000));
        SshProtocolException ex = await Assert.ThrowsAsync<SshProtocolException>(() => fake.Client.DeleteFileAsync("x", Ct));
        Assert.Contains("no outstanding request", ex.Message);
        SshConnectionException later = await Assert.ThrowsAsync<SshConnectionException>(() => fake.Client.DeleteFileAsync("x", Ct));
        Assert.IsType<SshProtocolException>(later.InnerException);
    }

    [Fact(Timeout = Limit)]
    public async Task Libssh_CVE_2026_59848_an_unsolicited_response_ends_the_session()
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(Silent);
        await fake.SendStatusAsync(7);
        await Assert.ThrowsAnyAsync<SshException>(async () =>
        {
            while (true)
            {
                await fake.Client.DeleteFileAsync("x", Ct);
            }
        });
    }

    [Fact(Timeout = Limit)]
    public async Task Libssh_CVE_2026_59848_a_duplicate_response_ends_the_session()
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(async (server, request) =>
        {
            await server.SendStatusAsync(request.Id);
            await server.SendStatusAsync(request.Id);
        });
        await fake.Client.DeleteFileAsync("x", Ct);
        await AssertEndedAsync(fake.Client);
    }

    [Fact(Timeout = Limit)]
    public async Task Libssh_CVE_2026_59848_a_flood_of_unsolicited_data_stops_at_the_first_packet()
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(async (server, request) =>
        {
            for (uint i = 0; i < 100; i++)
            {
                await server.SendDataAsync(request.Id + 1 + i, new byte[1000]);
            }
        });
        await Assert.ThrowsAsync<SshProtocolException>(() => fake.Client.ReadAllBytesAsync("x", Ct));
    }

    [Fact(Timeout = Limit)]
    public async Task A_response_of_the_wrong_type_ends_the_session()
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) => server.SendDataAsync(request.Id, [1, 2, 3]));
        SshProtocolException ex = await Assert.ThrowsAsync<SshProtocolException>(() => fake.Client.GetAttributesAsync("x", cancellationToken: Ct));
        Assert.Contains("doesn't allow", ex.Message);
    }

    [Fact(Timeout = Limit)]
    public async Task A_second_version_packet_ends_the_session()
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) => server.SendAsync(new Packet().U8(2).U32(3).ToFrame()));
        await Assert.ThrowsAsync<SshProtocolException>(() => fake.Client.GetFullPathAsync(".", Ct));
    }

    [Theory(Timeout = Limit)]
    [InlineData(uint.MaxValue)]
    [InlineData(0x80000000u)]
    [InlineData(256u * 1024 + 65)]
    public async Task An_oversized_length_is_rejected_from_the_header_alone(uint length)
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(async (server, request) =>
        {
            byte[] header = new byte[9];
            BinaryPrimitives.WriteUInt32BigEndian(header, length);
            header[4] = SftpMessage.Data;
            BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(5), request.Id);

            // No body follows, so only a check on the header itself can end this.
            await server.SendAsync(header);
        });
        SshProtocolException ex = await Assert.ThrowsAsync<SshProtocolException>(() => fake.Client.GetFullPathAsync(".", Ct));
        Assert.Contains("The limit is", ex.Message);
    }

    [Theory(Timeout = Limit)]
    [InlineData(0u)]
    [InlineData(1u)]
    [InlineData(4u)]
    public async Task A_length_too_small_to_hold_a_header_is_rejected(uint length)
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(async (server, request) =>
        {
            byte[] packet = new byte[9];
            BinaryPrimitives.WriteUInt32BigEndian(packet, length);
            await server.SendAsync(packet);
        });
        await Assert.ThrowsAsync<SshProtocolException>(() => fake.Client.GetFullPathAsync(".", Ct));
    }

    [Fact(Timeout = Limit)]
    public async Task A_packet_cut_off_in_its_header_is_a_protocol_failure()
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(async (server, request) =>
        {
            await server.SendAsync([0, 0, 0, 20, SftpMessage.Status]);
            await server.CloseAsync();
        });
        await Assert.ThrowsAsync<SshProtocolException>(() => fake.Client.GetFullPathAsync(".", Ct));
    }

    [Fact(Timeout = Limit)]
    public async Task A_packet_cut_off_in_its_body_is_a_protocol_failure()
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(async (server, request) =>
        {
            byte[] frame = new Packet().U8(SftpMessage.Status).U32(request.Id).U32(0).Text("a message").ToFrame();
            await server.SendAsync(frame[..^3]);
            await server.CloseAsync();
        });
        await Assert.ThrowsAsync<SshProtocolException>(() => fake.Client.DeleteFileAsync("x", Ct));
    }

    [Fact(Timeout = Limit)]
    public async Task A_connection_closed_between_packets_fails_every_waiting_call()
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(Silent);
        Task[] calls = [.. Enumerable.Range(0, 5).Select(_ => fake.Client.DeleteFileAsync("x", Ct))];
        await fake.WaitForRequestsAsync(5);
        await fake.CloseAsync();
        foreach (Task call in calls)
        {
            await Assert.ThrowsAsync<SshConnectionException>(() => call);
        }

        await Assert.ThrowsAsync<SshConnectionException>(() => fake.Client.DeleteFileAsync("x", Ct));
    }

    [Fact(Timeout = Limit)]
    public async Task A_stream_failure_of_any_type_comes_out_as_an_SshException()
    {
        (Stream client, _) = Zorg.Ssh.Tests.Transport.DuplexStream.CreatePair();
        byte[] version = new Packet().U8(SftpMessage.Version).U32(3).ToFrame();
        await using ThrowingStream stream = new(version, client);
        SftpClient sftp = await SftpClient.StartAsync(stream, stream, stream, null, SftpLimits.Default, Ct);
        await using (sftp)
        {
            SshConnectionException ex = await Assert.ThrowsAsync<SshConnectionException>(() => sftp.GetFullPathAsync(".", Ct));
            Assert.IsType<InvalidCastException>(ex.GetBaseException());
        }
    }

    // Every response parser, on every truncation of a valid body and on junk: nothing but SshException may escape.
    [Fact(Timeout = Limit)]
    public async Task Malformed_bodies_only_ever_give_SshProtocolException()
    {
        (byte Type, byte[] Body, Func<SftpClient, Task> Call)[] cases =
        [
            (SftpMessage.Handle, new Packet().Bytes([1, 2, 3, 4]).ToBytes(), c => c.OpenAsync("x", cancellationToken: Ct)),
            (SftpMessage.Name, new Packet().U32(1).Entry("name").ToBytes(), c => c.GetFullPathAsync(".", Ct)),
            (SftpMessage.Attrs, new Packet().U32(0x8000000F).U64(1).U32(2).U32(3).U32(4).U32(5).U32(6).U32(1).Text("a").Text("b").ToBytes(), c => c.GetAttributesAsync("x", cancellationToken: Ct)),
            (SftpMessage.Status, new Packet().U32(4).Text("failed").Text("en").ToBytes(), c => c.DeleteFileAsync("x", Ct)),
        ];

        Random random = new(1234);
        foreach ((byte type, byte[] body, Func<SftpClient, Task> call) in cases)
        {
            List<byte[]> bodies = [.. Enumerable.Range(0, body.Length).Select(cut => body[..cut])];
            bodies.AddRange(Enumerable.Range(0, 200).Select(_ =>
            {
                byte[] junk = new byte[random.Next(0, 64)];
                random.NextBytes(junk);
                return junk;
            }));

            foreach (byte[] sent in bodies)
            {
                await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) =>
                    server.SendAsync(new Packet().U8(type).U32(request.Id).Raw(sent).ToFrame()));
                Exception? thrown = await Record.ExceptionAsync(() => call(fake.Client));

                // Junk can happen to be valid, and a valid STATUS gives SftpException, so only the type family is asserted.
                if (thrown is not null)
                {
                    Assert.IsAssignableFrom<SshException>(thrown);
                }
            }
        }
    }

    [Fact(Timeout = Limit)]
    public async Task A_malformed_status_ends_the_session()
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) =>
            server.SendAsync(new Packet().U8(SftpMessage.Status).U32(request.Id).U32(4).U32(9999).ToFrame()));
        await Assert.ThrowsAsync<SshProtocolException>(() => fake.Client.DeleteFileAsync("x", Ct));
        await Assert.ThrowsAsync<SshConnectionException>(() => fake.Client.DeleteFileAsync("x", Ct));
    }

    [Fact(Timeout = Limit)]
    public async Task A_read_answered_with_more_than_was_asked_ends_the_session()
    {
        FakeFiles files = new() { Files = { ["f"] = new byte[10] } };
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) => request.Type == SftpMessage.Read
            ? server.SendDataAsync(request.Id, new byte[request.ReadArguments().Length + 1])
            : files.HandleAsync(server, request));
        await Assert.ThrowsAsync<SshProtocolException>(() => fake.Client.ReadAllBytesAsync("f", Ct));
    }

    [Theory(Timeout = Limit)]
    [InlineData(0)]
    [InlineData(257)]
    public async Task A_handle_of_an_illegal_size_ends_the_session(int length)
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) => server.SendHandleAsync(request.Id, new byte[length]));
        await Assert.ThrowsAsync<SshProtocolException>(() => fake.Client.OpenAsync("x", cancellationToken: Ct));
    }

    [Fact(Timeout = Limit)]
    public async Task A_file_size_past_the_range_of_a_long_ends_the_session()
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) => server.SendAttributesAsync(request.Id, ulong.MaxValue));
        await Assert.ThrowsAsync<SshProtocolException>(() => fake.Client.GetAttributesAsync("x", cancellationToken: Ct));
    }

    [Fact(Timeout = Limit)]
    public async Task Outstanding_requests_are_capped_and_a_silent_server_cant_hang_a_caller()
    {
        SftpLimits limits = new() { MaxOutstandingRequests = 4 };
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(Silent, limits: limits);
        using CancellationTokenSource cancel = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        Task[] calls = [.. Enumerable.Range(0, 10).Select(_ => fake.Client.DeleteFileAsync("x", cancel.Token))];

        await fake.WaitForRequestsAsync(4);
        await Task.Delay(200, Ct);
        Assert.Equal(4, fake.Requests.Count);

        await cancel.CancelAsync();
        foreach (Task call in calls)
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => call);
        }
    }

    [Fact(Timeout = Limit)]
    public async Task A_late_response_to_a_cancelled_request_is_still_valid_and_frees_its_slot()
    {
        SftpLimits limits = new() { MaxOutstandingRequests = 1 };
        TaskCompletionSource<uint> held = new();
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(
            async (server, request) =>
            {
                if (held.TrySetResult(request.Id))
                {
                    return;
                }

                await server.SendNamesAsync(request.Id, "/home");
            },
            limits: limits);

        using CancellationTokenSource cancel = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        Task first = fake.Client.DeleteFileAsync("x", cancel.Token);
        uint id = await held.Task;
        await cancel.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first);

        await fake.SendStatusAsync(id);
        Assert.Equal("/home", await fake.Client.GetFullPathAsync(".", Ct));
    }

    [Fact(Timeout = Limit)]
    public async Task A_handle_that_arrives_after_cancellation_is_closed()
    {
        TaskCompletionSource<uint> held = new();
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) =>
        {
            if (request.Type == SftpMessage.Open)
            {
                held.TrySetResult(request.Id);
                return ValueTask.CompletedTask;
            }

            return server.SendStatusAsync(request.Id);
        });

        using CancellationTokenSource cancel = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        Task open = fake.Client.OpenAsync("x", cancellationToken: cancel.Token);
        uint id = await held.Task;
        await cancel.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => open);

        await fake.SendHandleAsync(id, [1, 2, 3, 4]);
        await fake.WaitForRequestsAsync(1, r => r.Type == SftpMessage.Close);
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, fake.Requests.Single(r => r.Type == SftpMessage.Close).Body[4..]);
    }

    // A cancelled caller must not leave half a packet on the wire, or the next request would be garbage to the server.
    [Fact(Timeout = Limit)]
    public async Task Cancelling_a_write_stuck_on_backpressure_doesnt_tear_the_packet()
    {
        FakeFiles files = new();
        TaskCompletionSource open = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(
            async (server, request) =>
            {
                if (request.Type == SftpMessage.Write)
                {
                    await open.Task;
                }

                await files.HandleAsync(server, request);
            },
            limits: new SftpLimits { WriteChunk = 16 * 1024 },
            pauseThreshold: 4 * 1024);

        using CancellationTokenSource cancel = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        Task upload = fake.Client.WriteAllBytesAsync("big", new byte[1024 * 1024], cancel.Token);
        await fake.WaitForRequestsAsync(1, r => r.Type == SftpMessage.Write);
        await Task.Delay(100, Ct);
        await cancel.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => upload);

        open.SetResult();
        await fake.Client.WriteAllBytesAsync("after", new byte[] { 1, 2, 3 }, Ct);
        Assert.Equal(new byte[] { 1, 2, 3 }, await fake.Client.ReadAllBytesAsync("after", Ct));
    }

    [Fact(Timeout = Limit)]
    public async Task Zero_length_data_isnt_end_of_file()
    {
        byte[] content = [1, 2, 3, 4, 5];
        FakeFiles files = new() { Files = { ["f"] = content } };
        int sends = 0;
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) =>
            request.Type == SftpMessage.Read && Interlocked.Increment(ref sends) <= 2
                ? server.SendDataAsync(request.Id, [])
                : files.HandleAsync(server, request));

        Assert.Equal(content, await fake.Client.ReadAllBytesAsync("f", Ct));
    }

    [Fact(Timeout = Limit)]
    public async Task Endless_empty_reads_end_the_session_instead_of_spinning()
    {
        FakeFiles files = new() { Files = { ["f"] = new byte[1] } };
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) => request.Type == SftpMessage.Read
            ? server.SendDataAsync(request.Id, [])
            : files.HandleAsync(server, request));

        await Assert.ThrowsAsync<SshProtocolException>(() => fake.Client.ReadAllBytesAsync("f", Ct));
    }

    [Fact(Timeout = Limit)]
    public async Task Endless_empty_reads_through_a_file_stream_end_the_session()
    {
        FakeFiles files = new() { Files = { ["f"] = new byte[1] } };
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) => request.Type == SftpMessage.Read
            ? server.SendDataAsync(request.Id, [])
            : files.HandleAsync(server, request));

        await using SftpFile file = await fake.Client.OpenAsync("f", cancellationToken: Ct);
        await Assert.ThrowsAsync<SshProtocolException>(async () => await file.ReadAtLeastAsync(new byte[10], 1, throwOnEndOfStream: false, Ct));
    }

    [Fact(Timeout = Limit)]
    public async Task An_endless_file_stops_at_the_memory_limit()
    {
        FakeFiles files = new() { Files = { ["f"] = [] } };
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) => request.Type == SftpMessage.Read
            ? server.SendDataAsync(request.Id, new byte[request.ReadArguments().Length])
            : files.HandleAsync(server, request));

        fake.Client.Options = new SftpClientOptions { MaxReadAllBytes = 1024 * 1024 };
        SftpException ex = await Assert.ThrowsAsync<SftpException>(() => fake.Client.ReadAllBytesAsync("f", Ct));
        Assert.Contains("SftpClientOptions.MaxReadAllBytes", ex.Message);

        // That's a local limit, not a protocol failure, so the session lives on.
        Assert.False(await fake.Client.ExistsAsync("missing", Ct));
    }

    [Fact(Timeout = Limit)]
    public async Task An_endless_listing_stops_at_the_entry_limit()
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) => request.Type == SftpMessage.ReadDir
            ? server.SendNamesAsync(request.Id, "a", "b", "c", "d")
            : request.Type == SftpMessage.OpenDir ? server.SendHandleAsync(request.Id, [1]) : server.SendStatusAsync(request.Id));

        fake.Client.Options = new SftpClientOptions { MaxDirectoryEntries = 1000 };
        int seen = 0;
        SftpException ex = await Assert.ThrowsAsync<SftpException>(async () =>
        {
            await foreach (SftpEntry entry in fake.Client.ListDirectoryAsync("d", Ct))
            {
                seen++;
            }
        });
        Assert.Contains("SftpClientOptions.MaxDirectoryEntries", ex.Message);
        Assert.True(seen <= 1000);

        // The handle was closed on the way out.
        await fake.WaitForRequestsAsync(1, r => r.Type == SftpMessage.Close);
    }

    [Fact(Timeout = Limit)]
    public async Task An_endless_listing_can_be_cancelled()
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) => request.Type == SftpMessage.ReadDir
            ? server.SendNamesAsync(request.Id, "a")
            : request.Type == SftpMessage.OpenDir ? server.SendHandleAsync(request.Id, [1]) : server.SendStatusAsync(request.Id));

        using CancellationTokenSource cancel = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
        {
            int seen = 0;
            await foreach (SftpEntry entry in fake.Client.ListDirectoryAsync("d", cancel.Token))
            {
                if (++seen == 50)
                {
                    await cancel.CancelAsync();
                }
            }
        });
    }

    [Fact(Timeout = Limit)]
    public async Task Endless_empty_listings_end_the_session()
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) => request.Type == SftpMessage.ReadDir
            ? server.SendNamesAsync(request.Id)
            : request.Type == SftpMessage.OpenDir ? server.SendHandleAsync(request.Id, [1]) : server.SendStatusAsync(request.Id));

        await Assert.ThrowsAsync<SshProtocolException>(async () =>
        {
            await foreach (SftpEntry entry in fake.Client.ListDirectoryAsync("d", Ct))
            {
                Assert.Fail(entry.Name);
            }
        });
    }

    [Fact(Timeout = Limit)]
    public async Task Too_many_names_in_one_packet_end_the_session()
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(
            (server, request) => request.Type == SftpMessage.ReadDir
                ? server.SendNamesAsync(request.Id, [.. Enumerable.Range(0, 5).Select(i => $"n{i}")])
                : request.Type == SftpMessage.OpenDir ? server.SendHandleAsync(request.Id, [1]) : server.SendStatusAsync(request.Id),
            limits: new SftpLimits { MaxNamesPerBatch = 4 });

        SshProtocolException ex = await Assert.ThrowsAsync<SshProtocolException>(async () =>
        {
            await foreach (SftpEntry entry in fake.Client.ListDirectoryAsync("d", Ct))
            {
                Assert.Fail(entry.Name);
            }
        });
        Assert.Contains("names in one packet", ex.Message);
    }

    [Fact(Timeout = Limit)]
    public async Task A_name_count_larger_than_the_packet_is_rejected_before_allocating()
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) => request.Type == SftpMessage.ReadDir
            ? server.SendAsync(new Packet().U8(SftpMessage.Name).U32(request.Id).U32(4000).ToFrame())
            : request.Type == SftpMessage.OpenDir ? server.SendHandleAsync(request.Id, [1]) : server.SendStatusAsync(request.Id));

        SshProtocolException ex = await Assert.ThrowsAsync<SshProtocolException>(async () =>
        {
            await foreach (SftpEntry entry in fake.Client.ListDirectoryAsync("d", Ct))
            {
                Assert.Fail(entry.Name);
            }
        });
        Assert.Contains("exceeds the packet", ex.Message);
    }

    [Theory(Timeout = Limit)]
    [InlineData(0u)]
    [InlineData(2u)]
    public async Task Realpath_must_give_exactly_one_name(uint count)
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) =>
            server.SendAsync(new Packet().U8(SftpMessage.Name).U32(request.Id).U32(count).Entry("/a").Entry("/b").ToFrame()));
        await Assert.ThrowsAsync<SshProtocolException>(() => fake.Client.GetFullPathAsync(".", Ct));
    }

    [Fact(Timeout = Limit)]
    public async Task A_status_of_ok_where_data_is_needed_ends_the_session()
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) => server.SendStatusAsync(request.Id));
        await Assert.ThrowsAsync<SshProtocolException>(() => fake.Client.GetAttributesAsync("x", cancellationToken: Ct));
    }

    [Fact(Timeout = Limit)]
    public async Task Server_text_in_an_exception_is_cleaned()
    {
        string message = "bad\u001b[31m\r\nthing" + new string('x', 5000);
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) => server.SendStatusAsync(request.Id, FakeSftpServer.StatusFailure, message));
        SftpException ex = await Assert.ThrowsAsync<SftpException>(() => fake.Client.DeleteFileAsync("x", Ct));
        Assert.DoesNotContain('\u001b', ex.Message);
        Assert.DoesNotContain('\n', ex.Message);
        Assert.True(ex.Message.Length < 1000);
    }

    [Fact(Timeout = Limit)]
    public async Task An_unknown_status_code_keeps_its_number()
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) => server.SendStatusAsync(request.Id, 99));
        SftpException ex = await Assert.ThrowsAsync<SftpException>(() => fake.Client.DeleteFileAsync("x", Ct));
        Assert.Equal((SftpStatusCode)99, ex.StatusCode);
    }

    [Fact(Timeout = Limit)]
    public async Task A_version_other_than_3_is_refused()
    {
        (Task<SftpClient> client, Stream server) = await FakeSftpServer.StartRawAsync(new Packet().U8(SftpMessage.Version).U32(6).ToFrame());
        await using (server)
        {
            await Assert.ThrowsAsync<SshProtocolException>(() => client);
        }
    }

    [Fact(Timeout = Limit)]
    public async Task A_first_packet_that_isnt_version_is_refused()
    {
        (Task<SftpClient> client, Stream server) = await FakeSftpServer.StartRawAsync(new Packet().U8(SftpMessage.Status).U32(3).ToFrame());
        await using (server)
        {
            await Assert.ThrowsAsync<SshProtocolException>(() => client);
        }
    }

    [Fact(Timeout = Limit)]
    public async Task An_oversized_version_packet_is_refused()
    {
        byte[] header = new byte[5];
        BinaryPrimitives.WriteUInt32BigEndian(header, uint.MaxValue);
        header[4] = SftpMessage.Version;
        (Task<SftpClient> client, Stream server) = await FakeSftpServer.StartRawAsync(header);
        await using (server)
        {
            await Assert.ThrowsAsync<SshProtocolException>(() => client);
        }
    }

    [Fact(Timeout = Limit)]
    public async Task Too_many_extensions_are_refused()
    {
        Packet version = new Packet().U8(SftpMessage.Version).U32(3);
        for (int i = 0; i < 5; i++)
        {
            version.Text($"x{i}").Text("1");
        }

        (Task<SftpClient> client, Stream server) = await FakeSftpServer.StartRawAsync(version.ToFrame(), new SftpLimits { MaxExtensions = 4 });
        await using (server)
        {
            await Assert.ThrowsAsync<SshProtocolException>(() => client);
        }
    }

    [Fact(Timeout = Limit)]
    public async Task A_server_that_closes_before_version_gives_a_connection_failure()
    {
        (Task<SftpClient> client, Stream server) = await FakeSftpServer.StartRawAsync([], close: true);
        await using (server)
        {
            await Assert.ThrowsAnyAsync<SshException>(() => client);
        }
    }

    [Fact(Timeout = Limit)]
    public async Task Malformed_limits_end_the_start()
    {
        (Stream client, Stream server) = Zorg.Ssh.Tests.Transport.DuplexStream.CreatePair();
        await using (server)
        {
            await server.WriteAsync(new Packet().U8(SftpMessage.Version).U32(3).Text("limits@openssh.com").Text("1").ToFrame(), Ct);
            Task<SftpClient> started = SftpClient.StartAsync(client, client, client, null, SftpLimits.Default, Ct);
            byte[] request = new byte[9 + 9 + 4 + "limits@openssh.com".Length];
            await server.ReadExactlyAsync(request, Ct);
            uint id = BinaryPrimitives.ReadUInt32BigEndian(request.AsSpan(14));
            await server.WriteAsync(new Packet().U8(SftpMessage.ExtendedReply).U32(id).U64(1).ToFrame(), Ct);
            await Assert.ThrowsAsync<SshProtocolException>(() => started);
        }
    }

    private sealed class ThrowingStream(byte[] handshake, Stream inner) : Stream
    {
        private int _position;

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_position == handshake.Length)
            {
                throw new InvalidCastException("Not an exception type anyone would catch.");
            }

            int count = Math.Min(buffer.Length, handshake.Length - _position);
            handshake.AsMemory(_position, count).CopyTo(buffer);
            _position += count;
            return ValueTask.FromResult(count);
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) => ValueTask.CompletedTask;

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}

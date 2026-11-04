using System;
using System.Buffers.Binary;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Transport;

namespace Zorg.Ssh.Tests.Transport;

public class PacketReaderTests
{
    private const int Max = 262144;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static PacketReader Reader(byte[] data) => new(new MemoryStream(data), Max);

    private static byte[] Ascii(string text) => Encoding.ASCII.GetBytes(text);

    private static byte[] Plain(byte[] payload, int padding)
    {
        byte[] packet = new byte[5 + payload.Length + padding];
        BinaryPrimitives.WriteUInt32BigEndian(packet, (uint)(1 + payload.Length + padding));
        packet[4] = (byte)padding;
        payload.CopyTo(packet, 5);
        return packet;
    }

    [Theory]
    [InlineData("SSH-2.0-OpenSSH_10.6\r\n", "SSH-2.0-OpenSSH_10.6")]
    [InlineData("SSH-2.0-LfOnly\n", "SSH-2.0-LfOnly")]
    [InlineData("SSH-1.99-Cisco-1.25\r\n", "SSH-1.99-Cisco-1.25")]
    [InlineData("SSH-2.0-with comment here\r\n", "SSH-2.0-with comment here")]
    public async Task Identification_lines_are_accepted(string wire, string expected)
    {
        using PacketReader reader = Reader(Ascii(wire));
        byte[] line = await reader.ReadIdentificationAsync(allowPreamble: false, Ct);
        Assert.Equal(expected, Encoding.ASCII.GetString(line));
    }

    [Fact]
    public async Task A_client_skips_lines_before_the_identification()
    {
        using PacketReader reader = Reader(Ascii("Welcome\r\nto the server\nSSH-2.0-x\r\n"));
        byte[] line = await reader.ReadIdentificationAsync(allowPreamble: true, Ct);
        Assert.Equal("SSH-2.0-x", Encoding.ASCII.GetString(line));
    }

    [Fact]
    public async Task A_server_refuses_lines_before_the_identification()
    {
        using PacketReader reader = Reader(Ascii("hello\r\nSSH-2.0-x\r\n"));
        await Assert.ThrowsAsync<SshProtocolException>(async () => await reader.ReadIdentificationAsync(allowPreamble: false, Ct));
    }

    [Theory]
    [InlineData("SSH-1.5-old\r\n")]
    [InlineData("SSH-3.0-future\r\n")]
    [InlineData("SSH-2.0\r\n")]
    [InlineData("SSH-2.0-a\0b\r\n")]
    [InlineData("SSH-2.0-a\u0001b\r\n")]
    public async Task Bad_identification_lines_are_rejected(string wire)
    {
        using PacketReader reader = Reader(Ascii(wire));
        await Assert.ThrowsAsync<SshProtocolException>(async () => await reader.ReadIdentificationAsync(allowPreamble: true, Ct));
    }

    // SSH.NET 2026 advisory: an endless banner must not grow memory without limit.
    [Fact]
    public async Task An_endless_line_without_a_line_feed_is_capped()
    {
        using PacketReader reader = Reader(new byte[1_000_000]);
        await Assert.ThrowsAsync<SshProtocolException>(async () => await reader.ReadIdentificationAsync(allowPreamble: true, Ct));
    }

    [Fact]
    public async Task An_identification_line_over_255_bytes_is_rejected()
    {
        using PacketReader reader = Reader(Ascii("SSH-2.0-" + new string('a', 250) + "\r\n"));
        await Assert.ThrowsAsync<SshProtocolException>(async () => await reader.ReadIdentificationAsync(allowPreamble: false, Ct));
    }

    [Fact]
    public async Task Too_many_preamble_lines_are_rejected()
    {
        StringBuilder text = new();
        for (int i = 0; i <= PacketReader.MaxPreambleLines; i++)
        {
            text.Append('\n');
        }

        using PacketReader reader = Reader(Ascii(text + "SSH-2.0-x\r\n"));
        await Assert.ThrowsAsync<SshProtocolException>(async () => await reader.ReadIdentificationAsync(allowPreamble: true, Ct));
    }

    [Fact]
    public async Task Too_many_preamble_bytes_are_rejected()
    {
        StringBuilder text = new();
        for (int i = 0; i < 100; i++)
        {
            text.Append(new string('a', 100)).Append('\n');
        }

        using PacketReader reader = Reader(Ascii(text + "SSH-2.0-x\r\n"));
        await Assert.ThrowsAsync<SshProtocolException>(async () => await reader.ReadIdentificationAsync(allowPreamble: true, Ct));
    }

    [Fact]
    public async Task Bytes_after_the_identification_stay_for_the_first_packet()
    {
        byte[] line = Ascii("SSH-2.0-x\r\n");
        byte[] packet = Plain([20, 1, 2], 4);
        byte[] data = new byte[line.Length + packet.Length];
        line.CopyTo(data, 0);
        packet.CopyTo(data, line.Length);

        using PacketReader reader = Reader(data);
        await reader.ReadIdentificationAsync(allowPreamble: false, Ct);
        ReadOnlyMemory<byte> payload = await reader.ReadPacketAsync(NoneCipher.Instance, 0, Ct);
        Assert.Equal([20, 1, 2], payload.ToArray());
    }

    // SSH.NET 2026 advisory: packet size 0.
    [Theory]
    [InlineData(0u)]
    [InlineData(1u)]
    [InlineData(4u)]
    [InlineData(262145u)]
    [InlineData(uint.MaxValue)]
    [InlineData(0x80000000u)]
    public async Task Hostile_packet_lengths_are_rejected_before_any_allocation(uint length)
    {
        byte[] data = new byte[16];
        BinaryPrimitives.WriteUInt32BigEndian(data, length);
        using PacketReader reader = Reader(data);
        await Assert.ThrowsAsync<SshProtocolException>(async () => await reader.ReadPacketAsync(NoneCipher.Instance, 0, Ct));
    }

    [Theory]
    [InlineData(3)] // below the minimum padding
    [InlineData(255)] // more than the packet holds
    public async Task Bad_padding_is_rejected(byte padding)
    {
        byte[] data = Plain(new byte[11], 4);
        data[4] = padding;
        using PacketReader reader = Reader(data);
        await Assert.ThrowsAsync<SshProtocolException>(async () => await reader.ReadPacketAsync(NoneCipher.Instance, 0, Ct));
    }

    [Fact]
    public async Task An_empty_payload_is_rejected()
    {
        using PacketReader reader = Reader(Plain([], 7));
        await Assert.ThrowsAsync<SshProtocolException>(async () => await reader.ReadPacketAsync(NoneCipher.Instance, 0, Ct));
    }

    [Fact]
    public async Task End_of_stream_mid_packet_is_a_connection_failure()
    {
        byte[] packet = Plain(new byte[100], 4);
        using PacketReader reader = Reader(packet.AsSpan(0, 50).ToArray());
        await Assert.ThrowsAsync<SshConnectionException>(async () => await reader.ReadPacketAsync(NoneCipher.Instance, 0, Ct));
    }

    [Fact]
    public async Task A_packet_larger_than_the_start_buffer_grows_it()
    {
        byte[] payload = new byte[200_000];
        payload[^1] = 9;
        using PacketReader reader = Reader(Plain(payload, 4));
        ReadOnlyMemory<byte> read = await reader.ReadPacketAsync(NoneCipher.Instance, 0, Ct);
        Assert.Equal(payload.Length, read.Length);
        Assert.Equal(9, read.Span[^1]);
    }

    [Fact]
    public async Task Packets_read_one_byte_at_a_time_reassemble_across_many_compactions()
    {
        using MemoryStream all = new();
        for (int i = 0; i < 40; i++)
        {
            byte[] payload = new byte[3000];
            payload[0] = (byte)i;
            all.Write(Plain(payload, 4));
        }

        using PacketReader reader = new(new TrickleStream(all.ToArray(), 7), Max);
        for (int i = 0; i < 40; i++)
        {
            ReadOnlyMemory<byte> read = await reader.ReadPacketAsync(NoneCipher.Instance, (uint)i, Ct);
            Assert.Equal(3000, read.Length);
            Assert.Equal((byte)i, read.Span[0]);
        }
    }

    private sealed class TrickleStream(byte[] data, int chunk) : MemoryStream(data)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            base.ReadAsync(buffer[..Math.Min(chunk, buffer.Length)], cancellationToken);
    }
}

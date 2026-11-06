using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Connection;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Tests.Transport;
using Zorg.Ssh.Transport;
using static Zorg.Ssh.Tests.Forwarding.ScriptedServer;

namespace Zorg.Ssh.Tests.Connection;

/// <summary>
/// A stream whose writes can be held shut, which is what a peer that stops reading looks like from here. Holding the
/// transport's send loop in a write fills the send queue with no sleeps, and <see cref="Stuck"/> says when it's there.
/// </summary>
internal sealed class GatedStream(Stream inner) : Stream
{
    private readonly Lock _lock = new();
    private TaskCompletionSource? _gate;
    private TaskCompletionSource _stuck = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>Gets a task that completes once a write is held at the gate.</summary>
    public Task Stuck
    {
        get
        {
            lock (_lock)
            {
                return _stuck.Task;
            }
        }
    }

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public void Shut()
    {
        lock (_lock)
        {
            _gate ??= new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            _stuck = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        }
    }

    public void Open()
    {
        TaskCompletionSource? gate;
        lock (_lock)
        {
            gate = _gate;
            _gate = null;
        }

        gate?.TrySetResult();
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        Task? wait;
        lock (_lock)
        {
            wait = _gate?.Task;
            if (wait is not null)
            {
                _stuck.TrySetResult();
            }
        }

        if (wait is not null)
        {
            await wait.WaitAsync(cancellationToken);
        }

        await inner.WriteAsync(buffer, cancellationToken);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
        inner.ReadAsync(buffer, cancellationToken);

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        inner.ReadAsync(buffer, offset, count, cancellationToken);

    public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override void Flush() => inner.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            Open();
            inner.Dispose();
        }

        base.Dispose(disposing);
    }
}

/// <summary>
/// A real <see cref="SshConnection"/> against a peer that does only what the test says. It hands out channels
/// directly, so a test can reach both halves of a channel, and it files what the peer receives by channel.
/// </summary>
internal sealed class ChannelRig : IAsyncDisposable
{
    public const int PacketSize = 1024;

    private const int QueueCapacity = 4;

    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(20);

    private readonly GatedStream _gate;
    private readonly SshTransport _peer;
    private readonly ConcurrentDictionary<uint, Channel<byte>> _byChannel = new();
    private readonly Channel<byte[]> _other = Channel.CreateUnbounded<byte[]>();
    private readonly CancellationToken _token;
    private readonly Task _reading;
    private uint _nextBarrier = 100_000;

    private ChannelRig(GatedStream gate, SshConnection connection, SshTransport peer, CancellationToken token)
    {
        _gate = gate;
        _peer = peer;
        _token = token;
        Connection = connection;
        _reading = Task.Run(ReadAsync, CancellationToken.None);
    }

    public SshConnection Connection { get; }

    public static async Task<ChannelRig> StartAsync(CancellationToken cancellationToken)
    {
        (Stream clientSide, Stream peerSide) = DuplexStream.CreatePair();
        GatedStream gate = new(clientSide);
        TransportOptions defaults = TransportHarness.ClientOptions();
        TransportOptions options = new()
        {
            Role = defaults.Role,
            KexAlgorithms = defaults.KexAlgorithms,
            Ciphers = defaults.Ciphers,
            Macs = defaults.Macs,
            RekeyBytes = defaults.RekeyBytes,
            HandshakeTimeout = defaults.HandshakeTimeout,
            HostKeyValidator = defaults.HostKeyValidator,
            SendQueueCapacity = QueueCapacity,
        };
        Task<SshTransport> peer = SshTransport.StartAsync(peerSide, TransportHarness.ServerOptions(), cancellationToken);
        SshTransport client = await SshTransport.StartAsync(gate, options, cancellationToken);
        SshTransport server = await peer;
        TransportHarness.MarkConnected(client, server);

        SshConnection connection = new(client);
        connection.Start();
        return new ChannelRig(gate, connection, server, cancellationToken);
    }

    /// <summary>Opens a channel the peer knows as <paramref name="remoteId"/>.</summary>
    public async Task<SshChannel> OpenAsync(uint remoteId, uint window = 1 << 24)
    {
        Task<SshChannel> open = Connection.OpenChannelAsync("session", _token);
        byte[] request = await _other.Reader.ReadAsync(_token).AsTask().WaitAsync(Limit, _token);
        SshReader reader = new(request);
        reader.ReadByte();
        reader.ReadUtf8String();
        uint local = reader.ReadUInt32();
        await _peer.SendAsync(
            Message(w =>
            {
                w.Byte(MessageNumber.ChannelOpenConfirmation);
                w.UInt32(local);
                w.UInt32(remoteId);
                w.UInt32(window);
                w.UInt32(PacketSize);
            }),
            _token);
        return await open.WaitAsync(Limit, _token);
    }

    /// <summary>
    /// Stops the peer reading, then writes on <paramref name="channel"/> until the send queue is full. It returns how
    /// many packets were asked for, and the last write, which is left waiting for room.
    /// </summary>
    public async Task<(int Packets, Task Stuck)> FillQueueAsync(SshChannel channel)
    {
        _gate.Shut();
        byte[] packet = new byte[PacketSize];
        await channel.WriteAsync(packet, _token);
        await _gate.Stuck.WaitAsync(Limit, _token);

        // The send loop is held at the gate, so a write that doesn't finish here won't finish until it opens.
        int packets = 1;
        while (true)
        {
            ValueTask write = channel.WriteAsync(packet, _token);
            packets++;
            if (!write.IsCompleted)
            {
                return (packets, write.AsTask());
            }

            await write;
        }
    }

    /// <summary>Lets the peer read again.</summary>
    public void Drain() => _gate.Open();

    public Task SendAsync(byte number, uint localId) =>
        _peer.SendAsync(
            Message(w =>
            {
                w.Byte(number);
                w.UInt32(localId);
            }),
            _token).AsTask();

    public Task GrantWindowAsync(uint localId, uint bytes) =>
        _peer.SendAsync(
            Message(w =>
            {
                w.Byte(MessageNumber.ChannelWindowAdjust);
                w.UInt32(localId);
                w.UInt32(bytes);
            }),
            _token).AsTask();

    /// <summary>Returns the next message number the peer received for a channel.</summary>
    public async Task<byte> NextAsync(uint remoteId) =>
        await For(remoteId).Reader.ReadAsync(_token).AsTask().WaitAsync(Limit, _token);

    /// <summary>Reads what a channel received, up to and including <paramref name="last"/>.</summary>
    public async Task<List<byte>> ReadUntilAsync(uint remoteId, byte last)
    {
        List<byte> seen = [];
        byte number;
        do
        {
            number = await NextAsync(remoteId);
            seen.Add(number);
        }
        while (number != last);
        return seen;
    }

    /// <summary>
    /// Waits for everything queued so far to reach the peer, and returns what else a channel received. Deferred sends
    /// run in order, so a fresh channel's EOF arriving means whatever was deferred before it has gone.
    /// </summary>
    public async Task<List<byte>> RestAsync(uint remoteId)
    {
        uint barrier = _nextBarrier++;
        SshChannel channel = await OpenAsync(barrier);
        await channel.Input.DisposeAsync();
        Assert.Equal(MessageNumber.ChannelEof, await NextAsync(barrier));

        List<byte> seen = [];
        while (For(remoteId).Reader.TryRead(out byte number))
        {
            seen.Add(number);
        }

        return seen;
    }

    /// <summary>Ends the connection from the peer's side.</summary>
    public async Task KillPeerAsync() => await _peer.CloseAsync();

    public async ValueTask DisposeAsync()
    {
        await Connection.DisposeAsync();
        await _peer.CloseAsync();
        await _reading;
        await _peer.DisposeAsync();
    }

    private Channel<byte> For(uint remoteId) => _byChannel.GetOrAdd(remoteId, static _ => Channel.CreateUnbounded<byte>());

    private async Task ReadAsync()
    {
        try
        {
            while (true)
            {
                ReadOnlyMemory<byte> message = await _peer.ReceiveAsync(CancellationToken.None);
                byte number = message.Span[0];
                if (number is >= MessageNumber.ChannelWindowAdjust and <= MessageNumber.ChannelFailure)
                {
                    SshReader reader = new(message.Span);
                    reader.ReadByte();
                    For(reader.ReadUInt32()).Writer.TryWrite(number);
                }
                else
                {
                    _other.Writer.TryWrite(message.ToArray());
                }
            }
        }
        catch (Exception ex) when (ex is SshException or OperationCanceledException)
        {
            // The connection has ended, and that's the end of this loop.
        }
    }
}

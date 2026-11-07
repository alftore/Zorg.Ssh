#pragma warning disable CA1031 // The executor catches everything on purpose: the SUT's exceptions are judged by the oracles, not here.

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Sftp;
using Zorg.Ssh.Transport;

namespace Zorg.Ssh.Tests.Fuzzing.Stateful;

/// <summary>What the peer does when the SUT is an SFTP client: it is a small, honest SFTP server, whose next answer a fuzz op can corrupt.</summary>
internal sealed class SftpPeerServer
{
    private const uint Eof = 1;
    private readonly Lock _gate = new();
    private readonly List<byte> _buffer = [];
    private readonly Queue<byte[]> _armed = new();
    private readonly Dictionary<string, int> _listed = [];
    private readonly Channel<byte[]> _replies = Channel.CreateUnbounded<byte[]>();
    private bool _enabled;
    private int _handles;

    public uint SutChannel { get; set; }

    public uint PeerChannel { get; set; } = 100;

    public int Requests { get; private set; }

    public ChannelReader<byte[]> Replies => _replies.Reader;

    public void Enable()
    {
        lock (_gate)
        {
            _enabled = true;
        }

        Process();
    }

    /// <summary>Makes the next answer a mutation of the honest one (mode 2), or a fixed one (mode 1), or an unrequested one (mode 3).</summary>
    public void Arm(byte[] instruction)
    {
        if (instruction.Length > 0 && instruction[0] == 3)
        {
            _replies.Writer.TryWrite(instruction.AsSpan(1).ToArray());
            return;
        }

        lock (_gate)
        {
            if (_armed.Count < 64)
            {
                _armed.Enqueue(instruction);
            }
        }
    }

    public void Feed(ReadOnlySpan<byte> data)
    {
        lock (_gate)
        {
            if (_buffer.Count < (4 << 20))
            {
                _buffer.AddRange(data.ToArray());
            }
        }

        Process();
    }

    public void Complete() => _replies.Writer.TryComplete();

    private void Process()
    {
        while (true)
        {
            byte[] frame;
            byte[]? arming = null;
            lock (_gate)
            {
                if (!_enabled || _buffer.Count < 4)
                {
                    return;
                }

                uint length = BinaryPrimitives.ReadUInt32BigEndian([.. _buffer.Take(4)]);
                if (length is < 1 or > (1 << 20))
                {
                    _buffer.Clear();
                    return;
                }

                if (_buffer.Count < 4 + length)
                {
                    return;
                }

                frame = [.. _buffer.Take(4 + (int)length)];
                _buffer.RemoveRange(0, 4 + (int)length);
                Requests++;
                if (frame[4] != SftpMessage.Init && _armed.Count > 0)
                {
                    arming = _armed.Dequeue();
                }
            }

            byte[] honest = Answer(frame);
            byte[] reply = arming is null ? honest : Arm(arming, frame, honest);
            if (reply.Length > 0)
            {
                _replies.Writer.TryWrite(reply);
            }
        }
    }

    private static byte[] Arm(byte[] instruction, byte[] request, byte[] honest)
    {
        if (instruction.Length == 0)
        {
            return honest;
        }

        uint id = request.Length >= 9 ? BinaryPrimitives.ReadUInt32BigEndian(request.AsSpan(5)) : 0;
        if (instruction[0] == 1 && instruction.Length >= 2)
        {
            // A fixed answer of the given type with the request's id: the type may be one this request must not get.
            return Wire.SftpFrame(instruction[1], id, instruction[2..]);
        }

        if (instruction[0] == 2 && instruction.Length >= 9)
        {
            FuzzRandom random = new(BinaryPrimitives.ReadUInt64BigEndian(instruction.AsSpan(1)));
            byte[] mutated = FuzzMutator.MutateBinary(random, FuzzSeed.Binary("sftp reply", honest), [FuzzSeed.Binary("sftp reply", honest)]);
            return mutated;
        }

        return honest;
    }

    private byte[] Answer(byte[] frame)
    {
        byte type = frame[4];
        if (type == SftpMessage.Init)
        {
            return VersionFrame();
        }

        if (frame.Length < 9)
        {
            return [];
        }

        uint id = BinaryPrimitives.ReadUInt32BigEndian(frame.AsSpan(5));
        byte[] body = frame[9..];
        switch (type)
        {
            case SftpMessage.Open:
            case SftpMessage.OpenDir:
                _handles++;
                return Wire.SftpFrame(SftpMessage.Handle, id, new FuzzBlob().String(HandleBytes(_handles)).ToArray());
            case SftpMessage.Read:
                SshReader reader = new(body);
                try
                {
                    reader.ReadBinary();
                    ulong offset = reader.ReadUInt64();
                    uint wanted = reader.ReadUInt32();
                    return offset < 64
                        ? Wire.SftpFrame(SftpMessage.Data, id, new FuzzBlob().String(new byte[Math.Min(wanted, 64u)]).ToArray())
                        : Status(id, Eof);
                }
                catch (SshProtocolException)
                {
                    return Status(id, 4);
                }

            case SftpMessage.ReadDir:
                string key = Convert.ToHexString(body.Length > 4 ? body[4..Math.Min(body.Length, 12)] : body);
                if (_listed.TryAdd(key, 1))
                {
                    return Wire.SftpFrame(SftpMessage.Name, id, new FuzzBlob().UInt32(3).Raw(Entry(".")).Raw(Entry("..")).Raw(Entry("a.txt")).ToArray());
                }

                return Status(id, Eof);
            case SftpMessage.Stat or SftpMessage.Lstat or SftpMessage.Fstat:
                return Wire.SftpFrame(SftpMessage.Attrs, id, Attributes());
            case SftpMessage.RealPath or SftpMessage.ReadLink:
                return Wire.SftpFrame(SftpMessage.Name, id, new FuzzBlob().UInt32(1).Raw(Entry("/home/fuzzer")).ToArray());
            case SftpMessage.Extended:
                SshReader extended = new(body);
                try
                {
                    if (extended.ReadUtf8String() == "limits@openssh.com")
                    {
                        return Wire.SftpFrame(SftpMessage.ExtendedReply, id, new FuzzBlob().UInt64(262144).UInt64(32768).UInt64(32768).UInt64(64).ToArray());
                    }
                }
                catch (SshProtocolException)
                {
                    // Answered below.
                }

                return Status(id, 8);
            default:
                return Status(id, 0);
        }
    }

    private static byte[] VersionFrame()
    {
        byte[] body = Wire.SftpVersionBody(("limits@openssh.com", "1"), ("posix-rename@openssh.com", "1"));
        return new FuzzBlob().UInt32((uint)(1 + body.Length)).Byte(SftpMessage.Version).Raw(body).ToArray();
    }

    private static byte[] HandleBytes(int number) => [(byte)'H', (byte)(number >> 8), (byte)number, 0xA5];

    private static byte[] Status(uint id, uint code) => Wire.SftpFrame(SftpMessage.Status, id, new FuzzBlob().UInt32(code).String("status").String("en").ToArray());

    private static byte[] Attributes() => new FuzzBlob().UInt32(1 | 4 | 8).UInt64(5).UInt32(0x81A4).UInt32(1_700_000_000).UInt32(1_700_000_100).ToArray();

    private static byte[] Entry(string name) => new FuzzBlob().String(name).String("-rw-r--r-- 1 fuzzer fuzzer 5 Jan 1 2024 " + name).Raw(Attributes()).ToArray();
}

/// <summary>Follows the SFTP answers an SFTP server sent to the peer, so a later request can carry a handle the server really issued.</summary>
internal sealed class SftpPeerClientView
{
    private readonly Lock _gate = new();
    private readonly List<byte> _buffer = [];

    public byte[]? LastHandle { get; private set; }

    public int Replies { get; private set; }

    public bool SawVersion { get; private set; }

    public void Feed(ReadOnlySpan<byte> data)
    {
        lock (_gate)
        {
            if (_buffer.Count < (4 << 20))
            {
                _buffer.AddRange(data.ToArray());
            }

            while (_buffer.Count >= 5)
            {
                uint length = BinaryPrimitives.ReadUInt32BigEndian([.. _buffer.Take(4)]);
                if (length is < 1 or > (1 << 20))
                {
                    _buffer.Clear();
                    return;
                }

                if (_buffer.Count < 4 + length)
                {
                    return;
                }

                byte[] frame = [.. _buffer.Take(4 + (int)length)];
                _buffer.RemoveRange(0, 4 + (int)length);
                Replies++;
                if (frame[4] == SftpMessage.Version)
                {
                    SawVersion = true;
                }
                else if (frame[4] == SftpMessage.Handle && frame.Length >= 13)
                {
                    SshReader reader = new(frame.AsSpan(9));
                    try
                    {
                        LastHandle = reader.ReadBinary().ToArray();
                    }
                    catch (SshProtocolException)
                    {
                        // A malformed handle reply isn't kept.
                    }
                }
            }
        }
    }
}

/// <summary>Plays the ops of one input against a connected peer. The ops decide what is sent and when. Nothing here knows what the SUT should answer.</summary>
internal sealed class SequenceExecutor
{
    private static readonly TimeSpan BarrierLimit = TimeSpan.FromSeconds(8);

    private readonly StatefulPeer _peer;
    private readonly Func<byte, Task>? _app;
    private readonly SftpPeerServer _sftpServer = new();
    private readonly SftpPeerClientView _sftpView = new();
    private int _awaitCursor;
    private TimeSpan _awaitSpent;
    private readonly Task? _replySender;

    public SequenceExecutor(StatefulPeer peer, Func<byte, Task>? app)
    {
        _peer = peer;
        _app = app;
        peer.OnMessage = OnMessage;
        _replySender = Task.Run(SendRepliesAsync);
    }

    /// <summary>Gets how many ops ran before the connection ended or the ops did.</summary>
    public int OpsRun { get; private set; }

    public int AwaitMisses { get; private set; }

    public SftpPeerServer SftpServer => _sftpServer;

    public SftpPeerClientView SftpView => _sftpView;

    public int AwaitHits { get; private set; }

    public async Task RunAsync(IReadOnlyList<FuzzOp> ops)
    {
        foreach (FuzzOp op in ops)
        {
            if (_peer.HasEnded || _peer.SendStalled)
            {
                break;
            }

            OpsRun++;
            switch (op.Kind)
            {
                case OpKind.Send:
                    await _peer.SendAsync(op.Body).ConfigureAwait(false);
                    break;
                case OpKind.Data:
                    await SendDataAsync(op.Body).ConfigureAwait(false);
                    break;
                case OpKind.SignedAuth:
                    await _peer.SendAsync(Sign(op.Body)).ConfigureAwait(false);
                    break;
                case OpKind.Await:
                    if (op.Body.Length > 0)
                    {
                        await AwaitMessageAsync(op.Body[0]).ConfigureAwait(false);
                    }

                    break;
                case OpKind.SftpRespond:
                    HandleSftp(op.Body);
                    break;
                case OpKind.Rekey:
                    try
                    {
                        _peer.Transport.RequestRekey();
                    }
                    catch (SshException)
                    {
                        // The connection is over.
                    }

                    break;
                case OpKind.App:
                    if (_app is not null && op.Body.Length > 0)
                    {
                        await _app(op.Body[0]).ConfigureAwait(false);
                    }

                    break;
                case OpKind.Pause:
                    await Task.Delay(2).ConfigureAwait(false);
                    break;
                case OpKind.Disconnect:
                    _peer.Vanish();
                    return;
                default:
                    break;
            }
        }
    }

    /// <summary>
    /// Sends a message nothing uses and waits for the SUT's UNIMPLEMENTED for it. The SUT reads in order, so the answer proves it
    /// has dispatched everything sent before. It returns false if the connection ended first, and throws if neither happens in time.
    /// </summary>
    public async Task<bool> BarrierAsync()
    {
        if (_peer.HasEnded)
        {
            return false;
        }

        int from = _peer.ReceivedCount;
        SentSequence sent = new();
        if (!await _peer.SendTrackedAsync(Wire.Barrier(), sent).ConfigureAwait(false))
        {
            return false;
        }

        int found = await _peer.WaitForAsync(
            from,
            m => m.Number == MessageNumber.Unimplemented && m.Payload.Length >= 5 && sent.Is(BinaryPrimitives.ReadUInt32BigEndian(m.Payload.AsSpan(1))),
            BarrierLimit).ConfigureAwait(false);
        if (found >= 0)
        {
            return true;
        }

        if (_peer.HasEnded)
        {
            return false;
        }

        if (_peer.SendStalled)
        {
            throw new StatefulFindingException("Hang", $"A send waited more than {StatefulPeer.SendStallLimit.TotalSeconds:0} s: the SUT stopped reading from the connection.");
        }

        throw new StatefulFindingException("Hang", $"The SUT answered a probe message neither with UNIMPLEMENTED nor by closing within {BarrierLimit.TotalSeconds:0} s: its receive loop is stuck.");
    }

    public async Task StopAsync()
    {
        _sftpServer.Complete();
        if (_replySender is { } sender)
        {
            await Task.WhenAny(sender, Task.Delay(TimeSpan.FromSeconds(2))).ConfigureAwait(false);
        }
    }

    private void OnMessage(PeerMessage message)
    {
        switch (message.Number)
        {
            case MessageNumber.ChannelOpen:
                // The SUT opened a channel: the first one's id is where SFTP answers go.
                SshReader open = new(message.Payload);
                try
                {
                    open.ReadByte();
                    open.ReadUtf8String();
                    uint sender = open.ReadUInt32();
                    if (_sftpServer.Requests == 0)
                    {
                        _sftpServer.SutChannel = sender;
                    }
                }
                catch (SshProtocolException)
                {
                    // Not a message the SUT builds.
                }

                break;
            case MessageNumber.ChannelData:
                SshReader data = new(message.Payload);
                try
                {
                    data.ReadByte();
                    data.ReadUInt32();
                    ReadOnlySpan<byte> bytes = data.ReadBinary();
                    _sftpServer.Feed(bytes);
                    _sftpView.Feed(bytes);
                }
                catch (SshProtocolException)
                {
                    // Not a message the SUT builds.
                }

                break;
            default:
                break;
        }
    }

    private async Task SendRepliesAsync()
    {
        ChannelReader<byte[]> replies = _sftpServer.Replies;
        try
        {
            await foreach (byte[] reply in replies.ReadAllAsync().ConfigureAwait(false))
            {
                for (int at = 0; at < reply.Length; at += 8192)
                {
                    byte[] chunk = reply.AsSpan(at, Math.Min(8192, reply.Length - at)).ToArray();
                    if (!await _peer.SendAsync(Wire.ChannelData(_sftpServer.SutChannel, chunk)).ConfigureAwait(false))
                    {
                        return;
                    }
                }
            }
        }
        catch (ChannelClosedException)
        {
            // Done.
        }
    }

    private void HandleSftp(byte[] body)
    {
        if (body.Length == 0)
        {
            return;
        }

        if (body[0] == 0)
        {
            _sftpServer.Enable();
        }
        else
        {
            _sftpServer.Arm(body);
        }
    }

    private async Task SendDataAsync(byte[] body)
    {
        if (body.Length < 5)
        {
            return;
        }

        bool swap = (body[0] & 1) != 0;
        bool extended = (body[0] & 2) != 0;
        uint channel = BinaryPrimitives.ReadUInt32BigEndian(body.AsSpan(1));
        byte[] bytes = body[5..];
        if (swap && _sftpView.LastHandle is { } handle)
        {
            bytes = SwapHandle(bytes, handle);
        }

        if (bytes.Length == 0)
        {
            await _peer.SendAsync(extended ? Wire.ChannelExtendedData(channel, 1, bytes) : Wire.ChannelData(channel, bytes)).ConfigureAwait(false);
            return;
        }

        for (int at = 0; at < bytes.Length; at += 16384)
        {
            byte[] chunk = bytes.AsSpan(at, Math.Min(16384, bytes.Length - at)).ToArray();
            if (!await _peer.SendAsync(extended ? Wire.ChannelExtendedData(channel, 1, chunk) : Wire.ChannelData(channel, chunk)).ConfigureAwait(false))
            {
                return;
            }
        }
    }

    private static byte[] SwapHandle(byte[] bytes, byte[] handle)
    {
        ReadOnlySpan<byte> marker = FuzzCorpus.HandleMarker;
        List<byte> result = [];
        int at = 0;
        while (at < bytes.Length)
        {
            int found = bytes.AsSpan(at).IndexOf(marker);
            if (found < 0)
            {
                result.AddRange(bytes.AsSpan(at).ToArray());
                break;
            }

            result.AddRange(bytes.AsSpan(at, found).ToArray());

            // The marker stands for a handle of its own length in the seed: [length][bytes]. Replace the whole string.
            if (result.Count >= 4 && result.Skip(result.Count - 4).SequenceEqual(new byte[] { 0, 0, 0, (byte)marker.Length }))
            {
                result.RemoveRange(result.Count - 4, 4);
                result.AddRange(new FuzzBlob().String(handle).ToArray());
            }
            else
            {
                result.AddRange(handle);
            }

            at += found + marker.Length;
        }

        return [.. result];
    }

    private async Task AwaitMessageAsync(byte number)
    {
        if (_awaitSpent >= StatefulLimits.AwaitBudget)
        {
            AwaitMisses++;
            return;
        }

        Stopwatch watch = Stopwatch.StartNew();
        int found = await _peer.WaitForAsync(_awaitCursor, m => m.Number == number, StatefulLimits.AwaitLimit).ConfigureAwait(false);
        _awaitSpent += watch.Elapsed;
        if (found >= 0)
        {
            _awaitCursor = found + 1;
            AwaitHits++;
        }
        else
        {
            AwaitMisses++;
        }
    }

    /// <summary>Signs a publickey request with the peer's real key and the real session id, so it passes the signature check.</summary>
    private byte[] Sign(byte[] body)
    {
        try
        {
            SshReader reader = new(body);
            reader.ReadByte();
            string user = reader.ReadUtf8String();
            string service = reader.ReadUtf8String();
            reader.ReadUtf8String();
            reader.ReadBoolean();
            string algorithm = reader.ReadUtf8String();
            ReadOnlySpan<byte> blob = reader.ReadBinary();
            byte[] signed = new FuzzBlob()
                .String(_peer.Transport.SessionId.Span)
                .Byte(MessageNumber.UserAuthRequest)
                .String(user)
                .String(service)
                .String("publickey")
                .Bool(true)
                .String(algorithm)
                .String(blob)
                .ToArray();
            byte[] signature = FuzzSecrets.PeerKey.Sign(algorithm, signed);
            return new FuzzBlob()
                .Byte(MessageNumber.UserAuthRequest)
                .String(user)
                .String(service)
                .String("publickey")
                .Bool(true)
                .String(algorithm)
                .String(blob)
                .String(signature)
                .ToArray();
        }
        catch (Exception ex) when (ex is SshProtocolException or ArgumentException or NotSupportedException or System.Security.Cryptography.CryptographicException)
        {
            // The mutator damaged the request beyond signing: it goes out as it is.
            return body;
        }
    }
}

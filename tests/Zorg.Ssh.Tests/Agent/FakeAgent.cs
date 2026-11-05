using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Tests.Agent;

/// <summary>
/// An agent as a stream: each complete request goes to <paramref name="respond"/>, and whatever bytes come back are
/// what the client reads, framing included, so a test can send anything. Null means no answer, and empty closes it.
/// </summary>
internal sealed class FakeAgentStream(Func<byte[], byte[]?> respond) : Stream
{
    private readonly Channel<byte[]> _replies = Channel.CreateUnbounded<byte[]>();
    private readonly List<byte> _received = [];
    private byte[] _current = [];
    private int _position;

    /// <summary>Gets whether the stream ends after the first reply, to cut a frame short.</summary>
    public bool CloseAfterReply { get; init; }

    public override bool CanRead => true;

    public override bool CanWrite => true;

    public override bool CanSeek => false;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        _received.AddRange(buffer.ToArray());
        while (_received.Count >= 4)
        {
            int length = (int)BinaryPrimitives.ReadUInt32BigEndian(_received.Take(4).ToArray());
            if (_received.Count < 4 + length)
            {
                break;
            }

            byte[] request = [.. _received.Skip(4).Take(length)];
            _received.RemoveRange(0, 4 + length);
            byte[]? reply = respond(request);
            if (reply is null)
            {
                continue;
            }

            if (reply.Length == 0)
            {
                _replies.Writer.TryComplete();
            }
            else
            {
                _replies.Writer.TryWrite(reply);
                if (CloseAfterReply)
                {
                    _replies.Writer.TryComplete();
                }
            }
        }

        return ValueTask.CompletedTask;
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (_position == _current.Length)
        {
            if (!await _replies.Reader.WaitToReadAsync(cancellationToken))
            {
                return 0;
            }

            _current = await _replies.Reader.ReadAsync(cancellationToken);
            _position = 0;
        }

        int count = Math.Min(buffer.Length, _current.Length - _position);
        _current.AsMemory(_position, count).CopyTo(buffer);
        _position += count;
        return count;
    }

    public override void Flush()
    {
    }

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

/// <summary>A working agent over <see cref="FakeAgentStream"/>, with a hook for lying about what it signs.</summary>
internal sealed class FakeAgent(params SshPrivateKey[] keys)
{
    /// <summary>Gets or sets the key that really signs, whichever key was asked for.</summary>
    public SshPrivateKey? SignWith { get; set; }

    /// <summary>Gets or sets the algorithm that's really used, whatever flags were sent.</summary>
    public string? ForceAlgorithm { get; set; }

    /// <summary>Gets or sets a check that refuses to sign for some keys.</summary>
    public Func<byte[], bool> Refuses { get; set; } = _ => false;

    /// <summary>Gets the flags of each sign request.</summary>
    public List<uint> Flags { get; } = [];

    /// <summary>Gets how many sign requests came in.</summary>
    public int SignRequests => Flags.Count;

    public static byte[] Frame(params byte[][] parts)
    {
        byte[] body = [.. parts.SelectMany(p => p)];
        byte[] frame = new byte[4 + body.Length];
        BinaryPrimitives.WriteUInt32BigEndian(frame, (uint)body.Length);
        body.CopyTo(frame, 4);
        return frame;
    }

    public static byte[] UInt32(uint value)
    {
        byte[] bytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        return bytes;
    }

    public static byte[] String(byte[] value) => [.. UInt32((uint)value.Length), .. value];

    public Stream Connect() => new FakeAgentStream(Respond);

    public byte[]? Respond(byte[] request)
    {
        switch (request[0])
        {
            case 11:
                List<byte[]> parts = [[12], UInt32((uint)keys.Length)];
                foreach (SshPrivateKey key in keys)
                {
                    parts.Add(String(key.PublicKey.Blob.ToArray()));
                    parts.Add(String("comment"u8.ToArray()));
                }

                return Frame([.. parts]);
            case 13:
                return Sign(request);
            default:
                return Frame([5]);
        }
    }

    private byte[] Sign(byte[] request)
    {
        SshReader reader = new(request);
        reader.ReadByte();
        byte[] blob = reader.ReadBinary().ToArray();
        byte[] data = reader.ReadBinary().ToArray();
        uint flags = reader.ReadUInt32();
        reader.EnsureEnd();
        Flags.Add(flags);
        SshPrivateKey? key = keys.FirstOrDefault(k => k.PublicKey.Blob.Span.SequenceEqual(blob));
        if (key is null || Refuses(blob))
        {
            return Frame([5]);
        }

        key = SignWith ?? key;
        string algorithm = ForceAlgorithm ?? flags switch
        {
            2 => "rsa-sha2-256",
            4 => "rsa-sha2-512",
            _ => key.SignatureAlgorithms[0],
        };
        return Frame([14], String(key.Sign(algorithm, data)));
    }
}

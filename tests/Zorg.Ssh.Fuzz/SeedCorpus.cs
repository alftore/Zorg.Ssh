using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Transport;

namespace Zorg.Ssh.Fuzz;

/// <summary>Writes starting inputs for each target, built from the same shapes the unit tests use.</summary>
internal static class SeedCorpus
{
    public static void Write(string directory)
    {
        WritePacketReaderSeeds(Path.Combine(directory, "packet-reader"));
        WriteKexInitSeeds(Path.Combine(directory, "kex-init"));
        WriteSftpSeeds(Path.Combine(directory, "sftp-response"));
    }

    private static void Save(string directory, string name, byte[] data)
    {
        Directory.CreateDirectory(directory);
        File.WriteAllBytes(Path.Combine(directory, name), data);
    }

    private static byte[] Concat(params byte[][] parts)
    {
        List<byte> all = [];
        foreach (byte[] part in parts)
        {
            all.AddRange(part);
        }

        return [.. all];
    }

    private static byte[] Plain(byte[] payload, int padding)
    {
        byte[] packet = new byte[5 + payload.Length + padding];
        BinaryPrimitives.WriteUInt32BigEndian(packet, (uint)(1 + payload.Length + padding));
        packet[4] = (byte)padding;
        payload.CopyTo(packet, 5);
        return packet;
    }

    private static void WritePacketReaderSeeds(string directory)
    {
        // The first byte decides whether an identification line is read. Even means yes.
        byte[] id = Encoding.ASCII.GetBytes("SSH-2.0-OpenSSH_10.6\r\n");
        byte[] preamble = Encoding.ASCII.GetBytes("Welcome\r\nto the server\nSSH-2.0-x\r\n");
        byte[] kex = KexInitSample().Encode();
        Save(directory, "id-only", Concat([0], id));
        Save(directory, "id-preamble", Concat([0], preamble));
        Save(directory, "id-kexinit", Concat([0], id, Plain(kex, 8)));
        Save(directory, "packets", Concat([1], Plain(kex, 8), Plain([21], 10), Plain([5, 0, 0, 0, 12, 115, 115, 104, 45, 117, 115, 101, 114], 4)));
        Save(directory, "short-padding", Concat([1], Plain([21], 4)));
    }

    private static KexInitMessage KexInitSample() => new()
    {
        KexAlgorithms = ["mlkem768x25519-sha256", "curve25519-sha256", "ext-info-c", "kex-strict-c-v00@openssh.com"],
        HostKeyAlgorithms = ["ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256"],
        CiphersClientToServer = ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"],
        CiphersServerToClient = ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"],
        MacsClientToServer = ["hmac-sha2-256-etm@openssh.com"],
        MacsServerToClient = ["hmac-sha2-256-etm@openssh.com"],
        CompressionClientToServer = ["none"],
        CompressionServerToClient = ["none"],
        FirstKexPacketFollows = true,
    };

    private static void WriteKexInitSeeds(string directory)
    {
        Save(directory, "full", KexInitSample().Encode());
        Save(directory, "minimal", new KexInitMessage
        {
            KexAlgorithms = ["curve25519-sha256"],
            HostKeyAlgorithms = ["ssh-ed25519"],
            CiphersClientToServer = ["aes128-ctr"],
            CiphersServerToClient = ["aes128-ctr"],
            MacsClientToServer = ["hmac-sha2-256"],
            MacsServerToClient = ["hmac-sha2-256"],
            CompressionClientToServer = ["none"],
            CompressionServerToClient = ["none"],
        }.Encode());
        Save(directory, "truncated", [MessageNumber.KexInit, 1, 2, 3]);
    }

    private static byte[] Sftp(byte selector, Action<Body> fill)
    {
        Body body = new();
        body.WriteByte(selector);
        fill(body);
        return body.ToArray();
    }

    private static void WriteSftpSeeds(string directory)
    {
        // Selector mod 6: 0 status, 1 handle, 2 data, 3 names, 4 attributes, 5 statvfs.
        Save(directory, "status-ok", Sftp(0, b =>
        {
            b.WriteUInt32(0);
            b.WriteUtf8String("Success");
            b.WriteUtf8String("en");
        }));
        Save(directory, "status-code-only", Sftp(0, b => b.WriteUInt32(2)));
        Save(directory, "handle", Sftp(1, b => b.WriteBinary("handle-0001"u8)));
        Save(directory, "data", Sftp(2, b => b.WriteBinary("hello, world"u8)));
        Save(directory, "names", Sftp(3, b =>
        {
            b.WriteUInt32(2);
            foreach (string name in new[] { "file.txt", "dir" })
            {
                b.WriteUtf8String(name);
                b.WriteUtf8String("-rw-r--r-- 1 u g 12 Jan 1 00:00 " + name);
                WriteAttributes(b);
            }
        }));
        Save(directory, "attrs", Sftp(4, WriteAttributes));
        Save(directory, "statvfs", Sftp(5, b =>
        {
            for (int i = 0; i < 11; i++)
            {
                b.WriteUInt64((ulong)(i + 1) * 1024);
            }
        }));
    }

    private static void WriteAttributes(Body b)
    {
        b.WriteUInt32(0x0000000F);
        b.WriteUInt64(4096);
        b.WriteUInt32(1000);
        b.WriteUInt32(1000);
        b.WriteUInt32(0x41ED);
        b.WriteUInt32(1700000000);
        b.WriteUInt32(1700000001);
    }

    /// <summary>A small big-endian byte builder for the seeds.</summary>
    private sealed class Body
    {
        private readonly List<byte> _bytes = [];

        public byte[] ToArray() => [.. _bytes];

        public void WriteByte(byte value) => _bytes.Add(value);

        public void WriteUInt32(uint value)
        {
            byte[] raw = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(raw, value);
            _bytes.AddRange(raw);
        }

        public void WriteUInt64(ulong value)
        {
            byte[] raw = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(raw, value);
            _bytes.AddRange(raw);
        }

        public void WriteBinary(ReadOnlySpan<byte> value)
        {
            WriteUInt32((uint)value.Length);
            _bytes.AddRange(value.ToArray());
        }

        public void WriteUtf8String(string value) => WriteBinary(Encoding.UTF8.GetBytes(value));
    }
}

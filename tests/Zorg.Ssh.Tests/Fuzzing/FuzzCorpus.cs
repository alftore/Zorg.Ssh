using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.KeyFiles;
using Zorg.Ssh.Crypto.Keys;
using Zorg.Ssh.KnownHosts;
using Zorg.Ssh.Sftp;
using Zorg.Ssh.Tests.Certificates;
using Zorg.Ssh.Tests.KeyFiles;
using Zorg.Ssh.Transport;

namespace Zorg.Ssh.Tests.Fuzzing;

/// <summary>A small big-endian writer for building seed inputs by hand.</summary>
internal sealed class FuzzBlob
{
    private readonly List<byte> _bytes = [];

    public byte[] ToArray() => [.. _bytes];

    public FuzzBlob Byte(byte value)
    {
        _bytes.Add(value);
        return this;
    }

    public FuzzBlob Raw(ReadOnlySpan<byte> value)
    {
        _bytes.AddRange(value.ToArray());
        return this;
    }

    public FuzzBlob UInt32(uint value)
    {
        Span<byte> buffer = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(buffer, value);
        return Raw(buffer);
    }

    public FuzzBlob UInt64(ulong value)
    {
        Span<byte> buffer = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(buffer, value);
        return Raw(buffer);
    }

    public FuzzBlob Bool(bool value) => Byte(value ? (byte)1 : (byte)0);

    public FuzzBlob String(ReadOnlySpan<byte> value) => UInt32((uint)value.Length).Raw(value);

    public FuzzBlob String(string value) => String(Encoding.UTF8.GetBytes(value));

    public FuzzBlob NameList(params string[] names) => String(string.Join(',', names));

    public FuzzBlob MPInt(ReadOnlySpan<byte> magnitude)
    {
        magnitude = magnitude.TrimStart((byte)0);
        return magnitude.IsEmpty ? UInt32(0) : (magnitude[0] & 0x80) != 0 ? UInt32((uint)magnitude.Length + 1).Byte(0).Raw(magnitude) : String(magnitude);
    }
}

/// <summary>
/// The seed inputs. They come from the keys in <see cref="FuzzKeys"/>, from fixed seeds, and from the builders the
/// other tests use, and nothing in them is random, so a seed number rebuilds the same input on any machine.
/// </summary>
internal static class FuzzCorpus
{
    /// <summary>The marker a request uses in place of a handle. The SFTP target swaps in the real handle from an earlier reply.</summary>
    public static readonly byte[] HandleMarker = "ZORG-HANDLE-SLOT"u8.ToArray();

    private static readonly Lazy<Keys> Material = new(() => new Keys());

    public static IReadOnlyList<byte[]> PublicBlobs => Material.Value.PublicBlobs;

    public static SshPrivateKey CaKey => Material.Value.Ca;

    public static SshPrivateKey SubjectKey(int index) => Material.Value.Subjects[index];

    // Public keys and certificates.

    public static IReadOnlyList<FuzzSeed> Certificates()
    {
        Keys keys = Material.Value;
        List<FuzzSeed> seeds = [];
        foreach (byte[] blob in keys.PublicBlobs)
        {
            seeds.Add(FuzzSeed.Binary("plain key " + seeds.Count, blob));
        }

        string[] names = ["ed25519", "ecdsa", "rsa"];
        for (int i = 0; i < keys.Subjects.Count; i++)
        {
            seeds.Add(FuzzSeed.Binary("host cert " + names[i], new CertificateBuilder(keys.Subjects[i], keys.Ca).Build()));
        }

        seeds.Add(FuzzSeed.Binary(
            "user cert with options",
            new CertificateBuilder(keys.Subjects[0], keys.Ca)
            {
                Type = SshCertificate.UserType,
                Serial = 0x1122334455667788,
                KeyId = "alice@example.com",
                Principals = ["alice", "root", "deploy"],
                ValidAfter = 1_700_000_000,
                ValidBefore = 1_800_000_000,
                CriticalOptions = ["force-command", "source-address"],
                Extensions = ["permit-pty", "permit-agent-forwarding", "permit-port-forwarding"],
            }.Build()));
        seeds.Add(FuzzSeed.Binary("cert no principals", new CertificateBuilder(keys.Subjects[1], keys.Ca) { Principals = [] }.Build()));
        return seeds;
    }

    public static IReadOnlyList<FuzzSeed> OpenSshKeyFiles() =>
    [
        FuzzSeed.Binary("ed25519", KeyFileTools.Unarmor(FuzzKeys.Ed25519OpenSsh)),
        FuzzSeed.Binary("ecdsa", KeyFileTools.Unarmor(FuzzKeys.EcdsaOpenSsh)),
        FuzzSeed.Binary("rsa", KeyFileTools.Unarmor(FuzzKeys.RsaOpenSsh)),
    ];

    /// <summary>The key file labels, in the order the first byte of an armored input selects them.</summary>
    public static readonly string[] Labels = [PemArmor.OpenSsh, PemArmor.Rsa, PemArmor.Ec, PemArmor.Pkcs8, PemArmor.EncryptedPkcs8];

    /// <summary>Binary key files with one byte in front that picks the PEM label. The armor is rebuilt around whatever the mutator makes.</summary>
    public static IReadOnlyList<FuzzSeed> ArmoredKeyFiles()
    {
        (int Label, string Name, string Text)[] files =
        [
            (0, "ossh ed25519", FuzzKeys.Ed25519OpenSsh),
            (0, "ossh ecdsa", FuzzKeys.EcdsaOpenSsh),
            (0, "ossh rsa", FuzzKeys.RsaOpenSsh),
            (1, "pkcs1 rsa", FuzzKeys.RsaPkcs1),
            (2, "sec1 ecdsa", FuzzKeys.EcdsaSec1),
            (3, "pkcs8 rsa", FuzzKeys.RsaPkcs8),
            (3, "pkcs8 ecdsa", FuzzKeys.EcdsaPkcs8),
            (3, "pkcs8 ed25519", FuzzKeys.Ed25519Pkcs8),
        ];
        return [.. files.Select(f => FuzzSeed.Binary(f.Name, [(byte)f.Label, .. KeyFileTools.Unarmor(f.Text)]))];
    }

    public static IReadOnlyList<FuzzSeed> KeyFileTexts() =>
    [
        FuzzSeed.Text("ossh ed25519", FuzzKeys.Ed25519OpenSsh + "\n"),
        FuzzSeed.Text("ossh ecdsa", FuzzKeys.EcdsaOpenSsh + "\n"),
        FuzzSeed.Text("pkcs1 rsa", FuzzKeys.RsaPkcs1 + "\n"),
        FuzzSeed.Text("sec1 ecdsa", FuzzKeys.EcdsaSec1 + "\n"),
        FuzzSeed.Text("pkcs8 ed25519", FuzzKeys.Ed25519Pkcs8 + "\n"),
        FuzzSeed.Text("pkcs8 ecdsa with extra blocks", "-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n" + FuzzKeys.EcdsaSec1 + "\n"),
        FuzzSeed.Text("legacy encrypted", "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF\n\nAAAA\n-----END RSA PRIVATE KEY-----\n"),
        FuzzSeed.Text("crlf", FuzzKeys.Ed25519Pkcs8.Replace("\n", "\r\n", StringComparison.Ordinal) + "\r\n"),
    ];

    // Key exchange.

    public static IReadOnlyList<FuzzSeed> KexInits()
    {
        KexInitMessage typical = new()
        {
            KexAlgorithms = ["mlkem768x25519-sha256", "curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha256", "ext-info-c", "kex-strict-c-v00@openssh.com"],
            HostKeyAlgorithms = ["ssh-ed25519-cert-v01@openssh.com", "ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256"],
            CiphersClientToServer = ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "aes256-ctr"],
            CiphersServerToClient = ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "aes256-ctr"],
            MacsClientToServer = ["hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com"],
            MacsServerToClient = ["hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com"],
            CompressionClientToServer = ["none"],
            CompressionServerToClient = ["none"],
        };
        KexInitMessage server = new()
        {
            KexAlgorithms = ["curve25519-sha256", "kex-strict-s-v00@openssh.com", "ext-info-s"],
            HostKeyAlgorithms = ["ssh-ed25519"],
            CiphersClientToServer = ["aes256-gcm@openssh.com"],
            CiphersServerToClient = ["aes256-gcm@openssh.com"],
            MacsClientToServer = ["hmac-sha2-256-etm@openssh.com"],
            MacsServerToClient = ["hmac-sha2-256-etm@openssh.com"],
            CompressionClientToServer = ["none", "zlib@openssh.com"],
            CompressionServerToClient = ["none", "zlib@openssh.com"],
            FirstKexPacketFollows = true,
        };
        KexInitMessage empty = new()
        {
            KexAlgorithms = [],
            HostKeyAlgorithms = [],
            CiphersClientToServer = [],
            CiphersServerToClient = [],
            MacsClientToServer = [],
            MacsServerToClient = [],
            CompressionClientToServer = [],
            CompressionServerToClient = [],
        };
        return
        [
            FuzzSeed.Binary("client", FixCookie(typical.Encode())),
            FuzzSeed.Binary("server", FixCookie(server.Encode())),
            FuzzSeed.Binary("empty lists", FixCookie(empty.Encode())),
        ];
    }

    public static KexInitMessage OurKexInit() => KexInitMessage.Parse(KexInits()[0].Data);

    private static byte[] FixCookie(byte[] message)
    {
        for (int i = 1; i <= 16; i++)
        {
            message[i] = (byte)i;
        }

        return message;
    }

    // The primitives. Each seed is a script of reads (the first bytes) followed by data that fits it.

    public static IReadOnlyList<FuzzSeed> ReaderScripts()
    {
        byte[] script1 = [(byte)ReaderOp.Byte, (byte)ReaderOp.Boolean, (byte)ReaderOp.UInt32, (byte)ReaderOp.UInt64, (byte)ReaderOp.Binary, (byte)ReaderOp.Utf8, (byte)ReaderOp.NameList, (byte)ReaderOp.MPInt, (byte)ReaderOp.End];
        byte[] data1 = new FuzzBlob().Byte(20).Bool(true).UInt32(0xDEADBEEF).UInt64(0x0102030405060708).String([1, 2, 3, 4, 5]).String("héllo").NameList("curve25519-sha256", "ecdh-sha2-nistp256").MPInt([0x00, 0x80, 0x01, 0x02]).ToArray();
        byte[] script2 = [(byte)ReaderOp.NameList, (byte)ReaderOp.NameList, (byte)ReaderOp.RawFromLength, (byte)ReaderOp.MPInt, (byte)ReaderOp.MPInt, (byte)ReaderOp.Binary, (byte)ReaderOp.End];
        byte[] data2 = new FuzzBlob().NameList("a").NameList().UInt32(3).Raw([9, 9, 9]).MPInt([]).MPInt(new byte[255]).String([]).ToArray();
        byte[] script3 = [(byte)ReaderOp.Raw16, (byte)ReaderOp.Utf8, (byte)ReaderOp.Utf8, (byte)ReaderOp.Byte, (byte)ReaderOp.UInt32, (byte)ReaderOp.End];
        byte[] data3 = new FuzzBlob().Raw(Enumerable.Range(0, 16).Select(i => (byte)i).ToArray()).String("ssh-ed25519").String(string.Empty).Byte(1).UInt32(0).ToArray();
        return
        [
            FuzzSeed.Binary("mixed", [(byte)script1.Length, .. script1, .. data1]),
            FuzzSeed.Binary("lists and mpints", [(byte)script2.Length, .. script2, .. data2]),
            FuzzSeed.Binary("kexinit head", [(byte)script3.Length, .. script3, .. data3]),
        ];
    }

    // known_hosts and config.

    public static IReadOnlyList<FuzzSeed> KnownHostsTexts()
    {
        string ed = FuzzKeys.Ed25519PublicLine;
        string ec = FuzzKeys.EcdsaPublicLine;
        string rsa = FuzzKeys.RsaPublicLine;
        string hashed = HashedLine("example.com", ed);
        string hashedPort = HashedLine("[git.example.com]:2222", ec);
        string whole = string.Join(
            "\n",
            "# a comment",
            "example.com " + ed,
            "*.example.org,!bad.example.org,10.0.0.? " + ec,
            "[host.example.net]:2222 " + rsa,
            hashed,
            hashedPort,
            "@revoked old.example.com " + ed,
            "@cert-authority *.corp.example.com " + ed,
            string.Empty,
            "   \t  indented.example.com\t" + ec + " trailing comment");
        return
        [
            FuzzSeed.Text("whole file", whole + "\n"),
            FuzzSeed.Text("one plain line", "example.com " + ed + "\n"),
            FuzzSeed.Text("one hashed line", hashed + "\r\n"),
            FuzzSeed.Text("patterns", "a*b*c*d*e*f*g?h?i* " + ed + "\n*,!* " + ec + "\n" + new string('*', 40) + "x " + rsa + "\n"),
            FuzzSeed.Text("bom and crlf", "﻿example.com " + rsa + "\r\n@revoked example.com " + rsa + "\r\n"),
        ];
    }

    private static string HashedLine(string name, string publicLine)
    {
        byte[] salt = Enumerable.Range(1, 20).Select(i => (byte)i).ToArray();
        byte[] hash = KnownHostsFile.HashName(salt, Encoding.UTF8.GetBytes(name));
        return $"|1|{Convert.ToBase64String(salt)}|{Convert.ToBase64String(hash)} {publicLine}";
    }

    public static readonly string[] KnownHostsTokens = ["@revoked", "@cert-authority", "|1|", "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ssh-ed25519-cert-v01@openssh.com", "*", "?", "!", "[example.com]:22", "example.com"];

    public static IReadOnlyList<FuzzSeed> ConfigTexts() =>
    [
        FuzzSeed.Text(
            "typical",
            "# my config\nHost web\n  HostName web.example.com\n  User alice\n  Port 2222\n  IdentityFile ~/.ssh/id_ed25519\n  IdentitiesOnly yes\n\nHost *.internal !gate.internal\n  ProxyJump bastion\n  User %r\n\nHost bastion\n  HostName 203.0.113.7\n  StrictHostKeyChecking accept-new\n  UserKnownHostsFile ~/.ssh/known_hosts2\n\nHost *\n  Port 22\n  User deploy\n  IdentityFile \"~/.ssh/with space\"\n"),
        FuzzSeed.Text(
            "tokens and quotes",
            "Host jump\n  HostName %h.example.com\n  IdentityFile ~/.ssh/%h_key\n  User \"quoted user\"\n  ProxyJump a@b:22,c,d:2200\nHost a b\tc\n  Port 22\nHost d\n  Hostname=eq.example.com\n  Port=2200\n"),
        FuzzSeed.Text("match", "Match host web exec \"true\"\n  User nobody\nHost web\n  HostName 192.0.2.1\nMatch all\n  Port 1\nHost after\n  Port 3\n"),
        FuzzSeed.Text("crlf", "Host x\r\n  HostName y\r\n  Port 5\r\n"),
        FuzzSeed.Text("many hosts", string.Concat(Enumerable.Range(0, 40).Select(i => $"Host h{i} *.h{i}\n  HostName 10.0.{i}.1\n  Port {1000 + i}\n  IdentityFile ~/.ssh/k{i}\n"))),
    ];

    public static readonly string[] ConfigTokens = ["Host", "HostName", "User", "Port", "IdentityFile", "IdentitiesOnly", "StrictHostKeyChecking", "UserKnownHostsFile", "ProxyJump", "Match", "all", "exec", "%h", "%r", "%%", "%d", "%u", "~", "~/.ssh/x", "none", "yes", "no", "*", "!*", "?"];

    // SFTP. Each seed is a selector byte and a body.

    public static IReadOnlyList<FuzzSeed> SftpResponseBodies()
    {
        byte[] attrsFull = new FuzzBlob().UInt32(0x0000000F).UInt64(123456).UInt32(1000).UInt32(1000).UInt32(0x81A4).UInt32(1_700_000_000).UInt32(1_700_000_100).ToArray();
        byte[] attrsNone = new FuzzBlob().UInt32(0).ToArray();
        byte[] attrsExtended = new FuzzBlob().UInt32(0x80000005).UInt64(7).UInt32(0x41ED).UInt32(2).String("name@example.com").String("data").String("other@example.com").String("more").ToArray();
        byte[] names = new FuzzBlob().UInt32(3)
            .String("file.txt").String("-rw-r--r-- 1 u g 1 Jan 1 file.txt").Raw(attrsFull)
            .String("dir").String("drwxr-xr-x 2 u g 0 Jan 1 dir").Raw(attrsNone)
            .String("xéÿ").String("long").Raw(attrsExtended)
            .ToArray();
        byte[] statvfs = new FuzzBlob().UInt64(4096).UInt64(4096).UInt64(1000).UInt64(500).UInt64(400).UInt64(100).UInt64(50).UInt64(40).UInt64(77).UInt64(1).UInt64(255).ToArray();
        return
        [
            FuzzSeed.Binary("status", [(byte)SftpReaderOp.Status, .. new FuzzBlob().UInt32(2).String("No such file").String("en").ToArray()]),
            FuzzSeed.Binary("status short", [(byte)SftpReaderOp.Status, .. new FuzzBlob().UInt32(0).ToArray()]),
            FuzzSeed.Binary("handle", [(byte)SftpReaderOp.Handle, .. new FuzzBlob().String(Enumerable.Range(0, 16).Select(i => (byte)i).ToArray()).ToArray()]),
            FuzzSeed.Binary("data", [(byte)SftpReaderOp.Data, .. new FuzzBlob().String(new byte[100]).ToArray()]),
            FuzzSeed.Binary("names", [(byte)SftpReaderOp.Names, .. names]),
            FuzzSeed.Binary("attrs full", [(byte)SftpReaderOp.Attributes, .. attrsFull]),
            FuzzSeed.Binary("attrs extended", [(byte)SftpReaderOp.Attributes, .. attrsExtended]),
            FuzzSeed.Binary("statvfs", [(byte)SftpReaderOp.FileSystem, .. statvfs]),
        ];
    }

    // SOCKS.

    public static IReadOnlyList<FuzzSeed> SocksRequests() =>
    [
        FuzzSeed.Binary("ipv4", new FuzzBlob().Raw([5, 1, 0]).Raw([5, 1, 0, 1, 93, 184, 216, 34, 0, 80]).ToArray()),
        FuzzSeed.Binary("domain", new FuzzBlob().Raw([5, 2, 0, 2]).Raw([5, 1, 0, 3, 11]).Raw("example.com"u8).Raw([1, 187]).ToArray()),
        FuzzSeed.Binary("ipv6", new FuzzBlob().Raw([5, 1, 0]).Raw([5, 1, 0, 4]).Raw(new byte[15]).Raw([1, 0, 22]).ToArray()),
        FuzzSeed.Binary("trailing tunnel data", new FuzzBlob().Raw([5, 1, 0]).Raw([5, 1, 0, 3, 3]).Raw("a.b"u8).Raw([0, 80]).Raw("GET / HTTP/1.1\r\n"u8).ToArray()),
        FuzzSeed.Binary("no acceptable method", new FuzzBlob().Raw([5, 1, 2]).ToArray()),
        FuzzSeed.Binary("socks4", new FuzzBlob().Raw([4, 1, 0, 80, 93, 184, 216, 34, 0]).ToArray()),
        FuzzSeed.Binary("bind command", new FuzzBlob().Raw([5, 1, 0]).Raw([5, 2, 0, 1, 10, 0, 0, 1, 0, 80]).ToArray()),
    ];

    // Transport packets.

    public static IReadOnlyList<FuzzSeed> PacketStreams()
    {
        byte[] kexInit = KexInits()[0].Data;
        byte[] newKeys = [21];
        byte[] ignore = [2, 0, 0, 0, 3, 1, 2, 3];
        byte[] disconnect = new FuzzBlob().Byte(1).UInt32(11).String("bye").String("en").ToArray();
        return
        [
            FuzzSeed.Binary("server hello then packets", [(byte)(1 + 1), .. "SSH-2.0-OpenSSH_10.0\r\n"u8, .. Plain(kexInit, 7), .. Plain(newKeys, 10), .. Plain(ignore, 4)]),
            FuzzSeed.Binary("banner lines first", [(byte)1, .. "Welcome to the host\r\nThis is a banner\nSSH-2.0-test\r\n"u8, .. Plain(kexInit, 12), .. Plain(disconnect, 6)]),
            FuzzSeed.Binary("lf only", [(byte)0, .. "SSH-1.99-old\n"u8, .. Plain(ignore, 4)]),
            FuzzSeed.Binary("minimal packet", [(byte)0, .. "SSH-2.0-x\r\n"u8, .. Plain([2], 4)]),
        ];
    }

    /// <summary>A plain (unencrypted) packet: length, padding length, payload, padding.</summary>
    public static byte[] Plain(byte[] payload, int padding)
    {
        byte[] packet = new byte[5 + payload.Length + padding];
        BinaryPrimitives.WriteUInt32BigEndian(packet, (uint)(1 + payload.Length + padding));
        packet[4] = (byte)padding;
        payload.CopyTo(packet, 5);
        return packet;
    }

    public const string SealedCipher = "chacha20-poly1305@openssh.com";

    public static PacketCipher SealedPacketCipher() => PacketCipherCatalog.Create(SealedCipher, null, Enumerable.Range(0, 64).Select(i => (byte)(i * 3)).ToArray(), [], []);

    /// <summary>Packets sealed with a fixed ChaCha20-Poly1305 key, the first one with sequence number 0.</summary>
    public static IReadOnlyList<FuzzSeed> SealedPackets()
    {
        List<FuzzSeed> seeds = [];
        using PacketCipher cipher = SealedPacketCipher();
        foreach (byte[] payload in new[] { KexInits()[0].Data, [2], new FuzzBlob().Byte(94).UInt32(5).String(new byte[40]).ToArray() })
        {
            int padding = 4;
            while ((1 + payload.Length + padding) % cipher.BlockSize != 0)
            {
                padding++;
            }

            byte[] packet = new byte[4 + 1 + payload.Length + padding + cipher.TagLength];
            BinaryPrimitives.WriteUInt32BigEndian(packet, (uint)(1 + payload.Length + padding));
            packet[4] = (byte)padding;
            payload.CopyTo(packet, 5);
            cipher.Seal(packet, 0);
            seeds.Add(FuzzSeed.Binary("sealed " + seeds.Count, packet));
        }

        return seeds;
    }

    public const string EamCipher = "aes128-ctr";
    public const string EamMac = "hmac-sha2-256";

    private static readonly byte[] EamKey = [.. Enumerable.Range(0, 16).Select(i => (byte)(i * 5))];
    private static readonly byte[] EamIv = [.. Enumerable.Range(0, 16).Select(i => (byte)(0xf0 + i))];
    private static readonly byte[] EamMacKey = [.. Enumerable.Range(0, 32).Select(i => (byte)(i * 7))];

    public static PacketCipher EamPacketCipher() => PacketCipherCatalog.Create(EamCipher, EamMac, EamKey, EamIv, EamMacKey);

    /// <summary>
    /// Encrypt-and-MAC packet streams with a fixed AES-128-CTR and HMAC-SHA-256 key, sequence numbers from 0. The first byte picks
    /// the form: even is the bytes as they go on the wire, odd is plaintext that <see cref="SealEamStream"/> seals packet by packet.
    /// The odd form gives mutated lengths and padding a valid MAC, so they get past the tag check to the checks behind it.
    /// </summary>
    public static IReadOnlyList<FuzzSeed> EamPackets()
    {
        List<byte[]> payloads = [KexInits()[0].Data, [2], new FuzzBlob().Byte(94).UInt32(5).String(new byte[40]).ToArray(), [21]];
        List<FuzzSeed> seeds = [];
        for (int count = 1; count <= payloads.Count; count++)
        {
            byte[] plain = [.. payloads.Take(count).SelectMany(EamPlain)];
            seeds.Add(FuzzSeed.Binary("eam sealed " + count, [0, .. SealEamStream(plain)]));
            seeds.Add(FuzzSeed.Binary("eam plain " + count, [1, .. plain]));
        }

        return seeds;
    }

    /// <summary>
    /// Seals a plaintext stream with the reference implementation, one packet per length field, sequence numbers from 0. A length that
    /// overruns the input takes what is left. The shape isn't checked, so every malformed packet still carries a valid MAC.
    /// </summary>
    public static byte[] SealEamStream(ReadOnlySpan<byte> plain)
    {
        List<byte> sealedBytes = [];
        System.Numerics.BigInteger counter = new(EamIv, isUnsigned: true, isBigEndian: true);
        uint sequence = 0;
        while (plain.Length >= 4)
        {
            uint length = BinaryPrimitives.ReadUInt32BigEndian(plain);
            int bodyLength = (int)Math.Min(length, (uint)(plain.Length - 4));
            sealedBytes.AddRange(Crypto.ReferenceCiphers.SealCtrEam(EamKey, ref counter, System.Security.Cryptography.HashAlgorithmName.SHA256, EamMacKey, sequence++, length, plain.Slice(4, bodyLength)));
            plain = plain[(4 + bodyLength)..];
        }

        sealedBytes.AddRange(plain.ToArray());
        return [.. sealedBytes];
    }

    private static byte[] EamPlain(byte[] payload)
    {
        int padding = 16 - ((5 + payload.Length) % 16);
        if (padding < 4)
        {
            padding += 16;
        }

        byte[] packet = new byte[5 + payload.Length + padding];
        BinaryPrimitives.WriteUInt32BigEndian(packet, (uint)(1 + payload.Length + padding));
        packet[4] = (byte)padding;
        payload.CopyTo(packet, 5);
        return packet;
    }

    // ssh-agent.

    public static IReadOnlyList<FuzzSeed> AgentFrames()
    {
        List<FuzzSeed> seeds = [];
        FuzzBlob answer = new FuzzBlob().Byte(12).UInt32((uint)PublicBlobs.Count);
        foreach (byte[] blob in PublicBlobs)
        {
            answer.String(blob).String("agent key comment");
        }

        byte[] certificate = new CertificateBuilder(SubjectKey(0), CaKey).Build();
        answer = new FuzzBlob().Byte(12).UInt32((uint)PublicBlobs.Count + 2).Raw(answer.ToArray().AsSpan(5)).String(certificate).String("cert").String([0, 0, 0, 1, 2]).String("unsupported key");
        seeds.Add(FuzzSeed.Binary("identities", Frame(AgentOp.List, answer.ToArray())));
        seeds.Add(FuzzSeed.Binary("no identities", Frame(AgentOp.List, [12, 0, 0, 0, 0])));
        seeds.Add(FuzzSeed.Binary("failure", Frame(AgentOp.List, [5])));
        seeds.Add(FuzzSeed.Binary("signature", Frame(AgentOp.Sign, new FuzzBlob().Byte(14).String(new FuzzBlob().String("ssh-ed25519").String(new byte[64]).ToArray()).ToArray())));
        seeds.Add(FuzzSeed.Binary("sign failure with extra", Frame(AgentOp.Sign, [5, 1, 2, 3])));
        return seeds;
    }

    private static byte[] Frame(AgentOp op, byte[] reply) => [(byte)op, .. new FuzzBlob().String(reply).ToArray()];

    // Public key authentication requests (the body after the method name).

    public static IReadOnlyList<FuzzSeed> PublicKeyRequests()
    {
        List<FuzzSeed> seeds = [];
        string[] algorithms = ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512"];
        for (int i = 0; i < PublicBlobs.Count; i++)
        {
            seeds.Add(FuzzSeed.Binary("query " + algorithms[i], new FuzzBlob().Bool(false).String(algorithms[i]).String(PublicBlobs[i]).ToArray()));
            byte[] signature = new FuzzBlob().String(algorithms[i]).String(new byte[i == 0 ? 64 : 70]).ToArray();
            seeds.Add(FuzzSeed.Binary("signed " + algorithms[i], new FuzzBlob().Bool(true).String(algorithms[i]).String(PublicBlobs[i]).String(signature).ToArray()));
        }

        return seeds;
    }

    // The SFTP server. Each seed is a run of framed requests: length, type, id, body.

    public static IReadOnlyList<FuzzSeed> SftpRequestRuns()
    {
        FuzzBlob open = new FuzzBlob().String("a.txt").UInt32(1).UInt32(0);
        FuzzBlob openWrite = new FuzzBlob().String("new/created.bin").UInt32(0x1A).UInt32(0);
        FuzzBlob read = new FuzzBlob().String(HandleMarker).UInt64(0).UInt32(64);
        FuzzBlob write = new FuzzBlob().String(HandleMarker).UInt64(3).String("hello");
        FuzzBlob close = new FuzzBlob().String(HandleMarker);
        byte[] attrs = new FuzzBlob().UInt32(0x4).UInt32(0x1A4).ToArray();
        return
        [
            FuzzSeed.Binary("read a file", Requests((SftpMessage.Open, open.ToArray()), (SftpMessage.Fstat, close.ToArray()), (SftpMessage.Read, read.ToArray()), (SftpMessage.Read, new FuzzBlob().String(HandleMarker).UInt64(1 << 20).UInt32(10).ToArray()), (SftpMessage.Close, close.ToArray()))),
            FuzzSeed.Binary("write a file", Requests((SftpMessage.MkDir, new FuzzBlob().String("new").Raw(attrs).ToArray()), (SftpMessage.Open, openWrite.ToArray()), (SftpMessage.Write, write.ToArray()), (SftpMessage.FSetStat, new FuzzBlob().String(HandleMarker).Raw(attrs).ToArray()), (SftpMessage.Close, close.ToArray()), (SftpMessage.Stat, new FuzzBlob().String("new/created.bin").ToArray()))),
            FuzzSeed.Binary("list", Requests((SftpMessage.OpenDir, new FuzzBlob().String("d").ToArray()), (SftpMessage.ReadDir, close.ToArray()), (SftpMessage.ReadDir, close.ToArray()), (SftpMessage.Close, close.ToArray()), (SftpMessage.RealPath, new FuzzBlob().String("d/../a.txt").ToArray()), (SftpMessage.Lstat, new FuzzBlob().String(".").ToArray()))),
            FuzzSeed.Binary("rename and remove", Requests((SftpMessage.Rename, new FuzzBlob().String("a.txt").String("d/b.txt").ToArray()), (SftpMessage.Remove, new FuzzBlob().String("d/b.txt").ToArray()), (SftpMessage.RmDir, new FuzzBlob().String("d").ToArray()), (SftpMessage.SetStat, new FuzzBlob().String("a.txt").Raw(attrs).ToArray()), (SftpMessage.SymLink, new FuzzBlob().String("link").String("a.txt").ToArray()), (SftpMessage.ReadLink, new FuzzBlob().String("link").ToArray()))),
            FuzzSeed.Binary("extensions", Requests((SftpMessage.Extended, new FuzzBlob().String("limits@openssh.com").ToArray()), (SftpMessage.Extended, new FuzzBlob().String("statvfs@openssh.com").String(".").ToArray()), (SftpMessage.Extended, new FuzzBlob().String("posix-rename@openssh.com").String("a.txt").String("c.txt").ToArray()), (SftpMessage.Open, open.ToArray()), (SftpMessage.Extended, new FuzzBlob().String("fsync@openssh.com").String(HandleMarker).ToArray()), (SftpMessage.Extended, new FuzzBlob().String("unknown@example.com").ToArray()))),
            FuzzSeed.Binary("escape attempts", Requests((SftpMessage.Open, new FuzzBlob().String("../outside.txt").UInt32(0x1A).UInt32(0).ToArray()), (SftpMessage.Remove, new FuzzBlob().String("../outside.txt").ToArray()), (SftpMessage.Rename, new FuzzBlob().String("a.txt").String("../moved.txt").ToArray()), (SftpMessage.MkDir, new FuzzBlob().String("/etc/zorg").UInt32(0).ToArray()), (SftpMessage.Stat, new FuzzBlob().String("..\\outside.txt").ToArray()))),
        ];
    }

    private static byte[] Requests(params (byte Type, byte[] Body)[] requests)
    {
        FuzzBlob blob = new();
        uint id = 1;
        foreach ((byte type, byte[] body) in requests)
        {
            blob.UInt32((uint)(5 + body.Length)).Byte(type).UInt32(id++).Raw(body);
        }

        return blob.ToArray();
    }

    private sealed class Keys
    {
        public Keys()
        {
            Ca = Ed25519PrivateKey.FromSeed(Enumerable.Range(100, 32).Select(i => (byte)i).ToArray());
            Subjects =
            [
                Ed25519PrivateKey.FromSeed(Enumerable.Range(1, 32).Select(i => (byte)i).ToArray()),
                SshKeyFile.Load(FuzzKeys.EcdsaOpenSsh),
                SshKeyFile.Load(FuzzKeys.RsaOpenSsh),
            ];
            PublicBlobs = [.. Subjects.Select(key => key.PublicKey.Blob.ToArray())];
        }

        public SshPrivateKey Ca { get; }

        public IReadOnlyList<SshPrivateKey> Subjects { get; }

        public IReadOnlyList<byte[]> PublicBlobs { get; }
    }
}

internal enum ReaderOp : byte
{
    End = 0,
    Byte,
    Boolean,
    UInt32,
    UInt64,
    Binary,
    Utf8,
    NameList,
    MPInt,
    RawFromLength,
    Raw16,
}

internal enum SftpReaderOp : byte
{
    Status,
    Handle,
    Data,
    Names,
    Attributes,
    FileSystem,
}

internal enum AgentOp : byte
{
    List,
    Sign,
}

/// <summary>A stream that reads from a fixed array and swallows writes, standing in for a socket, a pipe or a channel.</summary>
internal sealed class FuzzStream(byte[] input) : Stream
{
    private int _position;

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => _position;
        set => throw new NotSupportedException();
    }

    /// <summary>Gets how many bytes have been read.</summary>
    public int Consumed => _position;

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        int count = Math.Min(buffer.Length, input.Length - _position);
        input.AsSpan(_position, count).CopyTo(buffer);
        _position += count;
        return count;
    }

    public override System.Threading.Tasks.ValueTask<int> ReadAsync(Memory<byte> buffer, System.Threading.CancellationToken cancellationToken = default) =>
        new(Read(buffer.Span));

    public override System.Threading.Tasks.Task<int> ReadAsync(byte[] buffer, int offset, int count, System.Threading.CancellationToken cancellationToken) =>
        System.Threading.Tasks.Task.FromResult(Read(buffer.AsSpan(offset, count)));

    public override void Write(byte[] buffer, int offset, int count)
    {
    }

    public override void Write(ReadOnlySpan<byte> buffer)
    {
    }

    public override System.Threading.Tasks.ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, System.Threading.CancellationToken cancellationToken = default) => System.Threading.Tasks.ValueTask.CompletedTask;

    public override System.Threading.Tasks.Task WriteAsync(byte[] buffer, int offset, int count, System.Threading.CancellationToken cancellationToken) => System.Threading.Tasks.Task.CompletedTask;

    public override void Flush()
    {
    }

    public override System.Threading.Tasks.Task FlushAsync(System.Threading.CancellationToken cancellationToken) => System.Threading.Tasks.Task.CompletedTask;

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();
}

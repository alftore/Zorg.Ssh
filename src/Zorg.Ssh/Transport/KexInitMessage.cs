using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Transport;

/// <summary>An SSH_MSG_KEXINIT (RFC 4253 section 7.1).</summary>
internal sealed class KexInitMessage
{
    public required IReadOnlyList<string> KexAlgorithms { get; init; }

    public required IReadOnlyList<string> HostKeyAlgorithms { get; init; }

    public required IReadOnlyList<string> CiphersClientToServer { get; init; }

    public required IReadOnlyList<string> CiphersServerToClient { get; init; }

    public required IReadOnlyList<string> MacsClientToServer { get; init; }

    public required IReadOnlyList<string> MacsServerToClient { get; init; }

    public required IReadOnlyList<string> CompressionClientToServer { get; init; }

    public required IReadOnlyList<string> CompressionServerToClient { get; init; }

    public bool FirstKexPacketFollows { get; init; }

    /// <summary>Parses a KEXINIT. <paramref name="payload"/> includes the message number.</summary>
    public static KexInitMessage Parse(ReadOnlySpan<byte> payload)
    {
        SshReader reader = new(payload);
        reader.ReadByte();
        reader.ReadRaw(16);
        string[] kex = reader.ReadNameList();
        string[] hostKey = reader.ReadNameList();
        string[] cipherCs = reader.ReadNameList();
        string[] cipherSc = reader.ReadNameList();
        string[] macCs = reader.ReadNameList();
        string[] macSc = reader.ReadNameList();
        string[] compressionCs = reader.ReadNameList();
        string[] compressionSc = reader.ReadNameList();
        reader.ReadNameList();
        reader.ReadNameList();
        bool follows = reader.ReadBoolean();
        reader.ReadUInt32();
        reader.EnsureEnd();
        return new KexInitMessage
        {
            KexAlgorithms = kex,
            HostKeyAlgorithms = hostKey,
            CiphersClientToServer = cipherCs,
            CiphersServerToClient = cipherSc,
            MacsClientToServer = macCs,
            MacsServerToClient = macSc,
            CompressionClientToServer = compressionCs,
            CompressionServerToClient = compressionSc,
            FirstKexPacketFollows = follows,
        };
    }

    /// <summary>Encodes this message, with a fresh random cookie.</summary>
    public byte[] Encode()
    {
        SshWriter writer = new(1024);
        try
        {
            writer.WriteByte(MessageNumber.KexInit);
            Span<byte> cookie = stackalloc byte[16];
            RandomNumberGenerator.Fill(cookie);
            writer.WriteRaw(cookie);
            writer.WriteNameList(KexAlgorithms);
            writer.WriteNameList(HostKeyAlgorithms);
            writer.WriteNameList(CiphersClientToServer);
            writer.WriteNameList(CiphersServerToClient);
            writer.WriteNameList(MacsClientToServer);
            writer.WriteNameList(MacsServerToClient);
            writer.WriteNameList(CompressionClientToServer);
            writer.WriteNameList(CompressionServerToClient);
            writer.WriteNameList([]);
            writer.WriteNameList([]);
            writer.WriteBoolean(FirstKexPacketFollows);
            writer.WriteUInt32(0);
            return writer.ToArray();
        }
        finally
        {
            writer.Dispose();
        }
    }
}

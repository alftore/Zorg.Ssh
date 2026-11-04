using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.Keys;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Tests.Crypto;

/// <summary>
/// Real OpenSSH <c>ssh</c> against the server half of each key exchange. This isn't a transport: it speaks
/// just enough cleartext SSH to reach the reply. The client sends NEWKEYS only after it has checked the host
/// key signature over the exchange hash, and that hash covers Q_C, Q_S and K. So one NEWKEYS proves the wire
/// layout, the secret combination, the encoding of K and the signature format, all against an independent
/// implementation. Our client half is then tied to it by <see cref="KeyExchangeTests"/>.
/// </summary>
public class OpenSshKeyExchangeTests
{
    private const string ServerVersion = "SSH-2.0-ZorgSshKexTest";
    private const byte MsgKexInit = 20;
    private const byte MsgNewKeys = 21;
    private const byte MsgKexReply = 31;

    public static TheoryData<string> Methods => [.. KeyExchangeCatalog.Default];

    public static TheoryData<string> HostKeys => [.. HostKeyAlgorithms.Default];

    [Theory]
    [MemberData(nameof(Methods))]
    public async Task OpenSSH_accepts_each_key_exchange(string method)
    {
        using SshPrivateKey hostKey = SshPrivateKey.GenerateEd25519();
        KexResult result = await RunAsync(method, "ssh-ed25519", hostKey, Tamper.None);
        Assert.True(result.ClientSentNewKeys, result.ClientLog);
    }

    [Theory]
    [MemberData(nameof(HostKeys))]
    public async Task OpenSSH_accepts_each_host_key_algorithm(string algorithm)
    {
        using SshPrivateKey hostKey = algorithm switch
        {
            "ssh-ed25519" => SshPrivateKey.GenerateEd25519(),
            "rsa-sha2-512" or "rsa-sha2-256" => SshPrivateKey.GenerateRsa(2048),
            _ => SshPrivateKey.GenerateEcdsa(algorithm),
        };

        KexResult result = await RunAsync("curve25519-sha256", algorithm, hostKey, Tamper.None);
        Assert.True(result.ClientSentNewKeys, result.ClientLog);
    }

    // These show the tests above can fail: a wrong K or signature must stop the client before NEWKEYS.
    [Theory]
    [InlineData("curve25519-sha256", Tamper.SharedSecret)]
    [InlineData("mlkem768x25519-sha256", Tamper.SharedSecret)]
    [InlineData("sntrup761x25519-sha512", Tamper.SharedSecret)]
    [InlineData("curve25519-sha256", Tamper.Signature)]
    public async Task OpenSSH_refuses_a_wrong_exchange_hash(string method, Tamper tamper)
    {
        using SshPrivateKey hostKey = SshPrivateKey.GenerateEd25519();
        KexResult result = await RunAsync(method, "ssh-ed25519", hostKey, tamper);
        Assert.False(result.ClientSentNewKeys, result.ClientLog);
    }

    private static async Task<KexResult> RunAsync(string method, string hostKeyAlgorithm, SshPrivateKey hostKey, Tamper tamper)
    {
        string ssh = OpenSshTools.Require("ssh");
        (int _, string supported) = OpenSshTools.Run(ssh, ["-Q", "kex"]);
        if (!supported.Split('\n').Select(static line => line.Trim()).Contains(method))
        {
            Assert.Skip($"This OpenSSH doesn't have {method}.");
        }

        using TempDirectory directory = new();
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(60));

        using TcpListener listener = new(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using Process client = OpenSshTools.Start(ssh,
        [
            "-F", "none",
            "-p", port.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=" + Path.Combine(directory.Path, "known_hosts"),
            "-o", "KexAlgorithms=" + method,
            "-o", "HostKeyAlgorithms=" + hostKeyAlgorithm,
            "-o", "Ciphers=aes128-ctr",
            "-o", "MACs=hmac-sha2-256",
            "-l", "zorg",
            "127.0.0.1",
            "true",
        ]);

        Task<string> log = client.StandardError.ReadToEndAsync(timeout.Token);
        bool sentNewKeys;
        try
        {
            using TcpClient connection = await listener.AcceptTcpClientAsync(timeout.Token);
            sentNewKeys = await ServeAsync(connection.GetStream(), method, hostKeyAlgorithm, hostKey, tamper, timeout.Token);
        }
        finally
        {
            client.Kill(entireProcessTree: true);
        }

        await client.WaitForExitAsync(timeout.Token);
        return new KexResult(sentNewKeys, await log);
    }

    private static async Task<bool> ServeAsync(NetworkStream stream, string method, string hostKeyAlgorithm, SshPrivateKey hostKey, Tamper tamper, CancellationToken cancellationToken)
    {
        await stream.WriteAsync(Encoding.ASCII.GetBytes(ServerVersion + "\r\n"), cancellationToken);
        string clientVersion = await ReadLineAsync(stream, cancellationToken);

        byte[] clientKexInit = await ReadPacketAsync(stream, cancellationToken) ?? throw new EndOfStreamException();
        Assert.Equal(MsgKexInit, clientKexInit[0]);
        byte[] serverKexInit = BuildKexInit(method, hostKeyAlgorithm);
        await WritePacketAsync(stream, serverKexInit, cancellationToken);

        byte[] init = await ReadPacketAsync(stream, cancellationToken) ?? throw new EndOfStreamException();
        using KeyExchangeMethod exchange = KeyExchangeCatalog.Create(method)!;
        byte[] reply = BuildReply(exchange, init, clientVersion, clientKexInit, serverKexInit, hostKeyAlgorithm, hostKey, tamper);
        await WritePacketAsync(stream, reply, cancellationToken);
        await WritePacketAsync(stream, [MsgNewKeys], cancellationToken);

        try
        {
            byte[]? next = await ReadPacketAsync(stream, cancellationToken);
            return next is [MsgNewKeys];
        }
        catch (IOException)
        {
            return false;
        }
    }

    private static byte[] BuildKexInit(string method, string hostKeyAlgorithm)
    {
        SshWriter writer = new();
        try
        {
            writer.WriteByte(MsgKexInit);
            writer.WriteRaw(RandomNumberGenerator.GetBytes(16));
            writer.WriteNameList([method]);
            writer.WriteNameList([hostKeyAlgorithm]);
            writer.WriteNameList(["aes128-ctr"]);
            writer.WriteNameList(["aes128-ctr"]);
            writer.WriteNameList(["hmac-sha2-256"]);
            writer.WriteNameList(["hmac-sha2-256"]);
            writer.WriteNameList(["none"]);
            writer.WriteNameList(["none"]);
            writer.WriteNameList([]);
            writer.WriteNameList([]);
            writer.WriteBoolean(false);
            writer.WriteUInt32(0);
            return writer.ToArray();
        }
        finally
        {
            writer.Dispose();
        }
    }

    private static byte[] BuildReply(
        KeyExchangeMethod exchange,
        byte[] init,
        string clientVersion,
        byte[] clientKexInit,
        byte[] serverKexInit,
        string hostKeyAlgorithm,
        SshPrivateKey hostKey,
        Tamper tamper)
    {
        SshReader reader = new(init.AsSpan(1));
        byte[] clientValue = reader.ReadBinary().ToArray();
        reader.EnsureEnd();

        byte[] serverValue = exchange.ServerRespond(clientValue, out byte[] secret);
        if (tamper == Tamper.SharedSecret)
        {
            secret[^1] ^= 1;
        }

        // RFC 5656 section 4 and RFC 4253 section 8. K goes in already encoded.
        byte[] hostKeyBlob = hostKey.PublicKey.Blob.ToArray();
        SshWriter hashInput = new();
        byte[] exchangeHash;
        try
        {
            hashInput.WriteUtf8String(clientVersion);
            hashInput.WriteUtf8String(ServerVersion);
            hashInput.WriteBinary(clientKexInit);
            hashInput.WriteBinary(serverKexInit);
            hashInput.WriteBinary(hostKeyBlob);
            hashInput.WriteBinary(clientValue);
            hashInput.WriteBinary(serverValue);
            hashInput.WriteRaw(secret);
            exchangeHash = exchange.Hash(hashInput.Written);
        }
        finally
        {
            hashInput.Dispose();
        }

        byte[] signature = hostKey.Sign(hostKeyAlgorithm, exchangeHash);
        if (tamper == Tamper.Signature)
        {
            signature[^1] ^= 1;
        }

        SshWriter writer = new();
        try
        {
            writer.WriteByte(MsgKexReply);
            writer.WriteBinary(hostKeyBlob);
            writer.WriteBinary(serverValue);
            writer.WriteBinary(signature);
            return writer.ToArray();
        }
        finally
        {
            writer.Dispose();
        }
    }

    private static async Task<string> ReadLineAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        List<byte> line = [];
        byte[] one = new byte[1];
        while (line.Count < 255)
        {
            await stream.ReadExactlyAsync(one, cancellationToken);
            if (one[0] == (byte)'\n')
            {
                return Encoding.ASCII.GetString([.. line]).TrimEnd('\r');
            }

            line.Add(one[0]);
        }

        throw new InvalidDataException("The version line is too long.");
    }

    /// <summary>Reads one cleartext packet and returns its payload, or null at end of stream.</summary>
    private static async Task<byte[]?> ReadPacketAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        byte[] header = new byte[5];
        int read = await stream.ReadAtLeastAsync(header, header.Length, throwOnEndOfStream: false, cancellationToken);
        if (read < header.Length)
        {
            return null;
        }

        int length = BinaryPrimitives.ReadInt32BigEndian(header);
        int padding = header[4];
        Assert.InRange(length, padding + 1, 64 * 1024);
        byte[] body = new byte[length - 1];
        await stream.ReadExactlyAsync(body, cancellationToken);
        return body[..^padding];
    }

    private static async Task WritePacketAsync(NetworkStream stream, byte[] payload, CancellationToken cancellationToken)
    {
        int padding = 8 - ((5 + payload.Length) % 8);
        if (padding < 4)
        {
            padding += 8;
        }

        byte[] packet = new byte[5 + payload.Length + padding];
        BinaryPrimitives.WriteInt32BigEndian(packet, 1 + payload.Length + padding);
        packet[4] = (byte)padding;
        payload.CopyTo(packet, 5);
        await stream.WriteAsync(packet, cancellationToken);
    }

    public enum Tamper
    {
        None,
        SharedSecret,
        Signature,
    }

    private sealed record KexResult(bool ClientSentNewKeys, string ClientLog);
}

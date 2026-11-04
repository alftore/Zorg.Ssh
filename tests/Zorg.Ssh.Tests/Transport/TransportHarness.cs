using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipelines;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Transport;

namespace Zorg.Ssh.Tests.Transport;

/// <summary>Two connected in-memory streams, with real backpressure.</summary>
internal sealed class DuplexStream(Stream read, Stream write) : Stream
{
    public static (Stream Client, Stream Server) CreatePair(long pauseThreshold = 256 * 1024)
    {
        PipeOptions options = new(pauseWriterThreshold: pauseThreshold, resumeWriterThreshold: pauseThreshold / 2);
        Pipe toServer = new(options);
        Pipe toClient = new(options);
        return (
            new DuplexStream(toClient.Reader.AsStream(), toServer.Writer.AsStream()),
            new DuplexStream(toServer.Reader.AsStream(), toClient.Writer.AsStream()));
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

    public override void Flush() => write.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) => write.FlushAsync(cancellationToken);

    public override int Read(byte[] buffer, int offset, int count) => read.Read(buffer, offset, count);

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
        read.ReadAsync(buffer, cancellationToken);

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
        write.WriteAsync(buffer, cancellationToken);

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => write.Write(buffer, offset, count);

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            read.Dispose();
            write.Dispose();
        }

        base.Dispose(disposing);
    }
}

/// <summary>Builds connected transports for tests.</summary>
internal static class TransportHarness
{
    public static readonly SshPrivateKey HostKey = SshPrivateKey.GenerateEd25519();

    public static TransportOptions ClientOptions(
        IReadOnlyList<string>? kex = null,
        IReadOnlyList<string>? ciphers = null,
        IReadOnlyList<string>? macs = null,
        long rekeyBytes = 1L << 30,
        bool accept = true) => new()
        {
            Role = SshRole.Client,
            KexAlgorithms = kex ?? KeyExchangeCatalog.Default,
            Ciphers = ciphers ?? PacketCipherCatalog.DefaultCiphers,
            Macs = macs ?? PacketCipherCatalog.DefaultMacs,
            RekeyBytes = rekeyBytes,
            HandshakeTimeout = TimeSpan.FromSeconds(20),
            HostKeyValidator = (_, _) => ValueTask.FromResult(accept),
        };

    public static TransportOptions ServerOptions(
        IReadOnlyList<string>? kex = null,
        IReadOnlyList<string>? ciphers = null,
        IReadOnlyList<string>? macs = null,
        IReadOnlyList<SshPrivateKey>? hostKeys = null,
        long rekeyBytes = 1L << 30) => new()
        {
            Role = SshRole.Server,
            KexAlgorithms = kex ?? KeyExchangeCatalog.Default,
            Ciphers = ciphers ?? PacketCipherCatalog.DefaultCiphers,
            Macs = macs ?? PacketCipherCatalog.DefaultMacs,
            RekeyBytes = rekeyBytes,
            HostKeys = hostKeys ?? [HostKey],
            HandshakeTimeout = TimeSpan.FromSeconds(20),
        };

    public static async Task<(SshTransport Client, SshTransport Server)> ConnectAsync(
        TransportOptions client,
        TransportOptions server,
        CancellationToken cancellationToken)
    {
        (Stream clientStream, Stream serverStream) = DuplexStream.CreatePair();
        Task<SshTransport> serverTask = SshTransport.StartAsync(serverStream, server, cancellationToken);
        Task<SshTransport> clientTask = SshTransport.StartAsync(clientStream, client, cancellationToken);
        return (await clientTask, await serverTask);
    }

    public static void MarkConnected(params SshTransport[] transports)
    {
        foreach (SshTransport transport in transports)
        {
            transport.SetPhase(TransportPhase.Connected);
        }
    }
}

/// <summary>
/// A scriptable peer that writes raw unencrypted packets, for hostile tests of the initial key exchange.
/// </summary>
internal sealed class RawPeer(Stream stream) : IAsyncDisposable
{
    private readonly PacketReader _reader = new(stream, 262144);

    public static byte[] KexInitPayload(SshRole role, bool strict = true, bool extraNames = false, bool follows = false)
    {
        List<string> kex = ["curve25519-sha256"];
        if (extraNames)
        {
            kex.Insert(0, "mlkem768x25519-sha256");
        }

        if (strict)
        {
            kex.Add(role == SshRole.Client ? KexMarkers.StrictClientV00 : KexMarkers.StrictServerV00);
        }

        return new KexInitMessage
        {
            KexAlgorithms = kex,
            HostKeyAlgorithms = ["ssh-ed25519"],
            CiphersClientToServer = ["aes256-gcm@openssh.com"],
            CiphersServerToClient = ["aes256-gcm@openssh.com"],
            MacsClientToServer = ["hmac-sha2-256-etm@openssh.com"],
            MacsServerToClient = ["hmac-sha2-256-etm@openssh.com"],
            CompressionClientToServer = ["none"],
            CompressionServerToClient = ["none"],
            FirstKexPacketFollows = follows,
        }.Encode();
    }

    public async Task ExchangeIdentificationAsync(CancellationToken cancellationToken)
    {
        await stream.WriteAsync(Encoding.ASCII.GetBytes("SSH-2.0-RawPeer\r\n"), cancellationToken);
        await _reader.ReadIdentificationAsync(allowPreamble: true, cancellationToken);
    }

    public async Task SendAsync(byte[] payload, CancellationToken cancellationToken)
    {
        int padding = 8 - ((5 + payload.Length) % 8);
        if (padding < 4)
        {
            padding += 8;
        }

        byte[] packet = new byte[5 + payload.Length + padding];
        BinaryPrimitives.WriteUInt32BigEndian(packet, (uint)(1 + payload.Length + padding));
        packet[4] = (byte)padding;
        payload.CopyTo(packet, 5);
        await stream.WriteAsync(packet, cancellationToken);
    }

    public async Task SendRawAsync(byte[] bytes, CancellationToken cancellationToken) =>
        await stream.WriteAsync(bytes, cancellationToken);

    /// <summary>Reads unencrypted packets until one with the wanted number arrives.</summary>
    public async Task<byte[]> ReceiveAsync(byte wanted, uint sequence, CancellationToken cancellationToken)
    {
        while (true)
        {
            ReadOnlyMemory<byte> payload = await _reader.ReadPacketAsync(NoneCipher.Instance, sequence++, cancellationToken);
            if (payload.Span[0] == wanted)
            {
                return payload.ToArray();
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        _reader.Dispose();
        await stream.DisposeAsync();
    }
}

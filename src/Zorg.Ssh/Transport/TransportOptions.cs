using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Zorg.Ssh.Crypto;

namespace Zorg.Ssh.Transport;

/// <summary>Everything the transport needs. Each limit bounds something a peer could otherwise grow.</summary>
internal sealed class TransportOptions
{
    /// <summary>Gets our side of the connection.</summary>
    public required SshRole Role { get; init; }

    /// <summary>Gets the identification string we send, without its line ending.</summary>
    public string Identification { get; init; } = "SSH-2.0-Zorg.Ssh_0.1";

    public IReadOnlyList<string> KexAlgorithms { get; init; } = KeyExchangeCatalog.Default;

    public IReadOnlyList<string> HostKeyAlgorithms { get; init; } = Crypto.Keys.HostKeyAlgorithms.Default;

    public IReadOnlyList<string> Ciphers { get; init; } = PacketCipherCatalog.DefaultCiphers;

    public IReadOnlyList<string> Macs { get; init; } = PacketCipherCatalog.DefaultMacs;

    /// <summary>Gets the keys a server proves its identity with. Required for a server.</summary>
    public IReadOnlyList<SshPrivateKey> HostKeys { get; init; } = [];

    /// <summary>
    /// Gets the check a client runs on the first host key, after its signature has been verified.
    /// Required for a client: there's no default that accepts a key.
    /// </summary>
    public Func<SshPublicKey, CancellationToken, ValueTask<bool>>? HostKeyValidator { get; init; }

    /// <summary>Gets the signature algorithms a server lists in <c>server-sig-algs</c>.</summary>
    public IReadOnlyList<string> ServerSignatureAlgorithms { get; init; } = Crypto.Keys.HostKeyAlgorithms.Default;

    /// <summary>Gets the time allowed from connecting to the end of the first key exchange.</summary>
    public TimeSpan HandshakeTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Gets the time allowed for a rekey to finish.</summary>
    public TimeSpan RekeyTimeout { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>Gets whether we start rekeys. We always answer a peer's. Some network gear can't rekey at all.</summary>
    public bool RekeyEnabled { get; init; } = true;

    /// <summary>Gets the bytes in one direction after which we rekey.</summary>
    public long RekeyBytes { get; init; } = 1L << 30;

    /// <summary>Gets the packets in one direction after which we rekey.</summary>
    public long RekeyPackets { get; init; } = 1L << 31;

    /// <summary>Gets the time after which we rekey.</summary>
    public TimeSpan RekeyInterval { get; init; } = TimeSpan.FromHours(1);

    /// <summary>Gets the largest <c>packet_length</c> accepted.</summary>
    public int MaxPacketLength { get; init; } = 256 * 1024;

    /// <summary>Gets the most packets waiting to be sent. Writers wait when it's full.</summary>
    public int SendQueueCapacity { get; init; } = 64;

    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;

    public ILogger Logger { get; init; } = NullLogger.Instance;
}

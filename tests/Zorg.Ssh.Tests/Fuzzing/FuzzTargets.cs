using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading;
using Zorg.Ssh.Agent;
using Zorg.Ssh.Auth;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.KeyFiles;
using Zorg.Ssh.Crypto.Keys;
using Zorg.Ssh.Forwarding;
using Zorg.Ssh.KnownHosts;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Sftp;
using Zorg.Ssh.Tests.KeyFiles;
using Zorg.Ssh.Transport;

namespace Zorg.Ssh.Tests.Fuzzing;

/// <summary>
/// The one table of what each decoder may throw. Guarantee 3 says a hostile peer causes <see cref="SshException"/> types and
/// nothing else, so most rows are that. A row that says otherwise names the documentation it follows. Adding a type to a row
/// to make a target pass is wrong: it hides a bug. Fix the decoder, or record the finding.
/// </summary>
internal static class FuzzAllowedExceptions
{
    public const string Reader = "SshReader primitives";
    public const string KexInit = "KexInitMessage.Parse + Negotiate";
    public const string Certificate = "SshCertificate.ParseAny + CheckCaSignature";
    public const string OpenSshKey = "OpenSshKeyFormat.Parse";
    public const string KeyFileBinary = "SshKeyFile.Load (armored binary)";
    public const string KeyFileText = "SshKeyFile.Load (text)";
    public const string KnownHosts = "KnownHostsFile.Parse + Lookup";
    public const string Config = "SshConfig.Parse + Resolve";
    public const string SftpResponses = "SftpParser response readers";
    public const string Socks = "SocksHandshake.ReadRequestAsync";
    public const string PacketsPlain = "PacketReader (unencrypted)";
    public const string PacketsSealed = "PacketReader (ChaCha20-Poly1305)";
    public const string PacketsEam = "PacketReader (AES-CTR, encrypt-and-MAC)";
    public const string Agent = "SshAgentConnection replies";
    public const string SftpServer = "SftpServerSession.DispatchAsync";
    public const string PublicKeyRequest = "ServerAuthenticator.ParsePublicKey";

    public static IReadOnlyList<Type> For(string target) => target switch
    {
        // SshReader: "throws SshProtocolException on malformed input, never an index or argument exception."
        Reader => [typeof(SshProtocolException)],

        // KexInitMessage is read from a peer. Negotiation failures are SshNegotiationException, a SshProtocolException.
        KexInit => [typeof(SshProtocolException)],

        // SshCertificate.ParseCertificate: "Anything malformed throws SshProtocolException". SshPublicKey.Parse says the same.
        Certificate => [typeof(SshProtocolException)],

        // Internal step of SshKeyFile.Load. It throws SshKeyFileException itself and lets SshProtocolException from the reader
        // through. Load turns both into SshKeyFileException. See the findings in the report for anything else that escapes.
        OpenSshKey => [typeof(SshKeyFileException), typeof(SshProtocolException)],

        // SshKeyFile: "The text is treated as hostile. Every failure is a SshKeyFileException."
        KeyFileBinary or KeyFileText => [typeof(SshKeyFileException)],

        // KnownHostsFile.Parse: skips malformed lines; only a file over MaxFileLength throws SshHostKeyException.
        KnownHosts => [typeof(SshHostKeyException)],

        // SshConfig.Parse and Resolve: "SshConfigException: a keyword this class handles has a bad value."
        Config => [typeof(SshConfigException)],

        // SftpParser: "malformed input is an SshProtocolException".
        SftpResponses => [typeof(SshProtocolException)],

        // A SOCKS client is a local program on a socket. The caller (ForwardScope) treats an IOException as the connection
        // ending, and EndOfStreamException is one. The handshake documents no exception of its own.
        Socks => [typeof(IOException)],

        // PacketReader: SshProtocolException for bad framing, SshConnectionException when the stream ends.
        PacketsPlain or PacketsSealed or PacketsEam => [typeof(SshProtocolException), typeof(SshConnectionException)],

        // SshAgentConnection: "all it sends is untrusted", every failure is an SshAgentException.
        Agent => [typeof(SshAgentException)],

        // SftpServerSession.ServeAsync turns exactly these into a status reply for the client. Anything else it logs as unexpected.
        SftpServer => [typeof(SshProtocolException), typeof(SftpServerRefusedException), typeof(IOException), typeof(UnauthorizedAccessException), typeof(SecurityException), typeof(ArgumentException), typeof(NotSupportedException)],

        // ServerAuthenticator reads SshProtocolException from a malformed request and drops the connection.
        PublicKeyRequest => [typeof(SshProtocolException)],
        _ => throw new ArgumentException("No allowed exceptions are recorded for " + target, nameof(target)),
    };
}

/// <summary>Every fuzz target. Each is built when asked for, because building a corpus loads keys.</summary>
internal static class FuzzTargets
{
    private static readonly string ConfigHome = Path.Combine(Path.GetTempPath(), "zorg-fuzz-no-home-" + Guid.NewGuid().ToString("N"));

    private static readonly Lazy<IReadOnlyList<FuzzTarget>> AllTargets = new(Build);

    /// <summary>
    /// How many different stages a normal pass must reach in each target (see <see cref="FuzzNotes"/>), set a little under what
    /// the fixed seed run reaches. A target that falls under this has gone shallow: its inputs stop at the first check.
    /// </summary>
    private static readonly Dictionary<string, int> MinStages = new()
    {
        [FuzzAllowedExceptions.Reader] = 9,
        [FuzzAllowedExceptions.KexInit] = 5,
        [FuzzAllowedExceptions.Certificate] = 4,
        [FuzzAllowedExceptions.OpenSshKey] = 2,
        [FuzzAllowedExceptions.KeyFileBinary] = 3,
        [FuzzAllowedExceptions.KeyFileText] = 2,
        [FuzzAllowedExceptions.KnownHosts] = 4,
        [FuzzAllowedExceptions.Config] = 4,
        [FuzzAllowedExceptions.SftpResponses] = 6,
        [FuzzAllowedExceptions.Socks] = 3,
        [FuzzAllowedExceptions.PacketsPlain] = 3,
        [FuzzAllowedExceptions.PacketsSealed] = 1,
        [FuzzAllowedExceptions.PacketsEam] = 3,
        [FuzzAllowedExceptions.Agent] = 4,
        [FuzzAllowedExceptions.SftpServer] = 30,
        [FuzzAllowedExceptions.PublicKeyRequest] = 2,
    };

    public static IReadOnlyList<FuzzTarget> All => AllTargets.Value;

    public static FuzzTarget Named(string name) => All.Single(target => target.Name == name);

    private static List<FuzzTarget> Build() =>
    [
        ReaderTarget(),
        KexInitTarget(),
        CertificateTarget(),
        OpenSshKeyTarget(),
        KeyFileBinaryTarget(),
        KeyFileTextTarget(),
        KnownHostsTarget(),
        ConfigTarget(),
        SftpResponsesTarget(),
        SocksTarget(),
        PacketsPlainTarget(),
        PacketsSealedTarget(),
        PacketsEamTarget(),
        AgentTarget(),
        SftpServerTarget(),
        PublicKeyRequestTarget(),
        .. Stateful.StatefulTargets.Build(),
    ];

    private static FuzzTarget Make(string name, IReadOnlyList<FuzzSeed> corpus, Func<byte[], FuzzOutcome> execute, int iterations, Action<TargetTuning>? tune = null)
    {
        TargetTuning tuning = new();
        tune?.Invoke(tuning);
        return new FuzzTarget
        {
            Name = name,
            Corpus = corpus,
            Execute = execute,
            Allowed = FuzzAllowedExceptions.For(name),
            ShortIterations = iterations,
            AllocationSlack = tuning.Slack,
            AllocationPerByte = tuning.PerByte,
            Tokens = tuning.Tokens,
            MinAcceptedShare = tuning.MinAccepted,
            MinRefusalReasons = tuning.MinReasons,
            MinReachedStages = MinStages.GetValueOrDefault(name),
        };
    }

    private sealed class TargetTuning
    {
        public long Slack { get; set; } = 512 * 1024;

        public int PerByte { get; set; } = 64;

        public IReadOnlyList<string> Tokens { get; set; } = [];

        public double MinAccepted { get; set; } = 0.01;

        public int MinReasons { get; set; } = 3;
    }

    // SshReader.

    private static FuzzTarget ReaderTarget() => Make(FuzzAllowedExceptions.Reader, FuzzCorpus.ReaderScripts(), RunReaderScript, 3000, t => t.MinAccepted = 0.05);

    private static FuzzOutcome RunReaderScript(byte[] input)
    {
        if (input.Length == 0)
        {
            return FuzzOutcome.Skipped;
        }

        int scriptLength = Math.Min(input[0], input.Length - 1);
        ReadOnlySpan<byte> script = input.AsSpan(1, scriptLength);
        SshReader reader = new(input.AsSpan(1 + scriptLength));
        foreach (byte code in script)
        {
            int before = reader.Remaining;
            switch ((ReaderOp)(code % 11))
            {
                case ReaderOp.End:
                    reader.EnsureEnd();
                    return FuzzOutcome.Accepted;
                case ReaderOp.Byte:
                    reader.ReadByte();
                    break;
                case ReaderOp.Boolean:
                    reader.ReadBoolean();
                    break;
                case ReaderOp.UInt32:
                    reader.ReadUInt32();
                    break;
                case ReaderOp.UInt64:
                    reader.ReadUInt64();
                    break;
                case ReaderOp.Binary:
                    Require(reader.ReadBinary().Length <= before - 4, "ReadBinary returned more than was left");
                    break;
                case ReaderOp.Utf8:
                    Require(Encoding.UTF8.GetByteCount(reader.ReadUtf8String()) <= before - 4, "ReadUtf8String returned more than was left");
                    break;
                case ReaderOp.NameList:
                    CheckNames(reader.ReadNameList());
                    break;
                case ReaderOp.MPInt:
                    ReadOnlySpan<byte> value = reader.ReadMPInt();
                    Require(value.Length <= SshReader.MaxMPIntLength && (value.IsEmpty || value[0] != 0), "ReadMPInt returned an oversized value or one with a leading zero");
                    break;
                case ReaderOp.RawFromLength:
                    reader.ReadRaw((int)reader.ReadUInt32());
                    break;
                default:
                    reader.ReadRaw(16);
                    break;
            }

            Require(reader.Remaining <= before, "a read left more bytes than it started with");
            FuzzNotes.Reached("read " + (ReaderOp)(code % 11));
        }

        return FuzzOutcome.Accepted;
    }

    private static void CheckNames(string[] names)
    {
        Require(names.Length <= SshReader.MaxNameListCount, "a name-list held more than the limit");
        foreach (string name in names)
        {
            Require(name.Length > 0 && name.All(c => c is > ' ' and < '\u007f' && c != ','), "a name-list held an empty or unprintable name");
        }
    }

    private static void Require(bool condition, string what)
    {
        if (!condition)
        {
            throw new InvalidOperationException("Contract broken: " + what);
        }
    }

    // KEXINIT.

    private static FuzzTarget KexInitTarget() => Make(FuzzAllowedExceptions.KexInit, FuzzCorpus.KexInits(), RunKexInit, 2500, t => t.MinAccepted = 0.05);

    private static FuzzOutcome RunKexInit(byte[] input)
    {
        KexInitMessage message = KexInitMessage.Parse(input);
        FuzzNotes.Reached("KEXINIT parsed, first kex packet follows: " + message.FirstKexPacketFollows);
        foreach (IReadOnlyList<string> list in new[] { message.KexAlgorithms, message.HostKeyAlgorithms, message.CiphersClientToServer, message.CiphersServerToClient, message.MacsClientToServer, message.MacsServerToClient, message.CompressionClientToServer, message.CompressionServerToClient })
        {
            CheckNames([.. list]);
        }

        // What parsed must encode and parse back to the same lists.
        KexInitMessage again = KexInitMessage.Parse(message.Encode());
        Require(message.KexAlgorithms.SequenceEqual(again.KexAlgorithms) && message.CiphersServerToClient.SequenceEqual(again.CiphersServerToClient) && message.FirstKexPacketFollows == again.FirstKexPacketFollows, "a parsed KEXINIT did not survive Encode and Parse");
        KexInitMessage ours = FuzzCorpus.OurKexInit();
        foreach (SshRole role in new[] { SshRole.Client, SshRole.Server })
        {
            try
            {
                AlgorithmNegotiation.Negotiate(role, ours, message, static name => name.Contains("gcm", StringComparison.Ordinal) || name.StartsWith("chacha", StringComparison.Ordinal));
                FuzzNotes.Reached("negotiated as " + role);
            }
            catch (SshNegotiationException)
            {
                FuzzNotes.Reached("no common algorithm as " + role);
            }
        }

        return FuzzOutcome.Accepted;
    }

    // Certificates and public keys.

    private static FuzzTarget CertificateTarget() => Make(FuzzAllowedExceptions.Certificate, FuzzCorpus.Certificates(), RunCertificate, 2500, t => t.MinAccepted = 0.02);

    private static FuzzOutcome RunCertificate(byte[] input)
    {
        SshPublicKey key = SshCertificate.ParseAny(input);
        Require(key.Blob.Length > 0 && key.KeyType.Length > 0, "a parsed key has no blob or no type");
        FuzzNotes.Reached(key is SshCertificate ? "certificate parsed" : "plain key parsed");
        byte[] data = [1, 2, 3];
        foreach (byte[] signature in new[] { [], new byte[64], new byte[200] })
        {
            string algorithm = key.KeyType.StartsWith("ssh-rsa", StringComparison.Ordinal) || key.KeyType.StartsWith("rsa-sha2", StringComparison.Ordinal) ? "rsa-sha2-256" : key.KeyType;
            if (key.SupportsSignatureAlgorithm(algorithm))
            {
                // Verify "never throws because of the blob's contents".
                Require(!key.Verify(algorithm, data, signature), "a garbage signature verified");
            }
        }

        if (key is SshCertificate certificate)
        {
            FuzzNotes.Reached(certificate.CheckCaSignature() is null ? "certificate: CA signature ok" : "certificate: CA signature refused");
            Require(certificate.Principals.Count <= SshCertificate.MaxPrincipals, "a certificate held more principals than the limit");
            Require(certificate.CriticalOptions.Count <= SshCertificate.MaxOptions && certificate.Extensions.Count <= SshCertificate.MaxOptions, "a certificate held more options than the limit");
        }

        return FuzzOutcome.Accepted;
    }

    // Key files.

    private static FuzzTarget OpenSshKeyTarget() => Make(FuzzAllowedExceptions.OpenSshKey, FuzzCorpus.OpenSshKeyFiles(), RunOpenSshKey, 800, t => t.MinAccepted = 0.002);

    private static FuzzOutcome RunOpenSshKey(byte[] input)
    {
        using SshPrivateKey key = OpenSshKeyFormat.Parse(input, default);
        Require(key.PublicKey.Blob.Length > 0, "a parsed private key has no public key");
        FuzzNotes.Reached("loaded " + key.PublicKey.KeyType);
        return FuzzOutcome.Accepted;
    }

    private static FuzzTarget KeyFileBinaryTarget() => Make(FuzzAllowedExceptions.KeyFileBinary, FuzzCorpus.ArmoredKeyFiles(), RunKeyFileBinary, 300, t =>
    {
        t.MinAccepted = 0.01;
        t.Slack = 4 * 1024 * 1024;
    });

    private static FuzzOutcome RunKeyFileBinary(byte[] input)
    {
        if (input.Length == 0)
        {
            return FuzzOutcome.Skipped;
        }

        string text = KeyFileTools.Armor(FuzzCorpus.Labels[input[0] % FuzzCorpus.Labels.Length], input.AsSpan(1));
        using SshPrivateKey key = SshKeyFile.Load(text);
        Require(key.SignatureAlgorithms.Count > 0, "a loaded key has no signature algorithm");
        FuzzNotes.Reached("loaded " + key.PublicKey.KeyType);
        return FuzzOutcome.Accepted;
    }

    private static FuzzTarget KeyFileTextTarget() => Make(FuzzAllowedExceptions.KeyFileText, FuzzCorpus.KeyFileTexts(), RunKeyFileText, 300, t =>
    {
        t.MinAccepted = 0.01;
        t.Slack = 4 * 1024 * 1024;
        t.Tokens = ["-----BEGIN OPENSSH PRIVATE KEY-----", "-----END OPENSSH PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----", "-----BEGIN ENCRYPTED PRIVATE KEY-----", "Proc-Type: 4,ENCRYPTED", "DEK-Info: AES-128-CBC,00", "-----BEGIN CERTIFICATE-----", "-----BEGIN EC PARAMETERS-----"];
    });

    private static FuzzOutcome RunKeyFileText(byte[] input)
    {
        using SshPrivateKey key = SshKeyFile.Load(FuzzText.Decode(input));
        FuzzNotes.Reached("loaded " + key.PublicKey.KeyType);
        return FuzzOutcome.Accepted;
    }

    // Text formats.

    private static FuzzTarget KnownHostsTarget() => Make(FuzzAllowedExceptions.KnownHosts, FuzzCorpus.KnownHostsTexts(), RunKnownHosts, 500, t =>
    {
        t.MinAccepted = 0.3;
        t.Tokens = FuzzCorpus.KnownHostsTokens;
        t.MinReasons = 1;
    });

    private static FuzzOutcome RunKnownHosts(byte[] input)
    {
        KnownHostsFile file = KnownHostsFile.Parse(FuzzText.Decode(input));
        IReadOnlyList<byte[]> blobs = FuzzCorpus.PublicBlobs;
        foreach (KnownHostsEntry entry in file.Entries)
        {
            Require(entry.Blob.Length > 0 && entry.KeyType.Length > 0, "a parsed known_hosts entry has no key");
        }

        foreach ((string host, int port) in new[] { ("example.com", 22), ("host.example.net", 2222), ("10.0.0.1", 22), ("git.example.com", 2222), ("old.example.com", 22), ("x.corp.example.com", 22), ("indented.example.com", 22) })
        {
            for (int i = 0; i < blobs.Count; i++)
            {
                SshPublicKey key = SshPublicKey.Parse(blobs[i]);
                FuzzNotes.Reached("lookup " + file.Lookup(host, port, key));
                _ = file.IsRevoked(host, port, blobs[i]);
                _ = file.IsCertificateAuthority(host, port, blobs[i]);
            }

            _ = file.HasCertificateAuthority(host, port);
        }

        return file.Entries.Count > 0 ? FuzzOutcome.Accepted : FuzzOutcome.Rejected;
    }

    private static FuzzTarget ConfigTarget() => Make(FuzzAllowedExceptions.Config, FuzzCorpus.ConfigTexts(), RunConfig, 500, t =>
    {
        t.MinAccepted = 0.3;
        t.Tokens = FuzzCorpus.ConfigTokens;
    });

    private static FuzzOutcome RunConfig(byte[] input)
    {
        string text = FuzzText.Decode(input);

        // Include reads files. The fuzzer must not wander the disk, so such inputs are not run.
        if (text.Contains("include", StringComparison.OrdinalIgnoreCase))
        {
            return FuzzOutcome.Skipped;
        }

        SshConfig config = SshConfig.Parse(text, ConfigHome, null);
        try
        {
            foreach (string alias in new[] { "web", "bastion", "a.internal", "gate.internal", "h3", "jump", "x" })
            {
                SshHostConfig host = config.Resolve(alias);
                Require(host.Port is >= 1 and <= 65535 && host.HostName is not null && host.User is not null, "a resolved host has a bad port, name or user");
                FuzzNotes.Reached(host.Port != 22 ? "resolved a host with its own port" : "resolved a host on the default port");
                FuzzNotes.Reached(host.ProxyJump is null ? "resolved a host without a jump" : "resolved a host with a jump");
                FuzzNotes.Reached(host.IdentityFiles.Count > 0 ? "resolved a host with identity files" : "resolved a host without identity files");
            }
        }
        catch (SshConfigException)
        {
            // A token that is not supported, found at resolve time. The text itself parsed.
            FuzzNotes.Reached("resolve refused a token");
        }

        return FuzzOutcome.Accepted;
    }

    // SFTP client side.

    private static FuzzTarget SftpResponsesTarget() => Make(FuzzAllowedExceptions.SftpResponses, FuzzCorpus.SftpResponseBodies(), RunSftpResponse, 2500, t => t.MinAccepted = 0.05);

    private static FuzzOutcome RunSftpResponse(byte[] input)
    {
        if (input.Length == 0)
        {
            return FuzzOutcome.Skipped;
        }

        int length = input.Length - 1;
        byte[] buffer = ArrayPool<byte>.Shared.Rent(Math.Max(length, 1));
        input.AsSpan(1).CopyTo(buffer);
        SftpResponse response = new(SftpMessage.Status, buffer, length);
        try
        {
            switch ((SftpReaderOp)(input[0] % 6))
            {
                case SftpReaderOp.Status:
                    (SftpStatusCode code, string message) = SftpParser.ReadStatus(response);
                    _ = SftpParser.ToException(code, message, "/some/path");
                    break;
                case SftpReaderOp.Handle:
                    Require(SftpParser.ReadHandle(response).Length is >= 1 and <= SftpParser.MaxHandleLength, "a handle outside its limits was accepted");
                    break;
                case SftpReaderOp.Data:
                    (int offset, int count) = SftpParser.ReadData(response, 64 * 1024);
                    Require(offset >= 0 && count >= 0 && count <= 64 * 1024 && offset + count <= length, "ReadData points outside the body");
                    break;
                case SftpReaderOp.Names:
                    SftpEntry[] names = SftpParser.ReadNames(response, 4096);
                    Require(names.Length <= 4096, "ReadNames returned more than its limit");
                    break;
                case SftpReaderOp.Attributes:
                    SftpAttributes attributes = SftpParser.ReadAttributes(response);
                    Require(attributes.Size is null or >= 0, "negative size accepted");
                    break;
                default:
                    _ = SftpParser.ReadFileSystemInfo(response);
                    break;
            }
        }
        finally
        {
            response.Dispose();
        }

        FuzzNotes.Reached("parsed " + (SftpReaderOp)(input[0] % 6));
        return FuzzOutcome.Accepted;
    }

    // SOCKS.

    private static FuzzTarget SocksTarget() => Make(FuzzAllowedExceptions.Socks, FuzzCorpus.SocksRequests(), RunSocks, 3000, t =>
    {
        t.MinAccepted = 0.05;
        t.MinReasons = 2;
    });

    private static FuzzOutcome RunSocks(byte[] input)
    {
        FuzzStream stream = new(input);
        (string Host, int Port)? target = SocksHandshake.ReadRequestAsync(stream, CancellationToken.None).GetAwaiter().GetResult();
        if (target is not { } accepted)
        {
            return FuzzOutcome.Rejected;
        }

        Require(accepted.Host.Length is > 0 and <= SocksHandshake.MaxHostLength && accepted.Port is >= 1 and <= 65535 && !accepted.Host.Any(char.IsControl), "an accepted SOCKS target has a bad host or port");

        // It must read the request and not a byte more: what follows is the tunnel's.
        int methods = input[1];
        int addressStart = 2 + methods + 4;
        int addressLength = input[2 + methods + 3] switch
        {
            1 => 4,
            4 => 16,
            _ => 1 + input[addressStart],
        };
        Require(stream.Consumed == addressStart + addressLength + 2, $"the handshake read {stream.Consumed} bytes of a request that is {addressStart + addressLength + 2} bytes");
        FuzzNotes.Reached("SOCKS target, address type " + input[addressStart - 1]);
        return FuzzOutcome.Accepted;
    }

    // Transport packets.

    private static FuzzTarget PacketsPlainTarget() => Make(FuzzAllowedExceptions.PacketsPlain, FuzzCorpus.PacketStreams(), RunPacketsPlain, 2500, t =>
    {
        t.MinAccepted = 0.05;
        t.Slack = 1024 * 1024;
    });

    private static FuzzOutcome RunPacketsPlain(byte[] input)
    {
        if (input.Length == 0)
        {
            return FuzzOutcome.Skipped;
        }

        using PacketReader reader = new(new FuzzStream(input[1..]), 262144);
        int packets = 0;
        try
        {
            reader.ReadIdentificationAsync((input[0] & 1) != 0, CancellationToken.None).AsTask().GetAwaiter().GetResult();
            for (uint sequence = 0; sequence < 64; sequence++)
            {
                ReadOnlyMemory<byte> payload = reader.ReadPacketAsync(NoneCipher.Instance, sequence, CancellationToken.None).AsTask().GetAwaiter().GetResult();
                Require(payload.Length is >= 1 and <= 262144, "a packet payload has a bad length");
                packets++;
            }
        }
        catch (SshConnectionException) when (packets > 0)
        {
            // The stream ended after whole packets: the usual way a run of them stops.
        }

        FuzzNotes.Reached("packets read: " + Math.Min(packets, 3));
        return FuzzOutcome.Accepted;
    }

    private static FuzzTarget PacketsSealedTarget() => Make(FuzzAllowedExceptions.PacketsSealed, FuzzCorpus.SealedPackets(), RunPacketsSealed, 2000, t =>
    {
        t.MinAccepted = 0.005;
        t.Slack = 1024 * 1024;
        t.MinReasons = 2;
    });

    private static FuzzOutcome RunPacketsSealed(byte[] input)
    {
        using PacketCipher cipher = FuzzCorpus.SealedPacketCipher();
        using PacketReader reader = new(new FuzzStream(input), 262144);
        ReadOnlyMemory<byte> payload = reader.ReadPacketAsync(cipher, 0, CancellationToken.None).AsTask().GetAwaiter().GetResult();
        Require(payload.Length >= 1, "an empty payload was accepted");
        FuzzNotes.Reached("sealed packet opened");
        return FuzzOutcome.Accepted;
    }

    private static FuzzTarget PacketsEamTarget() => Make(FuzzAllowedExceptions.PacketsEam, FuzzCorpus.EamPackets(), RunPacketsEam, 2000, t =>
    {
        t.MinAccepted = 0.01;
        t.Slack = 1024 * 1024;
        t.MinReasons = 3;
    });

    private static FuzzOutcome RunPacketsEam(byte[] input)
    {
        if (input.Length == 0)
        {
            return FuzzOutcome.Skipped;
        }

        // The length is encrypted, so every packet goes through the first-block decrypt before anything is read for it.
        byte[] stream = (input[0] & 1) == 0 ? input[1..] : FuzzCorpus.SealEamStream(input.AsSpan(1));
        using PacketCipher cipher = FuzzCorpus.EamPacketCipher();
        using PacketReader reader = new(new FuzzStream(stream), 262144);
        int packets = 0;
        try
        {
            for (uint sequence = 0; sequence < 16; sequence++)
            {
                ReadOnlyMemory<byte> payload = reader.ReadPacketAsync(cipher, sequence, CancellationToken.None).AsTask().GetAwaiter().GetResult();
                Require(payload.Length is >= 1 and <= 262144, "a packet payload has a bad length");
                packets++;
            }
        }
        catch (SshConnectionException) when (packets > 0)
        {
            // The stream ended after whole packets.
        }

        FuzzNotes.Reached((input[0] & 1) == 0 ? "as sent" : "self-sealed");
        FuzzNotes.Reached("eam packets read: " + Math.Min(packets, 3));
        return FuzzOutcome.Accepted;
    }

    // ssh-agent.

    private static FuzzTarget AgentTarget() => Make(FuzzAllowedExceptions.Agent, FuzzCorpus.AgentFrames(), RunAgent, 1500, t =>
    {
        t.MinAccepted = 0.05;
        t.Slack = 1024 * 1024;
    });

    private static FuzzOutcome RunAgent(byte[] input)
    {
        if (input.Length == 0)
        {
            return FuzzOutcome.Skipped;
        }

        SshAgentConnection connection = new(new FuzzStream(input[1..]), TimeSpan.FromSeconds(30));
        if ((AgentOp)(input[0] % 2) == AgentOp.List)
        {
            IReadOnlyList<SshAgentIdentity> identities = connection.ListIdentitiesAsync(CancellationToken.None).GetAwaiter().GetResult();
            Require(identities.Count <= SshAgentConnection.MaxIdentities, "an agent reply gave more keys than the limit");
            foreach (SshAgentIdentity identity in identities)
            {
                Require(identity.SignatureAlgorithms.Count > 0 && identity.Blob.Length > 0, "an identity has no algorithm or blob");
            }

            FuzzNotes.Reached("identities listed: " + Math.Min(identities.Count, 3));
            return FuzzOutcome.Accepted;
        }

        byte[]? signature = connection.SignAsync(FuzzCorpus.PublicBlobs[0], [1, 2, 3], 0, CancellationToken.None).GetAwaiter().GetResult();
        return signature is null ? FuzzOutcome.Rejected : FuzzOutcome.Accepted;
    }

    // Public key authentication request.

    private static FuzzTarget PublicKeyRequestTarget() => Make(FuzzAllowedExceptions.PublicKeyRequest, FuzzCorpus.PublicKeyRequests(), RunPublicKeyRequest, 3000, t => t.MinAccepted = 0.05);

    private static FuzzOutcome RunPublicKeyRequest(byte[] input)
    {
        ServerAuthenticator.PublicKeyRequest request = ServerAuthenticator.ParsePublicKey(input);

        // What the server does next: a key it can't read is a failed attempt, not an error.
        try
        {
            SshPublicKey key = SshPublicKey.Parse(request.Blob);
            if (key.SupportsSignatureAlgorithm(request.Algorithm) && request.Signature is not null)
            {
                _ = key.Verify(request.Algorithm, [1, 2, 3], request.Signature);
            }
        }
        catch (SshProtocolException)
        {
            // Refused as a bad key. The request itself parsed.
        }

        FuzzNotes.Reached(request.Signature is null ? "request without signature parsed" : "request with signature parsed");
        return FuzzOutcome.Accepted;
    }

    // The SFTP server.

    private static FuzzTarget SftpServerTarget() => Make(FuzzAllowedExceptions.SftpServer, FuzzCorpus.SftpRequestRuns(), RunSftpServer, 100, t =>
    {
        t.MinAccepted = 0.3;
        t.Slack = 2 * 1024 * 1024;
        t.PerByte = 256;
        t.MinReasons = 1;
    });

    private static FuzzOutcome RunSftpServer(byte[] input)
    {
        using SftpFuzzRoot root = new();
        SftpServerOptions options = new() { RootDirectory = root.Root, MaxOpenHandles = 8 };
        SftpServerSession session = new(Stream.Null, Stream.Null, options);
        bool progressed = false;
        try
        {
            List<byte[]> handles = [];
            int position = 0;
            for (int request = 0; request < 64 && position + 9 <= input.Length; request++)
            {
                uint length = BinaryPrimitives.ReadUInt32BigEndian(input.AsSpan(position));
                if (length < 5 || length > input.Length - position - 4 || length > 65536)
                {
                    break;
                }

                byte type = input[position + 4];
                uint id = BinaryPrimitives.ReadUInt32BigEndian(input.AsSpan(position + 5));
                byte[] body = input.AsSpan(position + 9, (int)length - 5).ToArray();
                position += 4 + (int)length;
                SwapHandles(body, handles);
                if (WouldFillTheDisk(type, body))
                {
                    return FuzzOutcome.Skipped;
                }

                try
                {
                    session.DispatchAsync(type, id, body, CancellationToken.None).AsTask().GetAwaiter().GetResult();
                }
                catch (Exception exception) when (FuzzAllowedExceptions.For(FuzzAllowedExceptions.SftpServer).Any(allowed => allowed.IsInstanceOfType(exception)))
                {
                    // ServeAsync turns this into a status. The next request still runs.
                    FuzzNotes.Reached($"request {type} threw {exception.GetType().Name}");
                    continue;
                }

                ReadOnlySpan<byte> reply = session.LastReply.Span;
                byte replyType = reply[4];
                FuzzNotes.Reached($"request {type} answered with {(replyType == SftpMessage.Status ? "status " + BinaryPrimitives.ReadUInt32BigEndian(reply[9..]) : "reply type " + replyType)}");
                if (replyType == SftpMessage.Handle)
                {
                    SshReader reader = new(reply[9..]);
                    handles.Add(reader.ReadBinary().ToArray());
                }

                if (replyType != SftpMessage.Status || BinaryPrimitives.ReadUInt32BigEndian(reply[9..]) == 0)
                {
                    progressed = true;
                }
            }
        }
        finally
        {
            session.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }

        root.EnsureNothingEscaped();
        return progressed ? FuzzOutcome.Accepted : FuzzOutcome.Rejected;
    }

    /// <summary>Puts the real handle from an earlier reply where a request carries the marker.</summary>
    private static void SwapHandles(byte[] body, List<byte[]> handles)
    {
        ReadOnlySpan<byte> marker = FuzzCorpus.HandleMarker;
        int at = body.AsSpan().IndexOf(marker);
        while (at >= 0)
        {
            if (handles.Count > 0)
            {
                handles[^1].CopyTo(body.AsSpan(at));
            }

            int next = body.AsSpan(at + marker.Length).IndexOf(marker);
            at = next < 0 ? -1 : at + marker.Length + next;
        }
    }

    /// <summary>
    /// The server has no disk limit on purpose ("use a quota"), so a fuzz input that writes far past the end of a file, or sets
    /// a huge size, would really do it. These are not run.
    /// </summary>
    private static bool WouldFillTheDisk(byte type, byte[] body)
    {
        const ulong Limit = 8 * 1024 * 1024;
        try
        {
            SshReader reader = new(body);
            switch (type)
            {
                case SftpMessage.Write:
                    reader.ReadBinary();
                    return reader.ReadUInt64() > Limit;
                case SftpMessage.SetStat or SftpMessage.FSetStat:
                    reader.ReadBinary();
                    return (SftpAttributes.Read(ref reader).Size ?? 0) > (long)Limit;
                case SftpMessage.Extended:
                    return false;
                default:
                    return false;
            }
        }
        catch (SshProtocolException)
        {
            return false;
        }
    }
}

/// <summary>A fresh directory tree for one SFTP input, with a file outside the root that must stay as it is.</summary>
internal sealed class SftpFuzzRoot : IDisposable
{
    private const string OutsideText = "outside the root";

    private readonly string _base = Path.Combine(Path.GetTempPath(), "zorg-fuzz-sftp-" + Guid.NewGuid().ToString("N"));

    public SftpFuzzRoot()
    {
        Root = Path.Combine(_base, "root");
        Directory.CreateDirectory(Path.Combine(Root, "d"));
        File.WriteAllText(Path.Combine(Root, "a.txt"), "the quick brown fox");
        File.WriteAllText(Path.Combine(Root, "d", "b.txt"), "second file");
        File.WriteAllText(Path.Combine(_base, "outside.txt"), OutsideText);
    }

    public string Root { get; }

    public void EnsureNothingEscaped()
    {
        string[] entries = [.. Directory.GetFileSystemEntries(_base).Select(Path.GetFileName).Order(StringComparer.Ordinal)!];
        if (!entries.SequenceEqual(["outside.txt", "root"]) || File.ReadAllText(Path.Combine(_base, "outside.txt")) != OutsideText)
        {
            throw new InvalidOperationException("Contract broken: a request changed something outside the SFTP root. Now beside it: " + string.Join(", ", entries));
        }
    }

    public void Dispose()
    {
        for (int attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                foreach (string file in Directory.EnumerateFiles(_base, "*", SearchOption.AllDirectories))
                {
                    File.SetAttributes(file, FileAttributes.Normal);
                }

                Directory.Delete(_base, recursive: true);
                return;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                Thread.Sleep(5);
            }
        }
    }
}

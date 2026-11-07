using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Sftp;
using Zorg.Ssh.Transport;

namespace Zorg.Ssh.Tests.Fuzzing.Stateful;

/// <summary>
/// The stateful fuzz targets. Each runs a real in-memory SSH connection, key exchange and all, against a scripted hostile peer
/// that knows the session keys, so its fuzzed messages are MACed correctly and reach the policy, auth, connection, channel and
/// SFTP code that the stateless targets cannot. The corpus of each is a set of valid message sequences. Mutation changes bytes
/// inside messages and also reorders, replays, drops, retypes and floods whole messages.
/// </summary>
internal static class StatefulTargets
{
    public const string ServerPreAuth = "Stateful server, before login";
    public const string ServerConnection = "Stateful server, after login";
    public const string ClientAuth = "Stateful client, during login";
    public const string ClientConnection = "Stateful client, after login";
    public const string ServerSftp = "Stateful SFTP, server side";
    public const string ClientSftp = "Stateful SFTP, client side";
    public const string ServerRekey = "Stateful server, rekey and order";
    public const string ClientRekey = "Stateful client, rekey and order";

    private static readonly Lazy<ServerRig> PreAuthRig = new(() => new ServerRig(preAuth: true, Depth.Login));
    private static readonly Lazy<ServerRig> ConnectionRig = new(() => new ServerRig(preAuth: false));
    private static readonly Lazy<ServerRig> SftpRig = new(() => new ServerRig(preAuth: false));
    private static readonly Lazy<ServerRig> RekeyRig = new(() => new ServerRig(preAuth: false, Depth.Rekeyed));
    private static readonly Lazy<ClientRig> AuthRig = new(() => new ClientRig(Depth.Authenticated));
    private static readonly Lazy<ClientRig> ClientConnectionRigLazy = new(() => new ClientRig());
    private static readonly Lazy<ClientRig> ClientSftpRig = new(() => new ClientRig());
    private static readonly Lazy<ClientRig> ClientRekeyRig = new(() => new ClientRig(Depth.Rekeyed));

    public static IReadOnlyList<string> Names { get; } = [ServerPreAuth, ServerConnection, ClientAuth, ClientConnection, ServerSftp, ClientSftp, ServerRekey, ClientRekey];

    /// <summary>A fixed 32-byte value for the key exchange messages, so that a seed rebuilds the same input in every process.</summary>
    private static readonly byte[] KexPoint = SHA256.HashData("zorg-fuzz-kex-point"u8);

    private static byte[] PeerKeyBlob => FuzzSecrets.PeerKey.PublicKey.Blob.ToArray();

    public static List<FuzzTarget> Build() => InstallWatchers(
    [
        Make(ServerPreAuth, ServerPreAuthSeeds(), ServerPreAuthPool(), input => PreAuthRig.Value.Run(input, sftp: false), variants: 2, iterations: 24, minStages: 4),
        Make(ServerConnection, ServerConnectionSeeds(), ServerConnectionPool(), input => ConnectionRig.Value.Run(input, sftp: true), variants: 1, iterations: 24),
        Make(ClientAuth, ClientAuthSeeds(), ClientAuthPool(), input => AuthRig.Value.Run(input), variants: 1, iterations: 16, minStages: 8, minReasons: 1),
        Make(ClientConnection, ClientConnectionSeeds(), ClientConnectionPool(), input => ClientConnectionRigLazy.Value.Run(input), variants: 1, iterations: 12),
        Make(ServerSftp, ServerSftpSeeds(), ServerConnectionPool(), input => SftpRig.Value.Run(input, sftp: true), variants: 1, iterations: 12),
        Make(ClientSftp, ClientSftpSeeds(), ClientConnectionPool(), input => ClientSftpRig.Value.Run(input), variants: 1, iterations: 10, minReasons: 1),
        Make(ServerRekey, ServerRekeySeeds(), RekeyPool(ServerConnectionPool()), input => RekeyRig.Value.Run(input, sftp: true), variants: 1, iterations: 14),
        Make(ClientRekey, ClientRekeySeeds(), RekeyPool(ClientConnectionPool()), input => ClientRekeyRig.Value.Run(input), variants: 1, iterations: 10),
    ]);

    private static List<FuzzTarget> InstallWatchers(List<FuzzTarget> targets)
    {
        UnobservedTasks.Install();
        return targets;
    }

    private static FuzzTarget Make(string name, IReadOnlyList<(string Name, List<FuzzOp> Ops)> seeds, IReadOnlyList<FuzzOp> pool, Func<byte[], FuzzOutcome> run, int variants, int iterations, int minStages = 14, int minReasons = 2)
    {
        List<FuzzSeed> corpus = [.. seeds.Select(seed => FuzzSeed.Binary(seed.Name, FuzzOpCodec.Encode(0, seed.Ops)))];
        return new FuzzTarget
        {
            Name = name,
            Corpus = corpus,
            Execute = run,
            Allowed = [],
            ShortIterations = iterations,
            AllocationSlack = long.MaxValue / 4,
            AllocationPerByte = 0,
            MinAcceptedShare = 0.15,
            MinRefusalReasons = minReasons,
            MinReachedStages = minStages,
            InputLimit = StatefulLimits.InputLimit,
            Generate = seed =>
            {
                FuzzRandom random = new(seed);
                int pick = random.Next(seeds.Count);
                List<FuzzOp> mutated = SequenceMutator.Mutate(random, seeds[pick].Ops, pool);
                // The low nibble is the rig's variant, the high one the peer's cipher suite.
                return FuzzOpCodec.Encode((byte)(random.Next(variants) | (random.Next(StatefulLimits.PeerSuites.Count) << 4)), mutated);
            },
        };
    }

    // The scripted logins.

    private static List<FuzzOp> ServerLogin() =>
    [
        FuzzOp.Send(Wire.ServiceRequest()),
        FuzzOp.Await(MessageNumber.ServiceAccept),
        FuzzOp.Send(Wire.AuthPassword(Wire.Secret)),
        FuzzOp.Await(MessageNumber.UserAuthSuccess),
    ];

    private static List<FuzzOp> ClientLogin(bool withBanner = false, bool withExtInfo = false, int method = 0)
    {
        List<FuzzOp> ops = [];
        if (withExtInfo)
        {
            ops.Add(FuzzOp.Send(Wire.ExtInfo(("server-sig-algs", "ssh-ed25519,rsa-sha2-512"))));
        }

        ops.Add(FuzzOp.Await(MessageNumber.ServiceRequest));
        ops.Add(FuzzOp.Send(Wire.ServiceAccept()));
        ops.Add(FuzzOp.Await(MessageNumber.UserAuthRequest));
        if (withBanner)
        {
            ops.Add(FuzzOp.Send(Wire.AuthBanner("Welcome\r\n\u001b[31mred")));
        }

        ops.Add(FuzzOp.Send(Wire.AuthFailure(false, "publickey", "keyboard-interactive", "password")));
        switch (method)
        {
            case 0:
                // The key: a query the server says yes to, then the signed request it accepts.
                ops.Add(FuzzOp.Await(MessageNumber.UserAuthRequest));
                ops.Add(FuzzOp.Send(Wire.AuthPublicKeyOk("ssh-ed25519", PeerKeyBlob)));
                ops.Add(FuzzOp.Await(MessageNumber.UserAuthRequest));
                break;
            case 1:
                // The key is refused, then keyboard-interactive with one round of prompts.
                ops.Add(FuzzOp.Await(MessageNumber.UserAuthRequest));
                ops.Add(FuzzOp.Send(Wire.AuthFailure(false, "keyboard-interactive", "password")));
                ops.Add(FuzzOp.Await(MessageNumber.UserAuthRequest));
                ops.Add(FuzzOp.Send(Wire.AuthInfoRequest("login", "type it", ("Password: ", false), ("Code: ", true))));
                ops.Add(FuzzOp.Await(61));
                break;
            default:
                // Key and keyboard-interactive refused, then the password.
                ops.Add(FuzzOp.Await(MessageNumber.UserAuthRequest));
                ops.Add(FuzzOp.Send(Wire.AuthFailure(false, "keyboard-interactive", "password")));
                ops.Add(FuzzOp.Await(MessageNumber.UserAuthRequest));
                ops.Add(FuzzOp.Send(Wire.AuthFailure(true, "password")));
                ops.Add(FuzzOp.Await(MessageNumber.UserAuthRequest));
                break;
        }

        ops.Add(FuzzOp.Send(Wire.AuthSuccess()));
        return ops;
    }

    // Server, before login.

    private static IReadOnlyList<(string, List<FuzzOp>)> ServerPreAuthSeeds()
    {
        byte[] blob = PeerKeyBlob;
        return
        [
            ("passwords", [FuzzOp.Send(Wire.ServiceRequest()), FuzzOp.Await(MessageNumber.ServiceAccept), FuzzOp.Send(Wire.AuthNone()), FuzzOp.Send(Wire.AuthPassword("wrong")), FuzzOp.Send(Wire.AuthPassword(Wire.Secret)), FuzzOp.Send(Wire.AuthPassword(Wire.Secret, "other")), FuzzOp.Send(Wire.AuthPasswordChange(Wire.Secret, "new-" + Wire.Secret)), FuzzOp.Await(MessageNumber.UserAuthFailure)]),
            ("publickey", [FuzzOp.Send(Wire.ServiceRequest()), FuzzOp.Await(MessageNumber.ServiceAccept), FuzzOp.Send(Wire.AuthPublicKey("ssh-ed25519", blob, signed: false)), FuzzOp.Await(60), new FuzzOp(OpKind.SignedAuth, Wire.AuthPublicKey("ssh-ed25519", blob, signed: true)), FuzzOp.Send(Wire.AuthPassword(Wire.Secret)), FuzzOp.Await(MessageNumber.UserAuthFailure)]),
            ("publickey wrong signature", [FuzzOp.Send(Wire.ServiceRequest()), FuzzOp.Await(MessageNumber.ServiceAccept), FuzzOp.Send(new FuzzBlob().Raw(Wire.AuthPublicKey("ssh-ed25519", blob, signed: true)).String(new FuzzBlob().String("ssh-ed25519").String(new byte[64]).ToArray()).ToArray()), FuzzOp.Send(Wire.AuthPublicKey("ecdsa-sha2-nistp256", blob, signed: false)), FuzzOp.Await(MessageNumber.UserAuthFailure)]),
            ("keyboard-interactive and others", [FuzzOp.Send(Wire.ServiceRequest()), FuzzOp.Await(MessageNumber.ServiceAccept), FuzzOp.Send(Wire.AuthKeyboardInteractive()), FuzzOp.Send(Wire.AuthInfoResponse("a", "b")), FuzzOp.Send(new FuzzBlob().Byte(MessageNumber.UserAuthRequest).String(Wire.UserName).String("ssh-connection").String("hostbased").String("ssh-ed25519").String(blob).String("host").String(Wire.UserName).String(new byte[64]).ToArray()), FuzzOp.Send(new FuzzBlob().Byte(MessageNumber.UserAuthRequest).String(Wire.UserName).String("ssh-connection").String("gssapi-with-mic").UInt32(1).String([6, 9]).ToArray()), FuzzOp.Await(MessageNumber.UserAuthFailure)]),
            ("connection messages before login", [FuzzOp.Send(Wire.ServiceRequest()), FuzzOp.Await(MessageNumber.ServiceAccept), FuzzOp.Send(Wire.AuthNone()), FuzzOp.Send(Wire.ChannelOpen("session", 100)), FuzzOp.Send(Wire.Exec(0, "touch /tmp/x")), FuzzOp.Send(Wire.ChannelData(0, "x"u8.ToArray())), FuzzOp.Send(Wire.TcpIpForward("0.0.0.0", 2222)), FuzzOp.Send(Wire.ChannelOpen("direct-tcpip", 101, Wire.DirectTcpExtra("127.0.0.1", 22))), FuzzOp.Send(Wire.GlobalRequest("keepalive@openssh.com", true))]),
            ("service confusion", [FuzzOp.Send(Wire.ServiceRequest("ssh-connection")), FuzzOp.Send(Wire.ServiceRequest()), FuzzOp.Send(Wire.ServiceRequest()), FuzzOp.Send(Wire.AuthNone()), FuzzOp.Send(Wire.ExtInfo(("server-sig-algs", "ssh-ed25519"))), FuzzOp.Send(Wire.ServiceAccept())]),
            ("user changes", [FuzzOp.Send(Wire.ServiceRequest()), FuzzOp.Await(MessageNumber.ServiceAccept), FuzzOp.Send(Wire.AuthPassword("a", "alice")), FuzzOp.Send(Wire.AuthPassword("b", "bob")), FuzzOp.Send(new FuzzBlob().Byte(MessageNumber.UserAuthRequest).String("alice").String("other-service").String("none").ToArray())]),
            ("ignore and debug", [FuzzOp.Send(Wire.Ignore("pre")), FuzzOp.Send(Wire.Debug()), FuzzOp.Send(Wire.ServiceRequest()), FuzzOp.Send(Wire.Unimplemented(7)), FuzzOp.Await(MessageNumber.ServiceAccept), FuzzOp.Send(Wire.Ignore("mid")), FuzzOp.Send(Wire.AuthPassword("zzz")), FuzzOp.Send(Wire.Disconnect())]),
        ];
    }

    private static IReadOnlyList<FuzzOp> ServerPreAuthPool() =>
    [
        FuzzOp.Send(Wire.ChannelOpen("session", 100)),
        FuzzOp.Send(Wire.Exec(0, "id")),
        FuzzOp.Send(Wire.GlobalRequest("tcpip-forward", true, new FuzzBlob().String("0.0.0.0").UInt32(0).ToArray())),
        FuzzOp.Send(Wire.AuthSuccess()),
        FuzzOp.Send(Wire.ServiceAccept()),
        FuzzOp.Send(Wire.KexInit(SshRole.Client)),
        FuzzOp.Send(Wire.KexNewKeys()),
        FuzzOp.Send(Wire.KexEcdhInit(KexPoint)),
        FuzzOp.Send(Wire.ExtInfo(("server-sig-algs", "ssh-ed25519"))),
        FuzzOp.Send(Wire.AuthInfoResponse("x")),
        FuzzOp.Send(Wire.AuthPublicKeyOk("ssh-ed25519", PeerKeyBlob)),
        FuzzOp.Send(Wire.AuthFailure(false, "password")),
        FuzzOp.Send(Wire.ChannelOpenConfirmation(0, 100)),
        FuzzOp.Send(Wire.RequestSuccess()),
        FuzzOp.Send(Wire.Disconnect(2)),
        FuzzOp.Of(OpKind.Rekey),
    ];

    // Server, after login.

    private static IReadOnlyList<(string, List<FuzzOp>)> ServerConnectionSeeds()
    {
        List<FuzzOp> With(params FuzzOp[] rest) => [.. ServerLogin(), .. rest];
        return
        [
            ("exec with data", With(FuzzOp.Send(Wire.ChannelOpen("session", 100)), FuzzOp.Await(MessageNumber.ChannelOpenConfirmation), FuzzOp.Send(Wire.Env(0, "LANG", "C")), FuzzOp.Send(Wire.PtyRequest(0)), FuzzOp.Send(Wire.Exec(0, "run it")), FuzzOp.Await(MessageNumber.ChannelSuccess), FuzzOp.Data(0, new byte[3000]), FuzzOp.Data(0, new byte[100], extended: true), FuzzOp.Send(Wire.WindowAdjust(0, 4096)), FuzzOp.Send(Wire.ChannelEof(0)), FuzzOp.Await(MessageNumber.ChannelEof), FuzzOp.Send(Wire.ChannelClose(0)), FuzzOp.Await(MessageNumber.ChannelClose))),
            ("shell and window change", With(FuzzOp.Send(Wire.ChannelOpen("session", 100)), FuzzOp.Await(MessageNumber.ChannelOpenConfirmation), FuzzOp.Send(Wire.PtyRequest(0)), FuzzOp.Send(Wire.Shell(0)), FuzzOp.Send(Wire.WindowChange(0)), FuzzOp.Send(Wire.ChannelRequest(0, "signal", false, new FuzzBlob().String("TERM").ToArray())), FuzzOp.Send(Wire.ChannelRequest(0, "break", true, new FuzzBlob().UInt32(100).ToArray())), FuzzOp.Send(Wire.ChannelRequest(0, "x11-req", true, new FuzzBlob().Bool(false).String("MIT-MAGIC-COOKIE-1").String("00").UInt32(0).ToArray())), FuzzOp.Send(Wire.ChannelRequest(0, "auth-agent-req@openssh.com", true)), FuzzOp.Data(0, "ls\n"u8.ToArray()), FuzzOp.Send(Wire.ChannelClose(0)), FuzzOp.Await(MessageNumber.ChannelClose))),
            ("direct-tcpip", With(FuzzOp.Send(Wire.ChannelOpen("direct-tcpip", 101, Wire.DirectTcpExtra("127.0.0.1", (uint)SharedSink.Port))), FuzzOp.Await(MessageNumber.ChannelOpenConfirmation), FuzzOp.Data(0, new byte[5000]), FuzzOp.Send(Wire.WindowAdjust(0, 100)), FuzzOp.Send(Wire.ChannelEof(0)), FuzzOp.Send(Wire.ChannelClose(0)), FuzzOp.Send(Wire.ChannelOpen("direct-tcpip", 102, Wire.DirectTcpExtra("10.0.0.1", 80))), FuzzOp.Send(Wire.ChannelOpen("direct-tcpip", 103, Wire.DirectTcpExtra("", 0))), FuzzOp.Await(MessageNumber.ChannelOpenFailure))),
            ("global requests", With(FuzzOp.Send(Wire.TcpIpForward("0.0.0.0", 2222)), FuzzOp.Send(Wire.KeepAlive()), FuzzOp.Send(Wire.CancelTcpIpForward("0.0.0.0", 2222)), FuzzOp.Send(Wire.GlobalRequest("no-more-sessions@openssh.com", false)), FuzzOp.Send(Wire.GlobalRequest("hostkeys-prove-00@openssh.com", true, new FuzzBlob().String(PeerKeyBlob).ToArray())), FuzzOp.Send(Wire.GlobalRequest("unknown", true, [1, 2, 3])), FuzzOp.Send(Wire.RequestSuccess(1, 2)), FuzzOp.Send(Wire.RequestFailure()), FuzzOp.Await(MessageNumber.RequestFailure))),
            ("many channels", With(FuzzOp.Send(Wire.ChannelOpen("session", 100)), FuzzOp.Send(Wire.ChannelOpen("session", 101)), FuzzOp.Send(Wire.ChannelOpen("session", 102)), FuzzOp.Send(Wire.ChannelOpen("x11", 103)), FuzzOp.Send(Wire.ChannelOpen("forwarded-tcpip", 104, Wire.ForwardedTcpExtra("a", 1))), FuzzOp.Send(Wire.ChannelOpen("unknown@example.com", 105)), FuzzOp.Send(Wire.ChannelOpenWithLimits("session", 106, 0, 0)), FuzzOp.Send(Wire.ChannelOpenWithLimits("session", 107, uint.MaxValue, uint.MaxValue)), FuzzOp.Send(Wire.Exec(1, "two")), FuzzOp.Data(2, new byte[100]), FuzzOp.Send(Wire.ChannelClose(1)), FuzzOp.Send(Wire.ChannelClose(0)), FuzzOp.Await(MessageNumber.ChannelClose))),
            ("channel errors", With(FuzzOp.Send(Wire.ChannelOpen("session", 100)), FuzzOp.Await(MessageNumber.ChannelOpenConfirmation), FuzzOp.Send(Wire.ChannelData(5, [1])), FuzzOp.Send(Wire.ChannelEof(7)), FuzzOp.Send(Wire.ChannelSuccess(0)), FuzzOp.Send(Wire.ChannelFailure(0)), FuzzOp.Send(Wire.WindowAdjust(0, uint.MaxValue)), FuzzOp.Send(Wire.ChannelOpenConfirmation(0, 1)), FuzzOp.Send(Wire.ChannelOpenFailure(0, 1)), FuzzOp.Send(Wire.ExitStatus(0, 2)), FuzzOp.Send(Wire.ChannelRequest(0, "exec", true, [0, 0, 0, 5, 65])), FuzzOp.Send(Wire.ChannelClose(0)), FuzzOp.Send(Wire.ChannelClose(0)))),
            ("window exhaustion", With([FuzzOp.Send(Wire.ChannelOpen("session", 100)), FuzzOp.Await(MessageNumber.ChannelOpenConfirmation), FuzzOp.Send(Wire.Subsystem(0, "unread")), .. Enumerable.Repeat(FuzzOp.Send(Wire.ChannelData(0, new byte[30000])), 80), FuzzOp.Send(Wire.ChannelClose(0))])),
            ("request flood", With([FuzzOp.Send(Wire.ChannelOpen("session", 100)), FuzzOp.Await(MessageNumber.ChannelOpenConfirmation), .. Enumerable.Repeat(FuzzOp.Send(Wire.ChannelRequest(0, "env", true, new FuzzBlob().String("A").String("b").ToArray())), 40), FuzzOp.Send(Wire.ChannelClose(0))])),
            ("channel flood", With([.. Enumerable.Range(0, 14).Select(i => FuzzOp.Send(Wire.ChannelOpen("session", (uint)(100 + i)))), FuzzOp.Send(Wire.ChannelClose(0))])),
            ("subsystems", With(FuzzOp.Send(Wire.ChannelOpen("session", 100)), FuzzOp.Await(MessageNumber.ChannelOpenConfirmation), FuzzOp.Send(Wire.Subsystem(0, "unknown")), FuzzOp.Send(Wire.Env(0, new string('N', 300), "v", true)), FuzzOp.Send(Wire.Env(0, "OK", new string('v', 9000), true)), FuzzOp.Send(Wire.Subsystem(0, "sftp")), FuzzOp.Send(Wire.Exec(0, "late", true)), FuzzOp.Data(0, Wire.SftpInit()), FuzzOp.Send(Wire.ChannelEof(0)), FuzzOp.Send(Wire.ChannelClose(0)))),
        ];
    }

    private static IReadOnlyList<FuzzOp> ServerConnectionPool() =>
    [
        FuzzOp.Send(Wire.ChannelOpen("session", 100)),
        FuzzOp.Send(Wire.ChannelOpen("direct-tcpip", 101, Wire.DirectTcpExtra("127.0.0.1", (uint)SharedSink.Port))),
        FuzzOp.Send(Wire.Exec(0, "pool")),
        FuzzOp.Send(Wire.Subsystem(0, "sftp")),
        FuzzOp.Send(Wire.ChannelClose(0)),
        FuzzOp.Send(Wire.ChannelEof(0)),
        FuzzOp.Send(Wire.WindowAdjust(0, 70000)),
        FuzzOp.Data(0, new byte[2000]),
        FuzzOp.Data(0, new byte[400], extended: true),
        FuzzOp.Send(Wire.TcpIpForward("localhost", 8080)),
        FuzzOp.Send(Wire.KeepAlive()),
        FuzzOp.Send(Wire.ServiceRequest()),
        FuzzOp.Send(Wire.AuthPassword(Wire.Secret)),
        FuzzOp.Send(Wire.AuthSuccess()),
        FuzzOp.Send(Wire.KexInit(SshRole.Client)),
        FuzzOp.Send(Wire.KexNewKeys()),
        FuzzOp.Send(Wire.Unimplemented(3)),
        FuzzOp.Send(Wire.Ignore("pool")),
        FuzzOp.Of(OpKind.Rekey),
        FuzzOp.Of(OpKind.Pause),
        FuzzOp.App(0),
        FuzzOp.App(2),
        FuzzOp.App(3),
    ];

    // Client, during login.

    private static IReadOnlyList<(string, List<FuzzOp>)> ClientAuthSeeds() =>
    [
        ("key login", [.. ClientLogin(method: 0), FuzzOp.Send(Wire.Ignore())]),
        ("keyboard-interactive login", [.. ClientLogin(withBanner: true, method: 1)]),
        ("password login with ext info", [.. ClientLogin(withExtInfo: true, method: 2)]),
        ("refusals", [FuzzOp.Await(MessageNumber.ServiceRequest), FuzzOp.Send(Wire.ServiceAccept()), FuzzOp.Await(MessageNumber.UserAuthRequest), FuzzOp.Send(Wire.AuthFailure(false, "publickey", "password")), FuzzOp.Await(MessageNumber.UserAuthRequest), FuzzOp.Send(Wire.AuthFailure(false, "password")), FuzzOp.Await(MessageNumber.UserAuthRequest), FuzzOp.Send(Wire.AuthFailure(false)), FuzzOp.Send(Wire.Disconnect(14))]),
        ("password change request", [FuzzOp.Await(MessageNumber.ServiceRequest), FuzzOp.Send(Wire.ServiceAccept()), FuzzOp.Await(MessageNumber.UserAuthRequest), FuzzOp.Send(Wire.AuthFailure(false, "password")), FuzzOp.Await(MessageNumber.UserAuthRequest), FuzzOp.Send(new FuzzBlob().Byte(60).String("Password expired").String("en").ToArray())]),
        ("wrong messages in login", [FuzzOp.Await(MessageNumber.ServiceRequest), FuzzOp.Send(Wire.ServiceAccept("ssh-connection")), FuzzOp.Send(Wire.ServiceAccept()), FuzzOp.Send(Wire.AuthSuccess()), FuzzOp.Send(Wire.ChannelOpen("session", 100)), FuzzOp.Send(Wire.GlobalRequest("hostkeys-00@openssh.com", true))]),
        ("endless prompts", [FuzzOp.Await(MessageNumber.ServiceRequest), FuzzOp.Send(Wire.ServiceAccept()), FuzzOp.Await(MessageNumber.UserAuthRequest), FuzzOp.Send(Wire.AuthFailure(false, "keyboard-interactive")), FuzzOp.Await(MessageNumber.UserAuthRequest), FuzzOp.Send(Wire.AuthInfoRequest("a", "b")), FuzzOp.Send(Wire.AuthInfoRequest("a", "b", ("1", true))), FuzzOp.Send(Wire.AuthInfoRequest("a", "b", ("1", true), ("2", false))), FuzzOp.Send(Wire.AuthBanner("late")), FuzzOp.Send(Wire.AuthSuccess())]),
    ];

    private static IReadOnlyList<FuzzOp> ClientAuthPool() =>
    [
        FuzzOp.Send(Wire.AuthSuccess()),
        FuzzOp.Send(Wire.AuthFailure(false, "publickey")),
        FuzzOp.Send(Wire.AuthFailure(true, "password", "keyboard-interactive")),
        FuzzOp.Send(Wire.AuthBanner(new string('b', 20000))),
        FuzzOp.Send(Wire.AuthPublicKeyOk("ssh-ed25519", PeerKeyBlob)),
        FuzzOp.Send(Wire.AuthPublicKeyOk("ssh-rsa", PeerKeyBlob)),
        FuzzOp.Send(Wire.AuthInfoRequest("x", "y", ("p", false))),
        FuzzOp.Send(Wire.ExtInfo(("server-sig-algs", "rsa-sha2-256"), ("ping@openssh.com", "0"))),
        FuzzOp.Send(Wire.ServiceAccept()),
        FuzzOp.Send(Wire.ChannelOpen("forwarded-tcpip", 100, Wire.ForwardedTcpExtra("127.0.0.1", 22))),
        FuzzOp.Send(Wire.GlobalRequest("hostkeys-00@openssh.com", true)),
        FuzzOp.Send(Wire.ServiceRequest()),
        FuzzOp.Send(Wire.KexInit(SshRole.Server)),
        FuzzOp.Send(Wire.Unimplemented(2)),
        FuzzOp.Send(Wire.Disconnect(14)),
    ];

    // Client, after login.

    private static List<FuzzOp> ClientWith(int method, params FuzzOp[] rest) => [.. ClientLogin(method: method), .. rest];

    private static IReadOnlyList<(string, List<FuzzOp>)> ClientConnectionSeeds() =>
    [
        ("exec", ClientWith(0, FuzzOp.App(0), FuzzOp.Await(MessageNumber.ChannelOpen), FuzzOp.Send(Wire.ChannelOpenConfirmation(0, 100)), FuzzOp.Await(MessageNumber.ChannelRequest), FuzzOp.Send(Wire.ChannelSuccess(0)), FuzzOp.Send(Wire.ChannelData(0, "out"u8.ToArray())), FuzzOp.Send(Wire.ChannelExtendedData(0, 1, "err"u8.ToArray())), FuzzOp.Send(Wire.WindowAdjust(0, 1000)), FuzzOp.Send(Wire.ExitStatus(0, 3)), FuzzOp.Send(Wire.ExitSignal(0, "TERM")), FuzzOp.Send(Wire.ChannelEof(0)), FuzzOp.Send(Wire.ChannelClose(0)), FuzzOp.Await(MessageNumber.ChannelClose))),
        ("process", ClientWith(1, FuzzOp.App(1), FuzzOp.Await(MessageNumber.ChannelOpen), FuzzOp.Send(Wire.ChannelOpenConfirmation(0, 100)), FuzzOp.Await(MessageNumber.ChannelRequest), FuzzOp.Send(Wire.ChannelSuccess(0)), FuzzOp.Send(Wire.ChannelData(0, new byte[5000])), FuzzOp.Send(Wire.ChannelRequest(0, "keepalive@openssh.com", true)), FuzzOp.Send(Wire.ChannelEof(0)), FuzzOp.Send(Wire.ExitStatus(0, 0)), FuzzOp.Send(Wire.ChannelClose(0)), FuzzOp.Await(MessageNumber.ChannelClose))),
        ("shell", ClientWith(2, FuzzOp.App(5), FuzzOp.Await(MessageNumber.ChannelOpen), FuzzOp.Send(Wire.ChannelOpenConfirmation(0, 100)), FuzzOp.Await(MessageNumber.ChannelRequest), FuzzOp.Send(Wire.ChannelSuccess(0)), FuzzOp.Await(MessageNumber.ChannelRequest), FuzzOp.Send(Wire.ChannelSuccess(0)), FuzzOp.Send(Wire.ChannelData(0, "$ "u8.ToArray())), FuzzOp.Await(MessageNumber.ChannelRequest), FuzzOp.Send(Wire.ChannelFailure(0)), FuzzOp.Send(Wire.ChannelClose(0)))),
        ("remote forward", ClientWith(0, FuzzOp.App(3), FuzzOp.Await(MessageNumber.GlobalRequest), FuzzOp.Send(Wire.RequestSuccessPort(2200)), FuzzOp.Send(Wire.ChannelOpen("forwarded-tcpip", 101, Wire.ForwardedTcpExtra("127.0.0.1", 2200))), FuzzOp.Await(MessageNumber.ChannelOpenConfirmation), FuzzOp.Data(0, new byte[2000]), FuzzOp.Send(Wire.ChannelOpen("forwarded-tcpip", 102, Wire.ForwardedTcpExtra("127.0.0.1", 9999))), FuzzOp.Send(Wire.ChannelOpen("forwarded-tcpip", 103, Wire.ForwardedTcpExtra("127.0.0.1", 2200))), FuzzOp.Send(Wire.ChannelEof(0)), FuzzOp.Send(Wire.ChannelClose(0)), FuzzOp.Await(MessageNumber.GlobalRequest))),
        ("fixed remote forward", ClientWith(1, FuzzOp.App(6), FuzzOp.Await(MessageNumber.GlobalRequest), FuzzOp.Send(Wire.RequestSuccess()), FuzzOp.Send(Wire.ChannelOpen("forwarded-tcpip", 101, Wire.ForwardedTcpExtra("0.0.0.0", 8022))), FuzzOp.Await(MessageNumber.ChannelOpenConfirmation), FuzzOp.Data(0, new byte[300]), FuzzOp.Send(Wire.ChannelClose(0)), FuzzOp.Await(MessageNumber.GlobalRequest), FuzzOp.Send(Wire.RequestFailure()))),
        ("direct tcpip", ClientWith(2, FuzzOp.App(4), FuzzOp.Await(MessageNumber.ChannelOpen), FuzzOp.Send(Wire.ChannelOpenConfirmation(0, 100)), FuzzOp.Await(MessageNumber.ChannelData), FuzzOp.Send(Wire.ChannelData(0, new byte[300])), FuzzOp.Send(Wire.ChannelEof(0)), FuzzOp.Send(Wire.ChannelClose(0)))),
        ("refused open", ClientWith(0, FuzzOp.App(0), FuzzOp.Await(MessageNumber.ChannelOpen), FuzzOp.Send(Wire.ChannelOpenFailure(0, 2)), FuzzOp.App(7), FuzzOp.Await(MessageNumber.ChannelOpen), FuzzOp.Send(Wire.ChannelOpenConfirmation(1, 100)), FuzzOp.Await(MessageNumber.ChannelRequest), FuzzOp.Send(Wire.ChannelFailure(1)), FuzzOp.Send(Wire.ChannelClose(1)))),
        ("server initiated", ClientWith(1, FuzzOp.Send(Wire.ChannelOpen("session", 100)), FuzzOp.Send(Wire.ChannelOpen("x11", 101)), FuzzOp.Send(Wire.ChannelOpen("auth-agent@openssh.com", 102)), FuzzOp.Send(Wire.ChannelOpen("direct-tcpip", 103, Wire.DirectTcpExtra("a", 1))), FuzzOp.Send(Wire.ChannelOpen("forwarded-tcpip", 104, Wire.ForwardedTcpExtra("a", 1))), FuzzOp.Send(Wire.GlobalRequest("hostkeys-00@openssh.com", true, [0, 0, 0, 3, 1, 2, 3])), FuzzOp.Send(Wire.GlobalRequest("keepalive@openssh.com", true)), FuzzOp.Send(Wire.GlobalRequest("tcpip-forward", true)), FuzzOp.Send(Wire.Ignore()), FuzzOp.Await(MessageNumber.RequestFailure))),
    ];

    private static IReadOnlyList<FuzzOp> ClientConnectionPool() =>
    [
        FuzzOp.Send(Wire.ChannelOpenConfirmation(0, 100)),
        FuzzOp.Send(Wire.ChannelOpenConfirmation(1, 101)),
        FuzzOp.Send(Wire.ChannelOpenFailure(0, 1)),
        FuzzOp.Send(Wire.ChannelSuccess(0)),
        FuzzOp.Send(Wire.ChannelFailure(0)),
        FuzzOp.Send(Wire.ChannelData(0, new byte[1000])),
        FuzzOp.Send(Wire.ChannelExtendedData(0, 1, new byte[100])),
        FuzzOp.Send(Wire.ChannelExtendedData(0, 7, new byte[100])),
        FuzzOp.Send(Wire.WindowAdjust(0, 99999)),
        FuzzOp.Send(Wire.ChannelEof(0)),
        FuzzOp.Send(Wire.ChannelClose(0)),
        FuzzOp.Send(Wire.ExitStatus(0, 255)),
        FuzzOp.Send(Wire.RequestSuccess()),
        FuzzOp.Send(Wire.RequestSuccessPort(70000)),
        FuzzOp.Send(Wire.RequestFailure()),
        FuzzOp.Send(Wire.ChannelOpen("forwarded-tcpip", 110, Wire.ForwardedTcpExtra("127.0.0.1", 2200))),
        FuzzOp.Send(Wire.ChannelOpen("forwarded-tcpip", 111, Wire.ForwardedTcpExtra("127.0.0.1", 0))),
        FuzzOp.Send(Wire.GlobalRequest("keepalive@openssh.com", true)),
        FuzzOp.Send(Wire.AuthSuccess()),
        FuzzOp.Send(Wire.ServiceAccept()),
        FuzzOp.Send(Wire.KexInit(SshRole.Server)),
        FuzzOp.Send(Wire.KexNewKeys()),
        FuzzOp.Of(OpKind.Rekey),
        FuzzOp.Of(OpKind.Pause),
        FuzzOp.App(0),
        FuzzOp.App(1),
        FuzzOp.App(2),
        FuzzOp.App(3),
        FuzzOp.App(4),
        FuzzOp.App(8),
        FuzzOp.App(9),
    ];

    // SFTP.

    private static IReadOnlyList<(string, List<FuzzOp>)> ServerSftpSeeds()
    {
        List<FuzzOp> Session() => [.. ServerLogin(), FuzzOp.Send(Wire.ChannelOpen("session", 100)), FuzzOp.Await(MessageNumber.ChannelOpenConfirmation), FuzzOp.Send(Wire.Subsystem(0, "sftp")), FuzzOp.Await(MessageNumber.ChannelSuccess), FuzzOp.Data(0, Wire.SftpInit())];
        List<(string, List<FuzzOp>)> seeds = [];
        foreach (FuzzSeed run in FuzzCorpus.SftpRequestRuns())
        {
            List<FuzzOp> ops = Session();
            ops.Add(FuzzOp.Await(MessageNumber.ChannelData));

            // One request at a time, so a handle from one reply can fill the next request. The run is a series of framed requests.
            int at = 0;
            byte[] data = run.Data;
            while (at + 9 <= data.Length)
            {
                uint length = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(at));
                if (length < 5 || at + 4 + length > data.Length)
                {
                    break;
                }

                ops.Add(FuzzOp.Data(0, data.AsSpan(at, 4 + (int)length).ToArray(), swapHandles: true));
                ops.Add(FuzzOp.Await(MessageNumber.ChannelData));
                at += 4 + (int)length;
            }

            ops.Add(FuzzOp.Send(Wire.ChannelEof(0)));
            ops.Add(FuzzOp.Send(Wire.ChannelClose(0)));
            seeds.Add((run.Name, ops));
        }

        // Garbage that is not framed as SFTP at all, and an INIT of another version.
        seeds.Add(("bad framing", [.. Session(), FuzzOp.Data(0, [0xFF, 0xFF, 0xFF, 0xFF, 1]), FuzzOp.Send(Wire.ChannelClose(0))]));
        seeds.Add(("version 6", [.. ServerLogin(), FuzzOp.Send(Wire.ChannelOpen("session", 100)), FuzzOp.Send(Wire.Subsystem(0, "sftp")), FuzzOp.Data(0, new FuzzBlob().UInt32(5).Byte(1).UInt32(6).ToArray()), FuzzOp.Data(0, Wire.SftpFrame(SftpMessage.Stat, 1, new FuzzBlob().String("a.txt").ToArray())), FuzzOp.Send(Wire.ChannelClose(0))]));
        return seeds;
    }

    private static IReadOnlyList<(string, List<FuzzOp>)> ClientSftpSeeds()
    {
        List<FuzzOp> Session(int method, byte app = 2) => ClientWith(method, FuzzOp.App(app), FuzzOp.Await(MessageNumber.ChannelOpen), FuzzOp.Send(Wire.ChannelOpenConfirmation(0, 100)), FuzzOp.Await(MessageNumber.ChannelRequest), FuzzOp.Send(Wire.ChannelSuccess(0)), FuzzOp.Await(MessageNumber.ChannelData));
        byte[] Fixed(byte type, byte[] body) => [1, type, .. body];
        byte[] Mutated(ulong seed) => [2, .. new FuzzBlob().UInt64(seed).ToArray()];
        return
        [
            ("honest server", [.. Session(0), new FuzzOp(OpKind.SftpRespond, [0]), FuzzOp.Await(MessageNumber.ChannelClose), FuzzOp.Send(Wire.ChannelClose(0))]),
            ("files and streams", [.. Session(1, 8), new FuzzOp(OpKind.SftpRespond, [0]), FuzzOp.Await(MessageNumber.ChannelClose), FuzzOp.Send(Wire.ChannelClose(0))]),
            ("metadata", [.. Session(2, 9), new FuzzOp(OpKind.SftpRespond, [0]), new FuzzOp(OpKind.SftpRespond, [1, SftpMessage.Status, .. new FuzzBlob().UInt32(8).String("no").String("en").ToArray()]), FuzzOp.Await(MessageNumber.ChannelClose), FuzzOp.Send(Wire.ChannelClose(0))]),
            ("wrong type for handle", [.. Session(1), new FuzzOp(OpKind.SftpRespond, [0]), new FuzzOp(OpKind.SftpRespond, Fixed(SftpMessage.Status, new FuzzBlob().UInt32(0).String("ok").String("en").ToArray())), new FuzzOp(OpKind.SftpRespond, Fixed(SftpMessage.Data, new FuzzBlob().String(new byte[10]).ToArray())), FuzzOp.Send(Wire.ChannelClose(0))]),
            ("mutated replies", [.. Session(2), new FuzzOp(OpKind.SftpRespond, [0]), new FuzzOp(OpKind.SftpRespond, Mutated(11)), new FuzzOp(OpKind.SftpRespond, Mutated(12)), new FuzzOp(OpKind.SftpRespond, Mutated(13)), new FuzzOp(OpKind.SftpRespond, Mutated(14)), FuzzOp.Send(Wire.ChannelClose(0))]),
            ("stray replies", [.. Session(0), new FuzzOp(OpKind.SftpRespond, [0]), new FuzzOp(OpKind.SftpRespond, [3, .. Wire.SftpFrame(SftpMessage.Status, 4000, new FuzzBlob().UInt32(0).String("x").String("en").ToArray())]), new FuzzOp(OpKind.SftpRespond, [3, .. Wire.SftpFrame(SftpMessage.Version, 0, [])]), new FuzzOp(OpKind.SftpRespond, [3, .. Wire.SftpFrame(SftpMessage.Handle, 1, new FuzzBlob().String(new byte[300]).ToArray())]), FuzzOp.Send(Wire.ChannelClose(0))]),
            ("hostile version", [.. ClientWith(0, FuzzOp.App(2), FuzzOp.Await(MessageNumber.ChannelOpen), FuzzOp.Send(Wire.ChannelOpenConfirmation(0, 100)), FuzzOp.Await(MessageNumber.ChannelRequest), FuzzOp.Send(Wire.ChannelSuccess(0)), FuzzOp.Await(MessageNumber.ChannelData)), FuzzOp.Data(0, new FuzzBlob().UInt32((uint)(1 + Wire.SftpVersionBody(("a", "b"), ("limits@openssh.com", "1")).Length)).Byte(SftpMessage.Version).Raw(Wire.SftpVersionBody(("a", "b"), ("limits@openssh.com", "1"))).ToArray()), FuzzOp.Send(Wire.ChannelClose(0))]),
        ];
    }

    // Rekey and order.

    /// <summary>The pool of the rekey targets: what the others have, and messages injected into the peer's key exchange, and rekeys from the SUT's side.</summary>
    private static IReadOnlyList<FuzzOp> RekeyPool(IReadOnlyList<FuzzOp> pool) =>
    [
        .. pool,
        FuzzOp.Inject(0, Wire.ChannelOpen("session", 100)),
        FuzzOp.Inject(0, Wire.KeepAlive()),
        FuzzOp.Inject(1, Wire.ChannelData(0, new byte[100])),
        FuzzOp.Inject(2, Wire.Exec(0, "injected")),
        FuzzOp.Inject(3, Wire.WindowAdjust(0, 10)),
        FuzzOp.Inject(0, Wire.ChannelOpen("forwarded-tcpip", 120, Wire.ForwardedTcpExtra("127.0.0.1", 2200))),
        FuzzOp.Inject(0, Wire.AuthSuccess()),
        FuzzOp.Inject(0, Wire.ServiceRequest()),
        FuzzOp.Inject(1, Wire.Ignore("kex")),
        FuzzOp.Inject(2, Wire.Debug("kex")),
        FuzzOp.Inject(0, Wire.KexInit(SshRole.Client)),
        FuzzOp.Inject(1, Wire.KexNewKeys()),
        FuzzOp.Inject(2, Wire.KexEcdhInit(KexPoint)),
        FuzzOp.Canary(0),
        FuzzOp.Canary(1),
        FuzzOp.Canary(2),
        FuzzOp.Of(OpKind.SutRekey),
        FuzzOp.Of(OpKind.SutRekey),
    ];

    private static IReadOnlyList<(string, List<FuzzOp>)> ServerRekeySeeds()
    {
        List<FuzzOp> With(params FuzzOp[] rest) => [.. ServerLogin(), .. rest];
        FuzzOp[] Session() => [FuzzOp.Send(Wire.ChannelOpen("session", 100)), FuzzOp.Await(MessageNumber.ChannelOpenConfirmation), FuzzOp.Send(Wire.Exec(0, "run")), FuzzOp.Await(MessageNumber.ChannelSuccess)];
        return
        [
            ("rekey between data", With([.. Session(), FuzzOp.Data(0, new byte[2000]), FuzzOp.Of(OpKind.Rekey), FuzzOp.Data(0, new byte[2000]), FuzzOp.Of(OpKind.Rekey), FuzzOp.Send(Wire.ChannelEof(0)), FuzzOp.Send(Wire.ChannelClose(0)), FuzzOp.Await(MessageNumber.ChannelClose)])),
            ("kex messages after the exchange", With(FuzzOp.Of(OpKind.Rekey), FuzzOp.Send(Wire.Ignore()), FuzzOp.Send(Wire.KexNewKeys()), FuzzOp.Send(Wire.KexEcdhInit(KexPoint)), FuzzOp.Send(Wire.KexInit(SshRole.Client)), FuzzOp.Send(Wire.KexEcdhReply([1], [2], [3])))),
            ("rekey with channels open", With([.. Session(), FuzzOp.Send(Wire.ChannelOpen("session", 101)), FuzzOp.Of(OpKind.Rekey), FuzzOp.Send(Wire.WindowAdjust(0, 1000)), FuzzOp.Send(Wire.ChannelOpen("direct-tcpip", 102, Wire.DirectTcpExtra("127.0.0.1", (uint)SharedSink.Port))), FuzzOp.Of(OpKind.Rekey), FuzzOp.Send(Wire.KeepAlive()), FuzzOp.Await(MessageNumber.RequestFailure)])),
            ("replayed login and service", With(FuzzOp.Of(OpKind.Rekey), FuzzOp.Send(Wire.ServiceRequest()), FuzzOp.Send(Wire.AuthPassword(Wire.Secret)), FuzzOp.Send(Wire.ExtInfo(("server-sig-algs", "ssh-ed25519"))))),
            ("injected behind the peer's KEXINIT", With([.. Session(), FuzzOp.Of(OpKind.Rekey), FuzzOp.Inject(0, Wire.ChannelOpen("session", 100)), FuzzOp.Inject(0, Wire.Ignore("kex")), FuzzOp.Inject(2, Wire.KeepAlive()), FuzzOp.Inject(4, Wire.ChannelData(0, new byte[50])), FuzzOp.Send(Wire.KeepAlive())])),
            ("canary: a channel open during the peer's exchange", With(FuzzOp.Canary(0), FuzzOp.Canary(1))),
            ("kex messages injected in the exchange", With(FuzzOp.Of(OpKind.Rekey), FuzzOp.Inject(0, Wire.KexInit(SshRole.Client)), FuzzOp.Inject(1, Wire.KexNewKeys()), FuzzOp.Inject(0, Wire.KexEcdhInit(KexPoint)), FuzzOp.Inject(3, Wire.Debug("kex")), FuzzOp.Inject(0, Wire.ServiceRequest()), FuzzOp.Inject(0, Wire.AuthSuccess()))),
            ("the SUT rekeys, and its replies park", With([.. Session(), FuzzOp.Of(OpKind.SutRekey), FuzzOp.Send(Wire.KeepAlive()), FuzzOp.Send(Wire.KeepAlive()), FuzzOp.Send(Wire.ChannelOpen("session", 101)), FuzzOp.Data(0, new byte[500]), FuzzOp.Send(Wire.KeepAlive()), FuzzOp.Await(MessageNumber.RequestFailure), FuzzOp.Send(Wire.ChannelClose(0))])),
            ("the SUT rekeys and the peer injects", With([.. Session(), FuzzOp.Of(OpKind.SutRekey), FuzzOp.Inject(0, Wire.KeepAlive()), FuzzOp.Inject(5, Wire.ChannelOpen("session", 102)), FuzzOp.Send(Wire.KeepAlive()), FuzzOp.Await(MessageNumber.RequestFailure)])),
            ("out of order connection", With(FuzzOp.Send(Wire.ChannelClose(0)), FuzzOp.Send(Wire.ChannelData(0, [1])), FuzzOp.Send(Wire.ChannelOpen("session", 100)), FuzzOp.Send(Wire.ChannelOpen("session", 100)), FuzzOp.Send(Wire.ChannelEof(0)), FuzzOp.Send(Wire.ChannelData(0, [1])), FuzzOp.Send(Wire.ChannelClose(0)), FuzzOp.Send(Wire.ChannelClose(0)))),
        ];
    }

    private static IReadOnlyList<(string, List<FuzzOp>)> ClientRekeySeeds()
    {
        FuzzOp[] Exec() => [FuzzOp.App(0), FuzzOp.Await(MessageNumber.ChannelOpen), FuzzOp.Send(Wire.ChannelOpenConfirmation(0, 100)), FuzzOp.Await(MessageNumber.ChannelRequest), FuzzOp.Send(Wire.ChannelSuccess(0))];
        return
        [
            ("rekey between data", ClientWith(0, [.. Exec(), FuzzOp.Send(Wire.ChannelData(0, new byte[2000])), FuzzOp.Of(OpKind.Rekey), FuzzOp.Send(Wire.ChannelData(0, new byte[2000])), FuzzOp.Of(OpKind.Rekey), FuzzOp.Send(Wire.ExitStatus(0, 0)), FuzzOp.Send(Wire.ChannelEof(0)), FuzzOp.Send(Wire.ChannelClose(0)), FuzzOp.Await(MessageNumber.ChannelClose)])),
            ("kex messages after the exchange", ClientWith(1, FuzzOp.Of(OpKind.Rekey), FuzzOp.Send(Wire.Ignore()), FuzzOp.Send(Wire.KexNewKeys()), FuzzOp.Send(Wire.KexEcdhReply([1], [2], [3])), FuzzOp.Send(Wire.KexInit(SshRole.Server)), FuzzOp.Send(Wire.KexEcdhInit(KexPoint)))),
            ("rekey with channels open", ClientWith(0, [.. Exec(), FuzzOp.App(3), FuzzOp.Of(OpKind.Rekey), FuzzOp.Await(MessageNumber.GlobalRequest), FuzzOp.Send(Wire.RequestSuccessPort(2200)), FuzzOp.Of(OpKind.Rekey), FuzzOp.Send(Wire.ChannelOpen("forwarded-tcpip", 101, Wire.ForwardedTcpExtra("127.0.0.1", 2200))), FuzzOp.Send(Wire.ChannelClose(0))])),
            ("injected behind the peer's KEXINIT", ClientWith(0, [.. Exec(), FuzzOp.Of(OpKind.Rekey), FuzzOp.Inject(0, Wire.ChannelOpen("forwarded-tcpip", 120, Wire.ForwardedTcpExtra("127.0.0.1", 2200))), FuzzOp.Inject(0, Wire.GlobalRequest("hostkeys-00@openssh.com", true)), FuzzOp.Inject(2, Wire.ChannelData(0, new byte[50])), FuzzOp.Inject(3, Wire.Ignore("kex")), FuzzOp.Send(Wire.ExitStatus(0, 0))])),
            ("canary: a channel open during the peer's exchange", ClientWith(1, FuzzOp.Canary(0), FuzzOp.Canary(2))),
            ("kex messages injected in the exchange", ClientWith(2, FuzzOp.Of(OpKind.Rekey), FuzzOp.Inject(0, Wire.KexInit(SshRole.Server)), FuzzOp.Inject(1, Wire.KexNewKeys()), FuzzOp.Inject(0, Wire.KexEcdhReply([1], [2], [3])), FuzzOp.Inject(3, Wire.Debug("kex")), FuzzOp.Inject(0, Wire.ServiceAccept()), FuzzOp.Inject(0, Wire.AuthSuccess()))),
            ("the SUT rekeys, and its traffic parks", ClientWith(0, [.. Exec(), FuzzOp.Of(OpKind.SutRekey), FuzzOp.App(7), FuzzOp.Send(Wire.GlobalRequest("hostkeys-00@openssh.com", true)), FuzzOp.Send(Wire.ChannelData(0, new byte[500])), FuzzOp.Send(Wire.GlobalRequest("keepalive@openssh.com", true)), FuzzOp.Await(MessageNumber.ChannelOpen)])),
            ("the SUT rekeys and the peer injects", ClientWith(1, [.. Exec(), FuzzOp.Of(OpKind.SutRekey), FuzzOp.Inject(0, Wire.GlobalRequest("keepalive@openssh.com", true)), FuzzOp.Inject(5, Wire.ChannelOpen("session", 102)), FuzzOp.Send(Wire.GlobalRequest("keepalive@openssh.com", true))])),
            ("replayed login", ClientWith(2, FuzzOp.Of(OpKind.Rekey), FuzzOp.Send(Wire.ServiceAccept()), FuzzOp.Send(Wire.AuthSuccess()), FuzzOp.Send(Wire.ExtInfo(("server-sig-algs", "ssh-ed25519"))), FuzzOp.Send(Wire.AuthBanner("late")))),
        ];
    }

    // The rekey targets also use these: SSH_MSG numbers in the key exchange range, to the SUT in every state.
    internal static IReadOnlyList<byte> KexNumbers { get; } = [20, 21, 30, 31, 32, 33, 34, 49];
}

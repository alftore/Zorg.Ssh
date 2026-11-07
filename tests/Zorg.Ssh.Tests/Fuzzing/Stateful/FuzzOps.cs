using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Transport;

namespace Zorg.Ssh.Tests.Fuzzing.Stateful;

/// <summary>What the scripted peer does at one step of a stateful fuzz input.</summary>
internal enum OpKind : byte
{
    /// <summary>Sends the body as one SSH payload, encrypted with the real session keys.</summary>
    Send = 1,

    /// <summary>Sends channel data. Body: flags (1 = swap the SFTP handle marker, 2 = extended data), channel id (4), bytes.</summary>
    Data = 2,

    /// <summary>Sends a publickey userauth request. The body is the request without its signature, and the peer signs it with the session id.</summary>
    SignedAuth = 3,

    /// <summary>Waits a moment for the SUT to send the message number in the first byte.</summary>
    Await = 4,

    /// <summary>Answers the next SFTP request the SUT sent on its channel. Body: response type (1), then the response body. Type 2 answers INIT.</summary>
    SftpRespond = 5,

    /// <summary>Starts a key exchange from the peer's side.</summary>
    Rekey = 6,

    /// <summary>Starts an application action on the SUT client, by the number in the first byte.</summary>
    App = 7,

    /// <summary>Lets other threads run for a moment.</summary>
    Pause = 8,

    /// <summary>Closes the stream abruptly.</summary>
    Disconnect = 9,
}

/// <summary>One step. A whole input is a header byte and a list of these.</summary>
internal readonly record struct FuzzOp(OpKind Kind, byte[] Body)
{
    public static FuzzOp Send(byte[] payload) => new(OpKind.Send, payload);

    public static FuzzOp Await(byte number) => new(OpKind.Await, [number]);

    public static FuzzOp Of(OpKind kind) => new(kind, []);

    public static FuzzOp App(byte action) => new(OpKind.App, [action]);

    public static FuzzOp Data(uint channel, byte[] bytes, bool swapHandles = false, bool extended = false)
    {
        byte[] body = new byte[5 + bytes.Length];
        body[0] = (byte)((swapHandles ? 1 : 0) | (extended ? 2 : 0));
        BinaryPrimitives.WriteUInt32BigEndian(body.AsSpan(1), channel);
        bytes.CopyTo(body, 5);
        return new FuzzOp(OpKind.Data, body);
    }
}

/// <summary>The serialised form of an input: the variant byte, then for each op its kind, a 16-bit length and the body.</summary>
internal static class FuzzOpCodec
{
    public const int MaxOps = 600;
    public const int MaxBody = 60000;

    public static byte[] Encode(byte variant, IReadOnlyList<FuzzOp> ops)
    {
        List<byte> bytes = [variant];
        foreach (FuzzOp op in ops)
        {
            int length = Math.Min(op.Body.Length, MaxBody);
            bytes.Add((byte)op.Kind);
            bytes.Add((byte)(length >> 8));
            bytes.Add((byte)length);
            bytes.AddRange(op.Body.AsSpan(0, length).ToArray());
        }

        return [.. bytes];
    }

    /// <summary>Writes the ops of an input as text, so that a finding can be read without decoding base64.</summary>
    public static string Describe(byte[] input)
    {
        (byte variant, List<FuzzOp> ops) = Decode(input);
        StringBuilder text = new();
        text.Append("variant ").Append(variant).AppendLine();
        for (int i = 0; i < ops.Count; i++)
        {
            FuzzOp op = ops[i];
            string detail = op.Kind switch
            {
                OpKind.Send or OpKind.SignedAuth => op.Body.Length == 0 ? "(empty)" : StatefulLimits.Name(op.Body[0]) + " " + Hex(op.Body, 56),
                OpKind.Data => op.Body.Length < 5 ? "(short)" : $"channel {BinaryPrimitives.ReadUInt32BigEndian(op.Body.AsSpan(1))} flags {op.Body[0]} {op.Body.Length - 5} bytes {Hex(op.Body.AsSpan(5).ToArray(), 24)}",
                OpKind.Await => op.Body.Length == 0 ? string.Empty : StatefulLimits.Name(op.Body[0]),
                _ => Hex(op.Body, 24),
            };
            text.Append("  ").Append(i).Append(' ').Append(op.Kind).Append(' ').AppendLine(detail);
        }

        return text.ToString();
    }

    private static string Hex(byte[] bytes, int max) => Convert.ToHexString(bytes.AsSpan(0, Math.Min(max, bytes.Length))) + (bytes.Length > max ? "..." : string.Empty) + $" ({bytes.Length} bytes)";

    public static (byte Variant, List<FuzzOp> Ops) Decode(byte[] input)
    {
        List<FuzzOp> ops = [];
        if (input.Length == 0)
        {
            return (0, ops);
        }

        int at = 1;
        while (at + 3 <= input.Length && ops.Count < MaxOps)
        {
            OpKind kind = (OpKind)input[at];
            int length = (input[at + 1] << 8) | input[at + 2];
            at += 3;
            if (length > input.Length - at)
            {
                length = input.Length - at;
            }

            ops.Add(new FuzzOp(kind, input.AsSpan(at, length).ToArray()));
            at += length;
        }

        return (input[0], ops);
    }
}

/// <summary>Builds the SSH messages the scripted peer sends. Every one is well formed until the mutator touches it.</summary>
internal static class Wire
{
    public const string UserName = "fuzzer";

    /// <summary>The password the scripted peer logs in with. It must never reach a log or an exception message.</summary>
    public const string Secret = "Zorg-fuzz-S3cret-pw-7Q4x!";

    public const uint PeerWindow = 2 * 1024 * 1024;
    public const uint PeerMaxPacket = 32768;

    public static byte[] ServiceRequest(string service = "ssh-userauth") => new FuzzBlob().Byte(MessageNumber.ServiceRequest).String(service).ToArray();

    public static byte[] ServiceAccept(string service = "ssh-userauth") => new FuzzBlob().Byte(MessageNumber.ServiceAccept).String(service).ToArray();

    public static byte[] AuthNone(string user = UserName) => AuthHead(user, "ssh-connection", "none").ToArray();

    public static byte[] AuthPassword(string password, string user = UserName) =>
        AuthHead(user, "ssh-connection", "password").Bool(false).String(password).ToArray();

    public static byte[] AuthPasswordChange(string oldPassword, string newPassword, string user = UserName) =>
        AuthHead(user, "ssh-connection", "password").Bool(true).String(oldPassword).String(newPassword).ToArray();

    public static byte[] AuthKeyboardInteractive(string user = UserName) =>
        AuthHead(user, "ssh-connection", "keyboard-interactive").String(string.Empty).String(string.Empty).ToArray();

    /// <summary>A publickey request without a signature, as a query. <paramref name="signed"/> sets the boolean for a request the peer will sign.</summary>
    public static byte[] AuthPublicKey(string algorithm, byte[] blob, bool signed, string user = UserName) =>
        AuthHead(user, "ssh-connection", "publickey").Bool(signed).String(algorithm).String(blob).ToArray();

    public static byte[] AuthInfoResponse(params string[] answers)
    {
        FuzzBlob blob = new FuzzBlob().Byte(61).UInt32((uint)answers.Length);
        foreach (string answer in answers)
        {
            blob.String(answer);
        }

        return blob.ToArray();
    }

    public static byte[] AuthSuccess() => [MessageNumber.UserAuthSuccess];

    public static byte[] AuthFailure(bool partial = false, params string[] methods) =>
        new FuzzBlob().Byte(MessageNumber.UserAuthFailure).NameList(methods).Bool(partial).ToArray();

    public static byte[] AuthBanner(string text) => new FuzzBlob().Byte(MessageNumber.UserAuthBanner).String(text).String(string.Empty).ToArray();

    public static byte[] AuthPublicKeyOk(string algorithm, byte[] blob) => new FuzzBlob().Byte(60).String(algorithm).String(blob).ToArray();

    public static byte[] AuthInfoRequest(string name, string instruction, params (string Prompt, bool Echo)[] prompts)
    {
        FuzzBlob blob = new FuzzBlob().Byte(60).String(name).String(instruction).String(string.Empty).UInt32((uint)prompts.Length);
        foreach ((string prompt, bool echo) in prompts)
        {
            blob.String(prompt).Bool(echo);
        }

        return blob.ToArray();
    }

    public static byte[] ExtInfo(params (string Name, string Value)[] extensions)
    {
        FuzzBlob blob = new FuzzBlob().Byte(MessageNumber.ExtInfo).UInt32((uint)extensions.Length);
        foreach ((string name, string value) in extensions)
        {
            blob.String(name).String(value);
        }

        return blob.ToArray();
    }

    public static byte[] ChannelOpen(string type, uint senderChannel, byte[]? extra = null) =>
        new FuzzBlob().Byte(MessageNumber.ChannelOpen).String(type).UInt32(senderChannel).UInt32(PeerWindow).UInt32(PeerMaxPacket).Raw(extra ?? []).ToArray();

    public static byte[] ChannelOpenWithLimits(string type, uint senderChannel, uint window, uint maxPacket, byte[]? extra = null) =>
        new FuzzBlob().Byte(MessageNumber.ChannelOpen).String(type).UInt32(senderChannel).UInt32(window).UInt32(maxPacket).Raw(extra ?? []).ToArray();

    public static byte[] DirectTcpExtra(string host, uint port) => new FuzzBlob().String(host).UInt32(port).String("127.0.0.1").UInt32(40000).ToArray();

    public static byte[] ForwardedTcpExtra(string address, uint port) => new FuzzBlob().String(address).UInt32(port).String("203.0.113.7").UInt32(51000).ToArray();

    public static byte[] ChannelOpenConfirmation(uint recipient, uint sender) =>
        new FuzzBlob().Byte(MessageNumber.ChannelOpenConfirmation).UInt32(recipient).UInt32(sender).UInt32(PeerWindow).UInt32(PeerMaxPacket).ToArray();

    public static byte[] ChannelOpenFailure(uint recipient, uint reason, string text = "no") =>
        new FuzzBlob().Byte(MessageNumber.ChannelOpenFailure).UInt32(recipient).UInt32(reason).String(text).String(string.Empty).ToArray();

    public static byte[] WindowAdjust(uint recipient, uint bytes) => new FuzzBlob().Byte(MessageNumber.ChannelWindowAdjust).UInt32(recipient).UInt32(bytes).ToArray();

    public static byte[] ChannelData(uint recipient, byte[] data) => new FuzzBlob().Byte(MessageNumber.ChannelData).UInt32(recipient).String(data).ToArray();

    public static byte[] ChannelExtendedData(uint recipient, uint type, byte[] data) =>
        new FuzzBlob().Byte(MessageNumber.ChannelExtendedData).UInt32(recipient).UInt32(type).String(data).ToArray();

    public static byte[] ChannelEof(uint recipient) => new FuzzBlob().Byte(MessageNumber.ChannelEof).UInt32(recipient).ToArray();

    public static byte[] ChannelClose(uint recipient) => new FuzzBlob().Byte(MessageNumber.ChannelClose).UInt32(recipient).ToArray();

    public static byte[] ChannelSuccess(uint recipient) => new FuzzBlob().Byte(MessageNumber.ChannelSuccess).UInt32(recipient).ToArray();

    public static byte[] ChannelFailure(uint recipient) => new FuzzBlob().Byte(MessageNumber.ChannelFailure).UInt32(recipient).ToArray();

    public static byte[] ChannelRequest(uint recipient, string type, bool wantReply, byte[]? data = null) =>
        new FuzzBlob().Byte(MessageNumber.ChannelRequest).UInt32(recipient).String(type).Bool(wantReply).Raw(data ?? []).ToArray();

    public static byte[] Exec(uint recipient, string command, bool wantReply = true) => ChannelRequest(recipient, "exec", wantReply, new FuzzBlob().String(command).ToArray());

    public static byte[] Subsystem(uint recipient, string name, bool wantReply = true) => ChannelRequest(recipient, "subsystem", wantReply, new FuzzBlob().String(name).ToArray());

    public static byte[] Shell(uint recipient, bool wantReply = true) => ChannelRequest(recipient, "shell", wantReply);

    public static byte[] Env(uint recipient, string name, string value, bool wantReply = false) =>
        ChannelRequest(recipient, "env", wantReply, new FuzzBlob().String(name).String(value).ToArray());

    public static byte[] PtyRequest(uint recipient, bool wantReply = true) =>
        ChannelRequest(recipient, "pty-req", wantReply, new FuzzBlob().String("xterm").UInt32(80).UInt32(24).UInt32(0).UInt32(0).String([0]).ToArray());

    public static byte[] WindowChange(uint recipient) => ChannelRequest(recipient, "window-change", false, new FuzzBlob().UInt32(100).UInt32(30).UInt32(0).UInt32(0).ToArray());

    public static byte[] ExitStatus(uint recipient, uint status) => ChannelRequest(recipient, "exit-status", false, new FuzzBlob().UInt32(status).ToArray());

    public static byte[] ExitSignal(uint recipient, string signal) =>
        ChannelRequest(recipient, "exit-signal", false, new FuzzBlob().String(signal).Bool(false).String("died").String(string.Empty).ToArray());

    public static byte[] GlobalRequest(string name, bool wantReply, byte[]? data = null) =>
        new FuzzBlob().Byte(MessageNumber.GlobalRequest).String(name).Bool(wantReply).Raw(data ?? []).ToArray();

    public static byte[] TcpIpForward(string address, uint port, bool wantReply = true) =>
        GlobalRequest("tcpip-forward", wantReply, new FuzzBlob().String(address).UInt32(port).ToArray());

    public static byte[] CancelTcpIpForward(string address, uint port, bool wantReply = true) =>
        GlobalRequest("cancel-tcpip-forward", wantReply, new FuzzBlob().String(address).UInt32(port).ToArray());

    public static byte[] KeepAlive(bool wantReply = true) => GlobalRequest("keepalive@openssh.com", wantReply);

    public static byte[] RequestSuccess(params byte[] data) => [MessageNumber.RequestSuccess, .. data];

    public static byte[] RequestSuccessPort(uint port) => new FuzzBlob().Byte(MessageNumber.RequestSuccess).UInt32(port).ToArray();

    public static byte[] RequestFailure() => [MessageNumber.RequestFailure];

    public static byte[] Ignore(string text = "x") => new FuzzBlob().Byte(MessageNumber.Ignore).String(text).ToArray();

    public static byte[] Debug(string text = "x") => new FuzzBlob().Byte(MessageNumber.Debug).Bool(false).String(text).String(string.Empty).ToArray();

    public static byte[] Unimplemented(uint sequence) => new FuzzBlob().Byte(MessageNumber.Unimplemented).UInt32(sequence).ToArray();

    public static byte[] Disconnect(uint reason = 11) => new FuzzBlob().Byte(MessageNumber.Disconnect).UInt32(reason).String("bye").String(string.Empty).ToArray();

    /// <summary>A message number nothing uses. A live connection answers it with UNIMPLEMENTED, which is what makes it a barrier.</summary>
    public const byte BarrierNumber = 250;

    public static byte[] Barrier() => [BarrierNumber];

    // KEX messages, for the rekey and out-of-order targets.

    public static byte[] KexInit(SshRole role) => RawPeerKexInit(role);

    public static byte[] KexNewKeys() => [MessageNumber.NewKeys];

    public static byte[] KexEcdhInit(byte[] publicKey) => new FuzzBlob().Byte(MessageNumber.KexEcdhInit).String(publicKey).ToArray();

    public static byte[] KexEcdhReply(byte[] hostKey, byte[] publicKey, byte[] signature) =>
        new FuzzBlob().Byte(MessageNumber.KexEcdhReply).String(hostKey).String(publicKey).String(signature).ToArray();

    // SFTP, version 3.

    public static byte[] SftpFrame(byte type, uint id, byte[] body) => new FuzzBlob().UInt32((uint)(5 + body.Length)).Byte(type).UInt32(id).Raw(body).ToArray();

    public static byte[] SftpInit() => new FuzzBlob().UInt32(5).Byte(1).UInt32(3).ToArray();

    public static byte[] SftpVersionBody(params (string Name, string Value)[] extensions)
    {
        FuzzBlob blob = new FuzzBlob().UInt32(3);
        foreach ((string name, string value) in extensions)
        {
            blob.String(name).String(value);
        }

        return blob.ToArray();
    }

    public static string Printable(ReadOnlySpan<byte> bytes) => Encoding.ASCII.GetString(bytes);

    private static FuzzBlob AuthHead(string user, string service, string method) =>
        new FuzzBlob().Byte(MessageNumber.UserAuthRequest).String(user).String(service).String(method);

    private static byte[] RawPeerKexInit(SshRole role) => Transport.RawPeer.KexInitPayload(role, strict: true);
}

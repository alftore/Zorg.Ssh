using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipelines;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Zorg.Ssh.Agent;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Sftp;

namespace Zorg.Ssh.AotSmoke;

/// <summary>
/// A real client and server over an in-memory pipe: key exchange, password login, a command, an SFTP round trip,
/// then the agent protocol and <c>ssh_config</c> parsing. Everything on the connection path is reflection-free only
/// if it works when published, so this runs there.
/// </summary>
internal static class ConnectionSmoke
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(60);

    public static async Task<bool> RunAsync(Action<string, bool> check)
    {
        using CancellationTokenSource timeout = new(Limit);
        CancellationToken ct = timeout.Token;
        string root = Directory.CreateTempSubdirectory("zorg-aot-smoke-").FullName;
        try
        {
            using SshHostKey hostKey = SshHostKey.GenerateEd25519();
            await using SshServer server = await SshServer.StartAsync(
                new SshServerOptions
                {
                    HostKeys = [hostKey],
                    PasswordHandler = static (request, _) => ValueTask.FromResult(
                        request.Password == "smoke-password" ? SshAuthDecision.Accept : SshAuthDecision.Reject),
                    SessionHandler = (session, token) => HandleAsync(session, root, token),
                },
                ct);

            (Stream clientSide, Stream serverSide) = Duplex.CreatePair();
            Task serving = server.ServeStreamAsync(serverSide, ct);
            await using (SshClient client = await SshClient.ConnectOverStreamAsync(
                clientSide,
                new SshClientOptions
                {
                    Host = "smoke",
                    UserName = "smoke",
                    HostKeyPolicy = HostKeyPolicy.Fingerprint(hostKey.Sha256Fingerprint),
                    Credentials = [SshCredential.FromPassword("smoke-password")],
                },
                ct))
            {
                SshCommandResult result = await client.ExecuteAsync("echo hello", ct);
                check("connection exec", result.ExitCode == 7 && result.StandardOutput == "ran: echo hello\n");

                await using SftpClient sftp = await client.OpenSftpAsync(ct);
                byte[] contents = Encoding.ASCII.GetBytes("sftp round trip");
                await sftp.WriteAllBytesAsync("/smoke.txt", contents, ct);
                byte[] back = await sftp.ReadAllBytesAsync("/smoke.txt", ct);
                check("connection sftp", back.AsSpan().SequenceEqual(contents) && File.Exists(Path.Combine(root, "smoke.txt")));
            }

            await serving.WaitAsync(ct);
            await AgentAsync(check, ct);
            ConfigSmoke(check);
            return true;
        }
        catch (Exception ex) when (ex is SshException or IOException or OperationCanceledException or TimeoutException)
        {
            check($"connection smoke threw {ex.GetType().Name}: {ex.Message}", false);
            return false;
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static async Task<int> HandleAsync(SshServerSession session, string root, CancellationToken ct)
    {
        if (session is { Kind: SshSessionKind.Subsystem, Command: "sftp" })
        {
            return await SftpServer.ServeAsync(session, new SftpServerOptions { RootDirectory = root }, ct);
        }

        await session.Output.WriteAsync(Encoding.ASCII.GetBytes($"ran: {session.Command}\n"), ct);
        return 7;
    }

    private static async Task AgentAsync(Action<string, bool> check, CancellationToken ct)
    {
        using SshPrivateKey key = SshPrivateKey.GenerateEd25519();
        await using SshAgentConnection agent = new(new MiniAgent(key), TimeSpan.FromSeconds(10));
        IReadOnlyList<SshAgentIdentity> identities = await agent.ListIdentitiesAsync(ct);
        check("agent lists a key", identities.Count == 1 && identities[0].Blob.AsSpan().SequenceEqual(key.PublicKey.Blob.Span));

        byte[] data = Encoding.ASCII.GetBytes("agent signs this");
        byte[]? signature = await agent.SignAsync(identities[0].Blob, data, 0, ct);
        check("agent signature verifies", signature is not null && identities[0].Key.Verify("ssh-ed25519", data, signature));
    }

    private static void ConfigSmoke(Action<string, bool> check)
    {
        SshConfig config = SshConfig.Parse("Host web\n  HostName web.example.com\n  Port 2222\n  User deploy\n  IdentityFile ~/.ssh/id_web\n");
        SshHostConfig web = config.Resolve("web");
        check("ssh_config parse", web.HostName == "web.example.com" && web.Port == 2222 && web.User == "deploy" && web.IdentityFiles.Count == 1);

        // First value wins, and a wildcard block fills in what the specific one left out.
        SshConfig layered = SshConfig.Parse("Host web\n  Port 2200\nHost *\n  Port 22\n  User fallback\n");
        SshHostConfig layeredWeb = layered.Resolve("web");
        check("ssh_config precedence", layeredWeb.Port == 2200 && layeredWeb.User == "fallback" && layered.Resolve("other").Port == 22);
    }

    /// <summary>One pipe each way, so a client and a server can talk without a socket.</summary>
    private sealed class Duplex(Stream read, Stream write) : Stream
    {
        public static (Stream A, Stream B) CreatePair()
        {
            Pipe toServer = new();
            Pipe toClient = new();
            return (
                new Duplex(toClient.Reader.AsStream(), toServer.Writer.AsStream()),
                new Duplex(toServer.Reader.AsStream(), toClient.Writer.AsStream()));
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

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => read.ReadAsync(buffer, cancellationToken);

        public override void Write(byte[] buffer, int offset, int count) => write.Write(buffer, offset, count);

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) => write.WriteAsync(buffer, cancellationToken);

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                write.Dispose();
                read.Dispose();
            }

            base.Dispose(disposing);
        }
    }

    /// <summary>An agent holding one key. It answers list and sign requests, and refuses the rest.</summary>
    private sealed class MiniAgent(SshPrivateKey key) : Stream
    {
        private readonly Queue<byte[]> _replies = new();
        private readonly List<byte> _received = [];
        private byte[] _current = [];
        private int _position;

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

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
                _replies.Enqueue(Respond(request));
            }

            return ValueTask.CompletedTask;
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_position == _current.Length)
            {
                if (!_replies.TryDequeue(out byte[]? next))
                {
                    return ValueTask.FromResult(0);
                }

                _current = next;
                _position = 0;
            }

            int count = Math.Min(buffer.Length, _current.Length - _position);
            _current.AsMemory(_position, count).CopyTo(buffer);
            _position += count;
            return ValueTask.FromResult(count);
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        private static byte[] Frame(params byte[][] parts)
        {
            byte[] body = [.. parts.SelectMany(static p => p)];
            byte[] frame = new byte[4 + body.Length];
            BinaryPrimitives.WriteUInt32BigEndian(frame, (uint)body.Length);
            body.CopyTo(frame, 4);
            return frame;
        }

        private static byte[] UInt32(uint value)
        {
            byte[] bytes = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
            return bytes;
        }

        private static byte[] String(byte[] value) => [.. UInt32((uint)value.Length), .. value];

        private byte[] Respond(byte[] request)
        {
            switch (request[0])
            {
                case 11:
                    return Frame([12], UInt32(1), String(key.PublicKey.Blob.ToArray()), String("smoke"u8.ToArray()));
                case 13:
                    SshReader reader = new(request);
                    reader.ReadByte();
                    reader.ReadBinary();
                    byte[] data = reader.ReadBinary().ToArray();
                    return Frame([14], String(key.Sign("ssh-ed25519", data)));
                default:
                    return Frame([5]);
            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Zorg.Ssh.Auth;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Tests.Transport;
using Zorg.Ssh.Transport;

namespace Zorg.Ssh.Tests.Forwarding;

/// <summary>A TCP service on loopback, standing in for whatever a forward leads to.</summary>
internal sealed class TcpService : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _stop = new();
    private readonly List<Task> _connections = [];
    private readonly Task _loop;
    private int _accepted;

    public TcpService(Func<NetworkStream, CancellationToken, Task> handler)
    {
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _loop = Task.Run(() => AcceptAsync(handler));
    }

    public int Port { get; }

    public int Accepted => Volatile.Read(ref _accepted);

    public static TcpService Echo() => new(static async (stream, ct) =>
    {
        byte[] buffer = new byte[32 * 1024];
        while (true)
        {
            int read = await stream.ReadAsync(buffer, ct);
            if (read == 0)
            {
                return;
            }

            await stream.WriteAsync(buffer.AsMemory(0, read), ct);
        }
    });

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync();
        _listener.Stop();
        await _loop;
        Task[] connections;
        lock (_connections)
        {
            connections = [.. _connections];
        }

        await Task.WhenAll(connections);
        _listener.Dispose();
        _stop.Dispose();
    }

    private async Task AcceptAsync(Func<NetworkStream, CancellationToken, Task> handler)
    {
        while (true)
        {
            Socket socket;
            try
            {
                socket = await _listener.AcceptSocketAsync(_stop.Token);
            }
            catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException or InvalidOperationException)
            {
                return;
            }

            Interlocked.Increment(ref _accepted);
            Task connection = Task.Run(() => ServeAsync(socket, handler));
            lock (_connections)
            {
                _connections.Add(connection);
            }
        }
    }

    private async Task ServeAsync(Socket socket, Func<NetworkStream, CancellationToken, Task> handler)
    {
        using NetworkStream stream = new(socket, ownsSocket: true);
        try
        {
            await handler(stream, _stop.Token);
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or SocketException)
        {
            // The far end went, which many of these tests do on purpose.
        }
    }
}

/// <summary>
/// A server that does real key exchange and auth, then does only what the test script says. It's how a test
/// plays a server that lies. The connection layer here is the script, so nothing filters what it sends.
/// </summary>
internal sealed class ScriptedServer : IAsyncDisposable
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(20);

    private readonly SshTransport _transport;
    private readonly Channel<byte[]> _received = Channel.CreateUnbounded<byte[]>();
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _loop;

    private ScriptedServer(SshTransport transport)
    {
        _transport = transport;
        _loop = Task.Run(ReadAsync);
    }

    public static async Task<(ScriptedServer Server, SshClient Client)> ConnectAsync(CancellationToken cancellationToken, int maxForwarded = 64)
    {
        (Stream clientSide, Stream serverSide) = DuplexStream.CreatePair();
        Task<SshTransport> serving = Task.Run(
            async () =>
            {
                SshTransport transport = await SshTransport.StartAsync(serverSide, TransportHarness.ServerOptions(), cancellationToken);
                ServerAuthOptions auth = new() { Password = static (_, _, _) => ValueTask.FromResult(AuthDecision.Accept) };
                await new ServerAuthenticator(transport, auth).AuthenticateAsync(cancellationToken);
                return transport;
            },
            cancellationToken);

        SshClient client = await SshClient.ConnectOverStreamAsync(
            clientSide,
            new SshClientOptions
            {
                Host = "scripted",
                UserName = "alice",
                Credentials = [SshCredential.FromPassword("pw")],
                HostKeyPolicy = HostKeyPolicy.AcceptAnyUnsafe(),
                MaxForwardedConnections = maxForwarded,
            },
            cancellationToken);
        return (new ScriptedServer(await serving), client);
    }

    /// <summary>Gets or sets whether cancel-tcpip-forward is answered without the script, so closing a client takes no time.</summary>
    public bool AnswerCancels { get; set; } = true;

    public static byte[] Message(Action<SshRequestWriter> build)
    {
        SshRequestWriter writer = new();
        build(writer);
        return writer.ToArray();
    }

    public static byte[] ForwardedOpen(uint senderChannel, string address, int port) => Message(w =>
    {
        w.Byte(MessageNumber.ChannelOpen);
        w.String("forwarded-tcpip");
        w.UInt32(senderChannel);
        w.UInt32(1024 * 1024);
        w.UInt32(32 * 1024);
        w.String(address);
        w.UInt32((uint)port);
        w.String("203.0.113.9");
        w.UInt32(50000);
    });

    public async Task SendAsync(byte[] message, CancellationToken cancellationToken) =>
        await _transport.SendAsync(message, cancellationToken);

    /// <summary>Returns the next message from the client.</summary>
    public async Task<byte[]> NextAsync(CancellationToken cancellationToken) =>
        await _received.Reader.ReadAsync(cancellationToken).AsTask().WaitAsync(Limit, cancellationToken);

    /// <summary>Waits for the next message with this number, passing over the others.</summary>
    public async Task<byte[]> ExpectAsync(byte number, CancellationToken cancellationToken)
    {
        while (true)
        {
            byte[] message = await NextAsync(cancellationToken);
            if (message[0] == number)
            {
                return message;
            }
        }
    }

    /// <summary>
    /// Asks the client something it must answer. Messages are handled in order, so the answer proves it has
    /// taken in everything sent before, and that its receive loop is alive.
    /// </summary>
    public async Task PingAsync(CancellationToken cancellationToken)
    {
        await SendAsync(
            Message(static w =>
            {
                w.Byte(MessageNumber.GlobalRequest);
                w.String("ping@zorg");
                w.Bool(true);
            }),
            cancellationToken);
        await ExpectAsync(MessageNumber.RequestFailure, cancellationToken);
    }

    /// <summary>Reads an open's reply: the reason it was refused, or null if it was confirmed.</summary>
    public async Task<(uint? Refusal, uint ClientChannel)> OpenReplyAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            byte[] message = await NextAsync(cancellationToken);
            SshReader reader = new(message);
            byte number = reader.ReadByte();
            reader.ReadUInt32();
            if (number == MessageNumber.ChannelOpenFailure)
            {
                return (reader.ReadUInt32(), 0);
            }

            if (number == MessageNumber.ChannelOpenConfirmation)
            {
                return (null, reader.ReadUInt32());
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync();
        await _transport.CloseAsync();
        await _loop;
        await _transport.DisposeAsync();
        _stop.Dispose();
    }

    private static bool IsForwardCancel(ReadOnlySpan<byte> message)
    {
        if (message[0] != MessageNumber.GlobalRequest)
        {
            return false;
        }

        SshReader reader = new(message);
        reader.ReadByte();
        return reader.ReadUtf8String() == "cancel-tcpip-forward";
    }

    private async Task ReadAsync()
    {
        try
        {
            while (true)
            {
                ReadOnlyMemory<byte> message = await _transport.ReceiveAsync(_stop.Token);
                bool cancel = AnswerCancels && IsForwardCancel(message.Span);
                _received.Writer.TryWrite(message.ToArray());
                if (cancel)
                {
                    await _transport.SendAsync(new[] { MessageNumber.RequestSuccess }, _stop.Token);
                }
            }
        }
        catch (Exception ex) when (ex is SshException or OperationCanceledException)
        {
            _received.Writer.TryComplete();
        }
    }
}

/// <summary>The client side of SOCKS5, written out by hand so a test can get it wrong on purpose.</summary>
internal static class Socks
{
    public static byte[] DomainRequest(string host, int port, byte command = 1)
    {
        byte[] name = System.Text.Encoding.ASCII.GetBytes(host);
        byte[] request = new byte[7 + name.Length];
        request[0] = 5;
        request[1] = command;
        request[3] = 3;
        request[4] = (byte)name.Length;
        name.CopyTo(request, 5);
        request[^2] = (byte)(port >> 8);
        request[^1] = (byte)port;
        return request;
    }

    public static byte[] IPv4Request(IPAddress address, int port)
    {
        byte[] request = new byte[10];
        request[0] = 5;
        request[1] = 1;
        request[3] = 1;
        address.GetAddressBytes().CopyTo(request, 4);
        request[8] = (byte)(port >> 8);
        request[9] = (byte)port;
        return request;
    }

    /// <summary>Connects and does the greeting.</summary>
    public static async Task<TcpClient> GreetAsync(IPEndPoint proxy, CancellationToken cancellationToken)
    {
        TcpClient client = new();
        await client.ConnectAsync(proxy, cancellationToken);
        NetworkStream stream = client.GetStream();
        await stream.WriteAsync(new byte[] { 5, 1, 0 }, cancellationToken);
        byte[] answer = new byte[2];
        await stream.ReadExactlyAsync(answer, cancellationToken);
        return answer is [5, 0] ? client : throw new InvalidOperationException("The proxy refused the greeting.");
    }

    /// <summary>Sends a request and returns the reply code.</summary>
    public static async Task<byte> RequestAsync(TcpClient client, byte[] request, CancellationToken cancellationToken)
    {
        NetworkStream stream = client.GetStream();
        await stream.WriteAsync(request, cancellationToken);
        byte[] reply = new byte[10];
        await stream.ReadExactlyAsync(reply, cancellationToken);
        return reply[1];
    }
}

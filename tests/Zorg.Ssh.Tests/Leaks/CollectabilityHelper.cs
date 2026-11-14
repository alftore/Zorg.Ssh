using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Sftp;

namespace Zorg.Ssh.Tests.Leaks;

/// <summary>
/// The objects a scenario made, held weakly. A scenario is a separate method that runs everything and returns only this, so that
/// no local of the test, and no local the compiler kept alive in a Debug build, points at what the test checks.
/// </summary>
internal sealed class Tracked
{
    private readonly Lock _lock = new();
    private readonly List<(string Name, WeakReference Reference)> _items = [];

    public T Add<T>(string name, T value)
        where T : class
    {
        lock (_lock)
        {
            _items.Add((name, new WeakReference(value)));
        }

        return value;
    }

    /// <summary>Forces collections until every object is dead, or fails naming the ones still alive.</summary>
    public async Task AssertAllCollectedAsync(CancellationToken cancellationToken)
    {
        (string Name, WeakReference Reference)[] items;
        lock (_lock)
        {
            items = [.. _items];
        }

        Assert.NotEmpty(items);
        string[] alive = [];
        for (int attempt = 0; attempt < 20; attempt++)
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
            alive = [.. items.Where(static item => item.Reference.IsAlive).Select(static item => item.Name)];
            if (alive.Length == 0)
            {
                return;
            }

            // Loops that end on a cancelled token, or a completed close, need a moment to unwind before the last reference goes.
            await Task.Delay(50, cancellationToken);
        }

        Assert.Fail($"Disposed, but still reachable after forced collections: {string.Join(", ", alive)}");
    }
}

/// <summary>A server on loopback with a session handler that does what the scenarios ask of it.</summary>
internal sealed class LeakRig : IAsyncDisposable
{
    private readonly SshHostKey _hostKey = SshHostKey.GenerateEd25519();
    private readonly string _root = Path.Combine(Path.GetTempPath(), "zorg-leak-" + Guid.NewGuid().ToString("N"));
    private readonly Tracked? _sessions;
    private SshServer? _server;

    private LeakRig(Tracked? sessions)
    {
        _sessions = sessions;
        Directory.CreateDirectory(_root);
    }

    public SshServer Server => _server!;

    public string Fingerprint => _hostKey.Sha256Fingerprint;

    /// <summary>Starts a server. Each session the handler is given is added to <paramref name="sessions"/>. A direct-tcpip request is allowed when <paramref name="allow"/> says so.</summary>
    public static async Task<LeakRig> StartAsync(Tracked? sessions, CancellationToken cancellationToken, Func<SshDirectTcpRequest, bool>? allow = null)
    {
        LeakRig rig = new(sessions);
        rig._server = await SshServer.StartAsync(
            new SshServerOptions
            {
                HostKeys = [rig._hostKey],
                PasswordHandler = static (request, _) => ValueTask.FromResult(request.Password == "pw" ? SshAuthDecision.Accept : SshAuthDecision.Reject),
                SessionHandler = rig.HandleAsync,
                DirectTcpHandler = (request, _) => ValueTask.FromResult(allow?.Invoke(request) == true ? SshForwardDecision.Allow : SshForwardDecision.Deny),
                LoginGraceTime = TimeSpan.FromSeconds(30),
            },
            cancellationToken);
        return rig;
    }

    public SshClientOptions ClientOptions(string password = "pw", string? fingerprint = null, int? port = null) => new()
    {
        Host = "127.0.0.1",
        Port = port ?? Server.LocalEndPoint.Port,
        UserName = "alice",
        Credentials = [SshCredential.FromPassword(password)],
        HostKeyPolicy = HostKeyPolicy.Fingerprint(fingerprint ?? _hostKey.Sha256Fingerprint),
    };

    public async ValueTask DisposeAsync()
    {
        if (_server is not null)
        {
            await _server.DisposeAsync();
        }

        _hostKey.Dispose();
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
            // A leftover temp directory is not worth failing a test for.
        }
    }

    private async Task<int> HandleAsync(SshServerSession session, CancellationToken cancellationToken)
    {
        _sessions?.Add("server session", session);
        if (session is { Kind: SshSessionKind.Subsystem, Command: "sftp" })
        {
            return await SftpServer.ServeAsync(session, new SftpServerOptions { RootDirectory = _root }, cancellationToken);
        }

        if (session.Command == "cat")
        {
            await session.Input.CopyToAsync(session.Output, cancellationToken);
            return 0;
        }

        if (session.Command == "hang")
        {
            await Task.Delay(Timeout.Infinite, cancellationToken);
        }

        await session.Output.WriteAsync("hello"u8.ToArray(), cancellationToken);
        return 0;
    }
}

/// <summary>A TCP relay on loopback, so that a test can cut a connection with a reset or put bytes of its own into it.</summary>
internal sealed class Relay : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _stop = new();
    private readonly TaskCompletionSource<Socket> _client = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Task _loop;
    private readonly int _target;

    public Relay(int targetPort)
    {
        _target = targetPort;
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _loop = Task.Run(RunAsync);
    }

    public int Port { get; }

    /// <summary>Resets the client's connection, as a peer that crashed or a middlebox would.</summary>
    public async Task CutAsync(CancellationToken cancellationToken)
    {
        Socket client = await _client.Task.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken);
        client.LingerState = new LingerOption(enable: true, 0);
        await _stop.CancelAsync();
        client.Close();
    }

    /// <summary>Sends bytes of the test's own to the client, in the place of the server's.</summary>
    public async Task InjectToClientAsync(byte[] bytes, CancellationToken cancellationToken)
    {
        Socket client = await _client.Task.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken);
        await client.SendAsync(bytes, cancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync();
        _listener.Stop();
        await _loop;
        _listener.Dispose();
        _stop.Dispose();
    }

    private async Task RunAsync()
    {
        try
        {
            using Socket client = await _listener.AcceptSocketAsync(_stop.Token);
            using Socket server = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            await server.ConnectAsync(new IPEndPoint(IPAddress.Loopback, _target), _stop.Token);
            _client.TrySetResult(client);
            await Task.WhenAll(PumpAsync(client, server), PumpAsync(server, client));
        }
        catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException or IOException)
        {
            _client.TrySetCanceled();
        }
    }

    private async Task PumpAsync(Socket from, Socket to)
    {
        byte[] buffer = new byte[16 * 1024];
        try
        {
            while (true)
            {
                int read = await from.ReceiveAsync(buffer, _stop.Token);
                if (read == 0)
                {
                    break;
                }

                await to.SendAsync(buffer.AsMemory(0, read), _stop.Token);
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException or IOException)
        {
            // Cut, which is the point.
        }
    }
}

#pragma warning disable CA1031 // The rigs catch everything on purpose: what escapes the SUT is judged by the oracles.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Zorg.Ssh.Connection;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Sftp;
using Zorg.Ssh.Tests.Transport;

namespace Zorg.Ssh.Tests.Fuzzing.Stateful;

/// <summary>Limits of the stateful targets, and the one table of message names for the reports.</summary>
/// <summary>Adds up where the time of the stateful inputs goes, for the report.</summary>
internal static class StatefulTimings
{
    private static readonly Dictionary<string, (double Total, long Count)> Sums = [];

    public static void Add(string part, double milliseconds)
    {
        lock (Sums)
        {
            (double total, long count) = Sums.GetValueOrDefault(part);
            Sums[part] = (total + milliseconds, count + 1);
        }
    }

    public static string Summary()
    {
        lock (Sums)
        {
            return string.Join(", ", Sums.OrderBy(s => s.Key, StringComparer.Ordinal).Select(s => string.Create(CultureInfo.InvariantCulture, $"{s.Key} {s.Value.Total / s.Value.Count:F1} ms")));
        }
    }
}

internal static class StatefulLimits
{
    /// <summary>How long everything gets to end after the peer has vanished. A correct library needs milliseconds; this is for a loaded machine.</summary>
    public static readonly TimeSpan EndLimit = TimeSpan.FromSeconds(8);

    /// <summary>The wall time a whole input may take, more than the oracle waits add up to. The runner's own watchdog uses it.</summary>
    public static readonly TimeSpan InputLimit = TimeSpan.FromSeconds(45);

    /// <summary>
    /// How long the peer waits for a message it expects from the SUT before it goes on. A reply that is expected comes in well under a
    /// millisecond, so this only matters when a mutation removed the cause. A long run has every target busy at once, so it waits longer.
    /// </summary>
    public static TimeSpan AwaitLimit { get; } = FuzzSettings.LongRun is null ? TimeSpan.FromMilliseconds(60) : TimeSpan.FromMilliseconds(250);

    /// <summary>Gets how long one input may spend in all its waits for expected messages together.</summary>
    public static TimeSpan AwaitBudget { get; } = FuzzSettings.LongRun is null ? TimeSpan.FromMilliseconds(250) : TimeSpan.FromMilliseconds(1000);

    public static readonly SshAlgorithms FastAlgorithms = new() { KeyExchange = ["curve25519-sha256"] };

    private static readonly Dictionary<byte, string> Names = new()
    {
        [1] = "DISCONNECT",
        [2] = "IGNORE",
        [3] = "UNIMPLEMENTED",
        [4] = "DEBUG",
        [5] = "SERVICE_REQUEST",
        [6] = "SERVICE_ACCEPT",
        [7] = "EXT_INFO",
        [20] = "KEXINIT",
        [21] = "NEWKEYS",
        [30] = "KEX_ECDH_INIT",
        [31] = "KEX_ECDH_REPLY",
        [50] = "USERAUTH_REQUEST",
        [51] = "USERAUTH_FAILURE",
        [52] = "USERAUTH_SUCCESS",
        [53] = "USERAUTH_BANNER",
        [60] = "USERAUTH_60",
        [61] = "USERAUTH_61",
        [80] = "GLOBAL_REQUEST",
        [81] = "REQUEST_SUCCESS",
        [82] = "REQUEST_FAILURE",
        [90] = "CHANNEL_OPEN",
        [91] = "CHANNEL_OPEN_CONFIRMATION",
        [92] = "CHANNEL_OPEN_FAILURE",
        [93] = "CHANNEL_WINDOW_ADJUST",
        [94] = "CHANNEL_DATA",
        [95] = "CHANNEL_EXTENDED_DATA",
        [96] = "CHANNEL_EOF",
        [97] = "CHANNEL_CLOSE",
        [98] = "CHANNEL_REQUEST",
        [99] = "CHANNEL_SUCCESS",
        [100] = "CHANNEL_FAILURE",
    };

    public static string Name(byte number) => Names.TryGetValue(number, out string? name) ? $"{name}({number})" : $"unknown({number})";
}

/// <summary>A loopback listener that takes connections and reads them to the end. It is where an allowed forward goes.</summary>
internal sealed class SinkListener : IDisposable
{
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _loop;

    public SinkListener(int port = 0)
    {
        _listener = new TcpListener(IPAddress.Loopback, port);
        _listener.Start();
        _loop = Task.Run(AcceptAsync);
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    public void Dispose()
    {
        _stop.Cancel();
        _listener.Stop();
        _listener.Dispose();
        try
        {
            _loop.Wait(TimeSpan.FromSeconds(2));
        }
        catch (AggregateException)
        {
            // The loop ends with the listener.
        }

        _stop.Dispose();
    }

    private async Task AcceptAsync()
    {
        while (!_stop.IsCancellationRequested)
        {
            try
            {
                Socket socket = await _listener.AcceptSocketAsync(_stop.Token).ConfigureAwait(false);
                _ = Task.Run(() => DrainAsync(socket));
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                return;
            }
        }
    }

    private async Task DrainAsync(Socket socket)
    {
        using (socket)
        {
            byte[] buffer = new byte[4096];
            try
            {
                while (await socket.ReceiveAsync(buffer, _stop.Token).ConfigureAwait(false) > 0)
                {
                }
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                // The connection ended.
            }
        }
    }
}

/// <summary>What counts as an input that got deep, for the share of accepted inputs a target reports.</summary>
internal enum Depth
{
    /// <summary>The service was accepted and the SUT answered a login attempt.</summary>
    Login,

    /// <summary>The SUT logged the peer in, or the peer logged the SUT in.</summary>
    Authenticated,

    /// <summary>Logged in, and a channel was opened and confirmed.</summary>
    Channel,

    /// <summary>Logged in, and a second key exchange completed.</summary>
    Rekeyed,
}

/// <summary>One sink for the whole process, on a port every corpus knows, so a direct-tcpip open in a seed can name it.</summary>
internal static class SharedSink
{
    private static readonly Lazy<(SinkListener Sink, int Port)> Instance = new(() =>
    {
        TcpListener probe = new(IPAddress.Loopback, 0);
        probe.Start();
        int port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();
        return (new SinkListener(port), port);
    });

    public static int Port => Instance.Value.Port;
}

/// <summary>How an input ended, for the evidence of each target.</summary>
internal sealed class StatefulNotes
{
    private readonly List<string> _stages = [];

    /// <summary>Gets why the input was refused, if it was.</summary>
    public string? Refusal { get; private set; }

    /// <summary>Gets how long each part of the input took.</summary>
    public Dictionary<string, double> Milliseconds { get; } = [];

    /// <summary>Hands the notes to the runner. The runner reads them from the thread it started the input on, which the awaits above have left.</summary>
    public void Flush()
    {
        foreach (string stage in _stages)
        {
            FuzzNotes.Reached(stage);
        }

        if (Refusal is not null)
        {
            FuzzNotes.Refused(Refusal);
        }

        foreach (KeyValuePair<string, double> time in Milliseconds)
        {
            StatefulTimings.Add(time.Key, time.Value);
        }
    }

    public void Refuse(string reason) => Refusal = reason;

    public void Reached(string stage) => _stages.Add(stage);

    /// <summary>Reports what the peer saw of the SUT, and which of the peer's messages the SUT handled.</summary>
    public void Record(StatefulPeer peer, bool survived)
    {
        foreach (PeerMessage message in peer.Snapshot())
        {
            Reached("SUT sent " + StatefulLimits.Name(message.Number));
        }

        if (survived)
        {
            // The SUT dispatched everything the peer had sent before the probe, in order, and went on reading.
            foreach (KeyValuePair<byte, int> sent in peer.SentCounts)
            {
                Reached("handled " + StatefulLimits.Name(sent.Key));
            }

            Reached("connection survived the whole input");
        }

        if (peer.Transport.CompletedKeyExchanges >= 2)
        {
            Reached("phase: second key exchange completed");
        }
    }

    public static string Describe(StatefulPeer peer)
    {
        StringBuilder text = new();
        text.Append(CultureInfo.InvariantCulture, $"peer received {peer.ReceivedCount} messages ({string.Join(", ", peer.Snapshot().Select(m => StatefulLimits.Name(m.Number)).Take(24))}); peer ended by: ");
        text.Append(peer.EndedBy is null ? "(still connected)" : peer.EndedBy.GetType().Name + ": " + peer.EndedBy.Message);
        return text.ToString();
    }
}

/// <summary>The SSH server under test, with handlers that record what they were asked, so that a breach of guarantee 1 or 2 cannot go unseen.</summary>
internal sealed class ServerRig : IDisposable
{
    private readonly List<SshServer> _servers = [];
    private readonly Lock _inputGate = new();
    private int _sessionCalls;
    private int _directTcpCalls;
    private int _passwordCalls;
    private int _passwordAccepted;
    private int _publicKeyCalls;
    private SshConnection? _connection;
    private string _root = string.Empty;
    private int _inputs;

    public ServerRig(bool preAuth, Depth depth = Depth.Channel)
    {
        PreAuth = preAuth;
        Depth = depth;
        Logs = new CaptureLoggerFactory();
        _servers.Add(Start(variant: 0));
        if (preAuth)
        {
            _servers.Add(Start(variant: 1));
        }
    }

    public bool PreAuth { get; }

    public Depth Depth { get; }

    public CaptureLoggerFactory Logs { get; }

    public int SessionCalls => Volatile.Read(ref _sessionCalls);

    public int DirectTcpCalls => Volatile.Read(ref _directTcpCalls);

    public int PasswordCalls => Volatile.Read(ref _passwordCalls);

    public int PasswordAccepted => Volatile.Read(ref _passwordAccepted);

    public int SinkPort => SharedSink.Port;

    public SshConnection? Connection => Volatile.Read(ref _connection);

    public void Dispose()
    {
        foreach (SshServer server in _servers)
        {
            server.DisposeAsync().AsTask().Wait(TimeSpan.FromSeconds(15));
        }
    }

    /// <summary>Runs one input against a server. The caller blocks until it is judged.</summary>
    public FuzzOutcome Run(byte[] input, bool sftp)
    {
        lock (_inputGate)
        {
            StatefulNotes notes = new();
            try
            {
                return StatefulFindings.Run(input, () => RunAsync(input, sftp, notes).GetAwaiter().GetResult());
            }
            finally
            {
                notes.Flush();
            }
        }
    }

    private static string FingerprintOfPeerKey() => HostKeyPolicy.ComputeFingerprint(FuzzSecrets.PeerKey.PublicKey.Blob.Span);

    private SshServer Start(int variant)
    {
        SshServerOptions options = new()
        {
            Address = IPAddress.Loopback,
            Port = 0,
            HostKeys = [new SshHostKey(TransportHarness.HostKey)],
            Algorithms = StatefulLimits.FastAlgorithms,
            LoginGraceTime = TimeSpan.FromSeconds(20),
            ShutdownTimeout = TimeSpan.FromSeconds(10),
            LoggerFactory = Logs,
            Banner = PreAuth ? "Authorised use only" : null,
            MaxAuthAttempts = PreAuth ? 4 : 6,
            ConnectionStarted = connection => Volatile.Write(ref _connection, connection),
            PasswordHandler = PasswordAsync,
            PublicKeyHandler = (request, ct) => PublicKeyAsync(request, acceptKey: variant == 1),
            SessionHandler = SessionAsync,
            DirectTcpHandler = DirectTcpAsync,
            RequiredAuthMethods = PreAuth && variant == 1 ? ["password", "publickey"] : null,
        };
        return SshServer.StartAsync(options).GetAwaiter().GetResult();
    }

    private ValueTask<SshAuthDecision> PasswordAsync(SshPasswordRequest request, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _passwordCalls);

        // Before auth the handler always refuses, so nothing that follows can be reached without breaking guarantee 2. After it, only the real password passes.
        if (!PreAuth && request.UserName == Wire.UserName && request.Password == Wire.Secret)
        {
            Interlocked.Increment(ref _passwordAccepted);
            return ValueTask.FromResult(SshAuthDecision.Accept);
        }

        return ValueTask.FromResult(SshAuthDecision.Reject);
    }

    private ValueTask<SshAuthDecision> PublicKeyAsync(SshPublicKeyRequest request, bool acceptKey)
    {
        Interlocked.Increment(ref _publicKeyCalls);

        // In the second pre-auth rig the key is accepted but a password is required too, which the password handler never gives: the key
        // path runs to the end (query, signature, partial success) and the login still cannot finish. In the first rig every key is refused.
        // After login the peer's key is accepted, as an ordinary user's would be.
        bool matches = request.Sha256Fingerprint == FingerprintOfPeerKey() && request.UserName == Wire.UserName;
        return ValueTask.FromResult((acceptKey || !PreAuth) && matches ? SshAuthDecision.Accept : SshAuthDecision.Reject);
    }

    private ValueTask<SshForwardDecision> DirectTcpAsync(SshDirectTcpRequest request, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _directTcpCalls);
        return ValueTask.FromResult(!PreAuth && request.Host == "127.0.0.1" && request.Port == SharedSink.Port ? SshForwardDecision.Allow : SshForwardDecision.Deny);
    }

    private async Task<int> SessionAsync(SshServerSession session, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _sessionCalls);
        if (PreAuth)
        {
            return 1;
        }

        try
        {
            if (session.Kind == SshSessionKind.Subsystem && session.Command == "sftp")
            {
                return await SftpServer.ServeAsync(session, new SftpServerOptions { RootDirectory = _root, MaxOpenHandles = 8 }, cancellationToken).ConfigureAwait(false);
            }

            if (session.Kind is SshSessionKind.Exec or SshSessionKind.Shell)
            {
                byte[] buffer = new byte[4096];
                long total = 0;
                while (total < (1 << 20))
                {
                    int read = await session.Input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                    if (read == 0)
                    {
                        break;
                    }

                    total += read;
                }

                await session.Output.WriteAsync("ok\n"u8.ToArray(), cancellationToken).ConfigureAwait(false);
                await session.Error.WriteAsync("warn\n"u8.ToArray(), cancellationToken).ConfigureAwait(false);
                return 0;
            }

            return 1;
        }
        catch (Exception ex) when (ex is SshException or IOException or OperationCanceledException or ObjectDisposedException)
        {
            return 1;
        }
    }

    private async Task<FuzzOutcome> RunAsync(byte[] input, bool sftp, StatefulNotes notes)
    {
        Stopwatch watch = Stopwatch.StartNew();
        (byte variant, List<FuzzOp> ops) = FuzzOpCodec.Decode(input);
        SshServer server = _servers[PreAuth ? variant & 1 : 0];
        int sessionsBefore = SessionCalls;
        int directBefore = DirectTcpCalls;
        int acceptedBefore = PasswordAccepted;
        Logs.Clear();
        Volatile.Write(ref _connection, null);
        using SftpFuzzRoot? root = sftp ? new SftpFuzzRoot() : null;
        _root = root?.Root ?? string.Empty;
        _inputs++;

        (Stream peerStream, Stream sutStream) = DuplexStream.CreatePair();
        Task serve = server.ServeStreamAsync(sutStream);
        StatefulPeer? peer = null;
        SequenceExecutor? executor = null;
        bool survived = false;
        string? memory = null;
        try
        {
            using CancellationTokenSource handshake = new(TimeSpan.FromSeconds(20));
            try
            {
                peer = await StatefulPeer.StartAsync(peerStream, TransportHarness.ClientOptions(kex: ["curve25519-sha256"]), handshake.Token).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                throw new StatefulFindingException("Harness", "The unfuzzed key exchange with the SUT failed, which is a bug in the setup or the library: " + ex.GetType().Name + ": " + ex.Message);
            }

            notes.Milliseconds["handshake"] = watch.Elapsed.TotalMilliseconds;
            watch.Restart();
            executor = new SequenceExecutor(peer, app: null);
            await executor.RunAsync(ops).ConfigureAwait(false);
            survived = await executor.BarrierAsync().ConfigureAwait(false);
            if (survived)
            {
                memory = CheckBounds(Connection, 10);
            }

            notes.Record(peer, survived);
            notes.Milliseconds["ops and barrier"] = watch.Elapsed.TotalMilliseconds;
            watch.Restart();
        }
        finally
        {
            peer?.Vanish();
        }

        // The peer has gone. Everything on the SUT's side must now end by itself: no token is passed.
        string? hang = null;
        Exception? serveFailure = null;
        try
        {
            await serve.WaitAsync(StatefulLimits.EndLimit).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            hang = $"ServeStreamAsync did not complete within {StatefulLimits.EndLimit.TotalSeconds:0} s of the peer vanishing. The connection task, a handler or a pending call is stuck. {StatefulNotes.Describe(peer!)}";
        }
        catch (Exception ex)
        {
            serveFailure = ex;
        }

        if (executor is not null)
        {
            await executor.StopAsync().ConfigureAwait(false);
        }

        string? peerEnd = peer?.EndedBy?.Message;
        string description = StatefulNotes.Describe(peer!);
        bool authenticated = peer!.Snapshot().Any(m => m.Number == MessageNumber.UserAuthSuccess);
        bool confirmed = peer.Snapshot().Any(m => m.Number == MessageNumber.ChannelOpenConfirmation);
        bool failed = peer.Snapshot().Any(m => m.Number == MessageNumber.UserAuthFailure);
        bool rekeyed = peer.Transport.CompletedKeyExchanges >= 2;
        bool sawService = peer.Snapshot().Any(m => m.Number == MessageNumber.ServiceAccept);
        string[] logs = Logs.Entries;
        Exception[] logged = Logs.Exceptions;
        List<PeerMessage> received = peer.Snapshot();
        await peer.DisposeAsync().ConfigureAwait(false);

        // The verdicts, most serious first.
        if (PreAuth)
        {
            if (SessionCalls != sessionsBefore || DirectTcpCalls != directBefore)
            {
                throw new StatefulFindingException("GUARANTEE 2 BREACH", $"A handler ran before the user logged in: session handler calls {SessionCalls - sessionsBefore}, direct-tcpip handler calls {DirectTcpCalls - directBefore}. The password handler refuses everything. {description}");
            }

            if (authenticated || PasswordAccepted != acceptedBefore)
            {
                throw new StatefulFindingException("GUARANTEE 2 BREACH", $"The SUT sent USERAUTH_SUCCESS although no handler said yes to a complete login. {description}");
            }
        }

        if (peerEnd is not null && peerEnd.Contains("isn't allowed in this state", StringComparison.Ordinal))
        {
            throw new StatefulFindingException("GUARANTEE 1", $"The SUT sent a message that the message policy forbids in the state it was in: {peerEnd} {description}");
        }

        if (peer.SendStalled)
        {
            throw new StatefulFindingException("Hang", $"A send waited more than {StatefulPeer.SendStallLimit.TotalSeconds:0} s: the SUT stopped reading from the connection. {description}");
        }

        if (hang is not null)
        {
            throw new StatefulFindingException("Hang", hang);
        }

        if (serveFailure is not null)
        {
            throw new StatefulFindingException("Exception", $"ServeStreamAsync failed, and it is documented not to: {serveFailure.GetType().FullName}: {serveFailure.Message}{Environment.NewLine}{serveFailure}");
        }

        foreach (Exception exception in logged)
        {
            if (SutExceptions.Judge(exception) is { } why)
            {
                throw new StatefulFindingException("Exception", $"{why}{Environment.NewLine}{exception}");
            }
        }

        if (FuzzSecrets.Scan().Find(logs.Concat(logged.Select(e => e.ToString())).Concat(received.Select(m => Encoding.Latin1.GetString(m.Payload)))) is { } leak)
        {
            throw new StatefulFindingException("GUARANTEE 4", leak);
        }

        if (memory is not null)
        {
            throw new StatefulFindingException("Memory bound", memory + " " + description);
        }

        if (root is not null)
        {
            root.EnsureNothingEscaped();
        }

        if (_inputs % 20 == 0)
        {
            foreach (Exception unobserved in UnobservedTasks.Drain())
            {
                throw new StatefulFindingException("Unobserved task exception", $"A background task of type {unobserved.Data["task"]} faulted and nobody awaited it (within the last 20 inputs): {unobserved.GetType().FullName}: {unobserved.Message}{Environment.NewLine}{unobserved}");
            }
        }

        notes.Milliseconds["teardown and verdict"] = watch.Elapsed.TotalMilliseconds;
        bool deep = Depth switch
        {
            Depth.Login => sawService && failed,
            Depth.Authenticated => authenticated,
            Depth.Rekeyed => authenticated && rekeyed,
            _ => authenticated && confirmed,
        };
        if (!deep)
        {
            notes.Refuse(PreAuth ? (sawService ? "service accepted, no failure reply" : "refused before the service") : (authenticated ? "logged in, no channel confirmed" : sawService ? "service accepted, not logged in" : "refused before auth"));
        }

        return deep ? FuzzOutcome.Accepted : FuzzOutcome.Rejected;
    }

    /// <summary>Checks the limits of what a connection may hold, on a live connection. Returns what was broken, or null.</summary>
    internal static string? CheckBounds(SshConnection? connection, int maxChannels)
    {
        if (connection is null)
        {
            return null;
        }

        List<string> broken = [];
        if (connection.ChannelCount > maxChannels)
        {
            broken.Add($"{connection.ChannelCount} channels are held, over the limit of {maxChannels}");
        }

        if (connection.IncomingQueued > 16)
        {
            broken.Add($"{connection.IncomingQueued} peer opens wait, over the queue of 16");
        }

        if (connection.OpeningCount > maxChannels)
        {
            broken.Add($"{connection.OpeningCount} outgoing opens wait");
        }

        if (connection.PendingGlobalRequests > 32)
        {
            broken.Add($"{connection.PendingGlobalRequests} global requests wait, over the limit of 32");
        }

        if (connection.DeferredCount > 64)
        {
            broken.Add($"{connection.DeferredCount} deferred sends wait");
        }

        foreach (SshChannel channel in connection.ChannelSnapshot())
        {
            long window = channel.ReceiveWindowRemaining;
            if (window is < 0 or > SshChannel.DefaultWindow)
            {
                broken.Add($"channel {channel.LocalId} has a receive window of {window}, outside 0..{SshChannel.DefaultWindow}");
            }

            if (channel.QueuedRequestCount > 16)
            {
                broken.Add($"channel {channel.LocalId} queues {channel.QueuedRequestCount} requests, over the limit of 16");
            }
        }

        return broken.Count == 0 ? null : "Guarantee 3, memory: " + string.Join("; ", broken) + ".";
    }
}

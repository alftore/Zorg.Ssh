#pragma warning disable CA1031 // The harness catches everything on purpose: what escapes the SUT is judged afterwards.

using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Transport;

namespace Zorg.Ssh.Tests.Fuzzing.Stateful;

/// <summary>One message the SUT sent to the scripted peer.</summary>
internal sealed record PeerMessage(int Index, byte Number, byte[] Payload);

/// <summary>
/// The scripted hostile peer. It is a real <see cref="SshTransport"/> in the other role, so it ran the key exchange itself,
/// knows the session keys and can encrypt any payload the fuzzer wants, MAC and all. Nothing in the library changes for it:
/// the payload goes in through the same <see cref="SshTransport.SendAsync"/> every upper layer uses. It also follows the
/// phases the way a real peer would, so a message the SUT sends in the wrong phase shows up as the peer's own policy refusing it.
/// </summary>
internal sealed class StatefulPeer : IAsyncDisposable
{
    /// <summary>How long a send may wait before the peer calls the SUT stalled. A SUT that reads never lets a send wait this long.</summary>
    public static readonly TimeSpan SendStallLimit = TimeSpan.FromSeconds(8);

    private readonly Lock _gate = new();
    private readonly List<PeerMessage> _received = [];
    private readonly TaskCompletionSource _ended = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Dictionary<byte, int> _sentCounts = [];
    private TaskCompletionSource _arrival = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private Task? _loop;
    private int _sendStalled;

    private StatefulPeer(SshTransport transport, Stream stream)
    {
        Transport = transport;
        Stream = stream;
    }

    public SshTransport Transport { get; }

    public Stream Stream { get; }

    /// <summary>Gets what ended the peer's receive loop. The SUT ended the connection, or sent something the peer's policy refuses.</summary>
    public Exception? EndedBy { get; private set; }

    public Task Ended => _ended.Task;

    public bool HasEnded => _ended.Task.IsCompleted;

    /// <summary>Gets whether a send waited longer than <see cref="SendStallLimit"/>, which means the SUT stopped reading.</summary>
    public bool SendStalled => Volatile.Read(ref _sendStalled) != 0;

    /// <summary>Gets a hook that runs on the receive loop for every message. It must not wait.</summary>
    public Action<PeerMessage>? OnMessage { get; set; }

    public bool SentAuthSuccess { get; private set; }

    public static async Task<StatefulPeer> StartAsync(Stream stream, TransportOptions options, CancellationToken cancellationToken)
    {
        SshTransport transport = await SshTransport.StartAsync(stream, options, cancellationToken).ConfigureAwait(false);
        StatefulPeer peer = new(transport, stream);

        // The transport answers UNIMPLEMENTED itself and never hands it up, so the peer listens for it here. It is delivered like any other message.
        transport.UnimplementedHandler = sequence => peer.Deliver(MessageNumber.Unimplemented, [MessageNumber.Unimplemented, (byte)(sequence >> 24), (byte)(sequence >> 16), (byte)(sequence >> 8), (byte)sequence]);
        peer._loop = Task.Run(peer.ReceiveLoopAsync, CancellationToken.None);
        return peer;
    }

    public IReadOnlyDictionary<byte, int> SentCounts
    {
        get
        {
            lock (_gate)
            {
                return new Dictionary<byte, int>(_sentCounts);
            }
        }
    }

    public int ReceivedCount
    {
        get
        {
            lock (_gate)
            {
                return _received.Count;
            }
        }
    }

    public List<PeerMessage> Snapshot()
    {
        lock (_gate)
        {
            return [.. _received];
        }
    }

    /// <summary>Encrypts and sends one payload. False if the connection is over or the SUT stopped reading.</summary>
    public Task<bool> SendAsync(byte[] payload) => SendTrackedAsync(payload, null);

    /// <summary>Like <see cref="SendAsync"/>, and records the sequence number the packet goes out with, which is how the SUT's UNIMPLEMENTED names it.</summary>
    public async Task<bool> SendTrackedAsync(byte[] payload, SentSequence? sent)
    {
        if (payload.Length == 0 || payload.Length > 32 * 1024 + 4096)
        {
            return false;
        }

        if (payload[0] == MessageNumber.UserAuthSuccess)
        {
            SentAuthSuccess = true;
        }

        if (Transport.Role == SshRole.Server)
        {
            // What a real server does as it logs the client in: the policy of the receive side follows the messages it sends.
            if (payload[0] == MessageNumber.UserAuthSuccess)
            {
                Transport.SetPhase(TransportPhase.Connected);
            }
        }

        try
        {
            using CancellationTokenSource limit = new(SendStallLimit);
            await Transport.SendAsync(payload, limit.Token, sent).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            Volatile.Write(ref _sendStalled, 1);
            return false;
        }
        catch (Exception ex) when (ex is SshException or ObjectDisposedException or IOException or InvalidOperationException)
        {
            return false;
        }

        lock (_gate)
        {
            _sentCounts[payload[0]] = _sentCounts.GetValueOrDefault(payload[0]) + 1;
        }

        return true;
    }

    /// <summary>Waits until a message the predicate likes has arrived after <paramref name="fromIndex"/>, or the connection ends, or the time runs out. Returns its index or -1.</summary>
    public async Task<int> WaitForAsync(int fromIndex, Func<PeerMessage, bool> wanted, TimeSpan limit)
    {
        using CancellationTokenSource timeout = new(limit);
        while (true)
        {
            Task arrival;
            lock (_gate)
            {
                for (int i = fromIndex; i < _received.Count; i++)
                {
                    if (wanted(_received[i]))
                    {
                        return i;
                    }
                }

                arrival = _arrival.Task;
            }

            if (HasEnded)
            {
                return -1;
            }

            try
            {
                await Task.WhenAny(arrival, _ended.Task).WaitAsync(timeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return -1;
            }
        }
    }

    /// <summary>Closes the stream the way a peer that vanishes does: no DISCONNECT, no goodbye.</summary>
    public void Vanish()
    {
        try
        {
            Stream.Dispose();
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
            // Already closed.
        }
    }

    public async ValueTask DisposeAsync()
    {
        Vanish();
        try
        {
            await Transport.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SshException or ObjectDisposedException or IOException)
        {
            // The connection was over already.
        }

        if (_loop is { } loop)
        {
            await Task.WhenAny(loop, Task.Delay(TimeSpan.FromSeconds(5))).ConfigureAwait(false);
        }
    }

    private void Deliver(byte number, byte[] payload)
    {
        PeerMessage message;
        lock (_gate)
        {
            message = new PeerMessage(_received.Count, number, payload);
            _received.Add(message);
        }

        OnMessage?.Invoke(message);
        TaskCompletionSource old;
        lock (_gate)
        {
            old = _arrival;
            _arrival = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        }

        old.TrySetResult();
    }

    private async Task ReceiveLoopAsync()
    {
        try
        {
            while (true)
            {
                ReadOnlyMemory<byte> payload = await Transport.ReceiveAsync(CancellationToken.None).ConfigureAwait(false);
                byte number = payload.Span[0];

                // The peer follows the same phase rules a real one does, so that what the SUT sends is judged by the real policy.
                switch (number)
                {
                    case MessageNumber.ServiceAccept when Transport.Role == SshRole.Client:
                    case MessageNumber.ServiceRequest when Transport.Role == SshRole.Server:
                        Transport.SetPhase(TransportPhase.Auth);
                        break;
                    case MessageNumber.UserAuthSuccess when Transport.Role == SshRole.Client:
                        Transport.SetPhase(TransportPhase.Connected);
                        break;
                }

                Deliver(number, payload.ToArray());
            }
        }
        catch (Exception ex)
        {
            EndedBy = ex;
        }
        finally
        {
            _ended.TrySetResult();
            TaskCompletionSource old;
            lock (_gate)
            {
                old = _arrival;
            }

            old.TrySetResult();
        }
    }
}

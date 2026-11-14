using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Zorg.Ssh.Benchmarks;

/// <summary>Pseudo-random bytes of a known length that remember the SHA-256 of what was read. Read-only, not seekable.</summary>
internal sealed class PatternStream : Stream
{
    private readonly IncrementalHash _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    private ulong _state;
    private long _remaining;
    private byte[]? _result;

    public PatternStream(long length, ulong seed)
    {
        _remaining = length;
        _state = seed | 1;
    }

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    /// <summary>The digest of everything read. Call it once, after the last read.</summary>
    public byte[] Digest() => _result ??= _hash.GetHashAndReset();

    public override int Read(Span<byte> buffer)
    {
        int count = (int)Math.Min(buffer.Length, _remaining);
        Span<byte> target = buffer[..count];
        ulong s = _state;
        for (int i = 0; i < target.Length; i++)
        {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            target[i] = (byte)(s >> 24);
        }

        _state = s;
        _remaining -= count;
        _hash.AppendData(target);
        return count;
    }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
        cancellationToken.IsCancellationRequested ? ValueTask.FromCanceled<int>(cancellationToken) : ValueTask.FromResult(Read(buffer.Span));

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _hash.Dispose();
        }

        base.Dispose(disposing);
    }
}

/// <summary>A write-only stream that keeps the SHA-256 and the length of what it was given.</summary>
internal sealed class HashSinkStream : Stream
{
    private readonly IncrementalHash _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    private byte[]? _result;

    public long Written { get; private set; }

    public override bool CanRead => false;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => Written;

    public override long Position
    {
        get => Written;
        set => throw new NotSupportedException();
    }

    public byte[] Digest() => _result ??= _hash.GetHashAndReset();

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        _hash.AppendData(buffer);
        Written += buffer.Length;
    }

    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return ValueTask.FromCanceled(cancellationToken);
        }

        Write(buffer.Span);
        return ValueTask.CompletedTask;
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override void Flush()
    {
    }

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _hash.Dispose();
        }

        base.Dispose(disposing);
    }
}

/// <summary>
/// A loopback TCP relay for exactly one connection that the harness can kill with a reset, to cut a connection in the
/// middle of a transfer. It listens on 127.0.0.1 only, and disposing it closes everything it opened.
/// </summary>
internal sealed class KillableRelay : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _cts = new();
    private readonly Lock _gate = new();
    private readonly Task _run;
    private TcpClient? _down;
    private TcpClient? _up;
    private bool _killed;

    public KillableRelay(int upstreamPort)
    {
        _listener.Start(1);
        _run = RunAsync(upstreamPort);
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    public void Kill()
    {
        TcpClient?[] sockets;
        lock (_gate)
        {
            if (_killed)
            {
                return;
            }

            _killed = true;
            sockets = [_down, _up];
        }

        _cts.Cancel();
        foreach (TcpClient? socket in sockets)
        {
            Abort(socket);
        }

        _listener.Stop();
    }

    public async ValueTask DisposeAsync()
    {
        Kill();
        await _run;
        _cts.Dispose();
        _listener.Dispose();
        _up?.Dispose();
        _down?.Dispose();
    }

    private static void Abort(TcpClient? socket)
    {
        if (socket is null)
        {
            return;
        }

        try
        {
            // A reset, not a clean close. A client that never connected has no socket yet.
            socket.Client?.LingerState = new LingerOption(true, 0);
        }
        catch (Exception e) when (e is SocketException or ObjectDisposedException or InvalidOperationException)
        {
            // Already closed.
        }

        socket.Dispose();
    }

    private static bool Expected(Exception e) =>
        e is OperationCanceledException or IOException or SocketException or ObjectDisposedException or InvalidOperationException;

    private async Task RunAsync(int upstreamPort)
    {
        try
        {
            TcpClient down = await _listener.AcceptTcpClientAsync(_cts.Token);
            TcpClient up = new();
            lock (_gate)
            {
                if (_killed)
                {
                    down.Dispose();
                    up.Dispose();
                    return;
                }

                _down = down;
                _up = up;
            }

            _listener.Stop();
            await up.ConnectAsync(IPAddress.Loopback, upstreamPort, _cts.Token);
            Task a = Pump(down, up);
            Task b = Pump(up, down);
            await Task.WhenAny(a, b);
            Kill();
            await Task.WhenAll(a, b);
        }
        catch (Exception e) when (Expected(e))
        {
            // The relay is cut on purpose, and a socket error after that is the point.
        }
        finally
        {
            Kill();
        }
    }

    private async Task Pump(TcpClient from, TcpClient to)
    {
        try
        {
            await from.GetStream().CopyToAsync(to.GetStream(), _cts.Token);
        }
        catch (Exception e) when (Expected(e))
        {
            // The other end went away.
        }
    }
}

/// <summary>A loopback echo listener for the port-forward operation. Connections are tracked so that disposing it closes them.</summary>
internal sealed class EchoListener : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _cts = new();
    private readonly ConcurrentDictionary<TcpClient, bool> _open = new();
    private readonly ConcurrentDictionary<Task, bool> _tasks = new();
    private readonly Task _accept;

    public EchoListener()
    {
        _listener.Start(64);
        _accept = AcceptAsync();
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    public int OpenConnections => _open.Count;

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync();
        _listener.Stop();
        foreach (TcpClient client in _open.Keys)
        {
            client.Dispose();
        }

        await _accept;
        await Task.WhenAll(_tasks.Keys);
        _cts.Dispose();
        _listener.Dispose();
    }

    private async Task AcceptAsync()
    {
        try
        {
            while (true)
            {
                TcpClient client = await _listener.AcceptTcpClientAsync(_cts.Token);
                _open[client] = true;
                Task task = EchoAsync(client);
                _tasks[task] = true;
                _ = task.ContinueWith(t => _tasks.TryRemove(t, out _), TaskScheduler.Default);
            }
        }
        catch (Exception e) when (e is OperationCanceledException or SocketException or ObjectDisposedException or InvalidOperationException)
        {
            // Disposed.
        }
    }

    private async Task EchoAsync(TcpClient client)
    {
        try
        {
            NetworkStream stream = client.GetStream();
            await stream.CopyToAsync(stream, _cts.Token);
        }
        catch (Exception e) when (e is OperationCanceledException or IOException or SocketException or ObjectDisposedException or InvalidOperationException)
        {
            // The peer closed or reset.
        }
        finally
        {
            _open.TryRemove(client, out _);
            client.Dispose();
        }
    }
}

/// <summary>Ordinary least squares over (x, y) pairs.</summary>
internal static class Regression
{
    /// <summary>The slope per unit of x, and R squared (0 when y is constant).</summary>
    public static (double Slope, double RSquared) Fit(IReadOnlyList<double> x, IReadOnlyList<double> y)
    {
        int n = x.Count;
        double mx = x.Average();
        double my = y.Average();
        double sxx = 0;
        double sxy = 0;
        double syy = 0;
        for (int i = 0; i < n; i++)
        {
            double dx = x[i] - mx;
            double dy = y[i] - my;
            sxx += dx * dx;
            sxy += dx * dy;
            syy += dy * dy;
        }

        if (sxx == 0)
        {
            return (0, 0);
        }

        double slope = sxy / sxx;
        double r2 = syy == 0 ? 0 : (sxy * sxy) / (sxx * syy);
        return (slope, r2);
    }

    public static string Format(double value) => value.ToString("F1", CultureInfo.InvariantCulture);
}

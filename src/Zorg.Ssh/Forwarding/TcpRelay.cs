using System;
using System.Buffers;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Zorg.Ssh.Connection;

namespace Zorg.Ssh.Forwarding;

/// <summary>
/// Joins a TCP socket to a channel for as long as either has something to say. Each direction has its own
/// loop, and a loop waits only on its own socket and its own channel's window. So a slow connection slows
/// itself and nothing else: its channel window fills, and the peer stops sending on that channel.
/// </summary>
internal static class TcpRelay
{
    private const int BufferSize = 32 * 1024;

    /// <summary>How long a local reader gets to take what's left once the channel has closed.</summary>
    private static readonly TimeSpan DrainTime = TimeSpan.FromSeconds(30);

    /// <summary>Opens a TCP connection, ready for <see cref="RunAsync"/>.</summary>
    public static async Task<Socket> ConnectAsync(string host, int port, CancellationToken cancellationToken)
    {
        Socket socket = new(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(host, port, cancellationToken).ConfigureAwait(false);
            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Runs until both directions have ended, or <paramref name="cancellationToken"/> fires. It owns the socket and
    /// the channel and closes both on every path, so a cancelled relay leaves nothing behind.
    /// </summary>
    public static async Task RunAsync(SshChannel channel, Socket socket, CancellationToken cancellationToken)
    {
        using NetworkStream network = new(socket, ownsSocket: true);
        using CancellationTokenSource upward = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using CancellationTokenSource downward = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        try
        {
            // Nothing reads it, and TCP has no such stream. Dropped data is credited, so it can't eat the window.
            await channel.ErrorOutput.DisposeAsync().ConfigureAwait(false);

#pragma warning disable CA2025 // Both are awaited below, before the sources are disposed.
            Task up = SocketToChannelAsync(network, channel, downward, upward.Token);
            Task down = ChannelToSocketAsync(channel, network, upward, downward.Token);
#pragma warning restore CA2025
            Task both = Task.WhenAll(up, down);

            if (await Task.WhenAny(both, channel.Closed).ConfigureAwait(false) != both)
            {
                // Nothing more can go up. What came down before the close still has to reach the local side.
                await upward.CancelAsync().ConfigureAwait(false);
                downward.CancelAfter(DrainTime);
            }

            await both.ConfigureAwait(false);
        }
        finally
        {
            await channel.DisposeAsync().ConfigureAwait(false);
        }
    }

    private static async Task SocketToChannelAsync(NetworkStream network, SshChannel channel, CancellationTokenSource downward, CancellationToken token)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        try
        {
            while (true)
            {
                int read = await network.ReadAsync(buffer, token).ConfigureAwait(false);
                if (read == 0)
                {
                    await channel.SendEofAsync(token).ConfigureAwait(false);
                    return;
                }

                await channel.WriteAsync(buffer.AsMemory(0, read), token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Told to stop.
        }
        catch (SshException)
        {
            // The channel closed. Data already received can still be on its way down, so that loop carries on.
        }
        catch (IOException)
        {
            // The local side failed, so nothing is left to deliver to.
            await downward.CancelAsync().ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static async Task ChannelToSocketAsync(SshChannel channel, NetworkStream network, CancellationTokenSource upward, CancellationToken token)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        try
        {
            while (true)
            {
                int read = await channel.Output.ReadAsync(buffer, token).ConfigureAwait(false);
                if (read == 0)
                {
                    network.Socket.Shutdown(SocketShutdown.Send);
                    return;
                }

                await network.WriteAsync(buffer.AsMemory(0, read), token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Told to stop, or the local reader took too long after the close.
        }
        catch (Exception ex) when (ex is SshException or IOException or SocketException)
        {
            // Either end has failed, so the other direction has no reason to go on.
            await upward.CancelAsync().ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
}

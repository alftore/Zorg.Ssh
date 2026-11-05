using System;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Zorg.Ssh.Forwarding;

/// <summary>
/// The server side of a SOCKS5 handshake (RFC 1928), for CONNECT with no authentication. Anyone who can reach
/// the port gets to send these bytes, so it reads exact lengths into one fixed buffer, and the caller's token
/// limits the time. It never reads past the request: what follows belongs to the tunnel.
/// </summary>
internal static class SocksHandshake
{
    public const byte ReplySucceeded = 0;
    public const byte ReplyGeneralFailure = 1;
    public const byte ReplyConnectionRefused = 5;
    public const byte ReplyCommandNotSupported = 7;
    public const byte ReplyAddressNotSupported = 8;

    /// <summary>The longest name DNS allows, so anything past this is no host.</summary>
    public const int MaxHostLength = 253;

    private const byte Version = 5;
    private const byte MethodNoAuthentication = 0;
    private const byte MethodNoneAcceptable = 0xFF;
    private const byte CommandConnect = 1;
    private const byte AddressIPv4 = 1;
    private const byte AddressDomain = 3;
    private const byte AddressIPv6 = 4;

    /// <summary>A length byte can say 255, and nothing else in the handshake is longer.</summary>
    private const int BufferSize = 255;

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>
    /// Reads the greeting and the request. Returns the target, or null if the client was refused, in which case
    /// it has already been told. After a target, the caller sends the reply with <see cref="SendReplyAsync"/>.
    /// </summary>
    public static async Task<(string Host, int Port)?> ReadRequestAsync(Stream stream, CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[BufferSize];
        await stream.ReadExactlyAsync(buffer.AsMemory(0, 2), cancellationToken).ConfigureAwait(false);
        if (buffer[0] != Version)
        {
            // SOCKS4 and anything else. There's no reply both sides would understand.
            return null;
        }

        int methods = buffer[1];
        await stream.ReadExactlyAsync(buffer.AsMemory(0, methods), cancellationToken).ConfigureAwait(false);
        if (buffer.AsSpan(0, methods).IndexOf(MethodNoAuthentication) < 0)
        {
            await stream.WriteAsync(new[] { Version, MethodNoneAcceptable }, cancellationToken).ConfigureAwait(false);
            return null;
        }

        await stream.WriteAsync(new[] { Version, MethodNoAuthentication }, cancellationToken).ConfigureAwait(false);

        await stream.ReadExactlyAsync(buffer.AsMemory(0, 4), cancellationToken).ConfigureAwait(false);
        if (buffer[0] != Version)
        {
            return null;
        }

        byte command = buffer[1];
        byte addressType = buffer[3];
        (string Host, int Port)? target = await ReadTargetAsync(stream, addressType, buffer, cancellationToken).ConfigureAwait(false);

        // Checked after the whole request is read, because closing on unread data can lose the reply on its way.
        byte refusal = ChooseRefusal(command, addressType, target is not null);
        if (refusal != ReplySucceeded)
        {
            await SendReplyAsync(stream, refusal, cancellationToken).ConfigureAwait(false);
            return null;
        }

        return target;
    }

    /// <summary>Sends the reply to a request. The bound address means nothing here, so it's all zeros.</summary>
    public static async Task SendReplyAsync(Stream stream, byte reply, CancellationToken cancellationToken)
    {
        byte[] message = [Version, reply, 0, AddressIPv4, 0, 0, 0, 0, 0, 0];
        await stream.WriteAsync(message, cancellationToken).ConfigureAwait(false);
    }

    private static byte ChooseRefusal(byte command, byte addressType, bool validTarget)
    {
        if (addressType is not (AddressIPv4 or AddressDomain or AddressIPv6))
        {
            return ReplyAddressNotSupported;
        }

        if (command != CommandConnect)
        {
            return ReplyCommandNotSupported;
        }

        return validTarget ? ReplySucceeded : ReplyGeneralFailure;
    }

    private static async Task<(string Host, int Port)?> ReadTargetAsync(Stream stream, byte addressType, byte[] buffer, CancellationToken cancellationToken)
    {
        string? host;
        switch (addressType)
        {
            case AddressIPv4:
            case AddressIPv6:
                int size = addressType == AddressIPv4 ? 4 : 16;
                await stream.ReadExactlyAsync(buffer.AsMemory(0, size), cancellationToken).ConfigureAwait(false);
                host = new IPAddress(buffer.AsSpan(0, size)).ToString();
                break;
            case AddressDomain:
                await stream.ReadExactlyAsync(buffer.AsMemory(0, 1), cancellationToken).ConfigureAwait(false);
                int length = buffer[0];
                await stream.ReadExactlyAsync(buffer.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
                host = ParseDomain(buffer.AsSpan(0, length));
                break;
            default:
                // The address has no known length, so there's nothing more to read.
                return null;
        }

        await stream.ReadExactlyAsync(buffer.AsMemory(0, 2), cancellationToken).ConfigureAwait(false);
        int port = (buffer[0] << 8) | buffer[1];
        return host is null || port == 0 ? null : (host, port);
    }

    private static string? ParseDomain(ReadOnlySpan<byte> name)
    {
        if (name.IsEmpty || name.Length > MaxHostLength)
        {
            return null;
        }

        try
        {
            string host = StrictUtf8.GetString(name);
            foreach (char c in host)
            {
                if (char.IsControl(c) || char.IsWhiteSpace(c))
                {
                    return null;
                }
            }

            return host;
        }
        catch (ArgumentException)
        {
            return null;
        }
    }
}

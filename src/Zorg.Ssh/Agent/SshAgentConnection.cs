using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Zorg.Ssh.Auth;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.Keys;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Agent;

/// <summary>A key an agent holds. Its comment isn't kept: nothing here needs that text, and the agent chose it.</summary>
/// <param name="Key">The public key or certificate.</param>
/// <param name="Blob">The blob as the agent sent it, which is how the agent finds the key again.</param>
/// <param name="SignatureAlgorithms">The signature algorithms for this key, most preferred first.</param>
internal sealed record SshAgentIdentity(SshPublicKey Key, byte[] Blob, IReadOnlyList<string> SignatureAlgorithms);

/// <summary>
/// The client side of the ssh-agent protocol (RFC 9987): listing keys and signing. The agent is another program, and
/// a socket path can point anywhere, so all it sends is untrusted: frames and counts are capped, every exchange has
/// a timeout, and a caller must check each signature against the key before using it.
/// </summary>
internal sealed class SshAgentConnection(Stream stream, TimeSpan timeout) : IAsyncDisposable
{
    /// <summary>The largest reply accepted, the same limit as OpenSSH. RFC 9987 sets none.</summary>
    public const int MaxFrameLength = 256 * 1024;

    /// <summary>The most keys accepted in one reply. Only a few can ever be offered to a server.</summary>
    public const int MaxIdentities = 1024;

    private const byte Failure = 5;
    private const byte RequestIdentities = 11;
    private const byte IdentitiesAnswer = 12;
    private const byte SignRequest = 13;
    private const byte SignResponse = 14;
    private const uint RsaSha256Flag = 2;
    private const uint RsaSha512Flag = 4;

    /// <summary>Gets the sign request flags for a signature algorithm, which is how an agent is told the RSA hash.</summary>
    public static uint FlagsFor(string signatureAlgorithm)
    {
        string plain = SshCertificate.PlainSignatureAlgorithm(signatureAlgorithm) ?? signatureAlgorithm;
        return plain switch
        {
            RsaPublicKey.Sha256 => RsaSha256Flag,
            RsaPublicKey.Sha512 => RsaSha512Flag,
            _ => 0,
        };
    }

    /// <summary>Lists the keys this library can use. Keys of other types are left out, as a blob it can't read can't be offered.</summary>
    public async Task<IReadOnlyList<SshAgentIdentity>> ListIdentitiesAsync(CancellationToken cancellationToken)
    {
        byte[] reply = await ExchangeAsync([RequestIdentities], cancellationToken).ConfigureAwait(false);
        return reply[0] switch
        {
            IdentitiesAnswer => ParseIdentities(reply),
            Failure => throw new SshAgentException("The agent refused to list its keys. Check that it's unlocked."),
            _ => throw UnexpectedReply(),
        };
    }

    /// <summary>Asks for a signature. Returns null if the agent refuses. The result isn't checked: see the class summary.</summary>
    public async Task<byte[]?> SignAsync(byte[] keyBlob, byte[] data, uint flags, CancellationToken cancellationToken)
    {
        SshRequestWriter request = new();
        request.Byte(SignRequest);
        request.Bytes(keyBlob);
        request.Bytes(data);
        request.UInt32(flags);
        byte[] reply = await ExchangeAsync(request.ToArray(), cancellationToken).ConfigureAwait(false);
        return reply[0] switch
        {
            SignResponse => ParseSignature(reply),

            // RFC 9987 allows a failure to carry more fields, so only the type counts.
            Failure => null,
            _ => throw UnexpectedReply(),
        };
    }

    /// <inheritdoc/>
    public ValueTask DisposeAsync() => stream.DisposeAsync();

    private static List<SshAgentIdentity> ParseIdentities(ReadOnlySpan<byte> reply)
    {
        try
        {
            SshReader reader = new(reply);
            reader.ReadByte();
            uint count = reader.ReadUInt32();
            if (count > MaxIdentities)
            {
                throw new SshAgentException($"The agent claims to hold {count} keys, more than the limit of {MaxIdentities}, so it wasn't used. Check that SSH_AUTH_SOCK points at a real agent.");
            }

            List<SshAgentIdentity> identities = [];
            for (uint i = 0; i < count; i++)
            {
                ReadOnlySpan<byte> blob = reader.ReadBinary();
                reader.ReadBinary(); // The comment.
                if (TryParseKey(blob, out SshPublicKey? key))
                {
                    identities.Add(new SshAgentIdentity(key, blob.ToArray(), AlgorithmsFor(key)));
                }
            }

            reader.EnsureEnd();
            return identities;
        }
        catch (SshProtocolException ex)
        {
            throw Malformed(ex);
        }
    }

    private static bool TryParseKey(ReadOnlySpan<byte> blob, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out SshPublicKey? key)
    {
        try
        {
            key = SshCertificate.ParseAny(blob);
            return true;
        }
        catch (SshProtocolException)
        {
            // Agents hold security keys and other types that aren't supported here. That isn't a fault in the agent.
            key = null;
            return false;
        }
    }

    private static IReadOnlyList<string> AlgorithmsFor(SshPublicKey key) => key switch
    {
        RsaPublicKey => [RsaPublicKey.Sha512, RsaPublicKey.Sha256],
        SshCertificate { Key: RsaPublicKey } =>
            [SshCertificate.CertificateAlgorithm(RsaPublicKey.Sha512), SshCertificate.CertificateAlgorithm(RsaPublicKey.Sha256)],
        _ => [key.KeyType],
    };

    private static byte[] ParseSignature(ReadOnlySpan<byte> reply)
    {
        try
        {
            SshReader reader = new(reply);
            reader.ReadByte();
            byte[] signature = reader.ReadBinary().ToArray();
            reader.EnsureEnd();
            return signature;
        }
        catch (SshProtocolException ex)
        {
            throw Malformed(ex);
        }
    }

    private static SshAgentException Malformed(Exception cause) =>
        new("The agent sent a malformed reply, so it wasn't used. Check that SSH_AUTH_SOCK points at a real agent.", cause);

    private static SshAgentException UnexpectedReply() =>
        new("The agent sent a reply of the wrong type, so it wasn't used. Check that SSH_AUTH_SOCK points at a real agent.");

    /// <summary>Sends a request and returns the reply, which is never empty.</summary>
    private async Task<byte[]> ExchangeAsync(byte[] request, CancellationToken cancellationToken)
    {
        using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        limit.CancelAfter(timeout);
        CancellationToken token = limit.Token;
        try
        {
            byte[] frame = new byte[sizeof(uint) + request.Length];
            BinaryPrimitives.WriteUInt32BigEndian(frame, (uint)request.Length);
            request.CopyTo(frame, sizeof(uint));

            // WaitAsync as well as the token: the stream may not honour cancellation, and an agent mustn't hang a login.
            await stream.WriteAsync(frame, token).AsTask().WaitAsync(token).ConfigureAwait(false);
            await stream.FlushAsync(token).WaitAsync(token).ConfigureAwait(false);

            byte[] header = new byte[sizeof(uint)];
            await stream.ReadExactlyAsync(header, token).AsTask().WaitAsync(token).ConfigureAwait(false);
            uint length = BinaryPrimitives.ReadUInt32BigEndian(header);
            if (length is 0 or > MaxFrameLength)
            {
                throw new SshAgentException($"The agent sent a reply of {length} bytes, outside the limit of {MaxFrameLength}, so it wasn't used. Check that SSH_AUTH_SOCK points at a real agent.");
            }

            byte[] reply = new byte[length];
            await stream.ReadExactlyAsync(reply, token).AsTask().WaitAsync(token).ConfigureAwait(false);
            return reply;
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            throw new SshAgentException($"The agent didn't answer within {timeout.TotalSeconds:0} seconds. If it's waiting for confirmation, answer it and try again.", ex);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
            throw new SshAgentException("The connection to the agent failed part way through a request. Check that the agent is still running.", ex);
        }
    }
}

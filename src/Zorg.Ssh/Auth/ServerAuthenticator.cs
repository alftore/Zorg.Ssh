using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.Keys;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Transport;

namespace Zorg.Ssh.Auth;

/// <summary>What an auth handler decided. The values match the public <c>SshAuthDecision</c>.</summary>
internal enum AuthDecision
{
    /// <summary>This attempt failed.</summary>
    Reject,

    /// <summary>This method passed.</summary>
    Accept,
}

/// <summary>The handlers and limits for server auth.</summary>
internal sealed class ServerAuthOptions
{
    public Func<string, string, CancellationToken, ValueTask<AuthDecision>>? Password { get; init; }

    /// <summary>Gets the check on a key. It's asked twice: for the query, and after the signature proves the key.</summary>
    public Func<string, SshPublicKey, CancellationToken, ValueTask<AuthDecision>>? PublicKey { get; init; }

    public int MaxAttempts { get; init; } = 6;

    /// <summary>Gets the methods that must all pass. Null means any one is enough.</summary>
    public IReadOnlyList<string>? RequiredMethods { get; init; }

    public string? Banner { get; init; }

    /// <summary>Gets whether a client may sign with legacy <c>ssh-rsa</c> (SHA-1): only when the server's algorithm list names it.</summary>
    public bool AllowRsaSha1 { get; init; }

    /// <summary>
    /// Gets the signature algorithms a client may use with a key (A4), other than legacy <c>ssh-rsa</c>, which <see cref="AllowRsaSha1"/>
    /// governs. Null means every algorithm the library implements.
    /// </summary>
    public IReadOnlyList<string>? PublicKeyAlgorithms { get; init; }
}

/// <summary>
/// Who logged in, and with which methods. Every method in a multi-step login stays on the record, and so does
/// every key the client proved it holds, in order. <paramref name="Key"/> is the last of them.
/// </summary>
internal sealed record AuthenticatedUser(string Name, IReadOnlyList<string> Methods, SshPublicKey? Key, IReadOnlyList<SshPublicKey> ProvenKeys);

/// <summary>
/// Server side of RFC 4252. Nothing past this class runs until it returns: the permission table keeps
/// connection messages out until <see cref="TransportPhase.Connected"/>, which only this class sets.
/// </summary>
internal sealed class ServerAuthenticator(SshTransport transport, ServerAuthOptions options)
{
    private const string UserAuthService = "ssh-userauth";
    private const string ConnectionService = "ssh-connection";
    private const byte PublicKeyOk = 60;
    private const int MaxKeyQueries = 64;

    /// <summary>Most keys one login may prove. A client with more is not a login, and none goes unrecorded.</summary>
    private const int MaxProvenKeys = 8;

    private readonly List<string> _succeeded = [];
    private readonly List<SshPublicKey> _provenKeys = [];
    private string? _user;
    private SshPublicKey? _provenKey;
    private int _attempts;
    private int _keyQueries;

    public async Task<AuthenticatedUser> AuthenticateAsync(CancellationToken cancellationToken)
    {
        await AcceptServiceAsync(cancellationToken).ConfigureAwait(false);
        transport.SetPhase(TransportPhase.Auth);
        if (options.Banner is { } banner)
        {
            await SendBannerAsync(banner, cancellationToken).ConfigureAwait(false);
        }

        while (true)
        {
            ReadOnlyMemory<byte> message = await transport.ReceiveAsync(cancellationToken).ConfigureAwait(false);

            // The table lets 60-79 through during auth for the methods that use them. None of ours do yet.
            if (message.Span[0] != MessageNumber.UserAuthRequest)
            {
                throw new SshProtocolException("The client sent an auth message that no method is waiting for.");
            }

            Request request = ParseRequest(message.Span);
            try
            {
                // RFC 4252 section 5: a change of user or service must not carry earlier progress with it.
                if (_user is not null && _user != request.User)
                {
                    throw new SshProtocolException("The client changed user during authentication.");
                }

                _user = request.User;
                if (request.Service != ConnectionService)
                {
                    throw new SshProtocolException("The client asked for an unknown service.");
                }

                AuthDecision decision = await HandleAsync(request, cancellationToken).ConfigureAwait(false);
                if (decision == AuthDecision.Accept && !_succeeded.Contains(request.Method))
                {
                    _succeeded.Add(request.Method);
                    if (Remaining().Count == 0)
                    {
                        SentSequence success = new();
                        await transport.SendAsync([MessageNumber.UserAuthSuccess], cancellationToken, success).ConfigureAwait(false);

                        // The connection answers the peer's next messages without queueing, ahead of anything still queued. So the success must have
                        // left the queue before the connection starts, or a channel open pipelined behind the login is confirmed before the login is.
                        await success.Taken.WaitAsync(cancellationToken).ConfigureAwait(false);
                        transport.SetPhase(TransportPhase.Connected);
                        return new AuthenticatedUser(_user, [.. _succeeded], _provenKey, [.. _provenKeys]);
                    }

                    await SendFailureAsync(partial: true, cancellationToken).ConfigureAwait(false);
                    continue;
                }

                if (request.Handled)
                {
                    continue;
                }

                // The "none" probe is how clients discover methods, so it isn't an attempt.
                if (request.Method != "none" && ++_attempts >= options.MaxAttempts)
                {
                    throw new SshProtocolException("Too many authentication failures.");
                }

                await SendFailureAsync(partial: false, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                // It can hold a password.
                CryptographicOperations.ZeroMemory(request.Body);
            }
        }
    }

    private static Request ParseRequest(ReadOnlySpan<byte> message)
    {
        SshReader reader = new(message);
        reader.ReadByte();
        string user = reader.ReadUtf8String();
        string service = reader.ReadUtf8String();
        string method = reader.ReadUtf8String();
        return new Request(user, service, method, reader.RemainingSpan.ToArray());
    }

    private static string ParseService(ReadOnlySpan<byte> message)
    {
        SshReader reader = new(message);
        reader.ReadByte();
        return reader.ReadUtf8String();
    }

    private static string ParsePassword(ReadOnlySpan<byte> body)
    {
        SshReader reader = new(body);
        if (reader.ReadBoolean())
        {
            throw new SshProtocolException("The client tried to change a password, which isn't supported.");
        }

        string password = reader.ReadUtf8String();
        reader.EnsureEnd();
        return password;
    }

    internal static PublicKeyRequest ParsePublicKey(ReadOnlySpan<byte> body)
    {
        SshReader reader = new(body);
        bool hasSignature = reader.ReadBoolean();
        string algorithm = reader.ReadUtf8String();
        byte[] blob = reader.ReadBinary().ToArray();
        byte[]? signature = hasSignature ? reader.ReadBinary().ToArray() : null;
        reader.EnsureEnd();
        return new PublicKeyRequest(algorithm, blob, signature);
    }

    private async Task AcceptServiceAsync(CancellationToken cancellationToken)
    {
        ReadOnlyMemory<byte> message = await transport.ReceiveAsync(cancellationToken).ConfigureAwait(false);
        string service = ParseService(message.Span);
        if (service != UserAuthService)
        {
            throw new SshProtocolException("The client asked for a service other than user authentication.");
        }

        SshRequestWriter reply = new();
        reply.Byte(MessageNumber.ServiceAccept);
        reply.String(UserAuthService);
        await transport.SendAsync(reply.ToArray(), cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask SendBannerAsync(string banner, CancellationToken cancellationToken)
    {
        SshRequestWriter writer = new();
        writer.Byte(MessageNumber.UserAuthBanner);
        writer.String(banner);
        writer.String(string.Empty);
        await transport.SendAsync(writer.ToArray(), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The required methods not yet passed. With none required, one success is enough.</summary>
    private List<string> Remaining()
    {
        if (options.RequiredMethods is { } required)
        {
            return [.. required.Where(m => !_succeeded.Contains(m))];
        }

        return _succeeded.Count > 0 ? [] : AvailableMethods();
    }

    private List<string> AvailableMethods()
    {
        List<string> methods = [];
        if (options.PublicKey is not null)
        {
            methods.Add("publickey");
        }

        if (options.Password is not null)
        {
            methods.Add("password");
        }

        return methods;
    }

    private async ValueTask SendFailureAsync(bool partial, CancellationToken cancellationToken)
    {
        byte[] payload;
        SshWriter writer = new(64);
        try
        {
            writer.WriteByte(MessageNumber.UserAuthFailure);
            writer.WriteNameList(Remaining());
            writer.WriteBoolean(partial);
            payload = writer.ToArray();
        }
        finally
        {
            writer.Dispose();
        }

        await transport.SendAsync(payload, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<AuthDecision> HandleAsync(Request request, CancellationToken cancellationToken)
    {
        // A required list limits what counts at all.
        if (options.RequiredMethods is { } required && !required.Contains(request.Method))
        {
            return AuthDecision.Reject;
        }

        switch (request.Method)
        {
            case "password" when options.Password is { } check:
                string password = ParsePassword(request.Body);
                return await WithinGraceAsync(check(request.User, password, cancellationToken), cancellationToken).ConfigureAwait(false);
            case "publickey" when options.PublicKey is { } check:
                return await HandlePublicKeyAsync(request, check, cancellationToken).ConfigureAwait(false);
            default:
                return AuthDecision.Reject;
        }
    }

    /// <summary>A handler that ignores its token can't hold a connection past the grace time.</summary>
    private static async ValueTask<AuthDecision> WithinGraceAsync(ValueTask<AuthDecision> check, CancellationToken cancellationToken) =>
        await check.AsTask().WaitAsync(cancellationToken).ConfigureAwait(false);

    private async ValueTask<AuthDecision> HandlePublicKeyAsync(
        Request request,
        Func<string, SshPublicKey, CancellationToken, ValueTask<AuthDecision>> check,
        CancellationToken cancellationToken)
    {
        PublicKeyRequest parsed = ParsePublicKey(request.Body);
        SshPublicKey key;
        try
        {
            key = SshPublicKey.Parse(parsed.Blob);
        }
        catch (SshProtocolException)
        {
            // A key we can't read is a failed attempt, not a reason to drop the connection.
            return AuthDecision.Reject;
        }

        bool rsaSha1 = options.AllowRsaSha1 && parsed.Algorithm == LegacyAlgorithms.RsaSha1 && LegacyRsa.CanVerify(key);
        if (!rsaSha1 && (!key.SupportsSignatureAlgorithm(parsed.Algorithm) || options.PublicKeyAlgorithms?.Contains(parsed.Algorithm) == false))
        {
            return AuthDecision.Reject;
        }

        // A query isn't an attempt, as clients offer several keys, but each one runs the handler.
        if (++_keyQueries > MaxKeyQueries)
        {
            throw new SshProtocolException("The client offered too many keys.");
        }

        AuthDecision decision = await WithinGraceAsync(check(request.User, key, cancellationToken), cancellationToken).ConfigureAwait(false);
        if (decision == AuthDecision.Reject)
        {
            return AuthDecision.Reject;
        }

        if (parsed.Signature is null)
        {
            SshRequestWriter reply = new();
            reply.Byte(PublicKeyOk);
            reply.String(parsed.Algorithm);
            reply.Bytes(parsed.Blob);
            await transport.SendAsync(reply.ToArray(), cancellationToken).ConfigureAwait(false);
            request.Handled = true;
            return AuthDecision.Reject;
        }

        // Guarantee 2: the handler's yes means nothing until the signature proves the client holds the key.
        byte[] signed = SignedData(request, parsed);
        bool valid = rsaSha1
            ? LegacyRsa.Verify(key, signed, parsed.Signature)
            : key.Verify(parsed.Algorithm, signed, parsed.Signature);
        if (!valid)
        {
            return AuthDecision.Reject;
        }

        // Every proven key stays on the record, also one whose step the method rule then refuses as a repeat.
        // A key that would be the ninth is refused, so no proven key is ever left off.
        if (!_provenKeys.Exists(k => k.Blob.Span.SequenceEqual(key.Blob.Span)))
        {
            if (_provenKeys.Count >= MaxProvenKeys)
            {
                return AuthDecision.Reject;
            }

            _provenKeys.Add(key);
        }

        _provenKey = key;
        return decision;
    }

    private byte[] SignedData(Request request, PublicKeyRequest parsed)
    {
        SshWriter writer = new(512);
        try
        {
            writer.WriteBinary(transport.SessionId.Span);
            writer.WriteByte(MessageNumber.UserAuthRequest);
            writer.WriteUtf8String(request.User);
            writer.WriteUtf8String(request.Service);
            writer.WriteUtf8String("publickey");
            writer.WriteBoolean(true);
            writer.WriteUtf8String(parsed.Algorithm);
            writer.WriteBinary(parsed.Blob);
            return writer.ToArray();
        }
        finally
        {
            writer.Dispose();
        }
    }

    private sealed record Request(string User, string Service, string Method, byte[] Body)
    {
        /// <summary>Gets or sets whether a reply has been sent already, as with PK_OK.</summary>
        public bool Handled { get; set; }
    }

    internal sealed record PublicKeyRequest(string Algorithm, byte[] Blob, byte[]? Signature);
}

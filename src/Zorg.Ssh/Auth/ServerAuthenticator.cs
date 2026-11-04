using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Transport;

namespace Zorg.Ssh.Auth;

/// <summary>What an auth handler decided.</summary>
internal enum AuthDecision
{
    /// <summary>This attempt failed.</summary>
    Reject,

    /// <summary>This attempt was good, but another method must succeed too.</summary>
    Partial,

    /// <summary>The user is logged in.</summary>
    Accept,
}

/// <summary>The handlers and limits for server auth.</summary>
internal sealed class ServerAuthOptions
{
    public Func<string, string, CancellationToken, ValueTask<AuthDecision>>? Password { get; init; }

    /// <summary>Gets the check on a key. It's asked twice: for the query, and after the signature proves the key.</summary>
    public Func<string, SshPublicKey, CancellationToken, ValueTask<AuthDecision>>? PublicKey { get; init; }

    public int MaxAttempts { get; init; } = 6;

    public string? Banner { get; init; }
}

/// <summary>Who logged in, and with which methods. Every method in a partial-auth chain stays on the record.</summary>
internal sealed record AuthenticatedUser(string Name, IReadOnlyList<string> Methods, SshPublicKey? Key);

/// <summary>
/// Server side of RFC 4252. Nothing past this class runs until it returns: the permission table keeps
/// connection messages out until <see cref="TransportPhase.Connected"/>, which only this class sets.
/// </summary>
internal sealed class ServerAuthenticator(SshTransport transport, ServerAuthOptions options)
{
    private const string UserAuthService = "ssh-userauth";
    private const string ConnectionService = "ssh-connection";
    private const byte PublicKeyOk = 60;

    private readonly List<string> _succeeded = [];
    private string? _user;
    private SshPublicKey? _provenKey;
    private int _attempts;

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
            Request request = ParseRequest(message.Span);

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
            switch (decision)
            {
                case AuthDecision.Accept:
                    _succeeded.Add(request.Method);
                    await transport.SendAsync([MessageNumber.UserAuthSuccess], cancellationToken).ConfigureAwait(false);
                    transport.SetPhase(TransportPhase.Connected);
                    return new AuthenticatedUser(_user, [.. _succeeded], _provenKey);
                case AuthDecision.Partial:
                    _succeeded.Add(request.Method);
                    await SendFailureAsync(partial: true, cancellationToken).ConfigureAwait(false);
                    break;
                default:
                    if (request.Handled)
                    {
                        break;
                    }

                    // The "none" probe is how clients discover methods, so it isn't an attempt.
                    if (request.Method != "none" && ++_attempts >= options.MaxAttempts)
                    {
                        throw new SshProtocolException("Too many authentication failures.");
                    }

                    await SendFailureAsync(partial: false, cancellationToken).ConfigureAwait(false);
                    break;
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

    private static string ParseService(ReadOnlySpan<byte> message)
    {
        SshReader reader = new(message);
        reader.ReadByte();
        return reader.ReadUtf8String();
    }

    private async ValueTask SendBannerAsync(string banner, CancellationToken cancellationToken)
    {
        SshRequestWriter writer = new();
        writer.Byte(MessageNumber.UserAuthBanner);
        writer.String(banner);
        writer.String(string.Empty);
        await transport.SendAsync(writer.ToArray(), cancellationToken).ConfigureAwait(false);
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
            writer.WriteNameList(AvailableMethods());
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
        switch (request.Method)
        {
            case "password" when options.Password is { } check:
                string password = ParsePassword(request.Body);
                return await check(request.User, password, cancellationToken).ConfigureAwait(false);
            case "publickey" when options.PublicKey is { } check:
                return await HandlePublicKeyAsync(request, check, cancellationToken).ConfigureAwait(false);
            default:
                return AuthDecision.Reject;
        }
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

        if (!key.SupportsSignatureAlgorithm(parsed.Algorithm))
        {
            return AuthDecision.Reject;
        }

        AuthDecision decision = await check(request.User, key, cancellationToken).ConfigureAwait(false);
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
        if (!key.Verify(parsed.Algorithm, signed, parsed.Signature))
        {
            return AuthDecision.Reject;
        }

        _provenKey = key;
        return decision;
    }

    private static PublicKeyRequest ParsePublicKey(ReadOnlySpan<byte> body)
    {
        SshReader reader = new(body);
        bool hasSignature = reader.ReadBoolean();
        string algorithm = reader.ReadUtf8String();
        byte[] blob = reader.ReadBinary().ToArray();
        byte[]? signature = hasSignature ? reader.ReadBinary().ToArray() : null;
        reader.EnsureEnd();
        return new PublicKeyRequest(algorithm, blob, signature);
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

    private sealed record PublicKeyRequest(string Algorithm, byte[] Blob, byte[]? Signature);
}

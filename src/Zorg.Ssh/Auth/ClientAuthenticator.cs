using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Zorg.Ssh.Agent;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.Keys;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Transport;

namespace Zorg.Ssh.Auth;

/// <summary>
/// Client side of RFC 4252. Asks for the auth service, then works through the credentials. Message 60
/// means different things per method, so it's read by whichever method is running.
/// </summary>
internal sealed class ClientAuthenticator(SshTransport transport, string userName, Action<string>? onBanner, bool allowRsaSha1 = false)
{
    private const string ConnectionService = "ssh-connection";
    private const byte PublicKeyOk = 60;
    private const byte PasswordChangeRequired = 60;
    private const byte InfoRequest = 60;
    private const byte InfoResponse = 61;
    private const int MaxPrompts = 32;
    private const int MaxInfoRounds = 16;
    private const int MaxBannerLength = 16 * 1024;

    /// <summary>What went wrong along the way that a failed login should mention. It's kept out of the way of a login that succeeds.</summary>
    private readonly List<string> _notes = [];
    private int _refusedKeys;

    private enum Outcome
    {
        Success,
        Failure,
        Partial,
    }

    public async Task AuthenticateAsync(IReadOnlyList<SshCredential> credentials, CancellationToken cancellationToken)
    {
        await RequestServiceAsync(cancellationToken).ConfigureAwait(false);

        // "none" asks the server which methods it accepts, and is all a few servers need.
        SendResult first = await SendNoneAsync(cancellationToken).ConfigureAwait(false);
        if (first.Outcome == Outcome.Success)
        {
            return;
        }

        IReadOnlyList<string> allowed = first.Methods;
        List<string> tried = [];
        foreach (SshCredential credential in credentials)
        {
            SendResult result = credential switch
            {
                PasswordCredential password when allowed.Contains("password") =>
                    await TryPasswordAsync(password, tried, cancellationToken).ConfigureAwait(false),
                KeyboardInteractiveCredential interactive when allowed.Contains("keyboard-interactive") =>
                    await TryKeyboardInteractiveAsync(interactive, tried, cancellationToken).ConfigureAwait(false),
                PrivateKeyCredential key when allowed.Contains("publickey") =>
                    await TryPublicKeyAsync(key, allowed, tried, cancellationToken).ConfigureAwait(false),
                AgentCredential agent when allowed.Contains("publickey") =>
                    await TryAgentAsync(agent, allowed, tried, cancellationToken).ConfigureAwait(false),
                _ => new SendResult(Outcome.Failure, allowed),
            };

            if (result.Outcome == Outcome.Success)
            {
                return;
            }

            allowed = result.Methods;
        }

        string notes = _notes.Count == 0 ? string.Empty : " " + string.Join(" ", _notes);
        throw new SshAuthenticationException(
            $"Authentication failed for {userName}. Tried [{string.Join(", ", tried)}]; the server accepts [{string.Join(", ", allowed)}]. Check the user name and credentials.{notes}",
            tried,
            allowed);
    }

    /// <summary>
    /// Picks the signature algorithm for a key. <paramref name="rsaSha1"/> says that legacy <c>ssh-rsa</c> is allowed and the
    /// key is a plain RSA key. Then, as OpenSSH does, a server with no <c>server-sig-algs</c> gets <c>ssh-rsa</c>, and so does
    /// one that lists it and no SHA-2 RSA algorithm. Otherwise nothing changes: the first algorithm, or the first the server lists.
    /// </summary>
    internal static string SignatureAlgorithmFor(IReadOnlyList<string> algorithms, IReadOnlyDictionary<string, byte[]> extensions, bool rsaSha1)
    {
        if (!extensions.TryGetValue("server-sig-algs", out byte[]? value))
        {
            return rsaSha1 ? LegacyAlgorithms.RsaSha1 : algorithms[0];
        }

        // OpenSSH lists plain algorithms only, so a certificate's algorithm is looked up by what's behind it.
        string[] supported = Encoding.ASCII.GetString(value).Split(',');
        string? listed = algorithms.FirstOrDefault(a => supported.Contains(a) || supported.Contains(SshCertificate.PlainSignatureAlgorithm(a)));
        if (listed is not null)
        {
            return listed;
        }

        return rsaSha1 && supported.Contains(LegacyAlgorithms.RsaSha1) ? LegacyAlgorithms.RsaSha1 : algorithms[0];
    }

    private bool UsesRsaSha1(SshPublicKey key) => allowRsaSha1 && LegacyRsa.CanVerify(key);

    private async ValueTask SendAsync(Action<SshRequestWriter> build, CancellationToken cancellationToken)
    {
        SshRequestWriter request = new();
        build(request);
        await request.BuildSendAndClearAsync((wire, ct) => transport.SendAsync(wire, ct), cancellationToken).ConfigureAwait(false);
    }

    private async Task RequestServiceAsync(CancellationToken cancellationToken)
    {
        await SendAsync(
            static w =>
            {
                w.Byte(MessageNumber.ServiceRequest);
                w.String("ssh-userauth");
            },
            cancellationToken).ConfigureAwait(false);

        ReadOnlyMemory<byte> reply = await transport.ReceiveAsync(cancellationToken).ConfigureAwait(false);
        if (reply.Span[0] != MessageNumber.ServiceAccept)
        {
            throw new SshProtocolException("The server didn't accept the auth service request.");
        }

        transport.SetPhase(TransportPhase.Auth);
    }

    private ValueTask<SendResult> SendNoneAsync(CancellationToken cancellationToken) =>
        RequestAsync("none", static _ => { }, cancellationToken);

    private async ValueTask<SendResult> RequestAsync(string method, Action<SshRequestWriter> body, CancellationToken cancellationToken)
    {
        await SendAsync(
            w =>
            {
                w.Byte(MessageNumber.UserAuthRequest);
                w.String(userName);
                w.String(ConnectionService);
                w.String(method);
                body(w);
            },
            cancellationToken).ConfigureAwait(false);
        return await ReadResultAsync(null, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Reads to the next final answer, handing message 60 to <paramref name="onMethodMessage"/> if a method expects one.</summary>
    private async ValueTask<SendResult> ReadResultAsync(Func<ReadOnlyMemory<byte>, ValueTask<SendResult?>>? onMethodMessage, CancellationToken cancellationToken)
    {
        while (true)
        {
            ReadOnlyMemory<byte> message = await transport.ReceiveAsync(cancellationToken).ConfigureAwait(false);
            switch (message.Span[0])
            {
                case MessageNumber.UserAuthSuccess:
                    transport.SetPhase(TransportPhase.Connected);
                    return new SendResult(Outcome.Success, []);
                case MessageNumber.UserAuthFailure:
                    return ParseFailure(message.Span);
                case MessageNumber.UserAuthBanner:
                    ReportBanner(message.Span);
                    break;
                default:
                    if (onMethodMessage is null)
                    {
                        throw new SshProtocolException($"The server sent auth message {message.Span[0]} with no method waiting for it.");
                    }

                    if (await onMethodMessage(message).ConfigureAwait(false) is { } result)
                    {
                        return result;
                    }

                    break;
            }
        }
    }

    private static SendResult ParseFailure(ReadOnlySpan<byte> message)
    {
        SshReader reader = new(message);
        reader.ReadByte();
        string[] methods = reader.ReadNameList();
        bool partial = reader.ReadBoolean();
        return new SendResult(partial ? Outcome.Partial : Outcome.Failure, methods);
    }

    private void ReportBanner(ReadOnlySpan<byte> message)
    {
        SshReader reader = new(message);
        reader.ReadByte();
        string banner = reader.ReadUtf8String();
        if (onBanner is null)
        {
            return;
        }

        // Banners are peer text that often reach a terminal, so control characters go, except line breaks.
        StringBuilder clean = new(Math.Min(banner.Length, MaxBannerLength));
        foreach (char c in banner)
        {
            if (clean.Length == MaxBannerLength)
            {
                break;
            }

            if (!char.IsControl(c) || c is '\n' or '\r' or '\t')
            {
                clean.Append(c);
            }
        }

        try
        {
            onBanner(clean.ToString());
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Application code failed. Login stops, rather than going on as if the banner had been shown.
            throw new SshAuthenticationException($"The banner handler threw {ex.GetType().Name}, so the login was stopped. See the inner exception.", ex);
        }
    }

    private async ValueTask<SendResult> TryPasswordAsync(PasswordCredential credential, List<string> tried, CancellationToken cancellationToken)
    {
        tried.Add("password");
        await SendAsync(
            w =>
            {
                w.Byte(MessageNumber.UserAuthRequest);
                w.String(userName);
                w.String(ConnectionService);
                w.String("password");
                w.Bool(false);
                w.String(credential.Password);
            },
            cancellationToken).ConfigureAwait(false);

        return await ReadResultAsync(
            message => message.Span[0] == PasswordChangeRequired
                ? throw new SshAuthenticationException($"The password for {userName} has expired. Change it, then connect again.")
                : throw new SshProtocolException("The server sent an unexpected password auth message."),
            cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<SendResult> TryKeyboardInteractiveAsync(KeyboardInteractiveCredential credential, List<string> tried, CancellationToken cancellationToken)
    {
        tried.Add("keyboard-interactive");
        await SendAsync(
            w =>
            {
                w.Byte(MessageNumber.UserAuthRequest);
                w.String(userName);
                w.String(ConnectionService);
                w.String("keyboard-interactive");
                w.String(string.Empty);
                w.String(string.Empty);
            },
            cancellationToken).ConfigureAwait(false);

        int rounds = 0;
        return await ReadResultAsync(
            async message =>
            {
                if (message.Span[0] != InfoRequest || ++rounds > MaxInfoRounds)
                {
                    throw new SshProtocolException("The server sent an unexpected or endless keyboard-interactive exchange.");
                }

                List<SshPrompt> prompts = ParsePrompts(message.Span);
                IReadOnlyList<string>? answers;
                try
                {
                    answers = await credential.Respond(prompts, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not SshException && !(ex is OperationCanceledException && cancellationToken.IsCancellationRequested))
                {
                    // Application code failed. Nothing is sent for these prompts, and the login stops.
                    throw new SshAuthenticationException($"The keyboard-interactive handler threw {ex.GetType().Name}, so the login was stopped. See the inner exception.", ex);
                }

                if (answers is null || answers.Count != prompts.Count)
                {
                    throw new SshAuthenticationException($"The keyboard-interactive handler returned {answers?.Count.ToString(CultureInfo.InvariantCulture) ?? "null"} answers for {prompts.Count} prompts. It must return one answer per prompt.");
                }

                await SendAsync(
                    w =>
                    {
                        w.Byte(InfoResponse);
                        w.UInt32((uint)answers.Count);
                        foreach (string answer in answers)
                        {
                            w.String(answer);
                        }
                    },
                    cancellationToken).ConfigureAwait(false);
                return null;
            },
            cancellationToken).ConfigureAwait(false);
    }

    private static List<SshPrompt> ParsePrompts(ReadOnlySpan<byte> message)
    {
        SshReader reader = new(message);
        reader.ReadByte();
        reader.ReadBinary();
        reader.ReadBinary();
        reader.ReadBinary();
        uint count = reader.ReadUInt32();
        if (count > MaxPrompts)
        {
            throw new SshProtocolException("The server sent too many keyboard-interactive prompts.");
        }

        List<SshPrompt> prompts = new((int)count);
        for (uint i = 0; i < count; i++)
        {
            string text = reader.ReadUtf8String();
            prompts.Add(new SshPrompt { Text = text, Echo = reader.ReadBoolean() });
        }

        return prompts;
    }

    private async ValueTask<SendResult> TryPublicKeyAsync(
        PrivateKeyCredential credential,
        IReadOnlyList<string> allowed,
        List<string> tried,
        CancellationToken cancellationToken)
    {
        SshPrivateKey key;
        try
        {
            key = credential.Load();
        }
        catch (SshKeyFileException ex) when (credential.OptionalName is { } name)
        {
            _notes.Add($"Skipped the identity file {name}: {ex.Message}");
            return new SendResult(Outcome.Failure, allowed);
        }

        try
        {
            string algorithm = SignatureAlgorithmFor(key.SignatureAlgorithms, transport.PeerExtensions, UsesRsaSha1(key.PublicKey));
            byte[] blob = key.PublicKey.Blob.ToArray();
            tried.Add($"publickey ({algorithm})");
            return await OfferKeyAsync(
                algorithm,
                blob,
                allowed,
                (data, _) => ValueTask.FromResult<byte[]?>(algorithm == LegacyAlgorithms.RsaSha1 ? LegacyRsa.Sign(key, data) : key.Sign(algorithm, data)),
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if (credential.OwnsKey)
            {
                key.Dispose();
            }
        }
    }

    private async ValueTask<SendResult> TryAgentAsync(
        AgentCredential credential,
        IReadOnlyList<string> allowed,
        List<string> tried,
        CancellationToken cancellationToken)
    {
        SendResult result = new(Outcome.Failure, allowed);
        try
        {
            SshAgentConnection agent = await credential.ConnectAsync(cancellationToken).ConfigureAwait(false);
            await using (agent.ConfigureAwait(false))
            {
                IReadOnlyList<SshAgentIdentity> identities = await agent.ListIdentitiesAsync(cancellationToken).ConfigureAwait(false);
                if (identities.Count == 0 && !credential.IsOptional)
                {
                    _notes.Add("The ssh-agent holds no keys this library can use. Add one with ssh-add.");
                }

                int limit = Math.Max(0, credential.MaxKeysOffered - _refusedKeys);
                int offered = 0;
                foreach (SshAgentIdentity identity in identities)
                {
                    if (offered == limit)
                    {
                        _notes.Add($"The ssh-agent holds {identities.Count} usable keys, but only {offered} were offered, because each refused key counts against the server's MaxAuthTries and too many end the connection. Choose a key with SshCredential.FromPrivateKeyFile, remove keys with ssh-add -d, or raise the limit with SshCredential.FromAgent(maxKeysOffered: ...).");
                        break;
                    }

                    offered++;
                    string algorithm = SignatureAlgorithmFor(identity.SignatureAlgorithms, transport.PeerExtensions, UsesRsaSha1(identity.Key));
                    tried.Add($"publickey ({algorithm}, agent)");
                    result = await OfferKeyAsync(
                        algorithm,
                        identity.Blob,
                        result.Methods,
                        (data, token) => SignWithAgentAsync(agent, identity, algorithm, data, token),
                        cancellationToken).ConfigureAwait(false);
                    if (result.Outcome != Outcome.Failure || !result.Methods.Contains("publickey"))
                    {
                        break;
                    }
                }
            }
        }
        catch (SshAgentException ex)
        {
            // The agent is only one credential. What comes after it may still work, and the failure says what happened.
            if (!credential.IsOptional)
            {
                _notes.Add(ex.Message);
            }
        }

        return result;
    }

    /// <summary>Returns null if the agent refuses this key. A signature that doesn't verify is a faulty or hostile agent, and it goes no further.</summary>
    private async ValueTask<byte[]?> SignWithAgentAsync(SshAgentConnection agent, SshAgentIdentity identity, string algorithm, byte[] data, CancellationToken cancellationToken)
    {
        byte[]? signature = await agent.SignAsync(identity.Blob, data, SshAgentConnection.FlagsFor(algorithm), cancellationToken).ConfigureAwait(false);
        if (signature is null)
        {
            _notes.Add($"The ssh-agent refused to sign with a {identity.Key.KeyType} key. It may be locked, or waiting for a confirmation that was declined.");
            return null;
        }

        bool valid = algorithm == LegacyAlgorithms.RsaSha1
            ? LegacyRsa.Verify(identity.Key, data, signature)
            : identity.Key.Verify(algorithm, data, signature);
        return valid
            ? signature
            : throw new SshAgentException($"The ssh-agent returned a signature that doesn't verify against the {identity.Key.KeyType} key it listed, or that isn't {algorithm}, so it wasn't sent and the agent wasn't used further. The agent may be faulty, or too old for this algorithm.");
    }

    /// <summary>Offers a key, then proves it if the server would take it. <paramref name="sign"/> gets the data to sign, and null from it abandons the key.</summary>
    private async ValueTask<SendResult> OfferKeyAsync(
        string algorithm,
        byte[] blob,
        IReadOnlyList<string> allowed,
        Func<byte[], CancellationToken, ValueTask<byte[]?>> sign,
        CancellationToken cancellationToken)
    {
        // Ask first: signing only for keys the server will take keeps failed attempts down.
        await SendAsync(
            w =>
            {
                w.Byte(MessageNumber.UserAuthRequest);
                w.String(userName);
                w.String(ConnectionService);
                w.String("publickey");
                w.Bool(false);
                w.String(algorithm);
                w.Bytes(blob);
            },
            cancellationToken).ConfigureAwait(false);

        bool accepted = false;
        SendResult? query = await ReadQueryAsync(() => accepted = true, cancellationToken).ConfigureAwait(false);
        if (!accepted)
        {
            _refusedKeys++;
            return query!;
        }

        byte[]? signature = await sign(SignedData(algorithm, blob), cancellationToken).ConfigureAwait(false);
        if (signature is null)
        {
            return new SendResult(Outcome.Failure, allowed);
        }

        await SendAsync(
            w =>
            {
                w.Byte(MessageNumber.UserAuthRequest);
                w.String(userName);
                w.String(ConnectionService);
                w.String("publickey");
                w.Bool(true);
                w.String(algorithm);
                w.Bytes(blob);
                w.Bytes(signature);
            },
            cancellationToken).ConfigureAwait(false);
        SendResult result = await ReadResultAsync(null, cancellationToken).ConfigureAwait(false);
        if (result.Outcome == Outcome.Failure)
        {
            _refusedKeys++;
        }

        return result;
    }

    private async ValueTask<SendResult?> ReadQueryAsync(Action onAccepted, CancellationToken cancellationToken)
    {
        SendResult? final = await ReadResultAsync(
            message =>
            {
                if (message.Span[0] != PublicKeyOk)
                {
                    throw new SshProtocolException("The server sent an unexpected publickey auth message.");
                }

                onAccepted();
                return ValueTask.FromResult<SendResult?>(new SendResult(Outcome.Failure, []));
            },
            cancellationToken).ConfigureAwait(false);
        return final;
    }

    private byte[] SignedData(string algorithm, byte[] blob)
    {
        SshWriter writer = new(512);
        try
        {
            writer.WriteBinary(transport.SessionId.Span);
            writer.WriteByte(MessageNumber.UserAuthRequest);
            writer.WriteUtf8String(userName);
            writer.WriteUtf8String(ConnectionService);
            writer.WriteUtf8String("publickey");
            writer.WriteBoolean(true);
            writer.WriteUtf8String(algorithm);
            writer.WriteBinary(blob);
            return writer.ToArray();
        }
        finally
        {
            writer.Dispose();
        }
    }

    private sealed record SendResult(Outcome Outcome, IReadOnlyList<string> Methods);
}

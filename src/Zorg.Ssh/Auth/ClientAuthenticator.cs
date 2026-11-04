using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Transport;

namespace Zorg.Ssh.Auth;

/// <summary>
/// Client side of RFC 4252. Asks for the auth service, then works through the credentials. Message 60
/// means different things per method, so it's read by whichever method is running.
/// </summary>
internal sealed class ClientAuthenticator(SshTransport transport, string userName, Action<string>? onBanner)
{
    private const string ConnectionService = "ssh-connection";
    private const byte PublicKeyOk = 60;
    private const byte PasswordChangeRequired = 60;
    private const byte InfoRequest = 60;
    private const byte InfoResponse = 61;
    private const int MaxPrompts = 32;
    private const int MaxInfoRounds = 16;
    private const int MaxBannerLength = 16 * 1024;

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
                    await TryPublicKeyAsync(key, tried, cancellationToken).ConfigureAwait(false),
                _ => new SendResult(Outcome.Failure, allowed),
            };

            if (result.Outcome == Outcome.Success)
            {
                return;
            }

            allowed = result.Methods;
        }

        throw new SshAuthenticationException(
            $"Authentication failed for {userName}. Tried [{string.Join(", ", tried)}]; the server accepts [{string.Join(", ", allowed)}]. Check the user name and credentials.",
            tried,
            allowed);
    }

    private static string SignatureAlgorithmFor(SshPrivateKey key, IReadOnlyDictionary<string, byte[]> extensions)
    {
        if (key.SignatureAlgorithms.Count == 1 || !extensions.TryGetValue("server-sig-algs", out byte[]? value))
        {
            return key.SignatureAlgorithms[0];
        }

        string[] supported = Encoding.ASCII.GetString(value).Split(',');
        return key.SignatureAlgorithms.FirstOrDefault(supported.Contains) ?? key.SignatureAlgorithms[0];
    }

    private async ValueTask SendAsync(Action<SshRequestWriter> build, CancellationToken cancellationToken)
    {
        SshRequestWriter request = new();
        build(request);
        await transport.SendAsync(request.ToArray(), cancellationToken).ConfigureAwait(false);
        request.Clear();
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

        onBanner(clean.ToString());
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
                IReadOnlyList<string> answers = await credential.Respond(prompts, cancellationToken).ConfigureAwait(false);
                if (answers.Count != prompts.Count)
                {
                    throw new ArgumentException("The keyboard-interactive handler must return one answer per prompt.", nameof(credential));
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
            prompts.Add(new SshPrompt(text, reader.ReadBoolean()));
        }

        return prompts;
    }

    private async ValueTask<SendResult> TryPublicKeyAsync(PrivateKeyCredential credential, List<string> tried, CancellationToken cancellationToken)
    {
        SshPrivateKey key = credential.Load();
        try
        {
            string algorithm = SignatureAlgorithmFor(key, transport.PeerExtensions);
            byte[] blob = key.PublicKey.Blob.ToArray();
            tried.Add($"publickey ({algorithm})");

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
                return query!;
            }

            byte[] signature = Sign(key, algorithm, blob);
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
            return await ReadResultAsync(null, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if (credential.OwnsKey)
            {
                key.Dispose();
            }
        }
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

    private byte[] Sign(SshPrivateKey key, string algorithm, byte[] blob)
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
            return key.Sign(algorithm, writer.Written);
        }
        finally
        {
            writer.Dispose();
        }
    }

    private sealed record SendResult(Outcome Outcome, IReadOnlyList<string> Methods);
}

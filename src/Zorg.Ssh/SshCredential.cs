using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Zorg.Ssh;

/// <summary>One prompt from a keyboard-interactive exchange.</summary>
/// <param name="Text">The prompt to show. It's chosen by the server, so treat it as untrusted.</param>
/// <param name="Echo">Whether the answer may be shown as it's typed.</param>
/// <example>
/// <code>
/// SshCredential.FromKeyboardInteractive((prompts, ct) =>
///     ValueTask.FromResult&lt;IReadOnlyList&lt;string&gt;&gt;([.. prompts.Select(p => Ask(p.Text))]));
/// </code>
/// </example>
public sealed record SshPrompt(string Text, bool Echo);

/// <summary>A way to prove who the user is. List several in <see cref="SshClientOptions.Credentials"/>, and they're tried in order.</summary>
/// <example>
/// <code>
/// Credentials = [SshCredential.FromPrivateKeyFile("~/.ssh/id_ed25519"), SshCredential.FromPassword(password)],
/// </code>
/// </example>
public abstract class SshCredential
{
    private protected SshCredential()
    {
    }

    /// <summary>Creates a password credential.</summary>
    /// <param name="password">The password.</param>
    /// <returns>The credential.</returns>
    /// <example>
    /// <code>
    /// SshCredential credential = SshCredential.FromPassword(password);
    /// </code>
    /// </example>
    public static SshCredential FromPassword(string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        return new PasswordCredential(password);
    }

    /// <summary>Creates a credential that answers keyboard-interactive prompts.</summary>
    /// <param name="respond">Returns one answer per prompt.</param>
    /// <returns>The credential.</returns>
    /// <example>
    /// <code>
    /// SshCredential credential = SshCredential.FromKeyboardInteractive((prompts, ct) =>
    ///     ValueTask.FromResult&lt;IReadOnlyList&lt;string&gt;&gt;([.. prompts.Select(_ => code)]));
    /// </code>
    /// </example>
    public static SshCredential FromKeyboardInteractive(Func<IReadOnlyList<SshPrompt>, CancellationToken, ValueTask<IReadOnlyList<string>>> respond)
    {
        ArgumentNullException.ThrowIfNull(respond);
        return new KeyboardInteractiveCredential(respond);
    }
}

/// <summary>A password.</summary>
internal sealed class PasswordCredential(string password) : SshCredential
{
    public string Password { get; } = password;
}

/// <summary>Answers to server prompts.</summary>
internal sealed class KeyboardInteractiveCredential(
    Func<IReadOnlyList<SshPrompt>, CancellationToken, ValueTask<IReadOnlyList<string>>> respond) : SshCredential
{
    public Func<IReadOnlyList<SshPrompt>, CancellationToken, ValueTask<IReadOnlyList<string>>> Respond { get; } = respond;
}

/// <summary>A private key, loaded when it's needed and disposed afterwards.</summary>
internal sealed class PrivateKeyCredential(Func<Crypto.SshPrivateKey> load, bool ownsKey) : SshCredential
{
    public Crypto.SshPrivateKey Load() => load();

    public bool OwnsKey { get; } = ownsKey;
}

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

    /// <summary>Creates a credential from a private key file. It's read when it's needed, and <c>~</c> means the home directory.</summary>
    /// <param name="path">The key file: OpenSSH, PKCS#1, SEC1 or PKCS#8 format.</param>
    /// <param name="passphrase">The passphrase, if the file is encrypted.</param>
    /// <returns>The credential.</returns>
    /// <example>
    /// <code>
    /// SshCredential credential = SshCredential.FromPrivateKeyFile("~/.ssh/id_ed25519");
    /// </code>
    /// </example>
    public static SshCredential FromPrivateKeyFile(string path, string? passphrase = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        return new PrivateKeyCredential(
            () =>
            {
                try
                {
                    return Crypto.KeyFiles.SshKeyFile.Load(System.IO.File.ReadAllText(ExpandHome(path)), passphrase);
                }
                catch (Exception ex) when (ex is System.IO.IOException or UnauthorizedAccessException)
                {
                    throw new SshKeyFileException($"Couldn't read the key file {path}: {ex.Message}", ex);
                }
            },
            ownsKey: true);
    }

    /// <summary>Creates a credential from the text of a private key.</summary>
    /// <param name="keyText">The key file's contents.</param>
    /// <param name="passphrase">The passphrase, if the key is encrypted.</param>
    /// <returns>The credential.</returns>
    /// <example>
    /// <code>
    /// SshCredential credential = SshCredential.FromPrivateKey(secrets.Get("deploy-key"));
    /// </code>
    /// </example>
    public static SshCredential FromPrivateKey(string keyText, string? passphrase = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyText);
        return new PrivateKeyCredential(() => Crypto.KeyFiles.SshKeyFile.Load(keyText, passphrase), ownsKey: true);
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

    internal static string ExpandHome(string path) =>
        path.StartsWith("~/", StringComparison.Ordinal) || path.StartsWith("~\\", StringComparison.Ordinal)
            ? System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), path[2..])
            : path;
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

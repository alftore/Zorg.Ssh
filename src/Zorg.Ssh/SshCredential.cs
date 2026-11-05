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

    /// <summary>
    /// Creates a credential from a private key file, and optionally the OpenSSH certificate issued for that key. Both are
    /// read when they're needed, and <c>~</c> means the home directory. A certificate must be a user certificate for
    /// this key. Whether it's in date and has the right principals is for the server to say.
    /// </summary>
    /// <param name="path">The key file: OpenSSH, PKCS#1, SEC1 or PKCS#8 format.</param>
    /// <param name="passphrase">The passphrase, if the file is encrypted.</param>
    /// <param name="certificatePath">The certificate, usually the file ending <c>-cert.pub</c> that <c>ssh-keygen -s</c> wrote.</param>
    /// <returns>The credential.</returns>
    /// <example>
    /// <code>
    /// SshCredential plain = SshCredential.FromPrivateKeyFile("~/.ssh/id_ed25519");
    /// SshCredential certified = SshCredential.FromPrivateKeyFile("~/.ssh/id_ed25519", null, "~/.ssh/id_ed25519-cert.pub");
    /// </code>
    /// </example>
    public static SshCredential FromPrivateKeyFile(string path, string? passphrase = null, string? certificatePath = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        return certificatePath is null
            ? new PrivateKeyCredential(() => LoadKey(path, passphrase), ownsKey: true)
            : new PrivateKeyCredential(() => LoadCertifiedKey(path, passphrase, certificatePath), ownsKey: true);
    }

    /// <summary>
    /// Creates a credential that signs through an ssh-agent, so the private keys stay in the agent. The agent is found
    /// when it's needed: <paramref name="agentPath"/>, then <c>SSH_AUTH_SOCK</c> (a Unix socket, or a <c>\\.\pipe\</c>
    /// name), then on Windows the OpenSSH pipe <c>\\.\pipe\openssh-ssh-agent</c>. Each key is offered in the agent's
    /// order, and a key is only signed with once the server says it would take it. Every signature is checked against
    /// the key before it's sent.
    /// </summary>
    /// <param name="agentPath">Where the agent is, to use something other than the default.</param>
    /// <param name="maxKeysOffered">
    /// How many keys to offer at most, counting keys already refused in this login. Servers count each refused key
    /// against <c>MaxAuthTries</c>, which is 6 for OpenSSH, and then disconnect. If keys are left over, the login
    /// failure says so.
    /// </param>
    /// <returns>The credential.</returns>
    /// <example>
    /// <code>
    /// Credentials = [SshCredential.FromAgent(), SshCredential.FromPassword(password)],
    /// </code>
    /// </example>
    public static SshCredential FromAgent(string? agentPath = null, int maxKeysOffered = AgentCredential.DefaultMaxKeysOffered)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxKeysOffered, 1);
        return new AgentCredential(ct => Agent.SshAgentEndpoint.ConnectAsync(agentPath, ct), maxKeysOffered, isOptional: false);
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

    /// <summary>
    /// Makes a credential for an identity file named in a config file. Such a file may turn out to be unusable, such as
    /// when it's encrypted, and that must not end the login, as the next credential may work. A certificate beside
    /// the key is used, as <c>ssh</c> does.
    /// </summary>
    internal static SshCredential FromIdentityFile(string path)
    {
        string certificate = path + "-cert.pub";
        return new PrivateKeyCredential(
            () => System.IO.File.Exists(certificate) ? LoadCertifiedKey(path, null, certificate) : LoadKey(path, null),
            ownsKey: true,
            optionalName: path);
    }

    private static Crypto.SshPrivateKey LoadKey(string path, string? passphrase) =>
        Crypto.KeyFiles.SshKeyFile.Load(ReadKeyFile(path, "key"), passphrase);

    private static Crypto.Keys.CertifiedPrivateKey LoadCertifiedKey(string path, string? passphrase, string certificatePath)
    {
        string certificate = ReadKeyFile(certificatePath, "certificate");
        Crypto.SshPrivateKey key = LoadKey(path, passphrase);
        try
        {
            return Crypto.Keys.CertifiedPrivateKey.Adopt(key, certificate);
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    private static string ReadKeyFile(string path, string what)
    {
        try
        {
            return System.IO.File.ReadAllText(ExpandHome(path));
        }
        catch (Exception ex) when (ex is System.IO.IOException or UnauthorizedAccessException)
        {
            throw new SshKeyFileException($"Couldn't read the {what} file {path}: {ex.Message}", ex);
        }
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
internal sealed class PrivateKeyCredential(Func<Crypto.SshPrivateKey> load, bool ownsKey, string? optionalName = null) : SshCredential
{
    public Crypto.SshPrivateKey Load() => load();

    public bool OwnsKey { get; } = ownsKey;

    /// <summary>Gets the name to report if this key can't be loaded and is skipped. Null means a failure ends the login.</summary>
    public string? OptionalName { get; } = optionalName;
}

/// <summary>Keys in an ssh-agent. The connection lasts for one login.</summary>
internal sealed class AgentCredential(Func<CancellationToken, ValueTask<System.IO.Stream>> connect, int maxKeysOffered, bool isOptional) : SshCredential
{
    /// <summary>The default limit. OpenSSH's <c>MaxAuthTries</c> is 6 and it disconnects on the sixth failure.</summary>
    public const int DefaultMaxKeysOffered = 5;

    /// <summary>The longest wait for one answer. It's long enough for a person to confirm a signature in the agent.</summary>
    public static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(20);

    public int MaxKeysOffered { get; } = maxKeysOffered;

    /// <summary>Gets whether a missing agent is normal, as it is when a config file implies the agent rather than the caller asking for it.</summary>
    public bool IsOptional { get; } = isOptional;

    public async ValueTask<Agent.SshAgentConnection> ConnectAsync(CancellationToken cancellationToken) =>
        new(await connect(cancellationToken).ConfigureAwait(false), RequestTimeout);
}

using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Zorg.Ssh.Crypto;

namespace Zorg.Ssh;

/// <summary>What a host key check sees about a server.</summary>
/// <param name="Host">The host name that was connected to.</param>
/// <param name="Port">The port.</param>
/// <param name="KeyType">The key type, for example <c>ssh-ed25519</c>.</param>
/// <param name="Sha256Fingerprint">The key's fingerprint in OpenSSH form, for example <c>SHA256:abc...</c>.</param>
/// <example>
/// <code>
/// HostKeyPolicy.Custom((key, ct) => ValueTask.FromResult(key.Sha256Fingerprint == expected));
/// </code>
/// </example>
public sealed record SshHostKeyInfo(string Host, int Port, string KeyType, string Sha256Fingerprint);

/// <summary>
/// Decides whether to trust a server's host key. There is no default that accepts unknown keys: without
/// this check, a connection can be intercepted without anyone noticing.
/// </summary>
/// <example>
/// <code>
/// HostKeyPolicy = HostKeyPolicy.Fingerprint("SHA256:n4cHVJ8c0vCpJiQJCbOgLEUxOkKrDhVJzcEKHnSSd9E"),
/// </code>
/// </example>
public abstract class HostKeyPolicy
{
    private protected HostKeyPolicy()
    {
    }

    /// <summary>
    /// Checks the server against an OpenSSH <c>known_hosts</c> file, the usual choice. An unknown host is refused:
    /// nothing is added to the file unless <paramref name="addUnknownHostsUnsafe"/> is set.
    /// </summary>
    /// <param name="path">The file. The default is <c>~/.ssh/known_hosts</c>.</param>
    /// <param name="addUnknownHostsUnsafe">
    /// Trusts a host seen for the first time, and records it, as <c>ssh -o StrictHostKeyChecking=accept-new</c>
    /// does. <b>A first connection can then be intercepted without anyone noticing.</b> A changed key is still refused.
    /// </param>
    /// <returns>The policy.</returns>
    /// <example>
    /// <code>
    /// HostKeyPolicy policy = HostKeyPolicy.KnownHostsFile();
    /// </code>
    /// </example>
    public static HostKeyPolicy KnownHostsFile(string path = "~/.ssh/known_hosts", bool addUnknownHostsUnsafe = false)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        return new KnownHostsPolicy(SshCredential.ExpandHome(path), addUnknownHostsUnsafe);
    }

    /// <summary>Trusts only the key with this fingerprint, the safest choice when you know it.</summary>
    /// <param name="sha256Fingerprint">The fingerprint from <c>ssh-keygen -lf</c>, starting <c>SHA256:</c>.</param>
    /// <returns>The policy.</returns>
    /// <example>
    /// <code>
    /// HostKeyPolicy policy = HostKeyPolicy.Fingerprint("SHA256:n4cHVJ8c0vCpJiQJCbOgLEUxOkKrDhVJzcEKHnSSd9E");
    /// </code>
    /// </example>
    public static HostKeyPolicy Fingerprint(string sha256Fingerprint)
    {
        ArgumentException.ThrowIfNullOrEmpty(sha256Fingerprint);
        return new CustomHostKeyPolicy((key, _) => ValueTask.FromResult(
            string.Equals(key.Sha256Fingerprint, sha256Fingerprint, StringComparison.Ordinal)));
    }

    /// <summary>Runs your own check. Return true to trust the key.</summary>
    /// <param name="check">The check. It runs once, during connection.</param>
    /// <returns>The policy.</returns>
    /// <example>
    /// <code>
    /// HostKeyPolicy policy = HostKeyPolicy.Custom((key, ct) => store.IsTrustedAsync(key.Sha256Fingerprint, ct));
    /// </code>
    /// </example>
    public static HostKeyPolicy Custom(Func<SshHostKeyInfo, CancellationToken, ValueTask<bool>> check)
    {
        ArgumentNullException.ThrowIfNull(check);
        return new CustomHostKeyPolicy(check);
    }

    /// <summary>
    /// Trusts any host key. <b>This removes protection against interception</b>, so use it only for tests
    /// against a machine you control.
    /// </summary>
    /// <returns>The policy.</returns>
    /// <example>
    /// <code>
    /// HostKeyPolicy policy = HostKeyPolicy.AcceptAnyUnsafe();
    /// </code>
    /// </example>
    public static HostKeyPolicy AcceptAnyUnsafe() => new CustomHostKeyPolicy(static (_, _) => ValueTask.FromResult(true));

    internal static string ComputeFingerprint(ReadOnlySpan<byte> blob) =>
        "SHA256:" + Convert.ToBase64String(SHA256.HashData(blob)).TrimEnd('=');

    internal abstract ValueTask<bool> CheckAsync(string host, int port, SshPublicKey key, CancellationToken cancellationToken);
}

/// <summary>A check against a known_hosts file. It explains itself by exception, because "not trusted" alone is no help here.</summary>
internal sealed class KnownHostsPolicy(string path, bool addUnknown) : HostKeyPolicy
{
    internal override ValueTask<bool> CheckAsync(string host, int port, SshPublicKey key, CancellationToken cancellationToken)
    {
        string fingerprint = ComputeFingerprint(key.Blob.Span);
        switch (KnownHosts.KnownHostsFile.Load(path).Lookup(host, port, key))
        {
            case KnownHosts.KnownHostStatus.Trusted:
                return ValueTask.FromResult(true);
            case KnownHosts.KnownHostStatus.Revoked:
                throw new SshHostKeyException($"The host key of {host} ({fingerprint}) is marked revoked in {path}. Don't connect until the administrator has replaced it.");
            case KnownHosts.KnownHostStatus.Changed:
                throw new SshHostKeyException($"The host key of {host} has changed to {fingerprint}, or the server offered a different key type from the one in {path}. This can mean an attack: check with the server's administrator before updating the file.");
            default:
                if (addUnknown)
                {
                    KnownHosts.KnownHostsFile.Append(path, host, port, key);
                    return ValueTask.FromResult(true);
                }

                throw new SshHostKeyException($"{host} isn't in {path}. Its key is {key.KeyType} {fingerprint}. Check that with the server's administrator, then add it, for example by connecting once with ssh.");
        }
    }
}

/// <summary>A check based on a delegate.</summary>
internal sealed class CustomHostKeyPolicy(Func<SshHostKeyInfo, CancellationToken, ValueTask<bool>> check) : HostKeyPolicy
{
    internal override ValueTask<bool> CheckAsync(string host, int port, SshPublicKey key, CancellationToken cancellationToken) =>
        check(new SshHostKeyInfo(host, port, key.KeyType, ComputeFingerprint(key.Blob.Span)), cancellationToken);
}

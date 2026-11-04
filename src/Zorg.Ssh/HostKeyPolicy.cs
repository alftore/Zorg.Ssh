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

/// <summary>A check based on a delegate.</summary>
internal sealed class CustomHostKeyPolicy(Func<SshHostKeyInfo, CancellationToken, ValueTask<bool>> check) : HostKeyPolicy
{
    internal override ValueTask<bool> CheckAsync(string host, int port, SshPublicKey key, CancellationToken cancellationToken) =>
        check(new SshHostKeyInfo(host, port, key.KeyType, ComputeFingerprint(key.Blob.Span)), cancellationToken);
}

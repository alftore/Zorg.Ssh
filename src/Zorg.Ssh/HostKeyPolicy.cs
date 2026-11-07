using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.Keys;
using Zorg.Ssh.KnownHosts;

namespace Zorg.Ssh;

/// <summary>What a host key check sees about a server.</summary>
/// <example>
/// <code>
/// HostKeyPolicy.Custom((key, ct) => ValueTask.FromResult(key.Sha256Fingerprint == expected));
/// </code>
/// </example>
public sealed record SshHostKeyInfo
{
    /// <summary>Gets the host name that was connected to.</summary>
    public required string Host { get; init; }

    /// <summary>Gets the port.</summary>
    public required int Port { get; init; }

    /// <summary>Gets the key type, for example <c>ssh-ed25519</c>.</summary>
    public required string KeyType { get; init; }

    /// <summary>Gets the key's fingerprint in OpenSSH form, for example <c>SHA256:abc...</c>.</summary>
    public required string Sha256Fingerprint { get; init; }

    /// <summary>
    /// Gets the key in OpenSSH public key form, <c>type base64</c>, as a <c>known_hosts</c> line or a <c>.pub</c> file
    /// holds it. A trust-on-first-use store can record this, and compare it next time.
    /// </summary>
    /// <example>
    /// <code>
    /// await File.AppendAllTextAsync(storePath, $"{key.Host} {key.PublicKey}\n", ct);
    /// </code>
    /// </example>
    public required string PublicKey { get; init; }

    /// <summary>Describes a key the server offered, as every check and <see cref="SshClient.HostKey"/> see it.</summary>
    internal static SshHostKeyInfo From(string host, int port, SshPublicKey key) => new()
    {
        Host = host,
        Port = port,
        KeyType = key.KeyType,
        Sha256Fingerprint = HostKeyPolicy.ComputeFingerprint(key.Blob.Span),
        PublicKey = $"{key.KeyType} {Convert.ToBase64String(key.Blob.Span)}",
    };
}

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
    /// Checks the server against an OpenSSH <c>known_hosts</c> file, the usual choice. An unknown host is refused, and
    /// nothing is ever written to the file. To trust a host on first use, see <see cref="KnownHostsFileAcceptNewUnsafe"/>.
    /// </summary>
    /// <param name="path">The file. The default is <c>~/.ssh/known_hosts</c>.</param>
    /// <param name="globalPaths">
    /// More files to read, as OpenSSH reads <c>/etc/ssh/ssh_known_hosts</c>, where an administrator puts <c>@revoked</c>
    /// and <c>@cert-authority</c> lines. They are looked up and never written to. The default, null, reads none, so that
    /// the result depends only on the files you name. <see cref="SshClientOptions.FromConfig"/> reads the OpenSSH defaults.
    /// </param>
    /// <param name="timeProvider">The clock for checking host certificates. The default is the system clock.</param>
    /// <returns>The policy.</returns>
    /// <remarks>
    /// A host certificate is accepted when a <c>@cert-authority</c> line for the host names its CA, and it's a host
    /// certificate, in date, with a principal that matches the host name and no critical options. A certificate with
    /// no principals is refused, although OpenSSH reads that as valid for any host. Any failure is a
    /// <see cref="SshHostKeyException"/> that says which check failed. <c>@revoked</c> applies to the certificate, its
    /// key and its CA.
    /// </remarks>
    /// <example>
    /// <code>
    /// HostKeyPolicy policy = HostKeyPolicy.KnownHostsFile();
    /// </code>
    /// </example>
    public static HostKeyPolicy KnownHostsFile(
        string path = "~/.ssh/known_hosts",
        IReadOnlyList<string>? globalPaths = null,
        TimeProvider? timeProvider = null) => CreateKnownHosts(path, addUnknown: false, globalPaths, timeProvider);

    /// <summary>
    /// Checks the server against an OpenSSH <c>known_hosts</c> file as <see cref="KnownHostsFile"/> does, but trusts a
    /// host seen for the first time and records it in <paramref name="path"/>, as <c>ssh -o StrictHostKeyChecking=accept-new</c>
    /// does. <b>A first connection can then be intercepted without anyone noticing.</b> A changed key is still refused.
    /// </summary>
    /// <param name="path">The file to check and to record new hosts in. The default is <c>~/.ssh/known_hosts</c>.</param>
    /// <param name="globalPaths">More files to read, as for <see cref="KnownHostsFile"/>. They are never written to.</param>
    /// <param name="timeProvider">The clock for checking host certificates. The default is the system clock.</param>
    /// <returns>The policy.</returns>
    /// <remarks>
    /// A host that a <c>@cert-authority</c> line covers is never recorded, so offering a plain key can't step around the
    /// CA. A file that can't keep what is written to it, such as <c>/dev/null</c> or <c>NUL</c>, makes the connection fail.
    /// </remarks>
    /// <example>
    /// <code>
    /// HostKeyPolicy policy = HostKeyPolicy.KnownHostsFileAcceptNewUnsafe();
    /// </code>
    /// </example>
    public static HostKeyPolicy KnownHostsFileAcceptNewUnsafe(
        string path = "~/.ssh/known_hosts",
        IReadOnlyList<string>? globalPaths = null,
        TimeProvider? timeProvider = null) => CreateKnownHosts(path, addUnknown: true, globalPaths, timeProvider);

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

    /// <summary>
    /// Runs your own check. Return true to trust the key. If the check throws, the key isn't trusted, and the connection
    /// fails with <see cref="SshHostKeyException"/> whose <see cref="Exception.InnerException"/> is yours.
    /// </summary>
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

    private static KnownHostsPolicy CreateKnownHosts(string path, bool addUnknown, IReadOnlyList<string>? globalPaths, TimeProvider? timeProvider)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        return new KnownHostsPolicy(
            [SshCredential.ExpandHome(path)],
            addUnknown,
            timeProvider ?? TimeProvider.System,
            globalPaths is null ? null : [.. globalPaths.Select(SshCredential.ExpandHome)]);
    }

    internal static string ComputeFingerprint(ReadOnlySpan<byte> blob) =>
        "SHA256:" + Convert.ToBase64String(SHA256.HashData(blob)).TrimEnd('=');

    /// <summary>Gets the host key algorithms to offer. Certificates are only asked for where they can be checked.</summary>
    internal virtual IReadOnlyList<string> HostKeyAlgorithmsFor(string host, int port) => HostKeyAlgorithms.Default;

    internal abstract ValueTask<bool> CheckAsync(string host, int port, SshPublicKey key, CancellationToken cancellationToken);
}

/// <summary>A check against a known_hosts file. It explains itself by exception, because "not trusted" alone is no help here.</summary>
internal sealed class KnownHostsPolicy(IReadOnlyList<string> paths, bool addUnknown, TimeProvider timeProvider, IReadOnlyList<string>? globalPaths = null) : HostKeyPolicy
{
    private string PathText => AllPaths.Length == 0 ? "the known hosts files (there are none)" : string.Join(", ", AllPaths);

    private string[] AllPaths => [.. paths, .. globalPaths ?? []];

    internal override IReadOnlyList<string> HostKeyAlgorithmsFor(string host, int port)
    {
        try
        {
            if (Load().Any(file => file.HasCertificateAuthority(host, port)))
            {
                return [.. SshCertificate.HostKeyAlgorithmNames, .. HostKeyAlgorithms.Default];
            }
        }
        catch (Exception ex) when (ex is SshHostKeyException or IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            // Plain algorithms never trust anything by themselves, and the check itself reports this failure.
        }

        return HostKeyAlgorithms.Default;
    }

    internal override ValueTask<bool> CheckAsync(string host, int port, SshPublicKey key, CancellationToken cancellationToken)
    {
        KnownHosts.KnownHostsFile[] files = Load();
        if (key is SshCertificate certificate)
        {
            HostCertificateCheck.Ensure(certificate, host, port, files, PathText, timeProvider.GetUtcNow());
            return ValueTask.FromResult(true);
        }

        string fingerprint = ComputeFingerprint(key.Blob.Span);
        KnownHostStatus[] statuses = [.. files.Select(file => file.Lookup(host, port, key))];
        if (statuses.Contains(KnownHostStatus.Revoked))
        {
            throw new SshHostKeyException($"The host key of {host} ({fingerprint}) is marked revoked in {PathText}. Don't connect until the administrator has replaced it.");
        }

        if (statuses.Contains(KnownHostStatus.Trusted))
        {
            return ValueTask.FromResult(true);
        }

        if (statuses.Contains(KnownHostStatus.Changed))
        {
            throw new SshHostKeyException($"The host key of {host} has changed to {fingerprint}, or the server offered a different key type from the one in {PathText}. This can mean an attack: check with the server's administrator before updating the file.");
        }

        // Recording a new key here would let an attacker step around the CA just by not offering a certificate.
        if (addUnknown && paths.Count > 0 && !files.Any(file => file.HasCertificateAuthority(host, port)))
        {
            KnownHosts.KnownHostsFile.Append(paths[0], host, port, key);
            return ValueTask.FromResult(true);
        }

        throw new SshHostKeyException($"{host} isn't in {PathText}. Its key is {key.KeyType} {fingerprint}. Check that with the server's administrator, then add it, for example by connecting once with ssh.");
    }

    private KnownHosts.KnownHostsFile[] Load() => [.. AllPaths.Select(KnownHosts.KnownHostsFile.Load)];
}

/// <summary>A check based on a delegate.</summary>
internal sealed class CustomHostKeyPolicy(Func<SshHostKeyInfo, CancellationToken, ValueTask<bool>> check) : HostKeyPolicy
{
    internal override ValueTask<bool> CheckAsync(string host, int port, SshPublicKey key, CancellationToken cancellationToken) =>
        key is SshCertificate
            ? throw new SshHostKeyException("The server sent a host certificate, which only HostKeyPolicy.KnownHostsFile can check.")
            : check(SshHostKeyInfo.From(host, port, key), cancellationToken);
}

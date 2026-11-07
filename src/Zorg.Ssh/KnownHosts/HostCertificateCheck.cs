using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Zorg.Ssh.Crypto.Keys;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.KnownHosts;

/// <summary>
/// Decides whether a host certificate is good for a host. By now the server has proved it holds the subject key, so
/// this is everything else. Each failure says which check failed, because "not trusted" tells an administrator nothing.
/// </summary>
internal static class HostCertificateCheck
{
    private const int MaxShownLength = 64;
    private const int MaxPrincipalsShown = 8;

    /// <summary>The last second a <see cref="DateTimeOffset"/> can hold, as a Unix time.</summary>
    private const ulong MaxPrintableTime = 253402300799;

    /// <summary>Returns if the certificate is good. Otherwise it throws <see cref="SshHostKeyException"/>.</summary>
    public static void Ensure(SshCertificate certificate, string host, int port, IReadOnlyList<KnownHostsFile> files, string pathText, DateTimeOffset now)
    {
        string subject = $"The host certificate of {host} (serial {certificate.Serial}, key ID \"{PeerText.Clean(certificate.KeyId, MaxShownLength)}\")";

        // First, so that a revoked CA reads as revoked and not as a broken signature or an expired certificate.
        if (files.Any(file => file.IsRevoked(host, port, certificate.Blob.Span) || file.IsRevoked(host, port, certificate.Key.Blob.Span)))
        {
            throw new SshHostKeyException($"{subject} is for a key marked revoked in {pathText}. Don't connect until the administrator has replaced it.");
        }

        // By value: the CA signed over the bytes it sent, but the CA's identity is its key, however its mpints are spelled.
        ReadOnlyMemory<byte> ca = RsaPublicKey.Canonicalize(certificate.SignatureKeyBlob.Span);
        if (files.Any(file => file.IsRevoked(host, port, ca.Span)))
        {
            throw new SshHostKeyException($"{subject} was signed by a CA marked revoked in {pathText}. Don't connect until the administrator has reissued it.");
        }

        if (!files.Any(file => file.IsCertificateAuthority(host, port, ca.Span)))
        {
            throw new SshHostKeyException($"{subject} was signed by a CA that {pathText} doesn't list for this host, whose fingerprint is {HostKeyPolicy.ComputeFingerprint(ca.Span)}. This can mean an attack: check the CA with the server's administrator.");
        }

        if (certificate.CheckCaSignature() is { } reason)
        {
            throw new SshHostKeyException($"{subject} was refused: {reason}. This can mean an attack, so the connection was closed.");
        }

        if (certificate.CertificateType != SshCertificate.HostType)
        {
            string type = certificate.CertificateType == SshCertificate.UserType ? "a user certificate" : "of an unknown certificate type";
            throw new SshHostKeyException($"{subject} is {type}, not a host certificate. A host must present a certificate issued with ssh-keygen -h.");
        }

        // None are defined for hosts, so any at all is one that isn't understood, and the format says to refuse those.
        if (certificate.CriticalOptions.Count != 0)
        {
            throw new SshHostKeyException($"{subject} has a critical option that isn't understood ({PeerText.Clean(certificate.CriticalOptions[0], MaxShownLength)}), so it must be refused. Ask the CA to reissue it without one.");
        }

        ulong time = (ulong)now.ToUnixTimeSeconds();
        if (time < certificate.ValidAfter)
        {
            throw new SshHostKeyException($"{subject} isn't valid yet: it starts at {Format(certificate.ValidAfter)}, and this machine's clock says {now:u}. Check both clocks.");
        }

        if (time >= certificate.ValidBefore)
        {
            throw new SshHostKeyException($"{subject} has expired: it ended at {Format(certificate.ValidBefore)}, and this machine's clock says {now:u}. Ask the administrator to renew it.");
        }

        // Empty means any host to OpenSSH. Here it's refused: one such certificate would pass for every host under the CA.
        if (certificate.Principals.Count == 0)
        {
            throw new SshHostKeyException($"{subject} names no principals, so nothing ties it to this host. Ask the CA to reissue it with ssh-keygen -n.");
        }

        if (!certificate.Principals.Any(p => KnownHostsEntry.MatchesGlob(p, host)))
        {
            string names = string.Join(", ", certificate.Principals.Take(MaxPrincipalsShown).Select(p => PeerText.Clean(p, MaxShownLength)));
            throw new SshHostKeyException($"{subject} isn't valid for this host name: it lists [{names}]. This can mean an attack. If it's the right server, connect by a name the certificate lists.");
        }
    }

    private static string Format(ulong unixSeconds) => unixSeconds > MaxPrintableTime
        ? unixSeconds.ToString(CultureInfo.InvariantCulture)
        : DateTimeOffset.FromUnixTimeSeconds((long)unixSeconds).ToString("u", CultureInfo.InvariantCulture);
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Zorg.Ssh.Crypto.KeyExchange;

namespace Zorg.Ssh.Crypto;

/// <summary>
/// The names <see cref="SshAlgorithms.LegacyUnsafe"/> appends to the defaults. Names only: nothing here reaches an
/// implementation, so <see cref="SshAlgorithms.Validate"/> can know them without keeping the code alive.
/// </summary>
/// <remarks>
/// Never added, whoever asks: <c>diffie-hellman-group1-sha1</c> (Logjam), the group exchange methods (a server-chosen
/// prime is a validation surface for little gain), <c>ssh-dss</c>, <c>3des-cbc</c>, arcfour, MD5 MACs and every CBC cipher.
/// </remarks>
internal static class LegacyAlgorithms
{
    public const string DhGroup14Sha256 = "diffie-hellman-group14-sha256";
    public const string DhGroup16Sha512 = "diffie-hellman-group16-sha512";
    public const string DhGroup14Sha1 = "diffie-hellman-group14-sha1";

    /// <summary>The <c>ssh-rsa</c> signature algorithm: RSA PKCS#1 v1.5 with SHA-1 (RFC 4253 section 6.6).</summary>
    public const string RsaSha1 = "ssh-rsa";

    public const string HmacSha1Etm = "hmac-sha1-etm@openssh.com";
    public const string HmacSha1 = "hmac-sha1";

    /// <summary>Gets the key exchange names, in the order they're appended.</summary>
    public static IReadOnlyList<string> KeyExchange { get; } = Array.AsReadOnly([DhGroup14Sha256, DhGroup16Sha512, DhGroup14Sha1]);

    /// <summary>Gets the host key and signature names.</summary>
    public static IReadOnlyList<string> HostKeys { get; } = Array.AsReadOnly([RsaSha1]);

    /// <summary>Gets the MAC names.</summary>
    public static IReadOnlyList<string> Macs { get; } = Array.AsReadOnly([HmacSha1Etm, HmacSha1]);

    /// <summary>Gets whether a name is one of these. A negotiated one is logged as a warning.</summary>
    public static bool IsLegacy(string? name) =>
        name is not null && (KeyExchange.Contains(name) || HostKeys.Contains(name) || Macs.Contains(name));

    /// <summary>Gets whether a name is a finite-field Diffie-Hellman method, which a server offers only when named explicitly.</summary>
    public static bool IsFiniteFieldDh(string name) => KeyExchange.Contains(name);
}

/// <summary>
/// Creates key exchange methods that <see cref="KeyExchangeCatalog"/> doesn't hold. An instance is made only by
/// <see cref="SshAlgorithms.LegacyUnsafe"/> or by an explicit <see cref="SshAlgorithms.KeyExchange"/> list, and the
/// transport reaches the methods only through it. An application that does neither never constructs one, so Native AOT
/// and trimming leave out the finite-field code (the modular exponentiation and the RFC 3526 primes).
/// </summary>
internal abstract class KeyExchangeExtension
{
    /// <summary>Creates one run of a method, or returns null if the name isn't one of this extension's.</summary>
    /// <param name="name">The negotiated name.</param>
    /// <param name="keyNeedBytes">The longest key, IV or MAC key the session will derive, in bytes.</param>
    public abstract KeyExchangeMethod? Create(string name, int keyNeedBytes);
}

/// <summary>The finite-field Diffie-Hellman methods.</summary>
internal sealed class FiniteFieldDhExtension : KeyExchangeExtension
{
    public static readonly FiniteFieldDhExtension Instance = new();

    private FiniteFieldDhExtension()
    {
    }

    /// <inheritdoc/>
    public override KeyExchangeMethod? Create(string name, int keyNeedBytes) => name switch
    {
        LegacyAlgorithms.DhGroup14Sha256 => new FiniteFieldDhKeyExchange(DiffieHellmanGroup.Group14, HashAlgorithmName.SHA256, keyNeedBytes),
        LegacyAlgorithms.DhGroup16Sha512 => new FiniteFieldDhKeyExchange(DiffieHellmanGroup.Group16, HashAlgorithmName.SHA512, keyNeedBytes),
        LegacyAlgorithms.DhGroup14Sha1 => new FiniteFieldDhKeyExchange(DiffieHellmanGroup.Group14, HashAlgorithmName.SHA1, keyNeedBytes),
        _ => null,
    };
}

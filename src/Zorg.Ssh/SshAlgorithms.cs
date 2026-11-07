using System;
using System.Collections.Generic;
using System.Linq;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.Keys;

namespace Zorg.Ssh;

/// <summary>
/// Which algorithms a connection offers, most preferred first. The defaults are current and need no tuning,
/// so set this only to narrow them, for example to meet a policy, or use <see cref="LegacyUnsafe"/> for old equipment.
/// Names that aren't supported are refused.
/// </summary>
/// <example>
/// <code>
/// Algorithms = new SshAlgorithms { Ciphers = ["aes256-gcm@openssh.com"] },
/// </code>
/// </example>
public sealed class SshAlgorithms
{
    private readonly IReadOnlyList<string> _keyExchange = KeyExchangeCatalog.Default;
    private readonly IReadOnlyList<string> _hostKeys = HostKeyAlgorithms.Default;
    private readonly bool _keyExchangeIsExplicit;
    private readonly bool _hostKeysIsExplicit;
    private readonly KeyExchangeExtension? _keyExchangeExtension;

    /// <summary>Creates the defaults, for narrowing with an object initializer.</summary>
    public SshAlgorithms()
    {
    }

    /// <summary>Makes a preset. Its lists don't count as explicit.</summary>
    private SshAlgorithms(IReadOnlyList<string> keyExchange, IReadOnlyList<string> hostKeys, IReadOnlyList<string> macs, KeyExchangeExtension extension)
    {
        _keyExchange = keyExchange;
        _hostKeys = hostKeys;
        Macs = macs;
        _keyExchangeExtension = extension;
    }

    /// <summary>Gets the defaults.</summary>
    public static SshAlgorithms Default { get; } = new();

    /// <summary>
    /// Gets the defaults followed by older algorithms that some network equipment, BMCs and old servers still need:
    /// <c>diffie-hellman-group14-sha256</c>, <c>diffie-hellman-group16-sha512</c> and <c>diffie-hellman-group14-sha1</c> key
    /// exchange, <c>ssh-rsa</c> (RSA with SHA-1) host keys and signatures, and the <c>hmac-sha1-etm@openssh.com</c> and
    /// <c>hmac-sha1</c> MACs. A peer that has anything better still gets it, and choosing a legacy algorithm logs a
    /// warning that names it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// None of these has a known attack that works against one live session, but SHA-1 signatures can be forged with a
    /// chosen-prefix collision for long-lived data, and the finite-field groups are slow. Use this only for a peer that has
    /// nothing else, and prefer to upgrade the peer. <c>diffie-hellman-group1-sha1</c>, group exchange, <c>ssh-dss</c>,
    /// 3DES, arcfour, MD5 and CBC are never offered. Certificates signed by their CA with SHA-1 stay refused.
    /// </para>
    /// <para>
    /// On a server, finite-field Diffie-Hellman costs CPU that a client can make it spend before login, so a server offers
    /// it only when <see cref="KeyExchange"/> names it explicitly, as OpenSSH 10's sshd does. This preset adds <c>ssh-rsa</c>
    /// and the SHA-1 MACs on a server, but not Diffie-Hellman. A narrowed list may name any of these algorithms directly.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// SshClientOptions options = new() { Host = "switch.example", UserName = "admin", HostKeyPolicy = policy, Algorithms = SshAlgorithms.LegacyUnsafe };
    /// </code>
    /// </example>
    public static SshAlgorithms LegacyUnsafe => LegacyPreset.Instance;

    /// <summary>Gets the key exchange methods.</summary>
    public IReadOnlyList<string> KeyExchange
    {
        get => _keyExchange;
        init
        {
            _keyExchange = value;
            _keyExchangeIsExplicit = true;

            // An explicit list may name a finite-field method. The extension is reached only from here and from
            // LegacyUnsafe, so an application that does neither lets trimming drop it.
            _keyExchangeExtension = FiniteFieldDhExtension.Instance;
        }
    }

    /// <summary>Gets the host key algorithms.</summary>
    public IReadOnlyList<string> HostKeys
    {
        get => _hostKeys;
        init
        {
            _hostKeys = value;
            _hostKeysIsExplicit = true;
        }
    }

    /// <summary>Gets the ciphers.</summary>
    public IReadOnlyList<string> Ciphers { get; init; } = PacketCipherCatalog.DefaultCiphers;

    /// <summary>Gets the MACs, used only with ciphers that don't authenticate on their own.</summary>
    public IReadOnlyList<string> Macs { get; init; } = PacketCipherCatalog.DefaultMacs;

    /// <summary>Gets whether <see cref="KeyExchange"/> was set, rather than taken from a preset. A server offers finite-field Diffie-Hellman only then.</summary>
    internal bool KeyExchangeIsExplicit => _keyExchangeIsExplicit;

    /// <summary>Gets whether <see cref="HostKeys"/> was set. Otherwise a client lets its host key policy put certificate algorithms first.</summary>
    internal bool HostKeysIsExplicit => _hostKeysIsExplicit;

    /// <summary>Gets the creator of the key exchange methods outside the default catalog, or null when none can be named.</summary>
    internal KeyExchangeExtension? KeyExchangeExtension => _keyExchangeExtension;

    /// <summary>Gets whether <c>ssh-rsa</c> (SHA-1) signatures may be used, for host keys and for user authentication.</summary>
    internal bool AllowsRsaSha1 => HostKeys.Contains(LegacyAlgorithms.RsaSha1);

    /// <summary>Gets what a server lists in <c>server-sig-algs</c>: the defaults, and <c>ssh-rsa</c> when it's allowed.</summary>
    internal IReadOnlyList<string> ServerSignatureAlgorithms =>
        AllowsRsaSha1 ? [.. HostKeyAlgorithms.Default, LegacyAlgorithms.RsaSha1] : HostKeyAlgorithms.Default;

    /// <summary>Gets the key exchange list a server offers: finite-field Diffie-Hellman only if it was named explicitly.</summary>
    internal IReadOnlyList<string> ServerKeyExchange =>
        KeyExchangeIsExplicit ? KeyExchange : [.. KeyExchange.Where(name => !LegacyAlgorithms.IsFiniteFieldDh(name))];

    /// <summary>
    /// Gets the host key list a client offers. An explicit list is the caller's. Otherwise the host key policy's list, which
    /// can put certificate algorithms first, followed by a preset's legacy names (<c>ssh-rsa</c> in <see cref="LegacyUnsafe"/>).
    /// </summary>
    internal IReadOnlyList<string> ClientHostKeys(Func<IReadOnlyList<string>> policyList) =>
        HostKeysIsExplicit ? HostKeys : [.. policyList(), .. HostKeys.Where(name => !HostKeyAlgorithms.Default.Contains(name))];

    /// <summary>Checks every name, so a typo fails here and not as a confusing negotiation error later.</summary>
    internal void Validate()
    {
        Check("KeyExchange", KeyExchange, KeyExchangeCatalog.Default, LegacyAlgorithms.KeyExchange);
        Check("HostKeys", HostKeys, HostKeyAlgorithms.Default, LegacyAlgorithms.HostKeys);
        Check("Ciphers", Ciphers, PacketCipherCatalog.DefaultCiphers, []);
        Check("Macs", Macs, PacketCipherCatalog.DefaultMacs, LegacyAlgorithms.Macs);
    }

    private static void Check(string family, IReadOnlyList<string> chosen, IReadOnlyList<string> supported, IReadOnlyList<string> legacy)
    {
        if (chosen.Count == 0)
        {
            throw new ArgumentException($"SshAlgorithms.{family} can't be empty.", family);
        }

        foreach (string name in chosen)
        {
            if (!supported.Contains(name) && !legacy.Contains(name))
            {
                string older = legacy.Count == 0 ? string.Empty : $" SshAlgorithms.LegacyUnsafe adds: {string.Join(", ", legacy)}.";
                throw new ArgumentException($"'{name}' isn't a supported value for SshAlgorithms.{family}. Supported: {string.Join(", ", supported)}.{older}", family);
            }
        }
    }

    /// <summary>Holds the preset, so that it, and the code it reaches, exist only once something asks for it.</summary>
    private static class LegacyPreset
    {
        // The legacy names go last, so a modern peer still negotiates a modern algorithm. Each KEXINIT is in the signed
        // exchange hash, so a man in the middle can't remove the modern names to push the choice down to these.
        public static readonly SshAlgorithms Instance = new(
            Array.AsReadOnly([.. KeyExchangeCatalog.Default, .. LegacyAlgorithms.KeyExchange]),
            Array.AsReadOnly([.. HostKeyAlgorithms.Default, .. LegacyAlgorithms.HostKeys]),
            Array.AsReadOnly([.. PacketCipherCatalog.DefaultMacs, .. LegacyAlgorithms.Macs]),
            FiniteFieldDhExtension.Instance);
    }
}

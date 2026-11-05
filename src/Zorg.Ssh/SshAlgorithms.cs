using System;
using System.Collections.Generic;
using System.Linq;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.Keys;

namespace Zorg.Ssh;

/// <summary>
/// Which algorithms a connection offers, most preferred first. The defaults are current and need no tuning,
/// so set this only to narrow them, for example to meet a policy. Names that aren't supported are refused.
/// </summary>
/// <example>
/// <code>
/// Algorithms = new SshAlgorithms { Ciphers = ["aes256-gcm@openssh.com"] },
/// </code>
/// </example>
public sealed class SshAlgorithms
{
    /// <summary>Gets the defaults.</summary>
    public static SshAlgorithms Default { get; } = new();

    /// <summary>Gets the key exchange methods.</summary>
    public IReadOnlyList<string> KeyExchange { get; init; } = KeyExchangeCatalog.Default;

    /// <summary>Gets the host key algorithms.</summary>
    public IReadOnlyList<string> HostKeys { get; init; } = HostKeyAlgorithms.Default;

    /// <summary>Gets the ciphers.</summary>
    public IReadOnlyList<string> Ciphers { get; init; } = PacketCipherCatalog.DefaultCiphers;

    /// <summary>Gets the MACs, used only with ciphers that don't authenticate on their own.</summary>
    public IReadOnlyList<string> Macs { get; init; } = PacketCipherCatalog.DefaultMacs;

    /// <summary>Checks every name, so a typo fails here and not as a confusing negotiation error later.</summary>
    internal void Validate()
    {
        Check("KeyExchange", KeyExchange, KeyExchangeCatalog.Default);
        Check("HostKeys", HostKeys, HostKeyAlgorithms.Default);
        Check("Ciphers", Ciphers, PacketCipherCatalog.DefaultCiphers);
        Check("Macs", Macs, PacketCipherCatalog.DefaultMacs);
    }

    private static void Check(string family, IReadOnlyList<string> chosen, IReadOnlyList<string> supported)
    {
        if (chosen.Count == 0)
        {
            throw new ArgumentException($"SshAlgorithms.{family} can't be empty.", family);
        }

        foreach (string name in chosen)
        {
            if (!supported.Contains(name))
            {
                throw new ArgumentException($"'{name}' isn't a supported value for SshAlgorithms.{family}. Supported: {string.Join(", ", supported)}.", family);
            }
        }
    }
}

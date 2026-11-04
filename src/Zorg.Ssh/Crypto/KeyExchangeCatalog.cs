using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Zorg.Ssh.Crypto.KeyExchange;
using Zorg.Ssh.Crypto.Keys;

namespace Zorg.Ssh.Crypto;

/// <summary>The key exchange methods this library implements, by their SSH names.</summary>
internal static class KeyExchangeCatalog
{
    /// <summary>Gets the default method names, most preferred first.</summary>
    public static IReadOnlyList<string> Default { get; } = Array.AsReadOnly(
    [
        "mlkem768x25519-sha256",
        "sntrup761x25519-sha512",
        "sntrup761x25519-sha512@openssh.com",
        "curve25519-sha256",
        "curve25519-sha256@libssh.org",
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
    ]);

    /// <summary>Creates one run of a method. Returns null if the name isn't known.</summary>
    public static KeyExchangeMethod? Create(string name) => name switch
    {
        "mlkem768x25519-sha256" => new HybridKeyExchange(MlKem768.Create(), HashAlgorithmName.SHA256, static key => MlKem768.IsValidEncapsulationKey(key)),
        "sntrup761x25519-sha512" or "sntrup761x25519-sha512@openssh.com" => new HybridKeyExchange(new Sntrup761(), HashAlgorithmName.SHA512),
        "curve25519-sha256" or "curve25519-sha256@libssh.org" => new Curve25519KeyExchange(),
        "ecdh-sha2-nistp256" => new EcdhKeyExchange(NistCurve.P256),
        "ecdh-sha2-nistp384" => new EcdhKeyExchange(NistCurve.P384),
        "ecdh-sha2-nistp521" => new EcdhKeyExchange(NistCurve.P521),
        _ => null,
    };
}

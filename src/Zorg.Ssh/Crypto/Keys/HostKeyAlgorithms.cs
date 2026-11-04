using System;
using System.Collections.Generic;

namespace Zorg.Ssh.Crypto.Keys;

/// <summary>The host key algorithms this library implements.</summary>
internal static class HostKeyAlgorithms
{
    /// <summary>Gets the default algorithm names, most preferred first.</summary>
    public static IReadOnlyList<string> Default { get; } = Array.AsReadOnly(
    [
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "rsa-sha2-512",
        "rsa-sha2-256",
    ]);
}

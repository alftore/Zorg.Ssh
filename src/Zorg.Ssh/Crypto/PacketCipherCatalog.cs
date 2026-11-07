using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Zorg.Ssh.Crypto.Ciphers;

namespace Zorg.Ssh.Crypto;

/// <summary>What negotiation and key derivation need to know about a cipher.</summary>
internal sealed record CipherInfo(string Name, int KeyLength, int IvLength, bool IsAead);

/// <summary>
/// What negotiation and key derivation need to know about a MAC. Every MAC here is an HMAC whose key and tag are as long as
/// its hash output. <paramref name="IsEtm"/> says whether it MACs the ciphertext (encrypt-then-MAC, with the length in
/// clear) or the plaintext (encrypt-and-MAC, RFC 4253 section 6.4, with the length encrypted).
/// </summary>
internal sealed record MacInfo(string Name, int KeyLength, bool IsEtm, HashAlgorithmName Hash);

/// <summary>The packet ciphers and MACs this library implements, in default preference order.</summary>
internal static class PacketCipherCatalog
{
    private const string Aes128Gcm = "aes128-gcm@openssh.com";
    private const string Aes256Gcm = "aes256-gcm@openssh.com";
    private const string ChaCha20Poly1305 = "chacha20-poly1305@openssh.com";
    private const string Aes128Ctr = "aes128-ctr";
    private const string Aes256Ctr = "aes256-ctr";
    private const string HmacSha256Etm = "hmac-sha2-256-etm@openssh.com";
    private const string HmacSha512Etm = "hmac-sha2-512-etm@openssh.com";
    private const string HmacSha256 = "hmac-sha2-256";
    private const string HmacSha512 = "hmac-sha2-512";

    private static readonly CipherInfo[] Ciphers =
    [
        new(Aes128Gcm, 16, 12, IsAead: true),
        new(Aes256Gcm, 32, 12, IsAead: true),
        new(ChaCha20Poly1305, 64, 0, IsAead: true),
        new(Aes128Ctr, 16, 16, IsAead: false),
        new(Aes256Ctr, 32, 16, IsAead: false),
    ];

    // In every case the key is as long as the hash output, which is also the tag length (RFC 6668 section 2).
    private static readonly MacInfo[] Macs =
    [
        new(HmacSha256Etm, 32, IsEtm: true, HashAlgorithmName.SHA256),
        new(HmacSha512Etm, 64, IsEtm: true, HashAlgorithmName.SHA512),
        new(HmacSha256, 32, IsEtm: false, HashAlgorithmName.SHA256),
        new(HmacSha512, 64, IsEtm: false, HashAlgorithmName.SHA512),
    ];

    /// <summary>Gets the cipher preference order for this machine: AES-GCM first with AES hardware, otherwise ChaCha.</summary>
    public static IReadOnlyList<string> DefaultCiphers { get; } = CipherOrder(HasAesHardware());

    /// <summary>
    /// Gets the MAC preference order. Encrypt-then-MAC first, then encrypt-and-MAC, so the older mode is chosen only when
    /// the peer has nothing better, as in OpenSSH 10's client order. Within each mode SHA-512 goes first, because it
    /// measured faster on CPUs without SHA-NI.
    /// </summary>
    public static IReadOnlyList<string> DefaultMacs { get; } = Array.AsReadOnly([HmacSha512Etm, HmacSha256Etm, HmacSha512, HmacSha256]);

    /// <summary>Finds a cipher by its exact SSH name.</summary>
    public static CipherInfo? FindCipher(string name) =>
        Array.Find(Ciphers, cipher => string.Equals(cipher.Name, name, StringComparison.Ordinal));

    /// <summary>Finds a MAC by its exact SSH name.</summary>
    public static MacInfo? FindMac(string name) =>
        Array.Find(Macs, mac => string.Equals(mac.Name, name, StringComparison.Ordinal));

    /// <summary>
    /// Creates one direction's cipher. The caller keeps ownership of the key spans, and zeroes them. An AEAD cipher
    /// ignores <paramref name="macName"/> and <paramref name="macKey"/>, because a MAC may be negotiated alongside it.
    /// Bad arguments are a bug in this library, since only names from this catalog can be negotiated, so they
    /// throw <see cref="ArgumentException"/>.
    /// </summary>
    public static PacketCipher Create(string cipherName, string? macName, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> macKey)
    {
        CipherInfo cipher = FindCipher(cipherName) ?? throw new ArgumentException("The cipher isn't in the catalog.", nameof(cipherName));
        if (key.Length != cipher.KeyLength)
        {
            throw new ArgumentException("The key length doesn't match the cipher.", nameof(key));
        }

        if (iv.Length != cipher.IvLength)
        {
            throw new ArgumentException("The IV length doesn't match the cipher.", nameof(iv));
        }

        if (cipher.IsAead)
        {
            return string.Equals(cipher.Name, ChaCha20Poly1305, StringComparison.Ordinal)
                ? new ChaCha20Poly1305Cipher(key)
                : new AesGcmCipher(key, iv);
        }

        MacInfo mac = (macName is null ? null : FindMac(macName))
            ?? throw new ArgumentException("This cipher needs a MAC from the catalog.", nameof(macName));
        if (macKey.Length != mac.KeyLength)
        {
            throw new ArgumentException("The MAC key length doesn't match the MAC.", nameof(macKey));
        }

        return mac.IsEtm
            ? new AesCtrEtmCipher(key, iv, mac.Hash, macKey, tagLength: mac.KeyLength)
            : new AesCtrEamCipher(key, iv, mac.Hash, macKey, tagLength: mac.KeyLength);
    }

    /// <summary>Gives the order for either kind of machine, so both can be tested on one.</summary>
    internal static IReadOnlyList<string> CipherOrder(bool aesHardware)
    {
        string[] order = aesHardware
            ? [Aes256Gcm, Aes128Gcm, ChaCha20Poly1305, Aes256Ctr, Aes128Ctr]
            : [ChaCha20Poly1305, Aes256Gcm, Aes128Gcm, Aes256Ctr, Aes128Ctr];
        return Array.AsReadOnly(order);
    }

    private static bool HasAesHardware() =>
        System.Runtime.Intrinsics.X86.Aes.IsSupported || System.Runtime.Intrinsics.Arm.Aes.IsSupported;
}

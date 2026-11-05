using System;
using System.Collections.Generic;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Crypto.Keys;

/// <summary>
/// An OpenSSH certificate, as <c>PROTOCOL.certkeys</c> defines it. It stands in for its subject key: signatures are
/// made and checked by that key. Parsing only reads the structure. Nothing here means the certificate is trusted:
/// that takes a known CA, <see cref="CheckCaSignature"/> and the checks on type, time and principals.
/// </summary>
internal sealed class SshCertificate : SshPublicKey
{
    /// <summary>The type number of a certificate for a user.</summary>
    public const uint UserType = 1;

    /// <summary>The type number of a certificate for a host.</summary>
    public const uint HostType = 2;

    /// <summary>The largest certificate accepted. A big RSA key with many principals stays well under this.</summary>
    public const int MaxBlobLength = 128 * 1024;

    /// <summary>The most principals accepted, the same limit as OpenSSH.</summary>
    public const int MaxPrincipals = 256;

    /// <summary>The most critical options or extensions accepted. OpenSSH defines a handful.</summary>
    public const int MaxOptions = 64;

    private const string Suffix = "-cert-v01@openssh.com";
    private const string RsaKeyType = "ssh-rsa-cert-v01@openssh.com";
    private const string Rsa512 = "rsa-sha2-512-cert-v01@openssh.com";
    private const string Rsa256 = "rsa-sha2-256-cert-v01@openssh.com";

    private readonly byte[] _blob;
    private readonly int _signedLength;
    private readonly byte[] _signature;

    private SshCertificate(string keyType, SshPublicKey key, CertificateFields fields, byte[] blob, int signedLength, byte[] signatureKey, byte[] signature)
    {
        KeyType = keyType;
        Key = key;
        Serial = fields.Serial;
        CertificateType = fields.Type;
        KeyId = fields.KeyId;
        Principals = fields.Principals;
        ValidAfter = fields.ValidAfter;
        ValidBefore = fields.ValidBefore;
        CriticalOptions = fields.CriticalOptions;
        Extensions = fields.Extensions;
        SignatureKeyBlob = signatureKey;
        _blob = blob;
        _signedLength = signedLength;
        _signature = signature;
    }

    /// <summary>Gets the host key algorithm names for certificates, most preferred first.</summary>
    public static IReadOnlyList<string> HostKeyAlgorithmNames { get; } = Array.AsReadOnly(
    [
        Ed25519PublicKey.Name + Suffix,
        "ecdsa-sha2-nistp256" + Suffix,
        "ecdsa-sha2-nistp384" + Suffix,
        "ecdsa-sha2-nistp521" + Suffix,
        Rsa512,
        Rsa256,
    ]);

    /// <inheritdoc/>
    public override string KeyType { get; }

    /// <inheritdoc/>
    public override ReadOnlyMemory<byte> Blob => _blob;

    /// <summary>Gets the subject key, the one that holds the private half.</summary>
    public SshPublicKey Key { get; }

    /// <summary>Gets the serial number. Zero means the CA assigned none.</summary>
    public ulong Serial { get; }

    /// <summary>Gets the type number. Don't assume it's one of the two defined values.</summary>
    public uint CertificateType { get; }

    /// <summary>Gets the key ID, which the CA chose. It's peer text, so clean it before showing it.</summary>
    public string KeyId { get; }

    /// <summary>Gets the names the certificate is valid for.</summary>
    public IReadOnlyList<string> Principals { get; }

    /// <summary>Gets the start of the validity period, in seconds since 1970.</summary>
    public ulong ValidAfter { get; }

    /// <summary>Gets the end of the validity period, in seconds since 1970. The maximum value means forever.</summary>
    public ulong ValidBefore { get; }

    /// <summary>Gets the names of the critical options. An option that isn't understood means refusal.</summary>
    public IReadOnlyList<string> CriticalOptions { get; }

    /// <summary>Gets the names of the extensions, which can be ignored.</summary>
    public IReadOnlyList<string> Extensions { get; }

    /// <summary>Gets the CA's public key blob, exactly as the certificate holds it.</summary>
    public ReadOnlyMemory<byte> SignatureKeyBlob { get; }

    /// <summary>Gets whether a key type name is one of the certificate types.</summary>
    public static bool IsCertificateType(string keyType) => PlainKeyType(keyType) is not null;

    /// <summary>Gets the plain signature algorithm behind a certificate algorithm, or null if it isn't one.</summary>
    public static string? PlainSignatureAlgorithm(string algorithm) => algorithm switch
    {
        Rsa512 => RsaPublicKey.Sha512,
        Rsa256 => RsaPublicKey.Sha256,
        RsaKeyType => null, // This one is a key type only. As a signature it would mean SHA-1.
        _ => PlainKeyType(algorithm),
    };

    /// <summary>Gets the certificate algorithm for a plain signature algorithm.</summary>
    public static string CertificateAlgorithm(string plainAlgorithm) => plainAlgorithm + Suffix;

    /// <summary>
    /// Reads a host key or agent identity, which may be a certificate. <see cref="SshPublicKey.Parse"/> stays plain
    /// only, so a certificate can't turn up anywhere that hasn't been written to handle one.
    /// </summary>
    public static SshPublicKey ParseAny(ReadOnlySpan<byte> blob)
    {
        SshReader reader = new(blob);
        return IsCertificateType(reader.ReadUtf8String()) ? ParseCertificate(blob) : SshPublicKey.Parse(blob);
    }

    /// <summary>Reads a certificate blob. Anything malformed throws <see cref="SshProtocolException"/>.</summary>
    public static SshCertificate ParseCertificate(ReadOnlySpan<byte> blob)
    {
        if (blob.Length > MaxBlobLength)
        {
            throw new SshProtocolException("The peer sent a certificate that's too large.");
        }

        SshReader reader = new(blob);
        string keyType = reader.ReadUtf8String();
        string plainType = PlainKeyType(keyType)
            ?? throw new SshProtocolException("The peer sent a certificate of an unsupported type.");
        reader.ReadBinary(); // The nonce only makes the signed data unpredictable.
        SshPublicKey key = ReadSubjectKey(plainType, ref reader);

        CertificateFields fields = new()
        {
            Serial = reader.ReadUInt64(),
            Type = reader.ReadUInt32(),
            KeyId = reader.ReadUtf8String(),
            Principals = ReadPrincipals(reader.ReadBinary()),
            ValidAfter = reader.ReadUInt64(),
            ValidBefore = reader.ReadUInt64(),
            CriticalOptions = ReadOptions(reader.ReadBinary(), strict: true),
            Extensions = ReadOptions(reader.ReadBinary(), strict: false),
        };

        reader.ReadBinary(); // Reserved. Its value has no meaning today.
        byte[] signatureKey = reader.ReadBinary().ToArray();
        int signedLength = blob.Length - reader.Remaining;
        byte[] signature = reader.ReadBinary().ToArray();
        reader.EnsureEnd();
        return new SshCertificate(keyType, key, fields, blob.ToArray(), signedLength, signatureKey, signature);
    }

    /// <inheritdoc/>
    public override bool SupportsSignatureAlgorithm(string signatureAlgorithm) =>
        PlainSignatureAlgorithm(signatureAlgorithm) is { } plain && Key.SupportsSignatureAlgorithm(plain);

    /// <inheritdoc/>
    public override bool Verify(string signatureAlgorithm, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signatureBlob) =>
        PlainSignatureAlgorithm(signatureAlgorithm) is { } plain && Key.Verify(plain, data, signatureBlob);

    /// <summary>
    /// Checks the CA's signature over everything before it. Returns null if it holds, or else the reason it doesn't.
    /// The CA key goes through the plain parser, so a CA that's itself a certificate fails here, and only signature
    /// types this library would accept from a host count, which leaves out SHA-1 <c>ssh-rsa</c>.
    /// </summary>
    public string? CheckCaSignature()
    {
        SshPublicKey ca;
        try
        {
            ca = SshPublicKey.Parse(SignatureKeyBlob.Span);
        }
        catch (SshProtocolException)
        {
            return IsCertificateBlob(SignatureKeyBlob.Span)
                ? "its CA key is itself a certificate, which isn't allowed"
                : "its CA key is invalid, of an unsupported type, or too weak";
        }

        if (!TryReadSignatureAlgorithm(_signature, out string? algorithm) || !ca.SupportsSignatureAlgorithm(algorithm))
        {
            return "the CA signed it with a signature type that's refused here, such as SHA-1 ssh-rsa, or one that doesn't fit the CA key";
        }

        return ca.Verify(algorithm, _blob.AsSpan(0, _signedLength), _signature)
            ? null
            : "the CA's signature doesn't verify, so it has been altered or wasn't made by that CA";
    }

    private static bool IsCertificateBlob(ReadOnlySpan<byte> blob)
    {
        try
        {
            SshReader reader = new(blob);
            return IsCertificateType(reader.ReadUtf8String());
        }
        catch (SshProtocolException)
        {
            return false;
        }
    }

    private static bool TryReadSignatureAlgorithm(ReadOnlySpan<byte> signature, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out string? algorithm)
    {
        try
        {
            SshReader reader = new(signature);
            algorithm = reader.ReadUtf8String();
            return true;
        }
        catch (SshProtocolException)
        {
            algorithm = null;
            return false;
        }
    }

    private static string? PlainKeyType(string keyType) => keyType switch
    {
        RsaKeyType => RsaPublicKey.Name,
        "ssh-ed25519-cert-v01@openssh.com" => Ed25519PublicKey.Name,
        "ecdsa-sha2-nistp256-cert-v01@openssh.com" => "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384-cert-v01@openssh.com" => "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521-cert-v01@openssh.com" => "ecdsa-sha2-nistp521",
        _ => null,
    };

    /// <summary>
    /// Reads the key fields and rebuilds a plain blob, so the subject key meets every check a plain key does.
    /// </summary>
    private static SshPublicKey ReadSubjectKey(string plainType, ref SshReader reader)
    {
        SshWriter writer = new(1024);
        try
        {
            writer.WriteUtf8String(plainType);
            writer.WriteBinary(reader.ReadBinary());
            if (plainType != Ed25519PublicKey.Name)
            {
                // RSA is e then n, and ECDSA is the curve then the point. Both are two strings.
                writer.WriteBinary(reader.ReadBinary());
            }

            return SshPublicKey.Parse(writer.Written);
        }
        finally
        {
            writer.Dispose();
        }
    }

    private static string[] ReadPrincipals(ReadOnlySpan<byte> packed)
    {
        SshReader reader = new(packed);
        List<string> principals = [];
        while (reader.Remaining > 0)
        {
            if (principals.Count == MaxPrincipals)
            {
                throw new SshProtocolException("The peer sent a certificate with too many principals.");
            }

            principals.Add(reader.ReadUtf8String());
        }

        return [.. principals];
    }

    private static string[] ReadOptions(ReadOnlySpan<byte> packed, bool strict)
    {
        SshReader reader = new(packed);
        List<string> names = [];
        while (reader.Remaining > 0)
        {
            string name = reader.ReadUtf8String();
            reader.ReadBinary();

            // The format asks for unique names in sorted order. That's enforced where a repeat could hide something: an
            // extension can be ignored anyway, and a sloppy CA shouldn't cost a working certificate.
            if (names.Count == MaxOptions || (strict && names.Count > 0 && string.CompareOrdinal(names[^1], name) >= 0))
            {
                throw new SshProtocolException("The peer sent a certificate whose options are repeated, unsorted or too many.");
            }

            names.Add(name);
        }

        return [.. names];
    }

    private readonly record struct CertificateFields
    {
        public ulong Serial { get; init; }

        public uint Type { get; init; }

        public string KeyId { get; init; }

        public string[] Principals { get; init; }

        public ulong ValidAfter { get; init; }

        public ulong ValidBefore { get; init; }

        public string[] CriticalOptions { get; init; }

        public string[] Extensions { get; init; }
    }
}

/// <summary>A private key that presents a certificate. It signs with the subject key. Dispose it to zero that key.</summary>
internal sealed class CertifiedPrivateKey : SshPrivateKey
{
    private readonly SshPrivateKey _key;
    private readonly SshCertificate _certificate;
    private readonly string[] _algorithms;

    /// <summary>Pairs a key with its certificate, and takes ownership of the key.</summary>
    public CertifiedPrivateKey(SshPrivateKey key, SshCertificate certificate)
    {
        _key = key;
        _certificate = certificate;
        _algorithms = new string[key.SignatureAlgorithms.Count];
        for (int i = 0; i < _algorithms.Length; i++)
        {
            _algorithms[i] = SshCertificate.CertificateAlgorithm(key.SignatureAlgorithms[i]);
        }
    }

    /// <inheritdoc/>
    public override SshPublicKey PublicKey => _certificate;

    /// <inheritdoc/>
    public override IReadOnlyList<string> SignatureAlgorithms => _algorithms;

    /// <summary>
    /// Reads the text of a <c>-cert.pub</c> file and pairs it with a key. Whoever calls this keeps ownership of the
    /// key if it throws. A failure is a <see cref="SshKeyFileException"/>.
    /// </summary>
    public static CertifiedPrivateKey Adopt(SshPrivateKey key, string certificateText)
    {
        SshCertificate certificate = ParseFile(certificateText);
        if (!certificate.Key.Blob.Span.SequenceEqual(key.PublicKey.Blob.Span))
        {
            throw new SshKeyFileException("The certificate is for a different key from the private key given. Use the certificate that was issued for this key.");
        }

        if (certificate.CertificateType != SshCertificate.UserType)
        {
            throw new SshKeyFileException("That's a host certificate, so it can't log in a user. Ask the CA for a user certificate.");
        }

        return new CertifiedPrivateKey(key, certificate);
    }

    /// <inheritdoc/>
    public override byte[] Sign(string signatureAlgorithm, ReadOnlySpan<byte> data) =>
        _key.Sign(
            SshCertificate.PlainSignatureAlgorithm(signatureAlgorithm)
                ?? throw new ArgumentException("This key can't make that signature algorithm.", nameof(signatureAlgorithm)),
            data);

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _key.Dispose();
        }

        base.Dispose(disposing);
    }

    private static SshCertificate ParseFile(string text)
    {
        const string Unreadable = "The certificate file is malformed. It should be the single line that ssh-keygen -s wrote to the -cert.pub file.";
        if (text.Length > 2 * SshCertificate.MaxBlobLength)
        {
            throw new SshKeyFileException("The file is too large to be a certificate. Check that this is the right file.");
        }

        string[] fields = text.Split((char[]?)null, 3, StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length < 2 || !SshCertificate.IsCertificateType(fields[0]))
        {
            throw new SshKeyFileException(Unreadable);
        }

        try
        {
            SshCertificate certificate = SshCertificate.ParseCertificate(Convert.FromBase64String(fields[1]));
            return certificate.KeyType == fields[0] ? certificate : throw new SshKeyFileException(Unreadable);
        }
        catch (Exception ex) when (ex is FormatException or SshProtocolException)
        {
            throw new SshKeyFileException(Unreadable, ex);
        }
    }
}

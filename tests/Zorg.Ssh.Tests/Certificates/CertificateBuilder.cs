using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.Keys;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Tests.Certificates;

/// <summary>A clock that says what it's told.</summary>
internal sealed class FixedTime(DateTimeOffset now) : TimeProvider
{
    public override DateTimeOffset GetUtcNow() => now;
}

/// <summary>
/// Writes certificates, including ones <c>ssh-keygen</c> refuses to make. These only prove that a hostile certificate is
/// turned away: <see cref="SshKeygenCertificateTests"/> is what shows the format itself was read correctly.
/// </summary>
internal sealed class CertificateBuilder(SshPrivateKey subject, SshPrivateKey ca)
{
    public ulong Serial { get; init; } = 7;

    public uint Type { get; init; } = SshCertificate.HostType;

    public string KeyId { get; init; } = "test host";

    public IReadOnlyList<string> Principals { get; init; } = ["host.example.com"];

    public ulong ValidAfter { get; init; }

    public ulong ValidBefore { get; init; } = ulong.MaxValue;

    public IReadOnlyList<string> CriticalOptions { get; init; } = [];

    public IReadOnlyList<string> Extensions { get; init; } = [];

    /// <summary>Gets a blob to name as the CA in place of the signing key's own.</summary>
    public byte[]? SignatureKeyBlob { get; init; }

    public byte[] Build()
    {
        byte[] plain = subject.PublicKey.Blob.ToArray();
        SshWriter writer = new(4096);
        try
        {
            writer.WriteUtf8String(subject.PublicKey.KeyType + "-cert-v01@openssh.com");
            writer.WriteBinary(new byte[32]);
            writer.WriteRaw(KeyFields(plain));
            writer.WriteUInt64(Serial);
            writer.WriteUInt32(Type);
            writer.WriteUtf8String(KeyId);
            writer.WriteBinary(PackStrings(Principals));
            writer.WriteUInt64(ValidAfter);
            writer.WriteUInt64(ValidBefore);
            writer.WriteBinary(PackOptions(CriticalOptions));
            writer.WriteBinary(PackOptions(Extensions));
            writer.WriteBinary([]);
            writer.WriteBinary(SignatureKeyBlob ?? ca.PublicKey.Blob.ToArray());
            byte[] signature = ca.Sign(ca.SignatureAlgorithms[0], writer.Written);
            writer.WriteBinary(signature);
            return writer.ToArray();
        }
        finally
        {
            writer.Dispose();
        }
    }

    public SshCertificate Parse() => SshCertificate.ParseCertificate(Build());

    public static string CaLine(string hosts, SshPrivateKey ca) => Line("@cert-authority", hosts, ca.PublicKey);

    public static string Line(string marker, string hosts, SshPublicKey key) =>
        $"{marker} {hosts} {key.KeyType} {Convert.ToBase64String(key.Blob.Span)}\n";

    /// <summary>The fields after the key type. A certificate holds them in the same order a plain blob does.</summary>
    private static byte[] KeyFields(byte[] plain)
    {
        SshReader reader = new(plain);
        reader.ReadBinary();
        return reader.RemainingSpan.ToArray();
    }

    private static byte[] PackStrings(IEnumerable<string> values)
    {
        using MemoryStream stream = new();
        foreach (string value in values)
        {
            WriteString(stream, Encoding.UTF8.GetBytes(value));
        }

        return stream.ToArray();
    }

    private static byte[] PackOptions(IEnumerable<string> names)
    {
        using MemoryStream stream = new();
        foreach (string name in names)
        {
            WriteString(stream, Encoding.UTF8.GetBytes(name));
            WriteString(stream, []);
        }

        return stream.ToArray();
    }

    private static void WriteString(MemoryStream stream, byte[] value)
    {
        stream.Write([.. BitConverter.GetBytes((uint)value.Length).Reverse()]);
        stream.Write(value);
    }
}

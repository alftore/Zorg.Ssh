using System;
using System.Linq;
using System.Text;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.Keys;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.AotSmoke;

/// <summary>Runs every key exchange both ways, and signs and verifies with every key type, so trimming can't drop them.</summary>
internal static class KeySmoke
{
    public static void Run(Action<string, bool> check)
    {
        foreach (string name in KeyExchangeCatalog.Default)
        {
            check($"kex {name}", Exchange(name));
        }

        byte[] data = Encoding.ASCII.GetBytes("zorg smoke");
        foreach (string algorithm in HostKeyAlgorithms.Default)
        {
            using SshPrivateKey key = Generate(algorithm);
            byte[] signature = key.Sign(algorithm, data);
            SshPublicKey parsed = SshPublicKey.Parse(key.PublicKey.Blob.Span);
            check($"sign {algorithm}", parsed.Verify(algorithm, data, signature));

            signature[^1] ^= 1;
            check($"tampered {algorithm}", !parsed.Verify(algorithm, data, signature));

            using SshPrivateKey ca = SshPrivateKey.GenerateEd25519();
            SshCertificate certificate = Certify(key, ca);
            string certificateAlgorithm = SshCertificate.CertificateAlgorithm(algorithm);
            using CertifiedPrivateKey certified = new(Generate(algorithm), certificate);
            check($"certificate {algorithm}", certificate.CheckCaSignature() is null && certificate.SupportsSignatureAlgorithm(certificateAlgorithm));
            check($"certificate signs {algorithm}", certificate.Verify(certificateAlgorithm, data, key.Sign(algorithm, data)));
            check($"certified key {algorithm}", certified.SignatureAlgorithms.Contains(certificateAlgorithm));
        }
    }

    /// <summary>Writes a certificate by hand, as the library only ever reads them.</summary>
    private static SshCertificate Certify(SshPrivateKey key, SshPrivateKey ca)
    {
        byte[] plain = key.PublicKey.Blob.ToArray();
        SshWriter writer = new(4096);
        try
        {
            SshReader reader = new(plain);
            reader.ReadBinary();
            writer.WriteUtf8String(key.PublicKey.KeyType + "-cert-v01@openssh.com");
            writer.WriteBinary(new byte[32]);
            writer.WriteRaw(reader.RemainingSpan);
            writer.WriteUInt64(1);
            writer.WriteUInt32(SshCertificate.HostType);
            writer.WriteUtf8String("smoke");
            writer.WriteBinary([]);
            writer.WriteUInt64(0);
            writer.WriteUInt64(ulong.MaxValue);
            writer.WriteBinary([]);
            writer.WriteBinary([]);
            writer.WriteBinary([]);
            writer.WriteBinary(ca.PublicKey.Blob.Span);
            writer.WriteBinary(ca.Sign("ssh-ed25519", writer.Written));
            return SshCertificate.ParseCertificate(writer.Written);
        }
        finally
        {
            writer.Dispose();
        }
    }

    private static bool Exchange(string name)
    {
        using KeyExchangeMethod? client = KeyExchangeCatalog.Create(name);
        using KeyExchangeMethod? server = KeyExchangeCatalog.Create(name);
        if (client is null || server is null)
        {
            return false;
        }

        byte[] serverValue = server.ServerRespond(client.CreateClientPublicValue(), out byte[] serverSecret);
        return client.ClientComputeSharedSecret(serverValue).SequenceEqual(serverSecret);
    }

    private static SshPrivateKey Generate(string algorithm) => algorithm switch
    {
        "ssh-ed25519" => SshPrivateKey.GenerateEd25519(),
        "rsa-sha2-512" or "rsa-sha2-256" => SshPrivateKey.GenerateRsa(2048),
        _ => SshPrivateKey.GenerateEcdsa(algorithm),
    };
}

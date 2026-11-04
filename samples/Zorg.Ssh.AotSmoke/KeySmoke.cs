using System;
using System.Linq;
using System.Text;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.Keys;

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

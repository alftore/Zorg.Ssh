using System;
using System.Text;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.KeyFiles;
using Zorg.Ssh.KnownHosts;

namespace Zorg.Ssh.AotSmoke;

/// <summary>Runs bcrypt_pbkdf on a published vector and reads a known_hosts line, so trimming can't drop either. Only public data is here.</summary>
internal static class KeyFileSmoke
{
    private const string PublicKey = "AAAAC3NzaC1lZDI1NTE5AAAAIJc4IwRGujG+KB4vrXZluqEvUZ06C3c0PpIj2XgGJIQI";

    public static void Run(Action<string, bool> check)
    {
        // From the pyca/bcrypt test suite.
        byte[] derived = new byte[32];
        BCryptPbkdf.DeriveKey(Encoding.ASCII.GetBytes("password"), Encoding.ASCII.GetBytes("salt"), 4, derived);
        check("bcrypt_pbkdf vector", Convert.ToHexStringLower(derived) == "5bbf0cc293587f1c3635555c27796598d47e579071bf427e9d8fbe842aba34d9");

        SshPublicKey key = SshPublicKey.Parse(Convert.FromBase64String(PublicKey));
        KnownHostsFile file = KnownHostsFile.Parse($"*.example.com,!bad.example.com ssh-ed25519 {PublicKey}\n");
        check("known_hosts trusted", file.Lookup("good.example.com", 22, key) == KnownHostStatus.Trusted);
        check("known_hosts negated", file.Lookup("bad.example.com", 22, key) == KnownHostStatus.Unknown);

        KnownHostsFile hashed = KnownHostsFile.Parse(KnownHostsFile.FormatLine("example.com", 2222, key) + "\n");
        check("known_hosts hashed", hashed.Lookup("example.com", 2222, key) == KnownHostStatus.Trusted);
    }
}

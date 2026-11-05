using System;
using System.IO;
using System.Linq;
using System.Text;
using Xunit;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.KeyFiles;
using Zorg.Ssh.Tests.Crypto;

namespace Zorg.Ssh.Tests.KeyFiles;

/// <summary>
/// Every file here is written by the real <c>ssh-keygen</c> at test time, so nothing checks this code against itself.
/// A private key never reaches the repository. A missing tool skips locally and fails in CI.
/// </summary>
public class SshKeygenKeyFileTests
{
    private const string Namespace = "zorg-test";

    public static TheoryData<string, string?> KeyTypes => new()
    {
        { "ed25519", null },
        { "ecdsa", "256" },
        { "ecdsa", "384" },
        { "ecdsa", "521" },
        { "rsa", "2048" },
        { "rsa", "3072" },
        { "rsa", "3073" }, // p and q don't divide the modulus evenly.
        { "rsa", "4096" },
    };

    public static TheoryData<string, string, string?> EncryptedMatrix
    {
        get
        {
            string[] ciphers =
            [
                "aes128-ctr", "aes192-ctr", "aes256-ctr",
                "aes128-cbc", "aes192-cbc", "aes256-cbc",
                "aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
                "chacha20-poly1305@openssh.com",
            ];
            TheoryData<string, string, string?> data = [];
            foreach (string cipher in ciphers)
            {
                data.Add(cipher, "ed25519", null);
                data.Add(cipher, "ecdsa", "256");
                data.Add(cipher, "ecdsa", "521");
                data.Add(cipher, "rsa", "2048");
            }

            return data;
        }
    }

    public static TheoryData<string, string?> PemKeyTypes => new()
    {
        { "ecdsa", "256" },
        { "ecdsa", "384" },
        { "ecdsa", "521" },
        { "rsa", "2048" },
        { "rsa", "3072" },
    };

    public static TheoryData<string, string?> Pkcs8KeyTypes => new()
    {
        { "ed25519", null },
        { "ecdsa", "256" },
        { "ecdsa", "384" },
        { "ecdsa", "521" },
        { "rsa", "2048" },
        { "rsa", "3072" },
    };

    [Theory]
    [MemberData(nameof(KeyTypes))]
    public void Unencrypted_OpenSSH_keys_load_and_sign(string type, string? bits)
    {
        GeneratedKey generated = KeyFileTools.Generate(type, bits);
        Assert.Contains("BEGIN OPENSSH PRIVATE KEY", generated.PrivateText, StringComparison.Ordinal);

        using SshPrivateKey key = SshKeyFile.Load(generated.PrivateText);
        KeyFileTools.AssertSignsFor(key, generated.PublicBlob);
    }

    [Theory]
    [MemberData(nameof(EncryptedMatrix))]
    public void Encrypted_OpenSSH_keys_load_with_every_cipher(string cipher, string type, string? bits)
    {
        GeneratedKey generated = KeyFileTools.Generate(type, bits, cipher: cipher, passphrase: KeyFileTools.Passphrase, rounds: "2");

        using SshPrivateKey key = SshKeyFile.Load(generated.PrivateText, KeyFileTools.Passphrase);
        KeyFileTools.AssertSignsFor(key, generated.PublicBlob);

        SshKeyFileException wrong = Assert.Throws<SshKeyFileException>(() => SshKeyFile.Load(generated.PrivateText, "not the passphrase"));
        Assert.Equal(SshKeyFile.WrongPassphrase, wrong.Message);

        SshKeyFileException none = Assert.Throws<SshKeyFileException>(() => SshKeyFile.Load(generated.PrivateText));
        Assert.Equal(SshKeyFile.PassphraseRequired, none.Message);
    }

    [Theory]
    [InlineData(null)] // ssh-keygen's own default.
    [InlineData("1")]
    [InlineData("100")]
    public void Encrypted_keys_load_at_real_round_counts(string? rounds)
    {
        GeneratedKey generated = KeyFileTools.Generate("ed25519", passphrase: KeyFileTools.Passphrase, rounds: rounds);
        using SshPrivateKey key = SshKeyFile.Load(generated.PrivateText, KeyFileTools.Passphrase);
        KeyFileTools.AssertSignsFor(key, generated.PublicBlob);
    }

    [Fact]
    public void A_non_ascii_passphrase_is_used_as_utf8()
    {
        const string Passphrase = "pässwörd ключ";
        GeneratedKey generated = KeyFileTools.Generate("ed25519", passphrase: Passphrase, rounds: "2");

        using SshPrivateKey key = SshKeyFile.Load(generated.PrivateText, Passphrase);
        KeyFileTools.AssertSignsFor(key, generated.PublicBlob);

        using SshPrivateKey fromBytes = SshKeyFile.Load(generated.PrivateText.AsSpan(), Encoding.UTF8.GetBytes(Passphrase));
        KeyFileTools.AssertSignsFor(fromBytes, generated.PublicBlob);
    }

    [Theory]
    [MemberData(nameof(PemKeyTypes))]
    public void Pem_keys_load_and_sign(string type, string? bits)
    {
        GeneratedKey generated = KeyFileTools.Generate(type, bits, format: "PEM");
        string label = type == "rsa" ? "BEGIN RSA PRIVATE KEY" : "BEGIN EC PRIVATE KEY";
        Assert.Contains(label, generated.PrivateText, StringComparison.Ordinal);

        using SshPrivateKey key = SshKeyFile.Load(generated.PrivateText);
        KeyFileTools.AssertSignsFor(key, generated.PublicBlob);
    }

    [Theory]
    [MemberData(nameof(PemKeyTypes))]
    public void Legacy_encrypted_pem_is_refused_with_its_own_message(string type, string? bits)
    {
        GeneratedKey generated = KeyFileTools.Generate(type, bits, format: "PEM", passphrase: KeyFileTools.Passphrase);
        Assert.Contains("Proc-Type: 4,ENCRYPTED", generated.PrivateText, StringComparison.Ordinal);

        SshKeyFileException refused = Assert.Throws<SshKeyFileException>(() => SshKeyFile.Load(generated.PrivateText, KeyFileTools.Passphrase));
        Assert.Equal(SshKeyFile.LegacyPem, refused.Message);
    }

    [Theory]
    [MemberData(nameof(Pkcs8KeyTypes))]
    public void Pkcs8_keys_load_and_sign(string type, string? bits)
    {
        GeneratedKey generated = KeyFileTools.Generate(type, bits, format: "PKCS8");
        Assert.Contains("BEGIN PRIVATE KEY", generated.PrivateText, StringComparison.Ordinal);

        using SshPrivateKey key = SshKeyFile.Load(generated.PrivateText);
        KeyFileTools.AssertSignsFor(key, generated.PublicBlob);
    }

    [Theory]
    [MemberData(nameof(Pkcs8KeyTypes))]
    public void Encrypted_pkcs8_keys_load_and_sign(string type, string? bits)
    {
        GeneratedKey generated = KeyFileTools.Generate(type, bits, format: "PKCS8", passphrase: KeyFileTools.Passphrase);
        Assert.Contains("BEGIN ENCRYPTED PRIVATE KEY", generated.PrivateText, StringComparison.Ordinal);

        using SshPrivateKey key = SshKeyFile.Load(generated.PrivateText, KeyFileTools.Passphrase);
        KeyFileTools.AssertSignsFor(key, generated.PublicBlob);

        SshKeyFileException wrong = Assert.Throws<SshKeyFileException>(() => SshKeyFile.Load(generated.PrivateText, "not the passphrase"));
        Assert.Equal(SshKeyFile.WrongPassphrase, wrong.Message);

        SshKeyFileException none = Assert.Throws<SshKeyFileException>(() => SshKeyFile.Load(generated.PrivateText));
        Assert.Equal(SshKeyFile.PassphraseRequired, none.Message);
    }

    // The verifier here is ssh-keygen, so this doesn't rest on this library's Verify at all.
    [Theory]
    [MemberData(nameof(KeyTypes))]
    public void Ssh_keygen_accepts_signatures_from_loaded_keys(string type, string? bits)
    {
        string keygen = OpenSshTools.Require("ssh-keygen");
        GeneratedKey generated = KeyFileTools.Generate(type, bits, passphrase: KeyFileTools.Passphrase, rounds: "2");
        using SshPrivateKey key = SshKeyFile.Load(generated.PrivateText, KeyFileTools.Passphrase);
        using TempDirectory directory = new();

        byte[] message = Encoding.ASCII.GetBytes("signed by a loaded key\n");
        foreach (string algorithm in key.SignatureAlgorithms)
        {
            byte[] signature = key.Sign(algorithm, Sshsig.SignedData(Namespace, message));
            string signatureFile = Path.Combine(directory.Path, "message.sig");
            File.WriteAllText(signatureFile, Sshsig.Armor(generated.PublicBlob, Namespace, signature));

            (int exitCode, string output) = OpenSshTools.Run(keygen, ["-Y", "check-novalidate", "-n", Namespace, "-s", signatureFile], message);
            Assert.True(exitCode == 0, output);

            (exitCode, _) = OpenSshTools.Run(keygen, ["-Y", "check-novalidate", "-n", Namespace, "-s", signatureFile], [.. message, 0x21]);
            Assert.NotEqual(0, exitCode);
        }
    }

    // A corrupted file can do anything but escape as another exception type, or load as some other key. The one
    // exception is an unencrypted PKCS#8 Ed25519 file: it holds a bare seed, and every 32 bytes are a valid seed.
    [Theory]
    [InlineData("ed25519", null, null, "")]
    [InlineData("ecdsa", "256", null, "")]
    [InlineData("rsa", "2048", null, "")]
    [InlineData("ed25519", null, null, KeyFileTools.Passphrase)]
    [InlineData("ecdsa", "256", "PEM", "")]
    [InlineData("rsa", "2048", "PEM", "")]
    [InlineData("ed25519", null, "PKCS8", "")]
    [InlineData("rsa", "2048", "PKCS8", "")]
    [InlineData("ecdsa", "256", "PKCS8", KeyFileTools.Passphrase)]
    public void Corrupted_real_files_only_ever_give_SshKeyFileException(string type, string? bits, string? format, string passphrase)
    {
        GeneratedKey generated = KeyFileTools.Generate(type, bits, format: format, passphrase: passphrase, rounds: format is null ? "1" : null);
        byte[] original = KeyFileTools.Unarmor(generated.PrivateText);
        string label = generated.PrivateText.Split('\n')[0].Trim()["-----BEGIN ".Length..^"-----".Length];
        byte[]? expected = type == "ed25519" && format == "PKCS8" && passphrase.Length == 0 ? null : generated.PublicBlob;
        Random random = new(20261105);

        for (int attempt = 0; attempt < 150; attempt++)
        {
            byte[] damaged = (byte[])original.Clone();
            damaged[random.Next(damaged.Length)] ^= (byte)(1 << random.Next(8));
            AssertSafe(KeyFileTools.Armor(label, damaged), passphrase, expected);
        }

        for (int length = 0; length < original.Length; length += Math.Max(1, original.Length / 150))
        {
            AssertSafe(KeyFileTools.Armor(label, original.AsSpan(0, length)), passphrase, expected);
        }
    }

    private static void AssertSafe(string text, string passphrase, byte[]? publicBlob)
    {
        try
        {
            using SshPrivateKey key = SshKeyFile.Load(text, passphrase);
            if (publicBlob is not null)
            {
                Assert.Equal(publicBlob, key.PublicKey.Blob.ToArray());
            }
        }
        catch (SshKeyFileException ex)
        {
            Assert.False(passphrase.Length != 0 && ex.ToString().Contains(passphrase, StringComparison.Ordinal));
            Assert.DoesNotContain(text.Split('\n').ElementAtOrDefault(1) ?? "no second line", ex.ToString(), StringComparison.Ordinal);
        }
    }
}

using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Text;
using Xunit;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.KeyFiles;
using Zorg.Ssh.Crypto.Keys;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Tests.KeyFiles;

/// <summary>
/// Files built to break one rule each. Every key here is random and made at test time. Each case starts from a file
/// proved good by <see cref="Baseline_files_load"/>, so a refusal shows the rule works, not that the builder is wrong.
/// </summary>
public class HostileKeyFileTests
{
    private const string Pass = "hostile-test-pass";

    private static readonly TimeSpan Instant = TimeSpan.FromSeconds(2);

    [Fact]
    public void Baseline_files_load()
    {
        (OpenSshFileBuilder ed25519, byte[] blob) = Ed25519File();
        using (SshPrivateKey key = SshKeyFile.Load(ed25519.ToText()))
        {
            KeyFileTools.AssertSignsFor(key, blob);
        }

        using RSA rsa = RSA.Create(2048);
        using (SshPrivateKey key = SshKeyFile.Load(RsaFile(rsa.ExportParameters(true)).ToText()))
        {
            Assert.Equal(RsaPublicKey.Name, key.PublicKey.KeyType);
        }

        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using (SshPrivateKey key = SshKeyFile.Load(EcdsaFile(ecdsa.ExportParameters(true)).ToText()))
        {
            Assert.Equal("ecdsa-sha2-nistp256", key.PublicKey.KeyType);
        }
    }

    [Fact]
    public void Every_truncation_of_an_OpenSSH_file_is_refused()
    {
        byte[] file = Ed25519File().File.ToBinary();
        for (int length = 0; length < file.Length; length++)
        {
            Refused(KeyFileTools.Armor("OPENSSH PRIVATE KEY", file.AsSpan(0, length)));
        }
    }

    [Fact]
    public void Every_truncation_of_a_private_section_is_refused()
    {
        (OpenSshFileBuilder file, _) = Ed25519File();
        byte[] section = file.Section;
        for (int length = 0; length < section.Length; length += 8)
        {
            file.Section = section[..length];
            Refused(file.ToText());
        }
    }

    [Theory]
    [InlineData(0xFFFFFFFFu)]
    [InlineData(0x80000000u)]
    [InlineData(0x7FFFFFFFu)]
    [InlineData(0x00FFFFFFu)]
    public void Huge_lengths_anywhere_are_refused(uint length)
    {
        byte[] file = Ed25519File().File.ToBinary();
        for (int offset = "openssh-key-v1\0".Length; offset <= file.Length - 4; offset++)
        {
            byte[] damaged = (byte[])file.Clone();
            BinaryPrimitives.WriteUInt32BigEndian(damaged.AsSpan(offset), length);
            try
            {
                SshKeyFile.Load(KeyFileTools.Armor("OPENSSH PRIVATE KEY", damaged)).Dispose();
            }
            catch (SshKeyFileException)
            {
                // The only exception allowed. A few offsets land in the comment or the padding bytes' neighbours.
            }
        }
    }

    [Fact]
    public void Huge_lengths_inside_the_private_section_are_refused()
    {
        (OpenSshFileBuilder file, byte[] blob) = Ed25519File();
        byte[] section = file.Section;
        int loaded = 0;
        for (int offset = 8; offset <= section.Length - 4; offset++)
        {
            byte[] damaged = (byte[])section.Clone();
            BinaryPrimitives.WriteUInt32BigEndian(damaged.AsSpan(offset), 0xFFFFFFF0);
            file.Section = damaged;
            try
            {
                using SshPrivateKey key = SshKeyFile.Load(file.ToText());

                // Only the text of the comment has no meaning, and that can't change which key this is.
                Assert.Equal(blob, key.PublicKey.Blob.ToArray());
                loaded++;
            }
            catch (SshKeyFileException)
            {
                // The expected result.
            }
        }

        Assert.True(loaded <= "comment".Length, "Only offsets wholly inside the comment can load.");
    }

    [Theory]
    [InlineData(BCryptPbkdf.MaxRounds + 1u)]
    [InlineData(1_000_000u)]
    [InlineData(0x7FFFFFFFu)]
    [InlineData(0x80000000u)]
    [InlineData(uint.MaxValue)]
    public void Huge_rounds_are_refused_at_once(uint rounds)
    {
        OpenSshFileBuilder file = EncryptedShell(OpenSshFileBuilder.BcryptOptions(new byte[16], rounds));

        Stopwatch watch = Stopwatch.StartNew();
        SshKeyFileException refused = Assert.Throws<SshKeyFileException>(() => SshKeyFile.Load(file.ToText(), Pass));
        Assert.True(watch.Elapsed < Instant, "The round count must be checked before any work.");
        Assert.Contains("rounds", refused.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Zero_rounds_and_an_empty_salt_are_refused()
    {
        Assert.Equal(SshKeyFile.Malformed, Refused(EncryptedShell(OpenSshFileBuilder.BcryptOptions(new byte[16], 0)).ToText(), Pass).Message);
        Assert.Equal(SshKeyFile.Malformed, Refused(EncryptedShell(OpenSshFileBuilder.BcryptOptions([], 16)).ToText(), Pass).Message);
    }

    [Fact]
    public void Wrong_check_ints_are_refused()
    {
        (OpenSshFileBuilder file, _) = Ed25519File();
        byte[] section = file.Section;
        section[7] ^= 1;
        Assert.Equal(SshKeyFile.Malformed, Refused(file.ToText()).Message);
    }

    [Fact]
    public void Wrong_check_ints_in_an_encrypted_file_read_as_a_wrong_passphrase()
    {
        // Encrypted for real, with the bad integers inside. CTR has no tag, so this is all a wrong passphrase leaves.
        (OpenSshFileBuilder plain, _) = Ed25519File();
        byte[] section = plain.Section;
        section[7] ^= 1;
        Array.Resize(ref section, (section.Length + 15) / 16 * 16);
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] keyAndIv = new byte[48];
        BCryptPbkdf.DeriveKey(Encoding.UTF8.GetBytes(Pass), salt, 1, keyAndIv);

        byte[] encrypted = new byte[section.Length];
        PrivateKeyCipher cipher = PrivateKeyCipher.Find("aes256-ctr"u8)!;
        Assert.True(cipher.Decrypt(keyAndIv.AsSpan(0, 32), keyAndIv.AsSpan(32), section, [], encrypted)); // CTR is its own inverse.

        plain.Cipher = "aes256-ctr";
        plain.Kdf = "bcrypt";
        plain.KdfOptions = OpenSshFileBuilder.BcryptOptions(salt, 1);
        plain.Section = encrypted;
        Assert.Equal(SshKeyFile.WrongPassphrase, Refused(plain.ToText(), Pass).Message);
    }

    [Fact]
    public void A_public_key_of_another_key_is_refused()
    {
        (OpenSshFileBuilder file, _) = Ed25519File();
        (_, byte[] otherBlob) = Ed25519File();
        file.PublicBlob = otherBlob;
        Assert.Equal(SshKeyFile.Mismatch, Refused(file.ToText()).Message);
    }

    [Fact]
    public void A_public_key_of_another_type_is_refused()
    {
        (OpenSshFileBuilder file, _) = Ed25519File();
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        file.PublicBlob = EcdsaFile(ecdsa.ExportParameters(true)).PublicBlob;
        Assert.Equal(SshKeyFile.Mismatch, Refused(file.ToText()).Message);
    }

    [Fact]
    public void An_Ed25519_seed_that_does_not_give_the_public_key_is_refused()
    {
        byte[] seed = RandomNumberGenerator.GetBytes(32);
        byte[] otherSeed = RandomNumberGenerator.GetBytes(32);
        using Ed25519PrivateKey key = Ed25519PrivateKey.FromSeed(seed);
        byte[] publicValue = key.PublicKey.Blob.Span[^32..].ToArray();

        // Both copies of the public value agree with each other. Only the seed is another key's.
        OpenSshFileBuilder file = new()
        {
            PublicBlob = key.PublicKey.Blob.ToArray(),
            Section = OpenSshFileBuilder.MakeSection(Ed25519PublicKey.Name, Ed25519Fields(otherSeed, publicValue, publicValue)),
        };
        Assert.Equal(SshKeyFile.Mismatch, Refused(file.ToText()).Message);
    }

    [Fact]
    public void An_Ed25519_private_value_with_another_public_half_is_refused()
    {
        byte[] seed = RandomNumberGenerator.GetBytes(32);
        using Ed25519PrivateKey key = Ed25519PrivateKey.FromSeed(seed);
        byte[] publicValue = key.PublicKey.Blob.Span[^32..].ToArray();
        byte[] wrong = (byte[])publicValue.Clone();
        wrong[0] ^= 1;

        OpenSshFileBuilder file = new()
        {
            PublicBlob = key.PublicKey.Blob.ToArray(),
            Section = OpenSshFileBuilder.MakeSection(Ed25519PublicKey.Name, Ed25519Fields(seed, publicValue, wrong)),
        };
        Assert.Equal(SshKeyFile.Mismatch, Refused(file.ToText()).Message);
    }

    [Fact]
    public void An_ECDSA_scalar_of_another_key_is_refused()
    {
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters parameters = ecdsa.ExportParameters(true);
        parameters.D = other.ExportParameters(true).D;
        Refused(EcdsaFile(parameters).ToText());
    }

    [Theory]
    [InlineData("zero")]
    [InlineData("order")]
    [InlineData("oversized")]
    public void An_ECDSA_scalar_out_of_range_is_refused(string kind)
    {
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters parameters = ecdsa.ExportParameters(true);
        parameters.D = kind switch
        {
            "zero" => new byte[32],
            "order" => Convert.FromHexString("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
            _ => RandomNumberGenerator.GetBytes(40),
        };
        Refused(EcdsaFile(parameters).ToText());
    }

    [Fact]
    public void An_ECDSA_public_point_off_the_curve_is_refused()
    {
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters parameters = ecdsa.ExportParameters(true);
        OpenSshFileBuilder file = EcdsaFile(parameters);
        byte[] blob = file.PublicBlob;
        blob[^1] ^= 1;
        Assert.Equal(SshKeyFile.UnsupportedKey, Refused(file.ToText()).Message);
    }

    [Theory]
    [InlineData("modulus")]
    [InlineData("d")]
    [InlineData("iqmp")]
    [InlineData("p")]
    [InlineData("q")]
    [InlineData("swapped-primes")]
    [InlineData("other-d")]
    public void Inconsistent_RSA_values_are_refused(string field)
    {
        using RSA rsa = RSA.Create(2048);
        using RSA other = RSA.Create(2048);
        RSAParameters parameters = rsa.ExportParameters(true);
        RSAParameters otherParameters = other.ExportParameters(true);
        byte[] publicBlob = RsaPublicKey.FromParameters(parameters.Exponent, parameters.Modulus).Blob.ToArray();

        switch (field)
        {
            case "modulus":
                parameters.Modulus = otherParameters.Modulus;
                break;
            case "d":
                parameters.D![^1] ^= 2;
                break;
            case "iqmp":
                parameters.InverseQ![^1] ^= 2;
                break;
            case "p":
                parameters.P![^1] ^= 2;
                break;
            case "q":
                parameters.Q![^1] ^= 2;
                break;
            case "swapped-primes":
                (parameters.P, parameters.Q) = (parameters.Q, parameters.P);
                break;
            default:
                parameters.D = otherParameters.D;
                break;
        }

        OpenSshFileBuilder file = RsaFile(parameters);
        file.PublicBlob = publicBlob;
        Refused(file.ToText());
    }

    [Fact]
    public void Even_RSA_primes_are_refused()
    {
        using RSA rsa = RSA.Create(2048);
        RSAParameters parameters = rsa.ExportParameters(true);
        parameters.P![^1] &= 0xFE;
        Assert.Equal(SshKeyFile.Malformed, Refused(RsaFile(parameters).ToText()).Message);
    }

    [Fact]
    public void Header_rules_are_enforced()
    {
        Check(static file => file.KeyCount = 0, SshKeyFile.Malformed);
        Check(static file => file.KeyCount = 2, SshKeyFile.Malformed);
        Check(static file => file.AfterSection = [0], SshKeyFile.Malformed);
        Check(static file => file.KdfOptions = [0], SshKeyFile.Malformed);
        Check(static file => file.Section = [.. file.Section, 9], SshKeyFile.Malformed);
        Check(static file => file.Kdf = "bcrypt", SshKeyFile.Malformed);
        Check(static file => file.Cipher = "aes256-ctr", SshKeyFile.Malformed);
        Check(static file => file.Section = [], SshKeyFile.Malformed);

        static void Check(Action<OpenSshFileBuilder> change, string message)
        {
            (OpenSshFileBuilder file, _) = Ed25519File();
            change(file);
            Assert.Equal(message, Refused(file.ToText()).Message);
        }
    }

    [Fact]
    public void Unknown_ciphers_and_kdfs_are_refused_without_echoing_them()
    {
        (OpenSshFileBuilder cipher, _) = Ed25519File();
        cipher.Cipher = "3des-cbc";
        Assert.DoesNotContain("3des", Refused(cipher.ToText()).Message, StringComparison.Ordinal);

        (OpenSshFileBuilder kdf, _) = Ed25519File();
        kdf.Kdf = "scrypt-from-the-file";
        Assert.DoesNotContain("scrypt", Refused(kdf.ToText()).Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Bad_padding_and_a_wrong_inner_type_are_refused()
    {
        (OpenSshFileBuilder padded, _) = Ed25519File();
        padded.Section = [.. padded.Section, 1, 2, 3, 4, 5, 6, 7, 9];
        Refused(padded.ToText());

        (OpenSshFileBuilder typed, _) = Ed25519File();
        byte[] section = typed.Section;
        section[12] ^= 1; // In the key type string.
        Assert.Equal(SshKeyFile.Mismatch, Refused(typed.ToText()).Message);
    }

    [Fact]
    public void A_tag_that_fails_reads_as_a_wrong_passphrase()
    {
        OpenSshFileBuilder file = EncryptedShell(OpenSshFileBuilder.BcryptOptions(new byte[16], 1));
        file.Cipher = "aes256-gcm@openssh.com";
        file.AfterSection = new byte[16];
        Assert.Equal(SshKeyFile.WrongPassphrase, Refused(file.ToText(), Pass).Message);

        file.Cipher = "chacha20-poly1305@openssh.com";
        Assert.Equal(SshKeyFile.WrongPassphrase, Refused(file.ToText(), Pass).Message);
    }

    [Fact]
    public void An_authenticated_cipher_with_no_tag_is_refused()
    {
        OpenSshFileBuilder file = EncryptedShell(OpenSshFileBuilder.BcryptOptions(new byte[16], 1));
        file.Cipher = "aes256-gcm@openssh.com";
        Assert.Equal(SshKeyFile.Malformed, Refused(file.ToText(), Pass).Message);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not a key file")]
    [InlineData("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJc4IwRGujG+KB4vrXZluqEvUZ06C3c0PpIj2XgGJIQI comment")]
    [InlineData("PuTTY-User-Key-File-3: ssh-ed25519")]
    [InlineData("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")]
    [InlineData("-----BEGIN DSA PRIVATE KEY-----\nAAAA\n-----END DSA PRIVATE KEY-----\n")]
    [InlineData("-----BEGIN OPENSSH PRIVATE KEY-----\n")]
    [InlineData("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n")]
    [InlineData("-----BEGIN OPENSSH PRIVATE KEY-----\n-----END OPENSSH PRIVATE KEY-----\n")]
    [InlineData("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n")]
    [InlineData("-----BEGIN OPENSSH PRIVATE KEY-----\n!!!!\n-----END OPENSSH PRIVATE KEY-----\n")]
    [InlineData("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n")]
    [InlineData("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n")]
    [InlineData("-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n")]
    [InlineData("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")]
    [InlineData("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n")]
    [InlineData("-----BEGIN -----\n-----END -----\n")]
    public void Text_that_is_not_a_key_is_refused(string text) => Refused(text, Pass);

    // A good key behind the padding, so the limit is the only thing that can refuse this.
    [Fact]
    public void An_oversized_file_is_refused_at_once()
    {
        string key = Ed25519File().File.ToText();
        SshKeyFile.Load(new string('\n', SshKeyFile.MaxFileLength - key.Length) + key).Dispose();

        string text = new string('\n', SshKeyFile.MaxFileLength - key.Length + 1) + key;
        Stopwatch watch = Stopwatch.StartNew();
        SshKeyFileException refused = Refused(text);
        Assert.True(watch.Elapsed < Instant);
        Assert.Contains("too large", refused.Message, StringComparison.Ordinal);
    }

    // Straight at the check, so that these don't depend on what a platform's importer happens to refuse.
    [Theory]
    [InlineData("n")]
    [InlineData("d")]
    [InlineData("p")]
    [InlineData("q")]
    [InlineData("dp")]
    [InlineData("dq")]
    [InlineData("iqmp")]
    public void The_consistency_check_catches_each_value_alone(string field)
    {
        using RSA rsa = RSA.Create(2048);
        RSAParameters key = rsa.ExportParameters(true);
        RsaKeyValues.EnsureConsistent(key.Modulus, key.Exponent, key.D, key.P, key.Q, key.DP, key.DQ, key.InverseQ);

        byte[] value = field switch
        {
            "n" => key.Modulus!,
            "d" => key.D!,
            "p" => key.P!,
            "q" => key.Q!,
            "dp" => key.DP!,
            "dq" => key.DQ!,
            _ => key.InverseQ!,
        };
        value[^1] ^= 2;

        SshKeyFileException refused = Assert.Throws<SshKeyFileException>(
            () => RsaKeyValues.EnsureConsistent(key.Modulus, key.Exponent, key.D, key.P, key.Q, key.DP, key.DQ, key.InverseQ));
        Assert.Equal(SshKeyFile.Mismatch, refused.Message);
    }

    [Theory]
    [InlineData(2047)]
    [InlineData(2041)]
    [InlineData(16385)]
    [InlineData(100_000)]
    public void Modulus_sizes_are_limited_to_the_exact_bit(int bits)
    {
        byte[] modulus = new byte[(bits + 7) / 8];
        modulus[0] = (byte)(1 << ((bits - 1) % 8));
        modulus[^1] |= 1;

        SshKeyFileException refused = Assert.Throws<SshKeyFileException>(
            () => RsaKeyValues.EnsureConsistent(modulus, [3], [3], [3], [3], [3], [3], [3]));
        Assert.Equal(SshKeyFile.UnsupportedKey, refused.Message);
    }

    [Theory]
    [InlineData(2048)]
    [InlineData(16384)]
    public void The_size_limits_themselves_are_allowed(int bits)
    {
        byte[] modulus = new byte[(bits + 7) / 8];
        modulus[0] = (byte)(1 << ((bits - 1) % 8));
        modulus[^1] |= 1;

        // Past the size check, and then these made-up values fail as a mismatch.
        SshKeyFileException refused = Assert.Throws<SshKeyFileException>(
            () => RsaKeyValues.EnsureConsistent(modulus, [3], [3], [3], [3], [3], [3], [3]));
        Assert.Equal(SshKeyFile.Mismatch, refused.Message);
    }

    [Fact]
    public void Many_begin_lines_cost_linear_time()
    {
        StringBuilder text = new();
        while (text.Length < SshKeyFile.MaxFileLength - 64)
        {
            text.Append("-----BEGIN X-----\n");
        }

        text.Append("-----END X-----\n");
        Stopwatch watch = Stopwatch.StartNew();
        Refused(text.ToString());
        Assert.True(watch.Elapsed < Instant);
    }

    [Fact]
    public void An_RSA_key_under_2048_bits_is_refused()
    {
        using RSA rsa = RSA.Create(1024);
        Assert.Equal(SshKeyFile.UnsupportedKey, Refused(rsa.ExportRSAPrivateKeyPem()).Message);
        Assert.Equal(SshKeyFile.UnsupportedKey, Refused(rsa.ExportPkcs8PrivateKeyPem()).Message);
    }

    [Fact]
    public void An_EC_key_on_another_curve_is_refused()
    {
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.brainpoolP256r1);
        Assert.Equal(SshKeyFile.UnsupportedKey, Refused(ecdsa.ExportECPrivateKeyPem()).Message);
        Assert.Equal(SshKeyFile.UnsupportedKey, Refused(ecdsa.ExportPkcs8PrivateKeyPem()).Message);
    }

    [Fact]
    public void A_PKCS1_key_with_inconsistent_values_is_refused()
    {
        using RSA rsa = RSA.Create(2048);
        byte[] der = rsa.ExportRSAPrivateKey();
        der[^1] ^= 2; // The last field: q^-1 mod p.
        Assert.Equal(SshKeyFile.Mismatch, Refused(KeyFileTools.Armor("RSA PRIVATE KEY", der)).Message);
    }

    // Windows ignores these fields on import, so without its own check this file loads there and fails on Linux.
    [Theory]
    [InlineData("n")]
    [InlineData("d")]
    [InlineData("p")]
    [InlineData("q")]
    [InlineData("dp")]
    [InlineData("dq")]
    [InlineData("iqmp")]
    public void Every_tampered_PKCS1_and_PKCS8_RSA_value_is_refused(string field)
    {
        using RSA rsa = RSA.Create(2048);
        RSAParameters key = rsa.ExportParameters(true);
        byte[] value = field switch
        {
            "n" => key.Modulus!,
            "d" => key.D!,
            "p" => key.P!,
            "q" => key.Q!,
            "dp" => key.DP!,
            "dq" => key.DQ!,
            _ => key.InverseQ!,
        };
        value[^1] ^= 2;
        byte[] pkcs1 = Pkcs1(key);

        Refused(KeyFileTools.Armor("RSA PRIVATE KEY", pkcs1));

        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(0);
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier("1.2.840.113549.1.1.1");
                writer.WriteNull();
            }

            writer.WriteOctetString(pkcs1);
        }

        Refused(KeyFileTools.Armor("PRIVATE KEY", writer.Encode()));
    }

    [Fact]
    public void An_RSA_key_with_no_tampering_passes_the_same_checks()
    {
        using RSA rsa = RSA.Create(2048);
        using SshPrivateKey key = SshKeyFile.Load(KeyFileTools.Armor("RSA PRIVATE KEY", Pkcs1(rsa.ExportParameters(true))));
        Assert.Equal(RsaPublicKey.Name, key.PublicKey.KeyType);
    }

    [Fact]
    public void A_multi_prime_RSA_key_is_refused()
    {
        using RSA rsa = RSA.Create(2048);
        byte[] der = rsa.ExportRSAPrivateKey();
        int version = der.AsSpan().IndexOf(new byte[] { 2, 1, 0 });
        der[version + 2] = 1;
        Assert.Equal(SshKeyFile.UnsupportedKey, Refused(KeyFileTools.Armor("RSA PRIVATE KEY", der)).Message);
    }

    [Fact]
    public void A_huge_fake_RSA_modulus_is_refused_quickly()
    {
        // A modulus this size would take minutes to sign with, if anything got that far.
        int size = 100_000;
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(0);
            WritePositive(writer, RandomNumberGenerator.GetBytes(size));
            writer.WriteInteger(65537);
            WritePositive(writer, RandomNumberGenerator.GetBytes(size));
            for (int i = 0; i < 5; i++)
            {
                WritePositive(writer, RandomNumberGenerator.GetBytes(size / 2));
            }
        }

        Stopwatch watch = Stopwatch.StartNew();
        Refused(KeyFileTools.Armor("RSA PRIVATE KEY", writer.Encode()));
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(10));
    }

    [Theory]
    [InlineData(Pkcs8KeyFormat.MaxPbkdf2Iterations + 1L)]
    [InlineData(int.MaxValue)]
    [InlineData(int.MaxValue + 1L)]
    [InlineData(long.MaxValue)]
    public void Huge_pbkdf2_counts_are_refused_at_once(long iterations)
    {
        string text = EncryptedPkcs8(iterations, new byte[64]);
        Stopwatch watch = Stopwatch.StartNew();
        SshKeyFileException refused = Refused(text, Pass);
        Assert.True(watch.Elapsed < Instant, "The BCL importer has no limit, so this must be checked here.");
        Assert.Contains("PBKDF2", refused.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Zero_and_negative_pbkdf2_counts_are_refused(long iterations) => Refused(EncryptedPkcs8(iterations, new byte[64]), Pass);

    [Fact]
    public void Encrypted_pkcs8_that_is_not_a_whole_number_of_blocks_is_refused()
    {
        Assert.Equal(SshKeyFile.Malformed, Refused(EncryptedPkcs8(1000, new byte[65]), Pass).Message);
    }

    [Fact]
    public void Encryption_that_is_not_pbes2_aes_is_refused_with_a_way_out()
    {
        using RSA rsa = RSA.Create(2048);
        string text = rsa.ExportEncryptedPkcs8PrivateKeyPem(Pass.AsSpan(), new PbeParameters(PbeEncryptionAlgorithm.TripleDes3KeyPkcs12, HashAlgorithmName.SHA1, 100));
        Assert.Contains("ssh-keygen -p", Refused(text, Pass).Message, StringComparison.Ordinal);
    }

    // The BCL here is a second writer of PKCS#8, beside OpenSSL behind ssh-keygen.
    [Theory]
    [InlineData("SHA1", PbeEncryptionAlgorithm.Aes128Cbc)]
    [InlineData("SHA256", PbeEncryptionAlgorithm.Aes192Cbc)]
    [InlineData("SHA384", PbeEncryptionAlgorithm.Aes256Cbc)]
    [InlineData("SHA512", PbeEncryptionAlgorithm.Aes256Cbc)]
    public void Pbes2_variants_from_the_BCL_load(string hash, PbeEncryptionAlgorithm encryption)
    {
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        string text = ecdsa.ExportEncryptedPkcs8PrivateKeyPem(Pass.AsSpan(), new PbeParameters(encryption, new HashAlgorithmName(hash), 1000));
        using SshPrivateKey key = SshKeyFile.Load(text, Pass);
        Assert.Equal("ecdsa-sha2-nistp384", key.PublicKey.KeyType);
    }

    [Fact]
    public void Decrypted_data_that_is_not_a_key_reads_as_a_wrong_passphrase()
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] iv = RandomNumberGenerator.GetBytes(16);
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(Pass, salt, 1000, HashAlgorithmName.SHA256, 16);
        using Aes aes = Aes.Create();
        aes.Key = key;
        byte[] ciphertext = aes.EncryptCbc(Encoding.ASCII.GetBytes("valid padding, but not a key"), iv, PaddingMode.PKCS7);

        string text = EncryptedPkcs8(1000, ciphertext, salt, iv);
        Assert.Equal(SshKeyFile.WrongPassphrase, Refused(text, Pass).Message);
    }

    [Fact]
    public void A_pkcs8_key_of_an_unknown_algorithm_is_refused()
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(0);
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier("1.3.101.113"); // Ed448.
            }

            writer.WriteOctetString(new byte[59]);
        }

        Assert.Equal(SshKeyFile.UnsupportedKey, Refused(KeyFileTools.Armor("PRIVATE KEY", writer.Encode())).Message);
    }

    [Fact]
    public void An_Ed25519_pkcs8_seed_of_the_wrong_length_is_refused()
    {
        AsnWriter inner = new(AsnEncodingRules.DER);
        inner.WriteOctetString(new byte[31]);
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(0);
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier("1.3.101.112");
            }

            writer.WriteOctetString(inner.Encode());
        }

        Assert.Equal(SshKeyFile.Malformed, Refused(KeyFileTools.Armor("PRIVATE KEY", writer.Encode())).Message);
    }

    [Fact]
    public void Armor_variations_real_files_have_are_accepted()
    {
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string pem = ecdsa.ExportECPrivateKeyPem();

        // openssl ecparam -genkey writes the curve ahead of the key.
        string withParameters = "-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n" + pem;
        SshKeyFile.Load(withParameters).Dispose();
        SshKeyFile.Load("Bag Attributes\n  friendlyName: x\n" + pem).Dispose();
        SshKeyFile.Load(pem.ReplaceLineEndings("\r\n")).Dispose();
        SshKeyFile.Load(pem.ReplaceLineEndings("\n")).Dispose();
    }

    [Fact]
    public void Failures_never_show_the_passphrase_or_the_key()
    {
        const string Secret = "S3cretPassphraseValue";
        byte[] seed = RandomNumberGenerator.GetBytes(32);
        (OpenSshFileBuilder file, _) = Ed25519File(seed);
        file.KeyCount = 3;

        SshKeyFileException[] failures =
        [
            Refused(file.ToText(), Secret),
            Refused(EncryptedShell(OpenSshFileBuilder.BcryptOptions(new byte[16], 1)).ToText(), Secret),
            Refused(EncryptedPkcs8(1000, new byte[64]), Secret),
        ];

        string hex = Convert.ToHexString(seed);
        string base64 = Convert.ToBase64String(seed);
        foreach (SshKeyFileException failure in failures)
        {
            string everything = failure.ToString();
            Assert.DoesNotContain(Secret, everything, StringComparison.Ordinal);
            Assert.DoesNotContain(hex, everything, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(base64, everything, StringComparison.Ordinal);
        }
    }

    private static SshKeyFileException Refused(string text, string? passphrase = null) =>
        Assert.Throws<SshKeyFileException>(() => SshKeyFile.Load(text, passphrase));

    private static (OpenSshFileBuilder File, byte[] Blob) Ed25519File(byte[]? seed = null)
    {
        seed ??= RandomNumberGenerator.GetBytes(32);
        using Ed25519PrivateKey key = Ed25519PrivateKey.FromSeed(seed);
        byte[] blob = key.PublicKey.Blob.ToArray();
        byte[] publicValue = blob[^32..];
        OpenSshFileBuilder file = new()
        {
            PublicBlob = blob,
            Section = OpenSshFileBuilder.MakeSection(Ed25519PublicKey.Name, Ed25519Fields(seed, publicValue, publicValue)),
        };
        return (file, blob);
    }

    private static byte[] Ed25519Fields(byte[] seed, byte[] publicValue, byte[] secondCopy)
    {
        SshWriter writer = new();
        try
        {
            writer.WriteBinary(publicValue);
            writer.WriteBinary([.. seed, .. secondCopy]);
            return writer.ToArray();
        }
        finally
        {
            writer.Dispose();
        }
    }

    private static OpenSshFileBuilder RsaFile(RSAParameters key)
    {
        SshWriter blob = new(1024);
        SshWriter fields = new(4096);
        try
        {
            blob.WriteUtf8String(RsaPublicKey.Name);
            blob.WriteMPInt(key.Exponent);
            blob.WriteMPInt(key.Modulus);

            fields.WriteMPInt(key.Modulus);
            fields.WriteMPInt(key.Exponent);
            fields.WriteMPInt(key.D);
            fields.WriteMPInt(key.InverseQ);
            fields.WriteMPInt(key.P);
            fields.WriteMPInt(key.Q);
            return new OpenSshFileBuilder
            {
                PublicBlob = blob.ToArray(),
                Section = OpenSshFileBuilder.MakeSection(RsaPublicKey.Name, fields.Written),
            };
        }
        finally
        {
            blob.Dispose();
            fields.Dispose();
        }
    }

    private static OpenSshFileBuilder EcdsaFile(ECParameters key)
    {
        const string Type = "ecdsa-sha2-nistp256";
        byte[] point = [0x04, .. key.Q.X!, .. key.Q.Y!];
        SshWriter blob = new();
        SshWriter fields = new();
        try
        {
            blob.WriteUtf8String(Type);
            blob.WriteUtf8String("nistp256");
            blob.WriteBinary(point);

            fields.WriteUtf8String("nistp256");
            fields.WriteBinary(point);
            fields.WriteMPInt(key.D);
            return new OpenSshFileBuilder
            {
                PublicBlob = blob.ToArray(),
                Section = OpenSshFileBuilder.MakeSection(Type, fields.Written),
            };
        }
        finally
        {
            blob.Dispose();
            fields.Dispose();
        }
    }

    /// <summary>A file with an encrypted header around a section of noise, for rules checked before decryption.</summary>
    private static OpenSshFileBuilder EncryptedShell(byte[] kdfOptions)
    {
        (OpenSshFileBuilder file, _) = Ed25519File();
        file.Cipher = "aes256-ctr";
        file.Kdf = "bcrypt";
        file.KdfOptions = kdfOptions;
        file.Section = RandomNumberGenerator.GetBytes(160);
        return file;
    }

    private static string EncryptedPkcs8(long iterations, byte[] ciphertext, byte[]? salt = null, byte[]? iv = null)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier("1.2.840.113549.1.5.13"); // PBES2
                using (writer.PushSequence())
                {
                    using (writer.PushSequence())
                    {
                        writer.WriteObjectIdentifier("1.2.840.113549.1.5.12"); // PBKDF2
                        using (writer.PushSequence())
                        {
                            writer.WriteOctetString(salt ?? new byte[16]);
                            writer.WriteInteger(iterations);
                            using (writer.PushSequence())
                            {
                                writer.WriteObjectIdentifier("1.2.840.113549.2.9"); // HMAC-SHA-256
                                writer.WriteNull();
                            }
                        }
                    }

                    using (writer.PushSequence())
                    {
                        writer.WriteObjectIdentifier("2.16.840.1.101.3.4.1.2"); // AES-128-CBC
                        writer.WriteOctetString(iv ?? new byte[16]);
                    }
                }
            }

            writer.WriteOctetString(ciphertext);
        }

        return KeyFileTools.Armor("ENCRYPTED PRIVATE KEY", writer.Encode());
    }

    private static byte[] Pkcs1(RSAParameters key)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(0);
            writer.WriteIntegerUnsigned(TrimZeros(key.Modulus));
            writer.WriteIntegerUnsigned(TrimZeros(key.Exponent));
            writer.WriteIntegerUnsigned(TrimZeros(key.D));
            writer.WriteIntegerUnsigned(TrimZeros(key.P));
            writer.WriteIntegerUnsigned(TrimZeros(key.Q));
            writer.WriteIntegerUnsigned(TrimZeros(key.DP));
            writer.WriteIntegerUnsigned(TrimZeros(key.DQ));
            writer.WriteIntegerUnsigned(TrimZeros(key.InverseQ));
        }

        return writer.Encode();
    }

    private static void WritePositive(AsnWriter writer, byte[] magnitude)
    {
        magnitude[0] = 0x7F;
        magnitude[^1] |= 1;
        writer.WriteIntegerUnsigned(TrimZeros(magnitude));
    }

    // Exported RSA values are fixed length, so about 1 in 256 starts with a zero, which ASN.1 doesn't allow.
    private static byte[] TrimZeros(ReadOnlySpan<byte> value)
    {
        int start = 0;
        while (start < value.Length - 1 && value[start] == 0)
        {
            start++;
        }

        return value[start..].ToArray();
    }
}

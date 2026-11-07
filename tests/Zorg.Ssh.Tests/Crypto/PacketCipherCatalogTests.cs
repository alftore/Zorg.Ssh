using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Xunit;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.Ciphers;
using static Zorg.Ssh.Tests.Crypto.CipherHarness;

namespace Zorg.Ssh.Tests.Crypto;

public class PacketCipherCatalogTests
{
    [Fact]
    public void Cipher_order_puts_GCM_first_with_AES_hardware()
    {
        Assert.Equal(
            [Aes256Gcm, Aes128Gcm, ChaCha, Aes256Ctr, Aes128Ctr],
            PacketCipherCatalog.CipherOrder(aesHardware: true));
    }

    [Fact]
    public void Cipher_order_puts_ChaCha_first_without_AES_hardware()
    {
        IReadOnlyList<string> order = PacketCipherCatalog.CipherOrder(aesHardware: false);

        Assert.Equal(ChaCha, order[0]);
        Assert.Equal(5, order.Count);
    }

    [Fact]
    public void DefaultCiphers_follows_this_machine()
    {
        bool aesHardware = System.Runtime.Intrinsics.X86.Aes.IsSupported || System.Runtime.Intrinsics.Arm.Aes.IsSupported;

        Assert.Equal(PacketCipherCatalog.CipherOrder(aesHardware), PacketCipherCatalog.DefaultCiphers);
    }

    [Fact]
    public void DefaultMacs_puts_EtM_before_encrypt_and_MAC_and_SHA_512_first_in_each() =>
        Assert.Equal([Sha512Etm, Sha256Etm, Sha512Eam, Sha256Eam], PacketCipherCatalog.DefaultMacs);

    [Fact]
    public void The_default_lists_cannot_be_changed_through_a_cast()
    {
        Assert.IsNotType<string[]>(PacketCipherCatalog.DefaultCiphers);
        Assert.IsNotType<string[]>(PacketCipherCatalog.DefaultMacs);
    }

    [Theory]
    [InlineData(Aes128Gcm, 16, 12, true)]
    [InlineData(Aes256Gcm, 32, 12, true)]
    [InlineData(ChaCha, 64, 0, true)]
    [InlineData(Aes128Ctr, 16, 16, false)]
    [InlineData(Aes256Ctr, 32, 16, false)]
    public void FindCipher_gives_the_lengths(string name, int keyLength, int ivLength, bool isAead) =>
        Assert.Equal(new CipherInfo(name, keyLength, ivLength, isAead), PacketCipherCatalog.FindCipher(name));

    [Theory]
    [InlineData(Sha256Etm, 32, true)]
    [InlineData(Sha512Etm, 64, true)]
    [InlineData(Sha256Eam, 32, false)]
    [InlineData(Sha512Eam, 64, false)]
    public void FindMac_gives_the_key_length_and_mode(string name, int keyLength, bool isEtm)
    {
        MacInfo mac = PacketCipherCatalog.FindMac(name)!;

        Assert.Equal((name, keyLength, isEtm), (mac.Name, mac.KeyLength, mac.IsEtm));

        // The key and the tag are both as long as the hash output.
        Assert.Equal(keyLength, CryptographicOperations.HashData(mac.Hash, []).Length);
    }

    [Theory]
    [InlineData(Aes128Ctr, Sha256Etm, typeof(AesCtrEtmCipher))]
    [InlineData(Aes256Ctr, Sha512Etm, typeof(AesCtrEtmCipher))]
    [InlineData(Aes128Ctr, Sha256Eam, typeof(AesCtrEamCipher))]
    [InlineData(Aes256Ctr, Sha512Eam, typeof(AesCtrEamCipher))]
    public void CTR_gets_the_mode_its_MAC_names(string cipherName, string macName, Type expected)
    {
        using PacketCipher cipher = Create(cipherName, macName);

        Assert.IsType(expected, cipher);
        Assert.Equal(expected == typeof(AesCtrEtmCipher), cipher.LengthExcludedFromPadding);
        Assert.Equal(expected == typeof(AesCtrEtmCipher) ? 4 : 16, cipher.LengthBlockSize);
    }

    [Theory]
    [InlineData("")]
    [InlineData("none")]
    [InlineData("aes192-ctr")]
    [InlineData("AES128-CTR")]
    [InlineData("aes128-cbc")]
    [InlineData("3des-cbc")]
    [InlineData("hmac-md5")]
    [InlineData("hmac-sha2-256-96")]
    [InlineData("umac-64@openssh.com")]
    public void Names_outside_the_catalog_are_not_found(string name)
    {
        Assert.Null(PacketCipherCatalog.FindCipher(name));
        Assert.Null(PacketCipherCatalog.FindMac(name));
    }

    [Fact]
    public void Encrypt_and_MAC_SHA_2_is_offered_after_every_EtM_MAC()
    {
        IReadOnlyList<string> macs = PacketCipherCatalog.DefaultMacs;
        int lastEtm = macs.Select((name, i) => (name, i)).Where(m => PacketCipherCatalog.FindMac(m.name)!.IsEtm).Max(m => m.i);
        int firstEam = macs.Select((name, i) => (name, i)).Where(m => !PacketCipherCatalog.FindMac(m.name)!.IsEtm).Min(m => m.i);

        Assert.True(lastEtm < firstEam);
    }

    [Theory]
    [InlineData(Aes128Gcm, typeof(AesGcmCipher))]
    [InlineData(Aes256Gcm, typeof(AesGcmCipher))]
    [InlineData(ChaCha, typeof(ChaCha20Poly1305Cipher))]
    public void AEAD_ciphers_ignore_a_negotiated_MAC(string cipherName, Type expected)
    {
        using PacketCipher withoutMac = PacketCipherCatalog.Create(cipherName, null, KeyFor(cipherName), IvFor(cipherName), []);
        using PacketCipher withMac = PacketCipherCatalog.Create(cipherName, Sha256Etm, KeyFor(cipherName), IvFor(cipherName), new byte[3]);

        Assert.IsType(expected, withoutMac);
        Assert.IsType(expected, withMac);
        Assert.Equal(16, withMac.TagLength);
    }

    [Fact]
    public void Create_rejects_what_it_cannot_build()
    {
        byte[] key16 = new byte[16];
        byte[] iv16 = new byte[16];
        byte[] mac32 = new byte[32];

        Assert.Throws<ArgumentException>(() => PacketCipherCatalog.Create("none", null, [], [], []));
        Assert.Throws<ArgumentException>(() => PacketCipherCatalog.Create(Aes256Ctr, Sha256Etm, key16, iv16, mac32));
        Assert.Throws<ArgumentException>(() => PacketCipherCatalog.Create(Aes128Ctr, Sha256Etm, key16, new byte[12], mac32));
        Assert.Throws<ArgumentException>(() => PacketCipherCatalog.Create(Aes128Ctr, null, key16, iv16, mac32));
        Assert.Throws<ArgumentException>(() => PacketCipherCatalog.Create(Aes128Ctr, "hmac-md5", key16, iv16, mac32));
        Assert.Throws<ArgumentException>(() => PacketCipherCatalog.Create(Aes128Ctr, Sha512Eam, key16, iv16, mac32));
        Assert.Throws<ArgumentException>(() => PacketCipherCatalog.Create(Aes128Ctr, Sha512Etm, key16, iv16, mac32));
        Assert.Throws<ArgumentException>(() => PacketCipherCatalog.Create(ChaCha, null, new byte[32], [], []));
        Assert.Throws<ArgumentException>(() => PacketCipherCatalog.Create(ChaCha, null, new byte[64], new byte[12], []));
        Assert.Throws<ArgumentException>(() => PacketCipherCatalog.Create(Aes128Gcm, null, key16, new byte[16], []));
    }
}

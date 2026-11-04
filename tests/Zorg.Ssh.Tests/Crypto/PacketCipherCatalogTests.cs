using System;
using System.Collections.Generic;
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
    public void DefaultMacs_puts_SHA_512_first() =>
        Assert.Equal([Sha512Etm, Sha256Etm], PacketCipherCatalog.DefaultMacs);

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
    [InlineData(Sha256Etm, 32)]
    [InlineData(Sha512Etm, 64)]
    public void FindMac_gives_the_key_length(string name, int keyLength) =>
        Assert.Equal(new MacInfo(name, keyLength), PacketCipherCatalog.FindMac(name));

    [Theory]
    [InlineData("")]
    [InlineData("none")]
    [InlineData("aes192-ctr")]
    [InlineData("AES128-CTR")]
    [InlineData("aes128-cbc")]
    [InlineData("3des-cbc")]
    [InlineData("hmac-sha2-256")]
    public void Names_outside_the_catalog_are_not_found(string name)
    {
        Assert.Null(PacketCipherCatalog.FindCipher(name));
        Assert.Null(PacketCipherCatalog.FindMac(name));
    }

    [Fact]
    public void Non_EtM_MACs_are_not_offered()
    {
        Assert.Null(PacketCipherCatalog.FindMac("hmac-sha2-256"));
        Assert.Null(PacketCipherCatalog.FindMac("hmac-sha2-512"));
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
        Assert.Throws<ArgumentException>(() => PacketCipherCatalog.Create(Aes128Ctr, "hmac-sha2-256", key16, iv16, mac32));
        Assert.Throws<ArgumentException>(() => PacketCipherCatalog.Create(Aes128Ctr, Sha512Etm, key16, iv16, mac32));
        Assert.Throws<ArgumentException>(() => PacketCipherCatalog.Create(ChaCha, null, new byte[32], [], []));
        Assert.Throws<ArgumentException>(() => PacketCipherCatalog.Create(ChaCha, null, new byte[64], new byte[12], []));
        Assert.Throws<ArgumentException>(() => PacketCipherCatalog.Create(Aes128Gcm, null, key16, new byte[16], []));
    }
}

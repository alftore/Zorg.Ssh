using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Zorg.Ssh.Crypto.KeyFiles;

/// <summary>
/// The ciphers OpenSSH can use for the private section of a key file. A file is one message, so these are one-shot,
/// unlike the packet ciphers. The sizes are the ones OpenSSH's cipher table gives.
/// </summary>
internal sealed class PrivateKeyCipher
{
    private const int AesBlock = 16;
    private const int GcmNonce = 12;
    private const int TagSize = 16;
    private const int ChaChaKey = 64;
    private const int ChaChaHalfKey = 32;
    private const int ChaChaBlock = 8;
    private const int ChaChaNonce = 12;
    private const int ChaChaKeystreamBlock = 64;
    private const int PolyKeySize = 32;

    private static readonly PrivateKeyCipher None = new(Mode.None, 0, 0, 8, 0);

    private readonly Mode _mode;

    private PrivateKeyCipher(Mode mode, int keyLength, int ivLength, int blockSize, int tagLength)
    {
        _mode = mode;
        KeyLength = keyLength;
        IvLength = ivLength;
        BlockSize = blockSize;
        TagLength = tagLength;
    }

    private enum Mode
    {
        None,
        Ctr,
        Cbc,
        Gcm,
        ChaCha,
    }

    /// <summary>Gets whether this is the <c>none</c> cipher, for a file with no passphrase.</summary>
    public bool IsNone => _mode == Mode.None;

    /// <summary>Gets the key length, in bytes.</summary>
    public int KeyLength { get; }

    /// <summary>Gets the IV length, in bytes.</summary>
    public int IvLength { get; }

    /// <summary>Gets the size the private section must be a multiple of. It applies to <c>none</c> too.</summary>
    public int BlockSize { get; }

    /// <summary>Gets the tag length. The tag follows the private section, outside its length.</summary>
    public int TagLength { get; }

    /// <summary>Finds a cipher by its name in the file. Returns null if it isn't supported.</summary>
    public static PrivateKeyCipher? Find(ReadOnlySpan<byte> name)
    {
        if (name.Length > 32 || !Ascii.IsValid(name))
        {
            return null;
        }

        return Encoding.ASCII.GetString(name) switch
        {
            "none" => None,
            "aes128-ctr" => new(Mode.Ctr, 16, AesBlock, AesBlock, 0),
            "aes192-ctr" => new(Mode.Ctr, 24, AesBlock, AesBlock, 0),
            "aes256-ctr" => new(Mode.Ctr, 32, AesBlock, AesBlock, 0),
            "aes128-cbc" => new(Mode.Cbc, 16, AesBlock, AesBlock, 0),
            "aes192-cbc" => new(Mode.Cbc, 24, AesBlock, AesBlock, 0),
            "aes256-cbc" => new(Mode.Cbc, 32, AesBlock, AesBlock, 0),
            "aes128-gcm@openssh.com" => new(Mode.Gcm, 16, GcmNonce, AesBlock, TagSize),
            "aes256-gcm@openssh.com" => new(Mode.Gcm, 32, GcmNonce, AesBlock, TagSize),
            "chacha20-poly1305@openssh.com" => new(Mode.ChaCha, ChaChaKey, 0, ChaChaBlock, TagSize),
            _ => null,
        };
    }

    /// <summary>Decrypts into <paramref name="plaintext"/>. Returns false if an authenticated cipher's tag fails.</summary>
    public bool Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext)
    {
        switch (_mode)
        {
            case Mode.Ctr:
                DecryptCtr(key, iv, ciphertext, plaintext);
                return true;
            case Mode.Cbc:
                DecryptCbc(key, iv, ciphertext, plaintext);
                return true;
            case Mode.Gcm:
                return DecryptGcm(key, iv, ciphertext, tag, plaintext);
            case Mode.ChaCha:
                return DecryptChaCha(key, ciphertext, tag, plaintext);
            default:
                ciphertext.CopyTo(plaintext);
                return true;
        }
    }

    private static void DecryptCtr(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
    {
        using Aes aes = Aes.Create();
        aes.SetKey(key);

        Span<byte> counter = stackalloc byte[AesBlock];
        Span<byte> keystream = stackalloc byte[AesBlock];
        iv.CopyTo(counter);
        ulong high = BinaryPrimitives.ReadUInt64BigEndian(counter);
        ulong low = BinaryPrimitives.ReadUInt64BigEndian(counter[8..]);
        for (int offset = 0; offset < ciphertext.Length; offset += AesBlock)
        {
            // ECB here is the block function of CTR: it only ever encrypts unique counter blocks.
            aes.EncryptEcb(counter, keystream, PaddingMode.None);
            int count = Math.Min(AesBlock, ciphertext.Length - offset);
            for (int i = 0; i < count; i++)
            {
                plaintext[offset + i] = (byte)(ciphertext[offset + i] ^ keystream[i]);
            }

            if (++low == 0)
            {
                high++;
            }

            BinaryPrimitives.WriteUInt64BigEndian(counter, high);
            BinaryPrimitives.WriteUInt64BigEndian(counter[8..], low);
        }

        CryptographicOperations.ZeroMemory(keystream);
    }

    private static void DecryptCbc(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
    {
        using Aes aes = Aes.Create();
        aes.SetKey(key);
        aes.DecryptCbc(ciphertext, iv, plaintext, PaddingMode.None);
    }

    private static bool DecryptGcm(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext)
    {
        using AesGcm gcm = new(key, TagSize);
        try
        {
            gcm.Decrypt(iv, ciphertext, tag, plaintext);
            return true;
        }
        catch (AuthenticationTagMismatchException)
        {
            return false;
        }
    }

    /// <summary>
    /// The packet construction at sequence number 0, with nothing in the length field: block 0 of the first 32 key
    /// bytes gives the Poly1305 key, the data starts at block 1, and the last 32 key bytes aren't used.
    /// </summary>
    private static bool DecryptChaCha(ReadOnlySpan<byte> key, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext)
    {
        WipeableChaCha chacha = new(key[..ChaChaHalfKey]);
        Span<byte> block = stackalloc byte[ChaChaKeystreamBlock];
        Span<byte> expected = stackalloc byte[TagSize];
        try
        {
            block.Clear();
            chacha.ProcessBytes(block, block);

            // This KeyParameter can't be zeroed, as in ChaCha20Poly1305Cipher. It's a one-time key for this file only.
            Poly1305 poly = new();
            poly.Init(new KeyParameter(block[..PolyKeySize]));
            poly.BlockUpdate(ciphertext);
            poly.DoFinal(expected);
            if (!CryptographicOperations.FixedTimeEquals(expected, tag))
            {
                return false;
            }

            chacha.ProcessBytes(ciphertext, plaintext);
            return true;
        }
        finally
        {
            chacha.Wipe();
            CryptographicOperations.ZeroMemory(block);
            CryptographicOperations.ZeroMemory(expected);
        }
    }

    /// <summary>A ChaCha20 engine keyed without a <see cref="KeyParameter"/>, which would keep a copy no one can zero.</summary>
    private sealed class WipeableChaCha : ChaCha7539Engine
    {
        public WipeableChaCha(ReadOnlySpan<byte> key)
        {
            byte[] nonce = new byte[ChaChaNonce];
            Init(forEncryption: true, new ParametersWithIV(new KeyParameter(new byte[ChaChaHalfKey]), nonce));

            byte[] copy = key.ToArray();
            try
            {
                SetKey(copy, nonce);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(copy);
            }

            Reset();
        }

        /// <summary>Replaces the key in the engine's state, then overwrites its last keystream block.</summary>
        public void Wipe()
        {
            SetKey(new byte[ChaChaHalfKey], new byte[ChaChaNonce]);
            Reset();

            Span<byte> scratch = stackalloc byte[1];
            ProcessBytes(scratch, scratch);
        }
    }
}

using System;
using System.Security.Cryptography;
using System.Text;
using Zorg.Ssh.Crypto.Keys;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Crypto.KeyFiles;

/// <summary>
/// The <c>openssh-key-v1</c> format, from OpenSSH's PROTOCOL.key. A public header holds the cipher, the KDF and the
/// public key. An encrypted private section then holds two equal check integers, the key, a comment and padding.
/// </summary>
internal static class OpenSshKeyFormat
{
    private const int MaxDerivedLength = 64;
    private const int Ed25519KeyLength = 32;

    private static ReadOnlySpan<byte> Magic => "openssh-key-v1\0"u8;

    /// <summary>Reads a decoded file.</summary>
    public static SshPrivateKey Parse(ReadOnlySpan<byte> data, ReadOnlySpan<byte> passphrase)
    {
        if (!data.StartsWith(Magic))
        {
            throw new SshKeyFileException(SshKeyFile.Malformed);
        }

        SshReader reader = new(data[Magic.Length..]);
        ReadOnlySpan<byte> cipherName = reader.ReadBinary();
        ReadOnlySpan<byte> kdfName = reader.ReadBinary();
        ReadOnlySpan<byte> kdfOptions = reader.ReadBinary();
        uint keyCount = reader.ReadUInt32();
        ReadOnlySpan<byte> publicBlob = reader.ReadBinary();
        ReadOnlySpan<byte> sealedSection = reader.ReadBinary();

        // The file's text stays out of these messages: it's unchecked, and messages reach logs.
        PrivateKeyCipher cipher = PrivateKeyCipher.Find(cipherName)
            ?? throw new SshKeyFileException("The key file is encrypted with a cipher that isn't supported. Change it with: ssh-keygen -p -Z aes256-ctr -f <file>");

        ReadOnlySpan<byte> tag = reader.ReadRaw(cipher.TagLength);
        reader.EnsureEnd();

        bool kdfIsNone = Ascii.Equals(kdfName, "none");
        bool kdfIsBcrypt = Ascii.Equals(kdfName, "bcrypt");
        if (!kdfIsNone && !kdfIsBcrypt)
        {
            throw new SshKeyFileException("The key file uses a key derivation that isn't supported. Change it with: ssh-keygen -p -f <file>");
        }

        if (keyCount != 1
            || kdfIsNone != cipher.IsNone
            || (kdfIsNone && !kdfOptions.IsEmpty)
            || sealedSection.IsEmpty
            || sealedSection.Length % cipher.BlockSize != 0)
        {
            throw new SshKeyFileException(SshKeyFile.Malformed);
        }

        SshPublicKey publicKey = ParsePublicKey(publicBlob);
        byte[] section = new byte[sealedSection.Length];
        try
        {
            if (cipher.IsNone)
            {
                sealedSection.CopyTo(section);
            }
            else
            {
                Decrypt(cipher, kdfOptions, passphrase, sealedSection, tag, section);
            }

            return ParsePrivateSection(section, publicKey, encrypted: !cipher.IsNone);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(section);
        }
    }

    private static SshPublicKey ParsePublicKey(ReadOnlySpan<byte> blob)
    {
        try
        {
            return SshPublicKey.Parse(blob);
        }
        catch (SshProtocolException ex)
        {
            throw new SshKeyFileException(SshKeyFile.UnsupportedKey, ex);
        }
    }

    private static void Decrypt(
        PrivateKeyCipher cipher,
        ReadOnlySpan<byte> kdfOptions,
        ReadOnlySpan<byte> passphrase,
        ReadOnlySpan<byte> sealedSection,
        ReadOnlySpan<byte> tag,
        Span<byte> section)
    {
        if (passphrase.IsEmpty)
        {
            throw new SshKeyFileException(SshKeyFile.PassphraseRequired);
        }

        SshReader options = new(kdfOptions);
        ReadOnlySpan<byte> salt = options.ReadBinary();
        uint rounds = options.ReadUInt32();
        options.EnsureEnd();
        if (salt.IsEmpty || rounds == 0)
        {
            throw new SshKeyFileException(SshKeyFile.Malformed);
        }

        // Checked ahead of any work, so a hostile count costs nothing.
        if (rounds > BCryptPbkdf.MaxRounds)
        {
            throw new SshKeyFileException($"The key file asks for more than {BCryptPbkdf.MaxRounds} key derivation rounds, which isn't accepted. Lower it with: ssh-keygen -p -a 24 -f <file>");
        }

        Span<byte> derived = stackalloc byte[MaxDerivedLength];
        derived = derived[..(cipher.KeyLength + cipher.IvLength)];
        try
        {
            BCryptPbkdf.DeriveKey(passphrase, salt, (int)rounds, derived);
            if (!cipher.Decrypt(derived[..cipher.KeyLength], derived[cipher.KeyLength..], sealedSection, tag, section))
            {
                throw new SshKeyFileException(SshKeyFile.WrongPassphrase);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(derived);
        }
    }

    private static SshPrivateKey ParsePrivateSection(ReadOnlySpan<byte> section, SshPublicKey publicKey, bool encrypted)
    {
        SshReader reader = new(section);
        uint check1 = reader.ReadUInt32();
        uint check2 = reader.ReadUInt32();
        if (check1 != check2)
        {
            // CTR and CBC have no tag, so this is how a wrong passphrase shows itself.
            throw new SshKeyFileException(encrypted ? SshKeyFile.WrongPassphrase : SshKeyFile.Malformed);
        }

        if (!Ascii.Equals(reader.ReadBinary(), publicKey.KeyType))
        {
            throw new SshKeyFileException(SshKeyFile.Mismatch);
        }

        SshPrivateKey key = ReadKey(ref reader, publicKey);
        try
        {
            reader.ReadBinary(); // The comment.
            CheckPadding(reader.RemainingSpan);
            if (!key.PublicKey.Blob.Span.SequenceEqual(publicKey.Blob.Span))
            {
                throw new SshKeyFileException(SshKeyFile.Mismatch);
            }

            return key;
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    private static SshPrivateKey ReadKey(ref SshReader reader, SshPublicKey publicKey)
    {
        if (publicKey.KeyType == Ed25519PublicKey.Name)
        {
            return ReadEd25519(ref reader);
        }

        if (publicKey.KeyType == RsaPublicKey.Name)
        {
            return ReadRsa(ref reader);
        }

        NistCurve curve = NistCurve.FromKeyType(publicKey.KeyType) ?? throw new SshKeyFileException(SshKeyFile.UnsupportedKey);
        return ReadEcdsa(ref reader, curve);
    }

    /// <summary>The private value is the 32-byte seed followed by a copy of the public key.</summary>
    private static Ed25519PrivateKey ReadEd25519(ref SshReader reader)
    {
        ReadOnlySpan<byte> publicValue = reader.ReadBinary();
        ReadOnlySpan<byte> privateValue = reader.ReadBinary();
        if (publicValue.Length != Ed25519KeyLength || privateValue.Length != 2 * Ed25519KeyLength)
        {
            throw new SshKeyFileException(SshKeyFile.Malformed);
        }

        if (!privateValue[Ed25519KeyLength..].SequenceEqual(publicValue))
        {
            throw new SshKeyFileException(SshKeyFile.Mismatch);
        }

        return Ed25519PrivateKey.FromSeed(privateValue[..Ed25519KeyLength]);
    }

    private static EcdsaPrivateKey ReadEcdsa(ref SshReader reader, NistCurve curve)
    {
        ReadOnlySpan<byte> identifier = reader.ReadBinary();
        ReadOnlySpan<byte> encodedPoint = reader.ReadBinary();
        ReadOnlySpan<byte> scalar = reader.ReadMPInt();
        if (!Ascii.Equals(identifier, curve.Identifier)
            || !curve.TryDecodePoint(encodedPoint, out ECPoint point)
            || scalar.IsEmpty
            || scalar.Length > curve.CoordinateLength)
        {
            throw new SshKeyFileException(SshKeyFile.Malformed);
        }

        byte[] d = Pad(scalar, curve.CoordinateLength);
        try
        {
            return EcdsaPrivateKey.Adopt(curve, ECDsa.Create(new ECParameters { Curve = curve.Curve, Q = point, D = d }));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(d);
        }
    }

    /// <summary>The file has n, e, d, iqmp, p and q. The BCL also wants d mod (p-1) and d mod (q-1).</summary>
    private static RsaPrivateKey ReadRsa(ref SshReader reader)
    {
        ReadOnlySpan<byte> n = reader.ReadMPInt();
        ReadOnlySpan<byte> e = reader.ReadMPInt();
        ReadOnlySpan<byte> d = reader.ReadMPInt();
        ReadOnlySpan<byte> iqmp = reader.ReadMPInt();
        ReadOnlySpan<byte> p = reader.ReadMPInt();
        ReadOnlySpan<byte> q = reader.ReadMPInt();

        // The BCL's layout: d as wide as n, and the rest half that, rounded up. Primes are odd, which Residue relies on.
        int size = n.Length;
        int half = (size + 1) / 2;
        if (n.IsEmpty || e.IsEmpty || d.IsEmpty || iqmp.IsEmpty || p.IsEmpty || q.IsEmpty
            || d.Length > size || iqmp.Length > half || p.Length > half || q.Length > half
            || (p[^1] & 1) == 0 || (q[^1] & 1) == 0)
        {
            throw new SshKeyFileException(SshKeyFile.Malformed);
        }

        RSAParameters parameters = new()
        {
            Modulus = n.ToArray(),
            Exponent = e.ToArray(),
            D = Pad(d, size),
            P = Pad(p, half),
            Q = Pad(q, half),
            InverseQ = Pad(iqmp, half),
            DP = RsaKeyValues.Residue(d, p, half),
            DQ = RsaKeyValues.Residue(d, q, half),
        };

        try
        {
            RsaKeyValues.EnsureConsistent(n, e, d, p, q, parameters.DP, parameters.DQ, iqmp);
            return RsaPrivateKey.Adopt(RSA.Create(parameters));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(parameters.D);
            CryptographicOperations.ZeroMemory(parameters.P);
            CryptographicOperations.ZeroMemory(parameters.Q);
            CryptographicOperations.ZeroMemory(parameters.InverseQ);
            CryptographicOperations.ZeroMemory(parameters.DP);
            CryptographicOperations.ZeroMemory(parameters.DQ);
        }
    }

    private static byte[] Pad(ReadOnlySpan<byte> value, int length)
    {
        byte[] padded = new byte[length];
        value.CopyTo(padded.AsSpan(length - value.Length));
        return padded;
    }

    /// <summary>The padding is the bytes 1, 2, 3 and so on. OpenSSH checks it, and anything else means a damaged file.</summary>
    private static void CheckPadding(ReadOnlySpan<byte> padding)
    {
        for (int i = 0; i < padding.Length; i++)
        {
            if (padding[i] != (byte)(i + 1))
            {
                throw new SshKeyFileException(SshKeyFile.Malformed);
            }
        }
    }
}

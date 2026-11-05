using System;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Text;

namespace Zorg.Ssh.Crypto.KeyFiles;

/// <summary>
/// Loads a private key from the text of a key file: OpenSSH's own format, PKCS#1, SEC1 or PKCS#8. The text is treated
/// as hostile. Every failure is a <see cref="SshKeyFileException"/>, and a loaded key has proved it can sign.
/// </summary>
internal static class SshKeyFile
{
    /// <summary>The longest file accepted, in characters. The same as OpenSSH's limit, far above any real key.</summary>
    public const int MaxFileLength = 1 << 20;

    /// <summary>The largest RSA modulus accepted, in bits. The same as OpenSSH, and it bounds the cost of signing.</summary>
    public const int MaxRsaBits = 16384;

    /// <summary>The message for a wrong passphrase.</summary>
    internal const string WrongPassphrase = "The passphrase is wrong, or the key file is damaged. Check the passphrase and try again.";

    /// <summary>The message for an encrypted file with no passphrase.</summary>
    internal const string PassphraseRequired = "The private key file is encrypted. Supply its passphrase.";

    /// <summary>The message for a file that isn't what it claims to be.</summary>
    internal const string Malformed = "The private key file is malformed. Check that it's a complete, unmodified private key file.";

    /// <summary>The message for a public key that doesn't belong to the private key beside it.</summary>
    internal const string Mismatch = "The public key in the file doesn't match its private key, so the file is damaged or has been altered. Generate a new key or restore the file.";

    /// <summary>The message for a valid key that isn't one this library uses.</summary>
    internal const string UnsupportedKey = "The key in the file isn't supported. Use an Ed25519 key, an ECDSA key on P-256, P-384 or P-521, or an RSA key of 2048 to 16384 bits.";

    /// <summary>The message for the encrypted PEM format that predates PKCS#8.</summary>
    internal const string LegacyPem = "The private key file uses the legacy encrypted PEM format (Proc-Type: 4,ENCRYPTED), which isn't supported. Convert it to OpenSSH's format with: ssh-keygen -p -f <file>";

    /// <summary>Loads a key.</summary>
    /// <param name="text">The whole file.</param>
    /// <param name="passphrase">The passphrase, if the file has one. It's used as UTF-8, as <c>ssh-keygen</c> does.</param>
    public static SshPrivateKey Load(string text, string? passphrase = null)
    {
        ArgumentNullException.ThrowIfNull(text);
        if (string.IsNullOrEmpty(passphrase))
        {
            return Load(text.AsSpan(), default);
        }

        byte[] passphraseBytes = Encoding.UTF8.GetBytes(passphrase);
        try
        {
            return Load(text.AsSpan(), passphraseBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passphraseBytes);
        }
    }

    /// <summary>Loads a key. Use this form to keep the passphrase in a buffer that you can zero.</summary>
    /// <param name="text">The whole file.</param>
    /// <param name="passphrase">The passphrase as raw bytes, or empty if there is none.</param>
    public static SshPrivateKey Load(ReadOnlySpan<char> text, ReadOnlySpan<byte> passphrase)
    {
        if (text.Length > MaxFileLength)
        {
            throw new SshKeyFileException("The file is too large to be a private key. Check that this is the right file.");
        }

        PemArmor.Block block = PemArmor.FindPrivateKey(text);
        if (block.LegacyEncrypted)
        {
            throw new SshKeyFileException(LegacyPem);
        }

        byte[] data = block.Decode();
        try
        {
#pragma warning disable CA2000 // Disposed below if the check fails. Otherwise it's returned, and the caller owns it.
            SshPrivateKey key = Parse(block.Label, data, passphrase);
#pragma warning restore CA2000
            try
            {
                EnsureCanSign(key);
            }
            catch
            {
                key.Dispose();
                throw;
            }

            return key;
        }
        catch (Exception ex) when (IsBadKeyData(ex))
        {
            throw new SshKeyFileException(Malformed, ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(data);
        }
    }

    /// <summary>Gets whether an exception is what the parsers and the platform throw for bad data, rather than a bug.</summary>
    internal static bool IsBadKeyData(Exception exception) => exception
        is CryptographicException
        or SshProtocolException
        or AsnContentException
        or ArgumentException
        or FormatException
        or OverflowException;

    private static SshPrivateKey Parse(string label, byte[] data, ReadOnlySpan<byte> passphrase)
    {
        switch (label)
        {
            case PemArmor.OpenSsh:
                return OpenSshKeyFormat.Parse(data, passphrase);
            case PemArmor.Rsa:
                return Pkcs8KeyFormat.ParsePkcs1(data);
            case PemArmor.Ec:
                return Pkcs8KeyFormat.ParseSec1(data);
            case PemArmor.Pkcs8:
                return Pkcs8KeyFormat.ParsePkcs8(data);
            default:
                return Pkcs8KeyFormat.ParseEncryptedPkcs8(data, passphrase);
        }
    }

    /// <summary>
    /// Makes one signature and checks it with the public key. This is the check that the private and public halves
    /// belong together: platform importers differ in what they verify, and one bad RSA value is enough to break it.
    /// </summary>
    private static void EnsureCanSign(SshPrivateKey key)
    {
        string algorithm = key.SignatureAlgorithms[0];
        Span<byte> challenge = stackalloc byte[32];
        RandomNumberGenerator.Fill(challenge);
        if (!key.PublicKey.Verify(algorithm, challenge, key.Sign(algorithm, challenge)))
        {
            throw new SshKeyFileException(Mismatch);
        }
    }
}

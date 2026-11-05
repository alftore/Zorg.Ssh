using System;
using System.Security.Cryptography;

namespace Zorg.Ssh.Crypto.KeyFiles;

/// <summary>
/// Finds the private key block in PEM text. This isn't <c>PemEncoding</c> because legacy encrypted files have RFC 1421
/// headers, which need their own message. It makes one pass, so the cost of a hostile file is linear.
/// </summary>
internal static class PemArmor
{
    /// <summary>The label of OpenSSH's format.</summary>
    public const string OpenSsh = "OPENSSH PRIVATE KEY";

    /// <summary>The label of a PKCS#1 RSA key.</summary>
    public const string Rsa = "RSA PRIVATE KEY";

    /// <summary>The label of a SEC1 EC key.</summary>
    public const string Ec = "EC PRIVATE KEY";

    /// <summary>The label of a PKCS#8 key.</summary>
    public const string Pkcs8 = "PRIVATE KEY";

    /// <summary>The label of an encrypted PKCS#8 key.</summary>
    public const string EncryptedPkcs8 = "ENCRYPTED PRIVATE KEY";

    private const string Begin = "-----BEGIN ";
    private const string End = "-----END ";
    private const string Dashes = "-----";

    /// <summary>
    /// Finds the first block with a known label. Others are stepped over, because <c>openssl ecparam -genkey</c>
    /// writes an <c>EC PARAMETERS</c> block ahead of the key.
    /// </summary>
    public static Block FindPrivateKey(ReadOnlySpan<char> text)
    {
        int position = 0;
        while (position < text.Length)
        {
            ReadOnlySpan<char> line = NextLine(text, ref position);
            if (line.StartsWith(Begin, StringComparison.Ordinal) && line.EndsWith(Dashes, StringComparison.Ordinal) && line.Length >= Begin.Length + Dashes.Length)
            {
                string? label = KnownLabel(line[Begin.Length..^Dashes.Length]);
                if (label is not null)
                {
                    return ReadBlock(text, position, label);
                }
            }
        }

        throw new SshKeyFileException("The text holds no private key. Check that this is the private key file, not the .pub file, and that a PuTTY key has been exported to OpenSSH format.");
    }

    private static Block ReadBlock(ReadOnlySpan<char> text, int position, string label)
    {
        bool legacyEncrypted = false;
        int bodyStart = position;
        bool inHeaders = true;
        while (position < text.Length)
        {
            int lineStart = position;
            ReadOnlySpan<char> line = NextLine(text, ref position);
            if (line.StartsWith(End, StringComparison.Ordinal))
            {
                if (!line.EndsWith(Dashes, StringComparison.Ordinal)
                    || line.Length < End.Length + Dashes.Length
                    || !line[End.Length..^Dashes.Length].SequenceEqual(label))
                {
                    break;
                }

                return new Block(label, text[bodyStart..lineStart], legacyEncrypted);
            }

            // RFC 1421 headers come first. Base64 has no colon, so a colon marks one.
            if (inHeaders && line.Contains(':'))
            {
                legacyEncrypted |= line.StartsWith("Proc-Type:", StringComparison.OrdinalIgnoreCase) && line.Contains("ENCRYPTED", StringComparison.OrdinalIgnoreCase);
                bodyStart = position;
            }
            else if (!line.IsEmpty)
            {
                inHeaders = false;
            }
        }

        throw new SshKeyFileException(SshKeyFile.Malformed);
    }

    private static string? KnownLabel(ReadOnlySpan<char> label) => label switch
    {
        OpenSsh => OpenSsh,
        Rsa => Rsa,
        Ec => Ec,
        Pkcs8 => Pkcs8,
        EncryptedPkcs8 => EncryptedPkcs8,
        _ => null,
    };

    /// <summary>Returns the next line without its ending or surrounding whitespace, and moves past it.</summary>
    private static ReadOnlySpan<char> NextLine(ReadOnlySpan<char> text, ref int position)
    {
        ReadOnlySpan<char> rest = text[position..];
        int end = rest.IndexOf('\n');
        position = end < 0 ? text.Length : position + end + 1;
        return (end < 0 ? rest : rest[..end]).Trim();
    }

    /// <summary>One armored block. The body is base64 with line breaks.</summary>
    internal readonly ref struct Block
    {
        private readonly ReadOnlySpan<char> _body;

        public Block(string label, ReadOnlySpan<char> body, bool legacyEncrypted)
        {
            Label = label;
            _body = body;
            LegacyEncrypted = legacyEncrypted;
        }

        /// <summary>Gets the label, one of the constants above.</summary>
        public string Label { get; }

        /// <summary>Gets whether the headers say this block is encrypted the legacy way.</summary>
        public bool LegacyEncrypted { get; }

        /// <summary>Decodes the body. The caller zeroes the result, which can be an unencrypted key.</summary>
        public byte[] Decode()
        {
            byte[] decoded = new byte[(_body.Length / 4 * 3) + 3];
            try
            {
                if (!Convert.TryFromBase64Chars(_body, decoded, out int written) || written == 0)
                {
                    throw new SshKeyFileException(SshKeyFile.Malformed);
                }

                return decoded.AsSpan(0, written).ToArray();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(decoded);
            }
        }
    }
}

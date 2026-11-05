using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Xunit;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Protocol;
using Zorg.Ssh.Tests.Crypto;

namespace Zorg.Ssh.Tests.KeyFiles;

/// <summary>A key file that <c>ssh-keygen</c> just wrote, with the blob from its .pub file.</summary>
internal sealed record GeneratedKey(string PrivateText, byte[] PublicBlob);

/// <summary>Runs <c>ssh-keygen</c> into a temporary directory. No private key is ever kept.</summary>
internal static class KeyFileTools
{
    public const string Passphrase = "correct horse battery";

    /// <summary>Generates a key and returns what it wrote. The files go when the method returns.</summary>
    public static GeneratedKey Generate(
        string type,
        string? bits = null,
        string? format = null,
        string? cipher = null,
        string passphrase = "",
        string? rounds = null)
    {
        string keygen = OpenSshTools.Require("ssh-keygen");
        using TempDirectory directory = new();
        string file = Path.Combine(directory.Path, "key");

        List<string> arguments = ["-q", "-t", type, "-N", passphrase, "-C", "zorg test key", "-f", file];
        AddOption(arguments, "-b", bits);
        AddOption(arguments, "-m", format);
        AddOption(arguments, "-Z", cipher);
        AddOption(arguments, "-a", rounds);

        (int exitCode, string output) = OpenSshTools.Run(keygen, arguments);
        Assert.True(exitCode == 0, output);
        return new GeneratedKey(File.ReadAllText(file), Sshsig.PublicKeyLine(File.ReadAllText(file + ".pub")));
    }

    /// <summary>Signs with every algorithm the key has, and checks each with the public key given.</summary>
    public static void AssertSignsFor(SshPrivateKey key, byte[] publicBlob)
    {
        Assert.Equal(publicBlob, key.PublicKey.Blob.ToArray());
        SshPublicKey publicKey = SshPublicKey.Parse(publicBlob);
        byte[] message = Encoding.ASCII.GetBytes("signed after loading from a file");
        Assert.NotEmpty(key.SignatureAlgorithms);
        foreach (string algorithm in key.SignatureAlgorithms)
        {
            byte[] signature = key.Sign(algorithm, message);
            Assert.True(publicKey.Verify(algorithm, message, signature), algorithm);

            signature[^1] ^= 1;
            Assert.False(publicKey.Verify(algorithm, message, signature), algorithm);
        }
    }

    /// <summary>Wraps binary data in PEM, with 70 characters to a line as OpenSSH writes it.</summary>
    public static string Armor(string label, ReadOnlySpan<byte> data)
    {
        string base64 = Convert.ToBase64String(data);
        StringBuilder text = new($"-----BEGIN {label}-----\n");
        for (int i = 0; i < base64.Length; i += 70)
        {
            text.Append(base64, i, Math.Min(70, base64.Length - i)).Append('\n');
        }

        return text.Append($"-----END {label}-----\n").ToString();
    }

    /// <summary>Returns the binary contents of an armored file.</summary>
    public static byte[] Unarmor(string text)
    {
        StringBuilder base64 = new();
        foreach (string line in text.Split('\n'))
        {
            if (!line.StartsWith("-----", StringComparison.Ordinal))
            {
                base64.Append(line.Trim());
            }
        }

        return Convert.FromBase64String(base64.ToString());
    }

    private static void AddOption(List<string> arguments, string option, string? value)
    {
        if (value is not null)
        {
            arguments.Add(option);
            arguments.Add(value);
        }
    }
}

/// <summary>Builds <c>openssh-key-v1</c> files field by field, so that a test can break exactly one thing.</summary>
internal sealed class OpenSshFileBuilder
{
    public string Cipher { get; set; } = "none";

    public string Kdf { get; set; } = "none";

    public byte[] KdfOptions { get; set; } = [];

    public uint KeyCount { get; set; } = 1;

    public byte[] PublicBlob { get; set; } = [];

    public byte[] Section { get; set; } = [];

    public byte[] AfterSection { get; set; } = [];

    /// <summary>Makes the <c>bcrypt</c> options field.</summary>
    public static byte[] BcryptOptions(ReadOnlySpan<byte> salt, uint rounds)
    {
        SshWriter writer = new();
        try
        {
            writer.WriteBinary(salt);
            writer.WriteUInt32(rounds);
            return writer.ToArray();
        }
        finally
        {
            writer.Dispose();
        }
    }

    /// <summary>Makes a private section from key fields already encoded, with padding to 8 bytes.</summary>
    public static byte[] MakeSection(string keyType, ReadOnlySpan<byte> fields, uint check1 = 0x12345678, uint check2 = 0x12345678, int blockSize = 8)
    {
        SshWriter writer = new();
        try
        {
            writer.WriteUInt32(check1);
            writer.WriteUInt32(check2);
            writer.WriteUtf8String(keyType);
            writer.WriteRaw(fields);
            writer.WriteUtf8String("comment");
            for (byte pad = 1; writer.Length % blockSize != 0; pad++)
            {
                writer.WriteByte(pad);
            }

            return writer.ToArray();
        }
        finally
        {
            writer.Dispose();
        }
    }

    public byte[] ToBinary()
    {
        SshWriter writer = new();
        try
        {
            writer.WriteRaw("openssh-key-v1\0"u8);
            writer.WriteUtf8String(Cipher);
            writer.WriteUtf8String(Kdf);
            writer.WriteBinary(KdfOptions);
            writer.WriteUInt32(KeyCount);
            writer.WriteBinary(PublicBlob);
            writer.WriteBinary(Section);
            writer.WriteRaw(AfterSection);
            return writer.ToArray();
        }
        finally
        {
            writer.Dispose();
        }
    }

    public string ToText() => KeyFileTools.Armor("OPENSSH PRIVATE KEY", ToBinary());
}

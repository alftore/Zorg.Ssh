using System;
using System.Text;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Crypto.Keys;

/// <summary>The outer signature format: <c>string algorithm</c>, <c>string signature</c>.</summary>
internal static class SignatureBlob
{
    /// <summary>Reads a blob. Returns false if it's malformed, has trailing data, or names another algorithm.</summary>
    public static bool TryRead(string expectedAlgorithm, ReadOnlySpan<byte> blob, out ReadOnlySpan<byte> signature)
    {
        signature = default;
        try
        {
            SshReader reader = new(blob);
            ReadOnlySpan<byte> algorithm = reader.ReadBinary();
            ReadOnlySpan<byte> value = reader.ReadBinary();
            reader.EnsureEnd();
            if (!Ascii.Equals(algorithm, expectedAlgorithm))
            {
                return false;
            }

            signature = value;
            return true;
        }
        catch (SshProtocolException)
        {
            return false;
        }
    }

    /// <summary>Writes a blob.</summary>
    public static byte[] Write(string algorithm, ReadOnlySpan<byte> signature)
    {
        SshWriter writer = new(signature.Length + algorithm.Length + 8);
        try
        {
            writer.WriteUtf8String(algorithm);
            writer.WriteBinary(signature);
            return writer.ToArray();
        }
        finally
        {
            writer.Dispose();
        }
    }
}

using System.Numerics;
using Xunit;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Tests.KnownHosts;

/// <summary>M5 review T1: an Ed25519 key must not have two accepted spellings, or revocation by blob would be dodged.</summary>
public sealed class Ed25519EncodingTests
{
    private static byte[] Blob(byte[] raw)
    {
        SshWriter writer = new(64);
        try
        {
            writer.WriteUtf8String("ssh-ed25519");
            writer.WriteBinary(raw);
            return writer.ToArray();
        }
        finally
        {
            writer.Dispose();
        }
    }

    [Fact]
    public void T1_an_Ed25519_key_has_one_accepted_spelling_for_every_small_y()
    {
        BigInteger p = (BigInteger.One << 255) - 19;
        for (int y = 2; y < 19; y++)
        {
            byte[] canonical = new byte[32];
            ((BigInteger)y).TryWriteBytes(canonical, out _, isUnsigned: true);
            byte[] alias = new byte[32];
            (p + y).TryWriteBytes(alias, out _, isUnsigned: true);
            Assert.False(Accepts(alias), $"y={y}: the non-canonical spelling is accepted");
        }
    }

    private static bool Accepts(byte[] raw)
    {
        try
        {
            SshPublicKey.Parse(Blob(raw));
            return true;
        }
        catch (SshProtocolException)
        {
            return false;
        }
    }
}

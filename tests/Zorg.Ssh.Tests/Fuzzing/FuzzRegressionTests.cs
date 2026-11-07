using System;
using System.Linq;
using System.Security.Cryptography;
using Xunit;
using Zorg.Ssh.Crypto.KeyFiles;
using Zorg.Ssh.Tests.KeyFiles;

namespace Zorg.Ssh.Tests.Fuzzing;

/// <summary>
/// One test for each finding the fuzzer has made, named for what it found, so the fix stays when the fuzzer's corpus or
/// mutator changes. The comment on each says which target found it and with which seed. Keys are built in code, never stored.
/// </summary>
public sealed class FuzzRegressionTests
{
    // Found by a two minute run on Windows: target OpenSshKeyFormat.Parse, seed 48426057202589510. The fuzzer had swapped the
    // public exponent and the private exponent in the private section of an openssh-key-v1 RSA file. That is still a consistent
    // key (e and d are each other's inverse), but its "public exponent" is as wide as the modulus. The platform (CNG) refuses
    // that with a CryptographicException, which OpenSshKeyFormat let through. SshKeyFile.Load already turned it into a
    // SshKeyFileException, so no caller saw it, but the parser's own contract is SshKeyFileException. The file is built here from
    // the generated RSA key with the two exponents exchanged.
    [Fact]
    public void An_RSA_key_file_with_an_exponent_the_platform_refuses_is_a_SshKeyFileException_not_a_CryptographicException()
    {
        FuzzKeys.RsaValues values = FuzzKeys.Rsa;
        FuzzKeys.RsaValues swapped = values with { E = values.D, D = values.E };
        byte[] file = FuzzKeys.RsaOpenSshFile(swapped, values.E);

        // Windows (CNG) refuses the key itself. OpenSSL imports it, and the library then refuses the exponent as a public key
        // (SshProtocolException). Either way the parser throws one of its own two types, and Load throws only SshKeyFileException.
        Exception? direct = Record.Exception(() => OpenSshKeyFormat.Parse(file, default).Dispose());
        Assert.True(direct is null or SshKeyFileException or SshProtocolException, direct?.ToString());
        Exception? loaded = Record.Exception(() => SshKeyFile.Load(KeyFileTools.Armor("OPENSSH PRIVATE KEY", file)).Dispose());
        Assert.True(loaded is null or SshKeyFileException, loaded?.ToString());
        if (OperatingSystem.IsWindows())
        {
            Assert.IsType<SshKeyFileException>(direct);
            Assert.IsType<CryptographicException>(direct.InnerException);
        }
    }

    // Found by a two minute run on Linux: target "PacketReader (AES-CTR, encrypt-and-MAC)", seed 18180106958315875163. The input
    // was the odd (self-sealed) form: a KEXINIT packet and then 10 KB of zero bytes, each four of which is a length of 0, so the
    // harness sealed about 2,600 empty packets with the reference cipher (an Aes object, an HMAC and a BigInteger counter for
    // each). The call allocated 2,256,232 bytes against a budget of 1,763,456: 2,243,912 of it in the sealing, 9,560 in creating
    // the cipher and 2,768 in the PacketReader, which stops at the first packet it refuses. The finding was the harness's, so the
    // sealing moved to FuzzTarget.Prepare, outside the measurement. This keeps the input and checks that what the runner measures
    // now, the library's reads, fits the budget with room to spare.
    [Fact]
    public void Sealing_thousands_of_empty_encrypt_and_MAC_packets_is_not_counted_against_the_packet_reader()
    {
        FuzzTarget target = FuzzTargets.Named(FuzzAllowedExceptions.PacketsEam);
        byte[] firstPacket = FuzzCorpus.EamPackets().First(s => s.Name == "eam plain 1").Data;
        byte[] input = [.. firstPacket, .. new byte[10_500]];
        Assert.NotNull(target.Prepare);
        byte[] prepared = target.Prepare(input);
        Assert.True(prepared.Length > input.Length + (2_000 * 32), $"the zeros sealed to {prepared.Length} bytes");

        long Measure()
        {
            long before = GC.GetAllocatedBytesForCurrentThread();
            try
            {
                target.Execute(prepared);
            }
            catch (Exception exception) when (target.Allowed.Any(type => type.IsInstanceOfType(exception)))
            {
                // A refusal is fine: the PacketReader refuses the first empty packet.
            }

            return GC.GetAllocatedBytesForCurrentThread() - before;
        }

        Measure();
        long allocated = Measure();
        Assert.True(allocated < target.AllocationBudget(input.Length) / 10, $"the reader allocated {allocated} bytes for an input of {input.Length}");
    }
}

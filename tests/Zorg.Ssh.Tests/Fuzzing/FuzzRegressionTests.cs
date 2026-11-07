using System;
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
}

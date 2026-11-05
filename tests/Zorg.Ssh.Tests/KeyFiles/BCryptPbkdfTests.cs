using System;
using System.Diagnostics;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Xunit;
using Zorg.Ssh.Crypto.KeyFiles;

namespace Zorg.Ssh.Tests.KeyFiles;

/// <summary>
/// Published vectors, none of them made by this code. "pyca" is the test suite of pyca/bcrypt, which wraps OpenBSD's
/// C. "go" is golang.org/x/crypto/ssh/internal/bcrypt_pbkdf.
/// </summary>
public class BCryptPbkdfTests
{
    private const string Lorem =
        "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do"
        + " eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut "
        + "enim ad minim veniam, quis nostrud exercitation ullamco laboris "
        + "nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor "
        + "in reprehenderit in voluptate velit esse cillum dolore eu fugiat"
        + " nulla pariatur. Excepteur sint occaecat cupidatat non proident,"
        + " sunt in culpa qui officia deserunt mollit anim id est laborum.";

    public static TheoryData<string, int, string, string, string> Vectors => new()
    {
        { "pyca 1", 4, Hex("password"), Hex("salt"), "5bbf0cc293587f1c3635555c27796598d47e579071bf427e9d8fbe842aba34d9" },
        { "pyca nul salt", 4, Hex("password"), "00", "c12b566235eee04c212598970a579a67" },
        { "pyca nul password", 4, "00", Hex("salt"), "6051be18c2f4f82cbf0efee5471b4bb9" },
        { "pyca nul ends", 4, Hex("password\0"), Hex("salt\0"), "7410e44cf4fa07bfaac8a928b1727fac001375e7bf7384370f48efd121743050" },
        { "pyca nul inside 1", 4, Hex("pass\0wor"), Hex("sa\0l"), "c2bffd9db38f6569efef4372f4de83c0" },
        { "pyca nul inside 2", 4, Hex("pass\0word"), Hex("sa\0lt"), "4ba4ac3925c0e8d7f0cdb6bb1684a56f" },
        {
            "pyca bigger key",
            8,
            Hex("password"),
            Hex("salt"),
            "e1367ec5151a33faac4cc1c144cd23fa15d5548493ecc99b9b5d9c0d3b27bec76227ea66088b849b20ab7aa478010246e74bba51723fefa9f9474d6508845e8d"
        },
        { "pyca more rounds", 42, Hex("password"), Hex("salt"), "833cf0dcf56db65608e8f0dc0ce882bd" },
        { "pyca long password", 8, Hex(Lorem), Hex("salis\0"), "10978b07253df57f71a162eb0e8ad30a" },
        { "pyca binary", 8, "0db3ac94b3ee53284f4a22893b3c24ae", "3a62f0f0dbcef823cfcc854856ea1028", "20443817" + "5eee7ce136c91b49a67923ff" },
        {
            "pyca very large key",
            8,
            "0db3ac94b3ee53284f4a22893b3c24ae",
            "3a62f0f0dbcef823cfcc854856ea1028",
            "2054b9fff34e37214403347468" + "28e9ed38de4b72e0a69adc170a13b5e8d646385ea4034ae6d26600ee2332c5ed40ad55"
            + "7c86e3403fbb30e4e1dc1ae06b99a071368f518d2c426651c9e7e437fd6c915b1bbfc3a4cea71491490ea7afb7dd0290"
            + "a678a4f441128db1792eab2776b21eb4238e0715add4127dff44e4b3e4cc4c4f9970083f3f74bd698873fdf648844f75"
            + "c9bf7f9e0c4d9e5d89a77839974929666167" + "07611cb901de31a19726b6e08c3a8001661f2d5c9dcc33b4aa072f90dd0b"
            + "3f548d5eeba4211397e2fb062e526e1d68f46a4ce256185b4badc2685fbe78e1c7657b59f83ab9ab80cf9318d6add1f5"
            + "933f12d6f36182c8e8115f68030a1244"
        },
        {
            "pyca utf-8",
            8,
            "e1bd88ceb4cf85cf83cf83ceb5cf8dcf82",
            "cea4ceb7cebbcead" + "cebcceb1cf87cebfcf82",
            "43666c9b09ef33ed8c27e8e8f3e2d8e6"
        },
        { "go 1", 12, Hex("password"), Hex("salt"), "1ae42c05d487bc02f64921a4ebe4ea93bcacfe135fda99974c06b7b01fae149a" },
        { "go 2", 3, Hex("passwordy\0PASSWORD\0"), Hex("salty\0SALT\0"), "7f310bd3e78c3280c59ce4595211a2928e8d4ec744c1ed2efc9f764e3388e0ad" },
        {
            "go 3",
            8,
            Hex("секретное слово"),
            Hex("посолить немножко"),
            "8df43fc6fe131fc47f0c9e39224bd94c70b6fcc8ee8135faddf61156e6cb2733ea765f315a3e1e4afc35bf8687d189254c1e05a6fe80c0617f9183d67260d6a115c6c94e3603e2303fbb43a76a64523ffda686b1d4518543"
        },
    };

    [Theory]
    [MemberData(nameof(Vectors))]
    public void Matches_published_vectors(string name, int rounds, string password, string salt, string expected)
    {
        byte[] output = new byte[expected.Length / 2];
        BCryptPbkdf.DeriveKey(Convert.FromHexString(password), Convert.FromHexString(salt), rounds, output);
        Assert.True(Convert.ToHexStringLower(output) == expected, name);
    }

    // From golang.org/x/crypto: the inner hash on its own, so a failure here points at the Blowfish layer.
    [Fact]
    public void Inner_hash_matches_the_published_vector()
    {
        byte[] password = [.. Enumerable.Range(0, 64).Select(static i => (byte)i)];
        byte[] salt = [.. Enumerable.Range(0, 64).Select(static i => (byte)(i + 64))];
        byte[] output = new byte[32];
        new BCryptPbkdf.Blowfish().Hash(password, salt, output);
        Assert.Equal("87904870eef9deddf8e7611a140106e6aaf1a363d9a2c504db356443721eb555", Convert.ToHexStringLower(output));
    }

    // Every word of the table feeds the key schedule, so one matching block shows the digits of pi are all right.
    [Fact]
    public void Pi_table_and_cipher_match_BouncyCastle_Blowfish()
    {
        byte[] key = Convert.FromHexString("fedcba9876543210");
        byte[] block = Convert.FromHexString("0123456789abcdef");
        byte[] expected = new byte[8];
        BlowfishEngine engine = new();
        engine.Init(forEncryption: true, new KeyParameter(key));
        engine.ProcessBlock(block, 0, expected, 0);

        // An 8-byte key repeats every two words, and the 16 words here repeat the same way.
        uint[] words = new uint[16];
        for (int i = 0; i < words.Length; i += 2)
        {
            words[i] = 0xfedcba98;
            words[i + 1] = 0x76543210;
        }

        BCryptPbkdf.Blowfish ours = new();
        ours.Reset();
        ours.ExpandPlainKey(words);
        (uint left, uint right) = ours.Encrypt(0x01234567, 0x89abcdef);
        Assert.Equal(Convert.ToHexStringLower(expected), $"{left:x8}{right:x8}");
    }

    [Fact]
    public void Output_is_interleaved_across_blocks()
    {
        // Two blocks of output take alternate bytes from each block, so one block's bytes sit at the even positions.
        byte[] longer = new byte[64];
        byte[] shorter = new byte[32];
        BCryptPbkdf.DeriveKey("pw"u8, "salt"u8, 2, longer);
        BCryptPbkdf.DeriveKey("pw"u8, "salt"u8, 2, shorter);
        for (int i = 0; i < 32; i++)
        {
            Assert.Equal(shorter[i], longer[2 * i]);
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(BCryptPbkdf.MaxRounds + 1)]
    [InlineData(int.MaxValue)]
    public void Rounds_outside_the_limit_are_refused_at_once(int rounds)
    {
        Stopwatch watch = Stopwatch.StartNew();
        Assert.Throws<ArgumentOutOfRangeException>(() => BCryptPbkdf.DeriveKey("pw"u8, "salt"u8, rounds, new byte[32]));
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(1));
    }

    [Fact]
    public void Empty_inputs_and_oversized_output_are_refused()
    {
        Assert.Throws<ArgumentException>(() => BCryptPbkdf.DeriveKey([], "salt"u8, 1, new byte[32]));
        Assert.Throws<ArgumentException>(() => BCryptPbkdf.DeriveKey("pw"u8, [], 1, new byte[32]));
        Assert.Throws<ArgumentException>(() => BCryptPbkdf.DeriveKey("pw"u8, "salt"u8, 1, []));
        Assert.Throws<ArgumentException>(() => BCryptPbkdf.DeriveKey("pw"u8, "salt"u8, 1, new byte[BCryptPbkdf.MaxOutputLength + 1]));
    }

    private static string Hex(string text) => Convert.ToHexStringLower(Encoding.UTF8.GetBytes(text));
}

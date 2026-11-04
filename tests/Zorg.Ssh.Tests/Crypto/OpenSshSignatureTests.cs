using System;
using System.IO;
using System.Text;
using Xunit;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.Keys;

namespace Zorg.Ssh.Tests.Crypto;

/// <summary>
/// Known answers from real OpenSSH. The fixtures were made once with OpenSSH 10.6 <c>ssh-keygen</c>: a key,
/// its .pub line, and <c>ssh-keygen -Y sign -n zorg-test</c> over the message below. Only public keys and
/// signatures are here. The private keys were deleted.
/// </summary>
public class OpenSshSignatureTests
{
    private const string Namespace = "zorg-test";

    private static readonly byte[] FixtureMessage = Encoding.ASCII.GetBytes("zorg.ssh known answer\n");

    public static TheoryData<string, string, string, string> Fixtures => new()
    {
        {
            "ssh-ed25519",
            "ssh-ed25519",
            "AAAAC3NzaC1lZDI1NTE5AAAAIJc4IwRGujG+KB4vrXZluqEvUZ06C3c0PpIj2XgGJIQI",
            "U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAglzgjBEa6Mb4oHi+tdmW6oS9RnToLdzQ+kiPZeAYkhAgAAAAJem9yZy10ZXN0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5AAAAQDPhkO2jvWsqEI7Fv8SbBote0YVTz22Tm/CS0Ym79gEfQlJhFGxs1joe1bWkufPBkZhKvvRofainlwkjWzEsCQ8="
        },
        {
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp256",
            "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLjkGZj3VrQzKVL1GGtwUFIjKQLGrApHq/7bL2Gv4LORxHOS34WEM6Poa9XyJBzLDXBu9WroAn6jOwdpwgD8ios=",
            "U1NIU0lHAAAAAQAAAGgAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAAhuaXN0cDI1NgAAAEEEuOQZmPdWtDMpUvUYa3BQUiMpAsasCker/tsvYa/gs5HEc5LfhYQzo+hr1fIkHMsNcG71augCfqM7B2nCAPyKiwAAAAl6b3JnLXRlc3QAAAAAAAAABnNoYTUxMgAAAGUAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAEoAAAAhAJFUDV7TZSKVCgTGJWFw1vezVmwhGWP7dkwWf/e1DqJDAAAAIQD8k/87qQ3Kof3H0X2tQbRn593WqkbWVdM/UKgUsfaeiw=="
        },
        {
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp384",
            "AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBDqV8S5xStQ1SM5J7fQd9MmN3falLevvQ/xM/u79Tt3oZAD7QDHn3z4wO2KJNrL5IHySEqmpuF2Qo2v+J6+TM8ysMvcbzJbxhWI2+yCiAsQmPZ2DN56Zx2zeMiaFHwxd3Q==",
            "U1NIU0lHAAAAAQAAAIgAAAATZWNkc2Etc2hhMi1uaXN0cDM4NAAAAAhuaXN0cDM4NAAAAGEEOpXxLnFK1DVIzknt9B30yY3d9qUt6+9D/Ez+7v1O3ehkAPtAMeffPjA7Yok2svkgfJISqam4XZCja/4nr5MzzKwy9xvMlvGFYjb7IKICxCY9nYM3npnHbN4yJoUfDF3dAAAACXpvcmctdGVzdAAAAAAAAAAGc2hhNTEyAAAAgwAAABNlY2RzYS1zaGEyLW5pc3RwMzg0AAAAaAAAADBGfQ1q+BR/cuYxMQBDL0pgNs+pS0+pELrwvoLe66m2pTcnCXE15nzIhbtLkR04heYAAAAwCc92Ub9cxnuh83Ux7z2YWno/hGs7RedbMlkUvICMCziglfsNmJk5SnzlcsrblEKH"
        },
        {
            "ecdsa-sha2-nistp521",
            "ecdsa-sha2-nistp521",
            "AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAAU4al0Jhhw2mfKrk78ra3DDmD9dx0t49VnykV4QtIkjSHuLszjtcF5/bK//y/9/cpfwu7DOZuwkAldFbM9wjRr2wH6DaQVh7e8DQxK0V010hrpxROJb+QA8kxRMlMdPqsl+RTaS//u6ancy0Vdo4gUdNRKei/Yco2otqhU/I+pFxqmMQ==",
            "U1NIU0lHAAAAAQAAAKwAAAATZWNkc2Etc2hhMi1uaXN0cDUyMQAAAAhuaXN0cDUyMQAAAIUEABThqXQmGHDaZ8quTvytrcMOYP13HS3j1WfKRXhC0iSNIe4uzOO1wXn9sr//L/39yl/C7sM5m7CQCV0Vsz3CNGvbAfoNpBWHt7wNDErRXTXSGunFE4lv5ADyTFEyUx0+qyX5FNpL/+7pqdzLRV2jiBR01Ep6L9hyjai2qFT8j6kXGqYxAAAACXpvcmctdGVzdAAAAAAAAAAGc2hhNTEyAAAApwAAABNlY2RzYS1zaGEyLW5pc3RwNTIxAAAAjAAAAEIBKpySCweyItvoLcwsi2cbJbA+r9J8p3tG5qbkl0FZf7P5jgVvqrUDJFrFuKKu4jQ/h7KlJ7joi6q14PI5Ws3dRnsAAABCAYFGIcAzHn2I6k7ep1TL0lCVDmLPuub3mYYvhT+6IkiFFk+hMD9YDaqjZdFrZy5q6Iob8LSLMJDT41tKj/a6c5Gb"
        },
        {
            "ssh-rsa",
            "rsa-sha2-512",
            "AAAAB3NzaC1yc2EAAAADAQABAAABgQDpkcpQ/46OuPteXygFSew0BWk81Iyh+rzHaSJyLqWD13zR4Y3JsvqcBdny7u2y//KadzHEdWOMPhcoTo5bflJxaqMdND179mYPAWz8NMxrAWRubmYKvzt7AghJwI/Am/93opLWUqCgt7Kmk2+DXk5OtX82xXLwwLWBFauKdn/hL2FnZCTpeY7sVTr71NxbhykKcqNxH0hy75xhRRBkcmPfoOl/wJxN6nyp6uDzXiYmNWHJKDrQlH9aBFj5NVKg1lBcdrWdHZeB5TUfba79eJgBTQHoqJV3SdRi4oKNpmglYncTnQGuaWe/wBnMFJKBNjJmcE9hyM9IJX3liH9Pdqfb/4TEvJSjKJIprdkk7G/X7Z3ufIV4Ku/wwVjyhulTC4fE7KI+EZ3XK1h3srjZuxYieETKIkZcRFjYEkP4V9xpCsmFQHeCXdS21YKKzyv674+Zr4+7SYK1JB/+nICXM4PCj9sQTuzJXzNlaDHZW2g8S9WXJB6QVBj19pLCCnXsPOM=",
            "U1NIU0lHAAAAAQAAAZcAAAAHc3NoLXJzYQAAAAMBAAEAAAGBAOmRylD/jo64+15fKAVJ7DQFaTzUjKH6vMdpInIupYPXfNHhjcmy+pwF2fLu7bL/8pp3McR1Y4w+FyhOjlt+UnFqox00PXv2Zg8BbPw0zGsBZG5uZgq/O3sCCEnAj8Cb/3eiktZSoKC3sqaTb4NeTk61fzbFcvDAtYEVq4p2f+EvYWdkJOl5juxVOvvU3FuHKQpyo3EfSHLvnGFFEGRyY9+g6X/AnE3qfKnq4PNeJiY1YckoOtCUf1oEWPk1UqDWUFx2tZ0dl4HlNR9trv14mAFNAeiolXdJ1GLigo2maCVidxOdAa5pZ7/AGcwUkoE2MmZwT2HIz0glfeWIf092p9v/hMS8lKMokimt2STsb9ftne58hXgq7/DBWPKG6VMLh8Tsoj4RndcrWHeyuNm7FiJ4RMoiRlxEWNgSQ/hX3GkKyYVAd4Jd1LbVgorPK/rvj5mvj7tJgrUkH/6cgJczg8KP2xBO7MlfM2VoMdlbaDxL1ZckHpBUGPX2ksIKdew84wAAAAl6b3JnLXRlc3QAAAAAAAAABnNoYTUxMgAAAZQAAAAMcnNhLXNoYTItNTEyAAABgAwv7IaNrvRthYyB/7wyIV3ucLy6ds5+ViNK+3JwK5/PUcLB+LZBfQzzTEEFRvws2r2JzoC4ej+9rUODS59woPBWjaQfxqhldIvv1gpzIlSEdRyiQH8usVyMaJ5hl3TvOEb5wG8FhdZyZOHDE4gfwjaPUO+6+46O3ul8Ytp+FFRM2qp5xbcXLoZRcMqN31CnUQ48TU1/HvxB6p6pSvPlfIIAiRA0gqgpLwy04uuArQY72MsnzQN1Q5/wbpLoAiZLh/n+dpjwAfC9ls4T/w0mQ9VV3nJ2aTKI0E7hNTEQbnp82HXvRo8uqMPdsPwrOXGg8U1/JHApV0yeaEAXkmV/3vruf87t8EMmW9TwoJC9naBK+Vu/aWtjqM3K2VJMZt11HFt+q+qH7N8ZAfq+3IogS/Mz69mF/vmG6WQ3tFzzQGrVIoZybbtr3i0YPvdllmq2avodV2dgak6JT+2mTzOH6Bw02Oo0X8EENvtt+Cx5GddEPjqbnZPPkLHtiHl29sdDDw=="
        },
    };

    public static TheoryData<string, string> GeneratedKeyTypes => new()
    {
        { "ed25519", "256" },
        { "ecdsa", "256" },
        { "ecdsa", "384" },
        { "ecdsa", "521" },
        { "rsa", "3072" },
    };

    public static TheoryData<string> Algorithms => [.. HostKeyAlgorithms.Default];

    [Theory]
    [MemberData(nameof(Fixtures))]
    public void Real_OpenSSH_keys_and_signatures_verify(string keyType, string algorithm, string publicKey, string sshsig)
    {
        byte[] blob = Convert.FromBase64String(publicKey);
        SshPublicKey key = SshPublicKey.Parse(blob);
        Assert.Equal(keyType, key.KeyType);
        Assert.Equal(blob, key.Blob.ToArray());

        (byte[] embedded, string space, string hash, byte[] signature) = Sshsig.Parse(sshsig);
        Assert.Equal(blob, embedded);
        Assert.Equal(Namespace, space);
        Assert.Equal("sha512", hash);
        Assert.Equal(algorithm, Sshsig.SignatureAlgorithm(signature));

        byte[] signed = Sshsig.SignedData(Namespace, FixtureMessage);
        Assert.True(key.Verify(algorithm, signed, signature));

        signed[^1] ^= 1;
        Assert.False(key.Verify(algorithm, signed, signature));
    }

    // Fresh keys each run, so this covers values a fixed fixture can't, such as r or s with leading zeros.
    [Theory]
    [MemberData(nameof(GeneratedKeyTypes))]
    public void Keys_generated_now_by_ssh_keygen_verify(string type, string bits)
    {
        string keygen = OpenSshTools.Require("ssh-keygen");
        using TempDirectory directory = new();
        string keyFile = Path.Combine(directory.Path, "key");
        (int exitCode, string output) = OpenSshTools.Run(keygen, ["-q", "-t", type, "-b", bits, "-N", string.Empty, "-C", string.Empty, "-f", keyFile]);
        Assert.True(exitCode == 0, output);

        byte[] blob = Sshsig.PublicKeyLine(File.ReadAllText(keyFile + ".pub"));
        SshPublicKey key = SshPublicKey.Parse(blob);
        Assert.Equal(blob, key.Blob.ToArray());

        for (int i = 0; i < 4; i++)
        {
            string messageFile = Path.Combine(directory.Path, $"message{i}");
            byte[] message = Encoding.ASCII.GetBytes($"message {i}\n");
            File.WriteAllBytes(messageFile, message);
            (exitCode, output) = OpenSshTools.Run(keygen, ["-Y", "sign", "-f", keyFile, "-n", Namespace, messageFile]);
            Assert.True(exitCode == 0, output);

            (byte[] embedded, _, _, byte[] signature) = Sshsig.Parse(File.ReadAllText(messageFile + ".sig"));
            Assert.Equal(blob, embedded);
            Assert.True(key.Verify(Sshsig.SignatureAlgorithm(signature), Sshsig.SignedData(Namespace, message), signature));
        }
    }

    [Theory]
    [MemberData(nameof(Algorithms))]
    public void Ssh_keygen_accepts_our_keys_and_signatures(string algorithm)
    {
        string keygen = OpenSshTools.Require("ssh-keygen");
        using TempDirectory directory = new();
        using SshPrivateKey key = algorithm switch
        {
            "ssh-ed25519" => SshPrivateKey.GenerateEd25519(),
            "rsa-sha2-512" or "rsa-sha2-256" => SshPrivateKey.GenerateRsa(2048),
            _ => SshPrivateKey.GenerateEcdsa(algorithm),
        };

        byte[] message = Encoding.ASCII.GetBytes("signed by Zorg.Ssh\n");
        byte[] signature = key.Sign(algorithm, Sshsig.SignedData(Namespace, message));
        string signatureFile = Path.Combine(directory.Path, "message.sig");
        File.WriteAllText(signatureFile, Sshsig.Armor(key.PublicKey.Blob.Span, Namespace, signature));

        (int exitCode, string output) = OpenSshTools.Run(keygen, ["-Y", "check-novalidate", "-n", Namespace, "-s", signatureFile], message);
        Assert.True(exitCode == 0, output);

        // The same call with another message must fail, or the check above shows nothing.
        (exitCode, _) = OpenSshTools.Run(keygen, ["-Y", "check-novalidate", "-n", Namespace, "-s", signatureFile], [.. message, 0x21]);
        Assert.NotEqual(0, exitCode);
    }
}

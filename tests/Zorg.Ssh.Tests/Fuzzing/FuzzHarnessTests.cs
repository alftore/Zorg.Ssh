using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using Xunit;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Tests.Fuzzing;

/// <summary>
/// The fuzzer's own tests. A fuzzer that finds nothing might be right or might be blind, so these plant three bugs of the three
/// kinds guarantee 3 names (a stray exception, a hang, a huge allocation) in small decoders, and check that each is found, and
/// that a correct decoder is not. They also check that the mutator reaches the length positions it exists for.
/// </summary>
public sealed class FuzzHarnessTests
{
    private static readonly TimeSpan Limit = TimeSpan.FromMilliseconds(600);

    private static readonly FuzzSeed[] LengthPrefixedSeeds =
    [
        FuzzSeed.Binary("one string", new FuzzBlob().String("hello world").ToArray()),
        FuzzSeed.Binary("two strings", new FuzzBlob().String("ssh-ed25519").String(new byte[32]).ToArray()),
    ];

    private static FuzzTarget Decoder(string name, Func<byte[], FuzzOutcome> execute) => new()
    {
        Name = name,
        Corpus = LengthPrefixedSeeds,
        Execute = execute,
        Allowed = [typeof(SshProtocolException)],
    };

    private static FuzzReport Run(FuzzTarget target, int iterations = 4000) =>
        FuzzRunner.Run(target, new FuzzRunOptions(FuzzSettings.DefaultRunSeed, iterations, null, null, Limit));

    /// <summary>The reference decoder: checks everything, so the harness must stay quiet.</summary>
    private static FuzzOutcome Correct(byte[] input)
    {
        SshReader reader = new(input);
        reader.ReadBinary();
        reader.ReadBinary();
        reader.EnsureEnd();
        return FuzzOutcome.Accepted;
    }

    [Fact]
    public void A_correct_decoder_produces_no_finding()
    {
        FuzzReport report = Run(Decoder("correct", Correct));
        Assert.Empty(report.Findings);
        Assert.True(report.Accepted > 0 && report.Rejected > 0);
    }

    [Fact]
    public void A_decoder_that_trusts_a_length_is_caught_as_a_wrong_exception_type()
    {
        // The classic bug: slice by the length field without checking it against what is left.
        static FuzzOutcome Trusting(byte[] input)
        {
            uint length = BinaryPrimitives.ReadUInt32BigEndian(input.AsSpan(0, 4));
            _ = input.AsSpan(4, (int)length).ToArray();
            return FuzzOutcome.Accepted;
        }

        FuzzReport report = Run(Decoder("trusts the length", Trusting));
        FuzzFinding finding = report.Findings.First(f => f.Kind == FuzzFindingKind.Exception);
        Assert.Contains("ArgumentOutOfRangeException", finding.Detail, StringComparison.Ordinal);
        Assert.Contains("target=trusts the length", finding.Describe(), StringComparison.Ordinal);
    }

    [Fact]
    public void A_decoder_that_wraps_a_protocol_error_in_another_type_is_caught()
    {
        static FuzzOutcome Wrapping(byte[] input)
        {
            try
            {
                return Correct(input);
            }
            catch (SshProtocolException ex)
            {
                throw new InvalidOperationException("wrapped", ex);
            }
        }

        FuzzReport report = Run(Decoder("wraps", Wrapping));
        Assert.Contains(report.Findings, f => f.Kind == FuzzFindingKind.Exception && f.Detail.Contains("InvalidOperationException", StringComparison.Ordinal));
    }

    [Fact]
    public void A_decoder_that_hangs_on_a_huge_length_is_caught()
    {
        using ManualResetEventSlim release = new();
        FuzzOutcome Spinning(byte[] input)
        {
            if (input.Length >= 4 && BinaryPrimitives.ReadUInt32BigEndian(input) >= 0x7FFFFFFF)
            {
                // A loop that counts down a hostile length. This one waits to be let go, so the test can end.
                release.Wait();
            }

            return Correct(input);
        }

        try
        {
            FuzzReport report = Run(Decoder("hangs", Spinning), 20000);
            FuzzFinding finding = Assert.Single(report.Findings, f => f.Kind == FuzzFindingKind.Hang);
            Assert.True(BinaryPrimitives.ReadUInt32BigEndian(finding.Input) >= 0x7FFFFFFF);
            Assert.Contains("seed=", finding.Describe(), StringComparison.Ordinal);
        }
        finally
        {
            release.Set();
        }
    }

    [Fact]
    public void A_decoder_that_allocates_by_a_hostile_length_is_caught()
    {
        // Capped at 16 MiB so the test itself is safe. The decoder it stands for would ask for the full 2 GiB.
        static FuzzOutcome Allocating(byte[] input)
        {
            if (input.Length >= 4)
            {
                uint length = BinaryPrimitives.ReadUInt32BigEndian(input);
                byte[] buffer = new byte[Math.Min(length, 16 * 1024 * 1024)];
                GC.KeepAlive(buffer);
            }

            return Correct(input);
        }

        FuzzReport report = Run(Decoder("allocates", Allocating), 8000);
        FuzzFinding finding = report.Findings.First(f => f.Kind == FuzzFindingKind.Allocation);
        Assert.True(finding.Input.Length < 100, "the input that costs a lot of memory is small");
        Assert.Contains("allocated", finding.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void Allocation_in_the_harness_prepare_step_is_not_counted_and_the_decoder_still_is()
    {
        // The prepare step stands for harness work such as sealing plaintext. It costs far over any budget, and its output is what
        // the decoder gets. A decoder that allocates by a hostile length behind it must still be caught.
        static byte[] Expensive(byte[] input)
        {
            byte[] scratch = new byte[8 * 1024 * 1024];
            GC.KeepAlive(scratch);
            return [.. input];
        }

        FuzzReport quiet = Run(new FuzzTarget { Name = "prepared", Corpus = LengthPrefixedSeeds, Execute = Correct, Prepare = Expensive, Allowed = [typeof(SshProtocolException)] }, 1000);
        Assert.DoesNotContain(quiet.Findings, f => f.Kind == FuzzFindingKind.Allocation);

        static FuzzOutcome Allocating(byte[] input)
        {
            if (input.Length >= 4)
            {
                GC.KeepAlive(new byte[Math.Min(BinaryPrimitives.ReadUInt32BigEndian(input), 16 * 1024 * 1024)]);
            }

            return Correct(input);
        }

        FuzzReport caught = Run(new FuzzTarget { Name = "prepared and allocating", Corpus = LengthPrefixedSeeds, Execute = Allocating, Prepare = Expensive, Allowed = [typeof(SshProtocolException)] }, 8000);
        Assert.Contains(caught.Findings, f => f.Kind == FuzzFindingKind.Allocation);
    }

    [Fact]
    public void The_generated_keys_are_the_same_on_every_machine_and_load_in_every_format()
    {
        // The hash is of the generated text, not a key. If it changes, BouncyCastle's generator changed (or the encoders did),
        // and fuzz seeds recorded before the change rebuild different inputs. Update it then, and say so in the commit.
        string all = string.Concat(FuzzKeys.RsaOpenSsh, FuzzKeys.RsaPkcs1, FuzzKeys.RsaPkcs8, FuzzKeys.EcdsaOpenSsh, FuzzKeys.EcdsaSec1, FuzzKeys.EcdsaPkcs8, FuzzKeys.Ed25519OpenSsh, FuzzKeys.Ed25519Pkcs8);
        string hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(all)));
        Assert.True(hash == "D050D6B6C6F5417A6A6842FE1445D8781361E53F8736FD3DD63D54EF9A6D6EBC", hash);

        foreach ((string text, string type) in new[]
        {
            (FuzzKeys.RsaOpenSsh, "ssh-rsa"), (FuzzKeys.RsaPkcs1, "ssh-rsa"), (FuzzKeys.RsaPkcs8, "ssh-rsa"),
            (FuzzKeys.EcdsaOpenSsh, "ecdsa-sha2-nistp256"), (FuzzKeys.EcdsaSec1, "ecdsa-sha2-nistp256"), (FuzzKeys.EcdsaPkcs8, "ecdsa-sha2-nistp256"),
            (FuzzKeys.Ed25519OpenSsh, "ssh-ed25519"), (FuzzKeys.Ed25519Pkcs8, "ssh-ed25519"),
        })
        {
            using Zorg.Ssh.Crypto.SshPrivateKey key = Zorg.Ssh.Crypto.KeyFiles.SshKeyFile.Load(text);
            Assert.Equal(type, key.PublicKey.KeyType);
        }
    }

    [Fact]
    public void The_length_finder_finds_every_length_field_of_a_KEXINIT()
    {
        byte[] message = FuzzCorpus.KexInits()[0].Data;
        List<int> expected = [];
        int offset = 17;
        for (int list = 0; list < 10; list++)
        {
            expected.Add(offset);
            offset += 4 + (int)BinaryPrimitives.ReadUInt32BigEndian(message.AsSpan(offset));
        }

        List<int> found = FuzzLengthFields.Find(message);
        Assert.All(expected, e => Assert.Contains(e, found));
    }

    [Fact]
    public void The_length_finder_finds_nested_lengths_in_a_certificate()
    {
        byte[] certificate = FuzzCorpus.Certificates().First(s => s.Name == "user cert with options").Data;
        List<int> found = FuzzLengthFields.Find(certificate);

        // The key type string, the nonce, then (for ed25519) the key; inside the principals string, one string for each.
        Assert.Contains(0, found);
        Assert.True(found.Count >= 12, $"only {found.Count} length fields found");
    }

    [Fact]
    public void The_mutator_puts_boundary_values_into_length_positions()
    {
        FuzzSeed seed = FuzzCorpus.KexInits()[0];
        int[] lengthOffsets = [17];
        Dictionary<uint, int> seen = [];
        for (ulong i = 0; i < 6000; i++)
        {
            byte[] mutated = FuzzMutator.MutateBinary(new FuzzRandom(i), seed, [seed], lengthOffsets);
            foreach (int field in FuzzLengthFields.Find(seed.Data))
            {
                if (field + 4 <= mutated.Length)
                {
                    uint value = BinaryPrimitives.ReadUInt32BigEndian(mutated.AsSpan(field));
                    seen[value] = seen.GetValueOrDefault(value) + 1;
                }
            }
        }

        foreach (uint boundary in new uint[] { 0, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0xFFFFFFFE, 0x00FFFFFF })
        {
            Assert.True(seen.GetValueOrDefault(boundary) > 20, $"boundary {boundary:X8} appeared {seen.GetValueOrDefault(boundary)} times");
        }
    }

    [Fact]
    public void Resizing_inside_a_string_keeps_the_input_parsing_far_more_often_than_chance()
    {
        // The mutator changes a string's size and fixes the lengths around it, so the message stays whole. For a KEXINIT that
        // means a longer name-list that still parses, which is how an input gets past the framing to the names themselves.
        FuzzSeed seed = FuzzCorpus.KexInits()[0];
        int parsed = 0;
        const int Count = 3000;
        for (ulong i = 0; i < Count; i++)
        {
            byte[] mutated = FuzzMutator.MutateBinary(new FuzzRandom(i + 7), seed, [seed]);
            if (mutated.Length != seed.Data.Length)
            {
                try
                {
                    _ = Zorg.Ssh.Transport.KexInitMessage.Parse(mutated);
                    parsed++;
                }
                catch (SshProtocolException)
                {
                    // Expected for most.
                }
            }
        }

        Assert.True(parsed > Count / 50, $"only {parsed} of {Count} resized inputs still parsed");
    }

    [Fact]
    public void Text_mutation_changes_a_base64_key_and_the_line_still_reads_as_base64()
    {
        FuzzSeed seed = FuzzCorpus.KnownHostsTexts()[1];
        int changedKeys = 0;
        for (ulong i = 0; i < 2000; i++)
        {
            string mutated = FuzzText.Decode(FuzzMutator.MutateText(new FuzzRandom(i), seed, [seed], FuzzCorpus.KnownHostsTokens));
            string[] fields = mutated.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length >= 3 && fields[2] != seed.AsText().Split(' ')[2].TrimEnd('\n') && Zorg.Ssh.KnownHosts.KnownHostsFile.Parse(mutated).Entries.Count == 1)
            {
                changedKeys++;
            }
        }

        Assert.True(changedKeys > 20, $"only {changedKeys} inputs kept a changed, still valid key line");
    }
}

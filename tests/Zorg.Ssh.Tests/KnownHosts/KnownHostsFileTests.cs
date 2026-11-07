using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Xunit;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.KnownHosts;
using Zorg.Ssh.Tests.Crypto;

namespace Zorg.Ssh.Tests.KnownHosts;

public class KnownHostsFileTests
{
    private static readonly SshPublicKey Key = NewEd25519();
    private static readonly SshPublicKey OtherKey = NewEd25519();
    private static readonly SshPublicKey EcdsaKey = NewEcdsa();

    [Fact]
    public void A_plain_line_trusts_its_key()
    {
        KnownHostsFile file = Parse(Line("example.com", Key));
        Assert.Equal(KnownHostStatus.Trusted, file.Lookup("example.com", 22, Key));
    }

    [Fact]
    public void A_host_not_listed_is_unknown()
    {
        KnownHostsFile file = Parse(Line("example.com", Key));
        Assert.Equal(KnownHostStatus.Unknown, file.Lookup("example.org", 22, Key));
        Assert.Equal(KnownHostStatus.Unknown, Parse(string.Empty).Lookup("example.com", 22, Key));
    }

    [Fact]
    public void Another_key_for_a_known_host_is_changed()
    {
        KnownHostsFile file = Parse(Line("example.com", Key));
        Assert.Equal(KnownHostStatus.Changed, file.Lookup("example.com", 22, OtherKey));
    }

    // Stricter than ssh, which would call this new and ask. See KnownHostsFile.Lookup.
    [Fact]
    public void A_key_of_another_type_for_a_known_host_is_changed()
    {
        KnownHostsFile file = Parse(Line("example.com", Key));
        Assert.Equal(KnownHostStatus.Changed, file.Lookup("example.com", 22, EcdsaKey));
    }

    [Fact]
    public void Any_listed_key_trusts_the_host()
    {
        KnownHostsFile file = Parse(Line("example.com", Key) + Line("example.com", OtherKey));
        Assert.Equal(KnownHostStatus.Trusted, file.Lookup("example.com", 22, Key));
        Assert.Equal(KnownHostStatus.Trusted, file.Lookup("example.com", 22, OtherKey));
    }

    [Fact]
    public void Comma_lists_cover_each_name()
    {
        KnownHostsFile file = Parse(Line("a.example,b.example,192.0.2.1", Key));
        Assert.Equal(KnownHostStatus.Trusted, file.Lookup("a.example", 22, Key));
        Assert.Equal(KnownHostStatus.Trusted, file.Lookup("b.example", 22, Key));
        Assert.Equal(KnownHostStatus.Trusted, file.Lookup("192.0.2.1", 22, Key));
        Assert.Equal(KnownHostStatus.Unknown, file.Lookup("c.example", 22, Key));
    }

    [Fact]
    public void Ports_use_the_bracket_form()
    {
        KnownHostsFile file = Parse(Line("[example.com]:2222", Key));
        Assert.Equal(KnownHostStatus.Trusted, file.Lookup("example.com", 2222, Key));
        Assert.Equal(KnownHostStatus.Unknown, file.Lookup("example.com", 22, Key));
        Assert.Equal(KnownHostStatus.Unknown, file.Lookup("example.com", 2223, Key));

        // A plain name means the default port only.
        Assert.Equal(KnownHostStatus.Unknown, Parse(Line("example.com", Key)).Lookup("example.com", 2222, Key));
    }

    [Fact]
    public void Ipv6_hosts_work_on_both_forms()
    {
        KnownHostsFile file = Parse(Line("::1,[::1]:2222", Key));
        Assert.Equal(KnownHostStatus.Trusted, file.Lookup("::1", 22, Key));
        Assert.Equal(KnownHostStatus.Trusted, file.Lookup("::1", 2222, Key));
    }

    [Fact]
    public void Wildcards_match()
    {
        KnownHostsFile file = Parse(Line("*.example.com,host?.example.org", Key));
        Assert.Equal(KnownHostStatus.Trusted, file.Lookup("a.b.example.com", 22, Key));
        Assert.Equal(KnownHostStatus.Trusted, file.Lookup("host1.example.org", 22, Key));
        Assert.Equal(KnownHostStatus.Unknown, file.Lookup("host12.example.org", 22, Key));
        Assert.Equal(KnownHostStatus.Unknown, file.Lookup("example.com", 22, Key));
    }

    [Fact]
    public void Negation_rules_a_name_out_wherever_it_stands()
    {
        foreach (string patterns in new[] { "*.example.com,!bad.example.com", "!bad.example.com,*.example.com" })
        {
            KnownHostsFile file = Parse(Line(patterns, Key));
            Assert.Equal(KnownHostStatus.Trusted, file.Lookup("good.example.com", 22, Key));
            Assert.Equal(KnownHostStatus.Unknown, file.Lookup("bad.example.com", 22, Key));
        }

        Assert.Equal(KnownHostStatus.Unknown, Parse(Line("!bad.example.com", Key)).Lookup("good.example.com", 22, Key));
    }

    [Fact]
    public void Host_names_ignore_ascii_case()
    {
        KnownHostsFile file = Parse(Line("Example.COM", Key));
        Assert.Equal(KnownHostStatus.Trusted, file.Lookup("EXAMPLE.com", 22, Key));
    }

    [Fact]
    public void Hashed_lines_match_only_their_host()
    {
        string line = KnownHostsFile.FormatLine("example.com", 22, Key);
        Assert.StartsWith("|1|", line, StringComparison.Ordinal);
        Assert.DoesNotContain("example", line, StringComparison.Ordinal);

        KnownHostsFile file = Parse(line + "\n");
        Assert.Equal(KnownHostStatus.Trusted, file.Lookup("example.com", 22, Key));
        Assert.Equal(KnownHostStatus.Trusted, file.Lookup("EXAMPLE.com", 22, Key));
        Assert.Equal(KnownHostStatus.Changed, file.Lookup("example.com", 22, OtherKey));
        Assert.Equal(KnownHostStatus.Unknown, file.Lookup("example.org", 22, Key));
        Assert.Equal(KnownHostStatus.Unknown, file.Lookup("example.com", 2222, Key));
    }

    // Worked by hand from the definition, not with this code: HMAC-SHA1 keyed with the salt, over the host name.
    [Fact]
    public void A_hashed_line_built_from_the_definition_matches()
    {
        byte[] salt = RandomNumberGenerator.GetBytes(20);
#pragma warning disable CA5350 // SHA-1 is what the known_hosts format hashes with.
        byte[] hash = HMACSHA1.HashData(salt, Encoding.ASCII.GetBytes("[example.com]:2222"));
#pragma warning restore CA5350
        string field = $"|1|{Convert.ToBase64String(salt)}|{Convert.ToBase64String(hash)}";
        Assert.Equal(KnownHostStatus.Trusted, Parse(Line(field, Key)).Lookup("example.com", 2222, Key));
    }

    [Fact]
    public void Revoked_wins_over_a_trusted_line_in_either_order()
    {
        string trusted = Line("example.com", Key);
        string revoked = "@revoked " + Line("*", Key);
        Assert.Equal(KnownHostStatus.Revoked, Parse(trusted + revoked).Lookup("example.com", 22, Key));
        Assert.Equal(KnownHostStatus.Revoked, Parse(revoked + trusted).Lookup("example.com", 22, Key));
    }

    [Fact]
    public void Revoked_only_applies_to_its_hosts_and_its_key()
    {
        KnownHostsFile file = Parse("@revoked " + Line("bad.example", Key) + Line("good.example", Key));
        Assert.Equal(KnownHostStatus.Trusted, file.Lookup("good.example", 22, Key));
        Assert.Equal(KnownHostStatus.Revoked, file.Lookup("bad.example", 22, Key));

        // A revoked line says nothing about other keys, and doesn't make the host known.
        Assert.Equal(KnownHostStatus.Unknown, file.Lookup("bad.example", 22, OtherKey));
    }

    [Fact]
    public void A_hashed_revoked_line_works()
    {
        KnownHostsFile file = Parse("@revoked " + KnownHostsFile.FormatLine("example.com", 22, Key) + "\n");
        Assert.Equal(KnownHostStatus.Revoked, file.Lookup("example.com", 22, Key));
    }

    // A CA key signs host certificates. Presented as a plain host key, it proves nothing.
    [Fact]
    public void A_cert_authority_key_is_kept_but_never_trusted_as_a_host_key()
    {
        KnownHostsFile file = Parse("@cert-authority " + Line("*.example.com", Key));
        KnownHostsEntry entry = Assert.Single(file.Entries);
        Assert.Equal(KnownHostMarker.CertificateAuthority, entry.Marker);
        Assert.Equal(Key.Blob.ToArray(), entry.Blob.ToArray());

        Assert.Equal(KnownHostStatus.Unknown, file.Lookup("a.example.com", 22, Key));
        Assert.Equal(KnownHostStatus.Unknown, file.Lookup("a.example.com", 22, OtherKey));
    }

    [Fact]
    public void Comparison_is_on_the_whole_blob()
    {
        byte[] blob = Key.Blob.ToArray();
        blob[^1] ^= 1;
        string line = $"example.com {Key.KeyType} {Convert.ToBase64String(blob)}\n";
        Assert.Equal(KnownHostStatus.Changed, Parse(line).Lookup("example.com", 22, Key));
    }

    [Theory]
    [InlineData("# a comment")]
    [InlineData("   ")]
    [InlineData("example.com")]
    [InlineData("example.com ssh-ed25519")]
    [InlineData("example.com ssh-ed25519 !!!notbase64!!!")]
    [InlineData("example.com ssh-ed25519 AAAA")]
    [InlineData("example.com ssh-ed25519 /////w==")]
    [InlineData("example.com 2048 65537 123456789")]
    [InlineData("@unknown example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5")]
    [InlineData("@revoked")]
    [InlineData("|1|x|y ssh-ed25519 AAAAC3NzaC1lZDI1NTE5")]
    [InlineData("|2|AAAA|AAAA ssh-ed25519 AAAAC3NzaC1lZDI1NTE5")]
    [InlineData("|1|AAAA ssh-ed25519 AAAAC3NzaC1lZDI1NTE5")]
    [InlineData("|1|AAAA|AAAA ssh-ed25519 AAAAC3NzaC1lZDI1NTE5")]
    public void Malformed_lines_are_skipped_and_the_rest_still_read(string bad)
    {
        KnownHostsFile file = Parse(bad + "\n" + Line("example.com", Key) + bad);
        Assert.Single(file.Entries);
        Assert.Equal(KnownHostStatus.Trusted, file.Lookup("example.com", 22, Key));
    }

    // One field wrong at a time, with the other a real 20 bytes, so each length check has to do the refusing.
    [Theory]
    [InlineData(19, 20)]
    [InlineData(21, 20)]
    [InlineData(20, 19)]
    [InlineData(20, 21)]
    public void Hashed_fields_must_be_20_bytes_each(int saltLength, int hashLength)
    {
        string salt = Convert.ToBase64String(new byte[saltLength]);
        string hash = Convert.ToBase64String(new byte[hashLength]);
        Assert.Empty(Parse(Line($"|1|{salt}|{hash}", Key)).Entries);
    }

    [Fact]
    public void A_hashed_field_of_the_right_length_is_kept()
    {
        string field = Convert.ToBase64String(new byte[20]);
        Assert.Single(Parse(Line($"|1|{field}|{field}", Key)).Entries);
    }

    [Fact]
    public void A_key_type_that_disagrees_with_its_blob_is_skipped()
    {
        string line = $"example.com ecdsa-sha2-nistp256 {Convert.ToBase64String(Key.Blob.Span)}\n";
        Assert.Empty(Parse(line).Entries);
    }

    // A key this library can't use still says the host is known, so it must not fall through to Unknown.
    [Fact]
    public void A_line_with_an_unsupported_key_type_still_makes_the_host_known()
    {
        byte[] blob = [0, 0, 0, 7, .. "ssh-dss"u8, 1, 2, 3];
        KnownHostsFile file = Parse($"example.com ssh-dss {Convert.ToBase64String(blob)}\n");
        Assert.Equal(KnownHostStatus.Changed, file.Lookup("example.com", 22, Key));
    }

    [Fact]
    public void Line_endings_comments_and_a_byte_order_mark_are_handled()
    {
        string text = "﻿# known hosts\r\n" + Line("a.example", Key).Replace("\n", " a comment\r\n", StringComparison.Ordinal) + "\t" + Line("b.example", Key).TrimEnd();
        KnownHostsFile file = Parse(text);
        Assert.Equal(2, file.Entries.Count);
        Assert.Equal(KnownHostStatus.Trusted, file.Lookup("a.example", 22, Key));
        Assert.Equal(KnownHostStatus.Trusted, file.Lookup("b.example", 22, Key));
    }

    [Fact]
    public void An_overlong_line_fails_and_is_not_skipped()
    {
        string longHosts = string.Join(',', Enumerable.Repeat("host.example", (KnownHostsFile.MaxLineLength / 12) + 1));
        Assert.Throws<SshHostKeyException>(() => Parse(Line(longHosts, Key) + Line("example.com", Key)));
    }

    // Reading part of it could drop a @revoked line, and turn Revoked into Unknown.
    [Fact]
    public void An_oversized_file_fails_rather_than_loses_lines()
    {
        char[] text = new char[KnownHostsFile.MaxFileLength + 1];
        text.AsSpan().Fill('\n');
        Assert.Throws<SshHostKeyException>(() => KnownHostsFile.Parse(text));
    }

    [Fact]
    public void Many_stars_cost_polynomial_time()
    {
        // Plain recursion takes exponential time on this.
        string pattern = string.Concat(Enumerable.Repeat("*a", 2000)) + "*b";
        string host = new('a', 250);
        KnownHostsFile file = Parse(Line(pattern, Key));

        Stopwatch watch = Stopwatch.StartNew();
        Assert.Equal(KnownHostStatus.Unknown, file.Lookup(host, 22, Key));
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(2));
    }

    [Theory]
    [InlineData("a\nb")]
    [InlineData("a\r\n* ssh-ed25519 AAAA")]
    [InlineData("a b")]
    [InlineData("a\tb")]
    [InlineData("a,b")]
    [InlineData("*")]
    [InlineData("a?")]
    [InlineData("!a")]
    [InlineData("|1|a|b")]
    [InlineData("#a")]
    [InlineData("@revoked")]
    [InlineData("[a]:22")]
    [InlineData("a\0b")]
    [InlineData("")]
    public void Names_that_would_change_the_file_cannot_be_written(string host)
    {
        Assert.ThrowsAny<ArgumentException>(() => KnownHostsFile.FormatLine(host, 22, Key));
        Assert.ThrowsAny<ArgumentException>(() => KnownHostsFile.FormatLine(host, 22, Key, hashed: false));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(65536)]
    public void Ports_out_of_range_are_refused(int port)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => KnownHostsFile.FormatLine("example.com", port, Key));
        Assert.Throws<ArgumentOutOfRangeException>(() => Parse(string.Empty).Lookup("example.com", port, Key));
    }

    [Fact]
    public void Plain_lines_can_be_written_on_request()
    {
        Assert.StartsWith("example.com ssh-ed25519 ", KnownHostsFile.FormatLine("EXAMPLE.com", 22, Key, hashed: false), StringComparison.Ordinal);
        Assert.StartsWith("[example.com]:2222 ssh-ed25519 ", KnownHostsFile.FormatLine("example.com", 2222, Key, hashed: false), StringComparison.Ordinal);
    }

    [Fact]
    public void Each_hashed_line_has_a_fresh_salt()
    {
        Assert.NotEqual(KnownHostsFile.FormatLine("example.com", 22, Key), KnownHostsFile.FormatLine("example.com", 22, Key));
    }

    [Fact]
    public void Append_creates_the_file_and_adds_to_it()
    {
        using TempDirectory directory = new();
        string path = Path.Combine(directory.Path, "known_hosts");

        KnownHostsFile.Append(path, "a.example", 22, Key);
        KnownHostsFile.Append(path, "b.example", 2222, OtherKey);

        KnownHostsFile file = KnownHostsFile.Load(path);
        Assert.Equal(KnownHostStatus.Trusted, file.Lookup("a.example", 22, Key));
        Assert.Equal(KnownHostStatus.Trusted, file.Lookup("b.example", 2222, OtherKey));
        Assert.All(file.Entries, static entry => Assert.True(entry.IsHashed));
    }

    [Fact]
    public void Append_does_not_join_a_last_line_with_no_ending()
    {
        using TempDirectory directory = new();
        string path = Path.Combine(directory.Path, "known_hosts");
        File.WriteAllText(path, Line("a.example", Key).TrimEnd());

        KnownHostsFile.Append(path, "b.example", 22, OtherKey);

        KnownHostsFile file = KnownHostsFile.Load(path);
        Assert.Equal(KnownHostStatus.Trusted, file.Lookup("a.example", 22, Key));
        Assert.Equal(KnownHostStatus.Trusted, file.Lookup("b.example", 22, OtherKey));
    }

    [Fact]
    public void A_file_that_does_not_exist_reads_as_empty()
    {
        using TempDirectory directory = new();
        Assert.Empty(KnownHostsFile.Load(Path.Combine(directory.Path, "known_hosts")).Entries);
        Assert.Empty(KnownHostsFile.Load(Path.Combine(directory.Path, "missing", "known_hosts")).Entries);
    }

    [Fact]
    public void An_oversized_file_on_disk_is_refused_before_reading()
    {
        using TempDirectory directory = new();
        string path = Path.Combine(directory.Path, "known_hosts");
        using (FileStream stream = File.Create(path))
        {
            stream.SetLength(KnownHostsFile.MaxFileLength + 1L);
        }

        Assert.Throws<SshHostKeyException>(() => KnownHostsFile.Load(path));
    }

    private static KnownHostsFile Parse(string text) => KnownHostsFile.Parse(text);

    private static string Line(string hosts, SshPublicKey key) => $"{hosts} {key.KeyType} {Convert.ToBase64String(key.Blob.Span)}\n";

    private static SshPublicKey NewEd25519()
    {
        using SshPrivateKey key = SshPrivateKey.GenerateEd25519();
        return key.PublicKey;
    }

    private static SshPublicKey NewEcdsa()
    {
        using SshPrivateKey key = SshPrivateKey.GenerateEcdsa("ecdsa-sha2-nistp256");
        return key.PublicKey;
    }
}

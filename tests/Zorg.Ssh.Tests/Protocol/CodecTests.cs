using System;
using Xunit;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Tests.Protocol;

public class CodecTests
{
    // The examples in RFC 4251 section 5.
    [Theory]
    [InlineData("", "00000000", "")]
    [InlineData("09a378f9b2e332a7", "0000000809a378f9b2e332a7", "09a378f9b2e332a7")]
    [InlineData("80", "000000020080", "80")]
    [InlineData("00000080", "000000020080", "80")]
    public void MPInt_matches_the_RFC_examples(string magnitudeHex, string encodedHex, string decodedHex)
    {
        SshWriter writer = new();
        try
        {
            writer.WriteMPInt(Convert.FromHexString(magnitudeHex));
            Assert.Equal(encodedHex, Convert.ToHexStringLower(writer.Written));
        }
        finally
        {
            writer.Dispose();
        }

        SshReader reader = new(Convert.FromHexString(encodedHex));
        Assert.Equal(decodedHex, Convert.ToHexStringLower(reader.ReadMPInt()));
        reader.EnsureEnd();
    }

    [Theory]
    [InlineData("00000002ff00")] // negative
    [InlineData("0000000180")] // negative
    public void MPInt_rejects_negative_values(string encodedHex) =>
        AssertMalformed(encodedHex, static (ref SshReader r) => r.ReadMPInt().Length);

    [Fact]
    public void MPInt_tolerates_redundant_leading_zeros()
    {
        SshReader reader = new(Convert.FromHexString("00000003000001"));
        Assert.Equal([1], reader.ReadMPInt().ToArray());
    }

    [Fact]
    public void MPInt_rejects_oversized_values()
    {
        byte[] data = new byte[4 + SshReader.MaxMPIntLength + 1];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(data, SshReader.MaxMPIntLength + 1);
        AssertMalformed(Convert.ToHexStringLower(data), static (ref SshReader r) => r.ReadMPInt().Length);
    }

    [Fact]
    public void NameList_round_trips()
    {
        string[] names = ["zlib", "none", "aes256-gcm@openssh.com"];
        SshWriter writer = new();
        try
        {
            writer.WriteNameList(names);
            SshReader reader = new(writer.Written);
            Assert.Equal(names, reader.ReadNameList());
            reader.EnsureEnd();
        }
        finally
        {
            writer.Dispose();
        }
    }

    // RFC 4251 section 5 name-list examples.
    [Theory]
    [InlineData("00000000", new string[0])]
    [InlineData("000000047a6c6962", new[] { "zlib" })]
    [InlineData("000000097a6c69622c6e6f6e65", new[] { "zlib", "none" })]
    public void NameList_matches_the_RFC_examples(string encodedHex, string[] expected)
    {
        SshReader reader = new(Convert.FromHexString(encodedHex));
        Assert.Equal(expected, reader.ReadNameList());
    }

    [Theory]
    [InlineData("000000012c")] // ","
    [InlineData("00000002612c")] // "a,"
    [InlineData("000000022c61")] // ",a"
    [InlineData("00000003612c2c")] // "a,,"
    public void NameList_rejects_empty_names(string encodedHex) =>
        AssertMalformed(encodedHex, static (ref SshReader r) => r.ReadNameList().Length);

    [Theory]
    [InlineData("00000001ff")]
    [InlineData("0000000100")]
    [InlineData("0000000120")]
    [InlineData("000000017f")]
    public void NameList_rejects_characters_outside_printable_ascii(string encodedHex) =>
        AssertMalformed(encodedHex, static (ref SshReader r) => r.ReadNameList().Length);

    [Fact]
    public void NameList_caps_the_number_of_names()
    {
        string list = string.Join(',', System.Linq.Enumerable.Repeat("a", SshReader.MaxNameListCount + 1));
        SshWriter writer = new();
        try
        {
            writer.WriteUtf8String(list);
            AssertMalformed(Convert.ToHexStringLower(writer.Written), static (ref SshReader r) => r.ReadNameList().Length);
        }
        finally
        {
            writer.Dispose();
        }
    }

    [Theory]
    [InlineData("")]
    [InlineData("00")]
    [InlineData("000000")]
    [InlineData("00000001")]
    [InlineData("ffffffff")]
    [InlineData("80000000")]
    [InlineData("7fffffff00")]
    public void Binary_string_with_a_hostile_length_is_a_protocol_error(string encodedHex) =>
        AssertMalformed(encodedHex, static (ref SshReader r) => r.ReadBinary().Length);

    [Fact]
    public void Utf8_rejects_invalid_sequences() =>
        AssertMalformed("00000002c328", static (ref SshReader r) => r.ReadUtf8String().Length);

    [Fact]
    public void Scalars_round_trip_and_any_nonzero_byte_is_true()
    {
        SshWriter writer = new();
        try
        {
            writer.WriteByte(7);
            writer.WriteBoolean(true);
            writer.WriteUInt32(0xDEADBEEF);
            writer.WriteUInt64(0x0102030405060708);
            writer.WriteUtf8String("héllo");
            SshReader reader = new(writer.Written);
            Assert.Equal(7, reader.ReadByte());
            Assert.True(reader.ReadBoolean());
            Assert.Equal(0xDEADBEEF, reader.ReadUInt32());
            Assert.Equal(0x0102030405060708UL, reader.ReadUInt64());
            Assert.Equal("héllo", reader.ReadUtf8String());
            reader.EnsureEnd();
        }
        finally
        {
            writer.Dispose();
        }

        SshReader truthy = new([0x7F]);
        Assert.True(truthy.ReadBoolean());
    }

    [Fact]
    public void EnsureEnd_rejects_trailing_data() =>
        AssertMalformed("0000", static (ref SshReader r) =>
        {
            r.ReadByte();
            r.EnsureEnd();
            return 0;
        });

    [Fact]
    public void Writer_grows_past_its_first_buffer_and_keeps_the_reserve()
    {
        SshWriter writer = new(capacity: 16, reserve: 5);
        try
        {
            byte[] big = new byte[100_000];
            big[^1] = 42;
            writer.WriteBinary(big);
            Assert.Equal(5 + 4 + big.Length, writer.Length);
            Assert.Equal(42, writer.Written[^1]);
        }
        finally
        {
            writer.Dispose();
        }
    }

    private delegate int ReadAction(ref SshReader reader);

    private static void AssertMalformed(string encodedHex, ReadAction read)
    {
        byte[] data = Convert.FromHexString(encodedHex);
        Assert.Throws<SshProtocolException>(() =>
        {
            SshReader reader = new(data);
            read(ref reader);
        });
    }
}

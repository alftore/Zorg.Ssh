using System;
using System.Buffers.Binary;
using System.IO;
using Xunit;
using Zorg.Ssh.Sftp;

namespace Zorg.Ssh.Tests.Sftp;

/// <summary>
/// The SFTP server reads a macOS entry's type from <c>lstat</c> so that a FIFO, socket or device isn't reported as a
/// regular file. The maintainers can't run macOS, so these pin how the bytes are read, and that a misread layout gives
/// no type rather than a wrong one.
/// </summary>
public sealed class MacFileTypeTests
{
    private const UnixFileMode Permissions = (UnixFileMode)0x1A4; // 0644

    /// <summary>A 64-bit-inode <c>struct stat</c>: st_dev (int32) at 0, st_mode (uint16) at 4.</summary>
    private static byte[] Stat64(uint mode)
    {
        byte[] status = new byte[144];
        BinaryPrimitives.WriteInt32LittleEndian(status, 0x01000004);
        BinaryPrimitives.WriteUInt16LittleEndian(status.AsSpan(4), (ushort)mode);
        return status;
    }

    [Theory]
    [InlineData(0x1000u)] // FIFO
    [InlineData(0x2000u)] // character device
    [InlineData(0x6000u)] // block device
    [InlineData(0xC000u)] // socket
    [InlineData(0x8000u)] // regular file
    public void The_type_is_read_when_the_permissions_beside_it_match(uint type)
    {
        Assert.Equal(type, LocalFile.ParseMacFileType(Stat64(type | 0x1A4), Permissions));
    }

    [Fact]
    public void Setuid_setgid_and_sticky_bits_are_part_of_the_match()
    {
        UnixFileMode withSpecials = Permissions | UnixFileMode.SetUser | UnixFileMode.SetGroup | UnixFileMode.StickyBit;
        Assert.Equal(0x1000u, LocalFile.ParseMacFileType(Stat64(0x1000 | 0xFA4), withSpecials));
        Assert.Null(LocalFile.ParseMacFileType(Stat64(0x1000 | 0x1A4), withSpecials));
    }

    [Fact]
    public void Permissions_that_differ_from_dotnets_give_no_type()
    {
        Assert.Null(LocalFile.ParseMacFileType(Stat64(0x1000 | 0x1ED), Permissions));
    }

    [Fact]
    public void The_legacy_x64_layout_read_at_the_wrong_offset_gives_no_type()
    {
        // Legacy struct stat: st_dev (int32) at 0, st_ino (uint32) at 4, st_mode (uint16) at 8. Read at offset 4, the
        // low half of the inode number stands in for the mode.
        byte[] status = new byte[144];
        BinaryPrimitives.WriteUInt32LittleEndian(status.AsSpan(4), 0x00123456);
        BinaryPrimitives.WriteUInt16LittleEndian(status.AsSpan(8), 0x1000 | 0x1A4);
        Assert.Null(LocalFile.ParseMacFileType(status, Permissions));
    }

    [Theory]
    [InlineData(0x0000u)]
    [InlineData(0x3000u)]
    [InlineData(0x5000u)]
    [InlineData(0xE000u)]
    [InlineData(0xF000u)]
    public void A_type_that_S_IFMT_cannot_hold_gives_no_type(uint type)
    {
        Assert.Null(LocalFile.ParseMacFileType(Stat64(type | 0x1A4), Permissions));
    }

    [Fact]
    public void A_buffer_too_short_to_hold_the_mode_gives_no_type()
    {
        Assert.Null(LocalFile.ParseMacFileType(new byte[5], Permissions));
    }

    [Theory]
    [InlineData(0x1000u, true)]
    [InlineData(0x2000u, true)]
    [InlineData(0x6000u, true)]
    [InlineData(0xC000u, true)]
    [InlineData(0x8000u, false)]
    [InlineData(0x4000u, false)]
    [InlineData(0xA000u, false)]
    [InlineData(0x0000u, false)]
    public void Only_FIFOs_devices_and_sockets_replace_the_type_dotnet_reported(uint type, bool replaces)
    {
        Assert.Equal(replaces, SftpServerAttributes.IsSpecialFileType(type));
    }
}

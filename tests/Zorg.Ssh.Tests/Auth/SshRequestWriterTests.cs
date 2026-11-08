using System;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Auth;

namespace Zorg.Ssh.Tests.Auth;

public class SshRequestWriterTests
{
    // A1: the array that carries a password to the transport must be zeroed once it has been sent.
    [Fact]
    public async Task The_wire_array_is_zeroed_after_sending()
    {
        SshRequestWriter w = new();
        w.Byte(50);
        w.String("alice");
        w.String("hunter2-secret");
        byte[]? seen = null;
        string? text = null;
        await w.BuildSendAndClearAsync(
            (wire, _) =>
            {
                seen = wire;
                text = Encoding.UTF8.GetString(wire);
                return ValueTask.CompletedTask;
            },
            TestContext.Current.CancellationToken);
        Assert.Contains("hunter2-secret", text);
        Assert.NotNull(seen);
        Assert.All(seen, b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task The_wire_array_is_zeroed_when_sending_fails()
    {
        SshRequestWriter w = new();
        w.String("hunter2-secret");
        byte[]? seen = null;
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await w.BuildSendAndClearAsync(
            (wire, _) =>
            {
                seen = wire;
                throw new InvalidOperationException();
            },
            TestContext.Current.CancellationToken));
        Assert.NotNull(seen);
        Assert.All(seen, b => Assert.Equal(0, b));
    }

    [Fact]
    public void String_writes_a_length_prefixed_utf8_value()
    {
        SshRequestWriter w = new();
        w.String("hé");
        Assert.Equal(new byte[] { 0, 0, 0, 3, (byte)'h', 0xC3, 0xA9 }, w.ToArray());
    }
}

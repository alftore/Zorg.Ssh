using System.Net;
using Xunit;

namespace Zorg.Ssh.Tests.Server;

/// <summary>The key an address is counted under for MaxUnauthenticatedPerAddress.</summary>
public sealed class PerAddressKeyTests
{
    [Theory]
    [InlineData("64:ff9b::192.0.2.1", "192.0.2.1")]
    [InlineData("64:ff9b::c000:201", "192.0.2.1")]
    [InlineData("64:ff9b::198.51.100.7", "198.51.100.7")]
    [InlineData("::ffff:192.0.2.1", "192.0.2.1")]
    public void An_embedded_ipv4_address_is_the_key(string address, string key)
    {
        Assert.Equal(IPAddress.Parse(key), PerAddressLimiter.KeyFor(IPAddress.Parse(address)));
    }

    [Fact]
    public void Two_nat64_clients_do_not_share_a_key()
    {
        Assert.NotEqual(
            PerAddressLimiter.KeyFor(IPAddress.Parse("64:ff9b::192.0.2.1")),
            PerAddressLimiter.KeyFor(IPAddress.Parse("64:ff9b::192.0.2.2")));
    }

    [Fact]
    public void One_nat64_client_cannot_lock_out_another()
    {
        PerAddressLimiter limiter = new(1);

        Assert.True(limiter.TryAcquire(IPAddress.Parse("64:ff9b::192.0.2.1")));
        Assert.False(limiter.TryAcquire(IPAddress.Parse("64:ff9b::192.0.2.1")));
        Assert.True(limiter.TryAcquire(IPAddress.Parse("64:ff9b::192.0.2.2")));
    }

    [Fact]
    public void Other_ipv6_addresses_still_share_their_64()
    {
        Assert.Equal(
            PerAddressLimiter.KeyFor(IPAddress.Parse("2001:db8:1:2::1")),
            PerAddressLimiter.KeyFor(IPAddress.Parse("2001:db8:1:2:ffff::9")));
        Assert.NotEqual(
            PerAddressLimiter.KeyFor(IPAddress.Parse("2001:db8:1:2::1")),
            PerAddressLimiter.KeyFor(IPAddress.Parse("2001:db8:1:3::1")));
    }
}

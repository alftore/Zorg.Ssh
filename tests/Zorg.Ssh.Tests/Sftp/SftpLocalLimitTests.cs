using System;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Sftp;

namespace Zorg.Ssh.Tests.Sftp;

/// <summary><see cref="SftpException.IsLocalLimit"/> is true for the library's own refusals and false for anything a server said.</summary>
public sealed class SftpLocalLimitTests
{
    private const int Limit = 20_000;

    [Theory(Timeout = Limit)]
    [InlineData(FakeSftpServer.StatusNoSuchFile)]
    [InlineData(4u)]
    [InlineData(3u)]
    [InlineData(8u)]
    public async Task A_status_the_server_sent_is_not_a_local_limit(uint status)
    {
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) => server.SendStatusAsync(request.Id, status, "no"));

        SftpException ex = await Assert.ThrowsAnyAsync<SftpException>(() => fake.Client.ReadAllBytesAsync("/x", TestContext.Current.CancellationToken));
        Assert.False(ex.IsLocalLimit);
        Assert.Equal((SftpStatusCode)status, ex.StatusCode);
    }

    [Fact]
    public void An_exception_built_by_a_caller_is_not_a_local_limit()
    {
        Assert.False(new SftpException().IsLocalLimit);
        Assert.False(new SftpException("m").IsLocalLimit);
        Assert.False(new SftpException("m", new InvalidOperationException()).IsLocalLimit);
        Assert.False(new SftpException("m", SftpStatusCode.Failure, "/p").IsLocalLimit);
        Assert.False(new SftpFileNotFoundException().IsLocalLimit);
        Assert.False(new SftpPermissionDeniedException().IsLocalLimit);
    }

    [Fact]
    public void An_unsafe_name_is_a_local_refusal_however_it_is_built()
    {
        Assert.True(new SftpUnsafeNameException().IsLocalLimit);
        Assert.True(new SftpUnsafeNameException("m").IsLocalLimit);
        Assert.True(new SftpUnsafeNameException("m", new InvalidOperationException()).IsLocalLimit);
        Assert.True(new SftpUnsafeNameException("m", "../x", "/d").IsLocalLimit);
    }
}

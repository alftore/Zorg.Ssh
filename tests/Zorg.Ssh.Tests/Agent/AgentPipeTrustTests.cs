using System;
using System.Diagnostics;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Agent;

namespace Zorg.Ssh.Tests.Agent;

/// <summary>M5 review T6: which Windows named pipe the agent client will talk to, and who may serve it.</summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")] // For the analyzer only: tests that need Windows skip themselves elsewhere.
public sealed class AgentPipeTrustTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData(@"\\.\pipe\..\UNC\attacker\pipe\agent")]
    [InlineData(@"\\.\pipe\../UNC/attacker/pipe/agent")]
    [InlineData("//./pipe/../UNC/attacker/pipe/agent")]
    [InlineData(@"\\.\pipe\..")]
    [InlineData(@"\\.\pipe\.")]
    [InlineData(@"\\.\pipe\")]
    [InlineData(@"\\.\pipe\sub\agent")]
    [InlineData(@"\\.\PIPE\a/b")]
    public void T6_a_pipe_name_that_escapes_the_pipe_namespace_is_refused(string path)
    {
        SshAgentException ex = Assert.Throws<SshAgentException>(() => SshAgentEndpoint.PipeNameOf(path));
        Assert.Contains("plain named pipe", ex.Message);
    }

    [Fact]
    public void T6_plain_pipe_names_and_other_paths_are_told_apart()
    {
        Assert.Equal("openssh-ssh-agent", SshAgentEndpoint.PipeNameOf(@"\\.\pipe\openssh-ssh-agent"));
        Assert.Equal("openssh-ssh-agent", SshAgentEndpoint.PipeNameOf("//./pipe/openssh-ssh-agent"));
        Assert.Equal("my.agent", SshAgentEndpoint.PipeNameOf(@"\\.\PIPE\my.agent"));
        Assert.Null(SshAgentEndpoint.PipeNameOf("/run/user/1000/agent.sock"));
        Assert.Null(SshAgentEndpoint.PipeNameOf(@"C:\Users\me\agent.sock"));
    }

    [Fact]
    public async Task T6_connecting_to_an_escaping_pipe_name_fails_before_any_connection_is_made()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Named pipes are the Windows transport.");

        await Assert.ThrowsAsync<SshAgentException>(async () => await SshAgentEndpoint.ConnectAsync(@"\\.\pipe\..\UNC\attacker\pipe\agent", Ct));
    }

    [Fact]
    public void T6_the_current_user_and_LocalSystem_may_serve_the_pipe_and_nobody_else()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows security identifiers.");
        using WindowsIdentity me = WindowsIdentity.GetCurrent();
        SecurityIdentifier current = me.User!;

        Assert.True(PipeServerCheck.IsAcceptableOwner(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), current));
        Assert.True(PipeServerCheck.IsAcceptableOwner(current, current));
        Assert.False(PipeServerCheck.IsAcceptableOwner(new SecurityIdentifier("S-1-5-21-111-222-333-1001"), current));
        Assert.False(PipeServerCheck.IsAcceptableOwner(new SecurityIdentifier(WellKnownSidType.WorldSid, null), current));
        Assert.False(PipeServerCheck.IsAcceptableOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), current));
        Assert.False(PipeServerCheck.IsAcceptableOwner(new SecurityIdentifier("S-1-5-21-111-222-333-1001"), null));
    }

    [Fact]
    public void T6_a_process_of_the_current_user_is_accepted_as_the_server()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows processes.");

        PipeServerCheck.EnsureTrustedProcess((uint)Environment.ProcessId, "test pipe");
    }

    [Fact]
    public void T6_a_server_process_that_can_not_be_identified_is_refused()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows processes.");

        // No such process: it can't be opened, and it isn't the agent service.
        SshAgentException ex = Assert.Throws<SshAgentException>(() => PipeServerCheck.EnsureTrustedProcess(0xFFFFFFF0, "test pipe"));
        Assert.Contains("Couldn't tell who runs", ex.Message);
    }

    [Fact]
    public void T6_a_process_of_another_account_is_refused_when_its_token_can_be_read()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows processes.");

        // Any process that runs as neither this user nor LocalSystem: a network or local service account, if one is
        // running and readable. Where none can be read, the SID rule above covers it.
        foreach (Process process in Process.GetProcesses())
        {
            using (process)
            {
                if (process.Id <= 4)
                {
                    continue;
                }

                try
                {
                    SshAgentException? refused = Record.Exception(() => PipeServerCheck.EnsureTrustedProcess((uint)process.Id, "test pipe")) as SshAgentException;
                    if (refused is not null && refused.Message.Contains("neither you nor the system", StringComparison.Ordinal))
                    {
                        return;
                    }
                }
                catch (InvalidOperationException)
                {
                    // The process ended.
                }
            }
        }

        Assert.Skip("No readable process of another account here, which is normal in a plain user session.");
    }
}

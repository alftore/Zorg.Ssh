using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Agent;
using Zorg.Ssh.Crypto.Keys;

namespace Zorg.Ssh.InteropTests;

/// <summary>
/// The agent client against real OpenSSH <c>ssh-agent</c> and <c>ssh-add</c>, logging in to real sshd. Git for Windows'
/// agent can't be reached from .NET, so the real agent runs in the container, and its socket comes out over an SSH exec
/// channel running socat. The protocol is real end to end, but on Windows the socket transport itself isn't exercised
/// here: <see cref="A_local_agent_signs_with_each_key_type_on_its_unix_socket"/> does that on Linux.
/// </summary>
public sealed class AgentInteropTests : IDisposable
{
    private const string Socket = "/tmp/agent.sock";

    private readonly KeygenTool _keygen = new();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => _keygen.Dispose();

    /// <summary>Starts sshd and a real agent holding these keys, added with real ssh-add in this order.</summary>
    private static async Task<SshPeerContainer> StartAsync(IReadOnlyList<string> agentKeys, IReadOnlyList<string> authorizedKeys, string setup = "", string sshdOptions = "", string addOptions = "")
    {
        PeerTools.RequireContainers();
        string image = await SshPeerContainer.BuildImageAsync("zorg-ssh-test/openssh-agent", Path.Combine(PeerTools.PeersPath, "openssh-agent"), Ct);
        StringBuilder script = new("mkdir -p /home/zorg/.ssh /home/zorg/k && ");
        script.Append(setup);
        foreach (string key in authorizedKeys)
        {
            script.Append($"echo {KeygenTool.Base64(key + ".pub")} | base64 -d >> /home/zorg/.ssh/authorized_keys && ");
        }

        List<string> names = [];
        for (int i = 0; i < agentKeys.Count; i++)
        {
            names.Add($"/home/zorg/k/{i}");
            script.Append(ContainerScript.WriteFile(agentKeys[i], names[i], "600"));
            if (File.Exists(agentKeys[i] + "-cert.pub"))
            {
                script.Append(ContainerScript.WriteFile(agentKeys[i] + "-cert.pub", names[i] + "-cert.pub"));
            }
        }

        script.Append("touch /home/zorg/.ssh/authorized_keys && chown -R zorg /home/zorg && chmod 700 /home/zorg/.ssh && chmod 600 /home/zorg/.ssh/authorized_keys && ");
        script.Append($"su zorg -s /bin/sh -c 'ssh-agent -a {Socket} > /dev/null && SSH_AUTH_SOCK={Socket} ssh-add -q {addOptions} {string.Join(' ', names)}' && ");
        script.Append($"exec /usr/sbin/sshd -D -e -o PasswordAuthentication=yes {sshdOptions}");
        return await SshPeerContainer.StartAsync(image, ["/bin/sh", "-c", script.ToString()], cancellationToken: Ct);
    }

    private static SshClientOptions Options(SshPeerContainer container, params SshCredential[] credentials) => new()
    {
        Host = container.Host,
        Port = container.Port,
        UserName = "zorg",
        Credentials = credentials,
        HostKeyPolicy = HostKeyPolicy.AcceptAnyUnsafe(),
    };

    /// <summary>A password login whose only job is to carry the agent socket out of the container.</summary>
    private static Task<SshClient> BridgeAsync(SshPeerContainer container) =>
        SshClient.ConnectAsync(Options(container, SshCredential.FromPassword("zorg-test")), Ct);

    private static AgentCredential RealAgent(SshClient bridge, int max = AgentCredential.DefaultMaxKeysOffered) => new(
        async ct => new ProcessStream(await bridge.StartProcessAsync($"exec socat - UNIX-CONNECT:{Socket}", null, ct)),
        max,
        isOptional: false);

    [InteropTheory]
    [InlineData("ed25519", "256")]
    [InlineData("ecdsa", "256")]
    [InlineData("ecdsa", "384")]
    [InlineData("ecdsa", "521")]
    [InlineData("rsa", "3072")]
    public async Task Each_key_type_logs_in_through_a_real_agent(string type, string bits)
    {
        string key = await _keygen.GenerateAsync(type, bits);
        await using SshPeerContainer container = await StartAsync([key], [key]);
        await using SshClient bridge = await BridgeAsync(container);

        await using SshClient client = await SshClient.ConnectAsync(Options(container, RealAgent(bridge)), Ct);
        Assert.Equal("zorg\n", (await client.ExecuteAsync("whoami", Ct)).StandardOutput);
    }

    [InteropFact]
    public async Task Both_RSA_hashes_come_from_a_real_agent()
    {
        string key = await _keygen.GenerateAsync("rsa", "3072");
        await using SshPeerContainer container = await StartAsync([key], [key]);
        await using SshClient bridge = await BridgeAsync(container);
        SshAgentConnection agent = await RealAgent(bridge).ConnectAsync(Ct);
        await using (agent)
        {
            SshAgentIdentity identity = Assert.Single(await agent.ListIdentitiesAsync(Ct));
            byte[] data = Encoding.ASCII.GetBytes("signed by a real agent");
            foreach (string algorithm in new[] { "rsa-sha2-256", "rsa-sha2-512" })
            {
                byte[]? signature = await agent.SignAsync(identity.Blob, data, SshAgentConnection.FlagsFor(algorithm), Ct);
                Assert.True(identity.Key.Verify(algorithm, data, signature!), algorithm);
            }

            // With no flag, a real agent falls back to SHA-1, which the check before sending turns away.
            byte[]? legacy = await agent.SignAsync(identity.Blob, data, 0, Ct);
            Assert.False(identity.Key.Verify("rsa-sha2-512", data, legacy!));
            Assert.False(identity.Key.Verify("rsa-sha2-256", data, legacy!));
        }
    }

    [InteropFact]
    public async Task The_list_matches_what_ssh_add_prints()
    {
        string first = await _keygen.GenerateAsync("ed25519", "256");
        string second = await _keygen.GenerateAsync("ecdsa", "384");
        string third = await _keygen.GenerateAsync("rsa", "3072");
        await using SshPeerContainer container = await StartAsync([first, second, third], []);
        await using SshClient bridge = await BridgeAsync(container);

        string printed = (await bridge.ExecuteAsync($"SSH_AUTH_SOCK={Socket} ssh-add -L", Ct)).StandardOutput;
        string[] expected = [.. printed.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(line => line.Split(' ')[1])];

        SshAgentConnection agent = await RealAgent(bridge).ConnectAsync(Ct);
        await using (agent)
        {
            IReadOnlyList<SshAgentIdentity> identities = await agent.ListIdentitiesAsync(Ct);
            Assert.Equal(3, expected.Length);
            Assert.Equal(expected, identities.Select(i => Convert.ToBase64String(i.Blob)));
        }
    }

    [InteropFact]
    public async Task A_certificate_in_a_real_agent_logs_in()
    {
        string ca = await _keygen.GenerateAsync("ed25519", "256");
        string key = await _keygen.GenerateAsync("ed25519", "256");
        await _keygen.SignAsync(ca, key, "-n", "zorg");
        string trust = ContainerScript.WriteFile(ca + ".pub", "/etc/ssh/user_ca.pub");
        await using SshPeerContainer container = await StartAsync([key], [], trust, "-o TrustedUserCAKeys=/etc/ssh/user_ca.pub");
        await using SshClient bridge = await BridgeAsync(container);

        SshAgentConnection agent = await RealAgent(bridge).ConnectAsync(Ct);
        await using (agent)
        {
            Assert.Contains(await agent.ListIdentitiesAsync(Ct), i => i.Key is SshCertificate);
        }

        await using SshClient client = await SshClient.ConnectAsync(Options(container, RealAgent(bridge)), Ct);
        Assert.Equal("zorg\n", (await client.ExecuteAsync("whoami", Ct)).StandardOutput);
    }

    // The reason for the cap. Without it, sshd's MaxAuthTries of 6 ends the connection with no useful message.
    [InteropFact]
    public async Task More_keys_than_MaxAuthTries_stop_with_a_clear_message()
    {
        List<string> keys = [];
        for (int i = 0; i < 8; i++)
        {
            keys.Add(await _keygen.GenerateAsync("ed25519", "256"));
        }

        await using SshPeerContainer container = await StartAsync(keys, [keys[^1]]);
        await using SshClient bridge = await BridgeAsync(container);

        SshAuthenticationException refused = await Assert.ThrowsAsync<SshAuthenticationException>(
            () => SshClient.ConnectAsync(Options(container, RealAgent(bridge)), Ct));
        Assert.Contains("holds 8 usable keys", refused.Message);
        Assert.Contains("only 5 were offered", refused.Message);
    }

    [InteropFact]
    public async Task A_password_works_after_a_capped_agent_on_real_sshd()
    {
        List<string> keys = [];
        for (int i = 0; i < 7; i++)
        {
            keys.Add(await _keygen.GenerateAsync("ed25519", "256"));
        }

        await using SshPeerContainer container = await StartAsync(keys, []);
        await using SshClient bridge = await BridgeAsync(container);

        await using SshClient client = await SshClient.ConnectAsync(Options(container, RealAgent(bridge), SshCredential.FromPassword("zorg-test")), Ct);
        Assert.Equal("zorg\n", (await client.ExecuteAsync("whoami", Ct)).StandardOutput);
    }

    [InteropFact]
    public async Task A_key_needing_confirmation_nobody_gives_is_reported()
    {
        string key = await _keygen.GenerateAsync("ed25519", "256");
        await using SshPeerContainer container = await StartAsync([key], [key], addOptions: "-c");
        await using SshClient bridge = await BridgeAsync(container);

        SshAuthenticationException refused = await Assert.ThrowsAsync<SshAuthenticationException>(
            () => SshClient.ConnectAsync(Options(container, RealAgent(bridge)), Ct));
        Assert.Contains("refused to sign", refused.Message);
    }

    // Read-only on purpose: this is the user's own agent, so nothing is added and nothing is signed.
    [InteropFact]
    public async Task The_Windows_OpenSSH_pipe_answers_when_the_service_runs()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "This is the Windows transport.");
        Assert.SkipUnless(Directory.GetFiles(@"\\.\pipe\").Any(p => p.EndsWith("openssh-ssh-agent", StringComparison.OrdinalIgnoreCase)), "The Windows OpenSSH agent service isn't running.");

        await using SshAgentConnection agent = new(await SshAgentEndpoint.ConnectAsync(@"\\.\pipe\openssh-ssh-agent", Ct), TimeSpan.FromSeconds(10));
        Assert.NotNull(await agent.ListIdentitiesAsync(Ct));
    }

    /// <summary>The variable that lets a test sign with the user's own Windows agent.</summary>
    private const string WindowsAgentVariable = "ZORG_TEST_WINDOWS_AGENT";

    // Signing is the one thing a test can do with the user's keys without changing them: nothing is added, removed or
    // locked, and the service isn't touched. It is still the user's agent, so a key held with a confirm constraint or
    // on a security token may ask them. That is why it is opt-in: ZORG_TEST_WINDOWS_AGENT=1. It signs a test blob with
    // every key the agent lists (what `ssh-add -L` shows), for every algorithm the key offers, and checks each signature
    // with the public key alone.
    [InteropFact]
    public async Task The_real_Windows_agent_signs_a_test_blob_for_each_key_it_lists()
    {
        Assert.SkipUnless(
            Environment.GetEnvironmentVariable(WindowsAgentVariable) == "1",
            $"Signs with the keys in the user's own Windows ssh-agent service, so it runs only when {WindowsAgentVariable}=1.");
        Assert.True(OperatingSystem.IsWindows(), $"{WindowsAgentVariable}=1 asks for the Windows agent pipe, and this isn't Windows.");

        const string Pipe = @"\\.\pipe\openssh-ssh-agent";
        Assert.True(
            Directory.GetFiles(@"\\.\pipe\").Any(p => p.EndsWith("openssh-ssh-agent", StringComparison.OrdinalIgnoreCase)),
            $"{WindowsAgentVariable}=1 but {Pipe} doesn't exist. The Windows OpenSSH Authentication Agent service isn't running. This test doesn't start it.");

        await using SshAgentConnection agent = new(await SshAgentEndpoint.ConnectAsync(Pipe, Ct), TimeSpan.FromSeconds(30));
        IReadOnlyList<SshAgentIdentity> identities = await agent.ListIdentitiesAsync(Ct);
        Assert.True(identities.Count > 0, "The agent lists no key this library can use (`ssh-add -L` shows what it holds). Load one yourself and run again.");

        byte[] data = Encoding.ASCII.GetBytes("Zorg.Ssh test blob, signed by the Windows agent");
        int signed = 0;
        foreach (SshAgentIdentity identity in identities)
        {
            foreach (string algorithm in identity.SignatureAlgorithms)
            {
                byte[]? signature = await agent.SignAsync(identity.Blob, data, SshAgentConnection.FlagsFor(algorithm), Ct);
                Assert.True(signature is not null, $"The agent refused to sign with {algorithm}.");
                Assert.True(identity.Key.Verify(algorithm, data, signature), $"The {algorithm} signature does not verify.");

                // The same signature must not verify for other data, or the check above proves nothing.
                Assert.False(identity.Key.Verify(algorithm, Encoding.ASCII.GetBytes("another blob"), signature), $"{algorithm} verified wrong data.");
                signed++;
            }
        }

        Assert.True(signed >= identities.Count);
    }

    // A real ssh-agent process on a real Unix socket, holding a throwaway key that ssh-keygen makes at test time. On
    // Windows no such agent can be reached from .NET, so this runs in the Linux gate (scripts/test-linux.sh --interop).
    [InteropTheory]
    [InlineData("ed25519", "256")]
    [InlineData("ecdsa", "256")]
    [InlineData("ecdsa", "384")]
    [InlineData("ecdsa", "521")]
    [InlineData("rsa", "3072")]
    public async Task A_local_agent_signs_with_each_key_type_on_its_unix_socket(string type, string bits)
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Git for Windows' agent uses an MSYS socket, which .NET can't reach.");
        string tools = Path.GetDirectoryName(PeerTools.RequireSshClient())!;
        string socket = _keygen.PathOf("agent.sock");
        string key = await _keygen.GenerateAsync(type, bits);

        using Process agentProcess = Process.Start(new ProcessStartInfo(Path.Combine(tools, "ssh-agent"))
        {
            ArgumentList = { "-D", "-a", socket },
            RedirectStandardOutput = true,
        })!;
        try
        {
            while (!File.Exists(socket))
            {
                await Task.Delay(20, Ct);
            }

            ProcessStartInfo add = new(Path.Combine(tools, "ssh-add")) { ArgumentList = { "-q", key }, RedirectStandardError = true };
            add.Environment[SshAgentEndpoint.Variable] = socket;
            using Process addProcess = Process.Start(add)!;
            await addProcess.WaitForExitAsync(Ct);
            Assert.Equal(0, addProcess.ExitCode);

            await using SshAgentConnection agent = new(await SshAgentEndpoint.ConnectAsync(socket, Ct), TimeSpan.FromSeconds(10));
            SshAgentIdentity identity = Assert.Single(await agent.ListIdentitiesAsync(Ct));
            byte[] data = Encoding.ASCII.GetBytes("over a real unix socket");
            foreach (string algorithm in identity.SignatureAlgorithms)
            {
                byte[]? signature = await agent.SignAsync(identity.Blob, data, SshAgentConnection.FlagsFor(algorithm), Ct);
                Assert.True(identity.Key.Verify(algorithm, data, signature!), algorithm);
                Assert.False(identity.Key.Verify(algorithm, Encoding.ASCII.GetBytes("other data"), signature!), algorithm);
            }
        }
        finally
        {
            agentProcess.Kill();
        }
    }

    /// <summary>The two halves of a remote process as one stream.</summary>
    private sealed class ProcessStream(SshProcess process) : Stream
    {
        public override bool CanRead => true;

        public override bool CanWrite => true;

        public override bool CanSeek => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            process.StandardOutput.ReadAsync(buffer, cancellationToken);

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
            process.StandardInput.WriteAsync(buffer, cancellationToken);

        public override Task FlushAsync(CancellationToken cancellationToken) => process.StandardInput.FlushAsync(cancellationToken);

        public override async ValueTask DisposeAsync()
        {
            await process.DisposeAsync();
            await base.DisposeAsync();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}

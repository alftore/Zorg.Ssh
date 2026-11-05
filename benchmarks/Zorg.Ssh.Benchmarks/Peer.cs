using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Renci.SshNet;
using Zorg.Ssh.InteropTests;
using SshNetClient = Renci.SshNet.SshClient;
using SshNetSftpClient = Renci.SshNet.SftpClient;
using TmdsClient = Tmds.Ssh.SshClient;
using TmdsSettings = Tmds.Ssh.SshClientSettings;

namespace Zorg.Ssh.Benchmarks;

/// <summary>
/// A real OpenSSH server in a container, pinned to one cipher, key exchange and host key type. Zorg.Ssh has no
/// public way to choose algorithms, so the server does the pinning: it's the only setting all three clients share.
/// </summary>
public sealed class Peer : IAsyncDisposable
{
    public const string DefaultCipher = "aes256-gcm@openssh.com";
    public const string DefaultKex = "curve25519-sha256";

    private const string UserName = "zorg";
    private const string Password = "zorg-test";
    private const string ImageTag = "zorg-ssh-bench/openssh-10:latest";

    private static readonly TimeSpan CommandTimeout = TimeSpan.FromMinutes(2);

    private readonly SshPeerContainer _container;

    private Peer(SshPeerContainer container) => _container = container;

    public string Host => _container.Host;

    public int Port => _container.Port;

    public string Banner => _container.Banner;

    public static async Task<Peer> StartAsync(string cipher = DefaultCipher, string kex = DefaultKex)
    {
        string image = await BuildImageAsync();

        // -o wins over sshd_config. LogLevel: the image logs verbosely for the interop tests, which isn't what's
        // being measured. PerSourcePenalties: a run makes thousands of connections from one address.
        string[] command =
        [
            "/usr/sbin/sshd", "-D", "-e",
            "-o", $"Ciphers={cipher}",
            "-o", $"KexAlgorithms={kex}",
            "-o", "HostKeyAlgorithms=ssh-ed25519",
            "-o", "LogLevel=ERROR",
            "-o", "PerSourcePenalties=no",
        ];

        return new Peer(await SshPeerContainer.StartAsync(image, command));
    }

    /// <summary>Builds the image from the interop tests' Dockerfile. The engine's layer cache makes a repeat cheap.</summary>
    public static Task<string> BuildImageAsync()
    {
        string peers = typeof(Peer).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .Single(a => a.Key == "PeersPath").Value!;
        return SshPeerContainer.BuildImageAsync(ImageTag, Path.Combine(peers, "openssh-10"));
    }

    /// <summary>Runs a shell command in the container as the test user, without going through SSH.</summary>
    public Task<string> RunInContainerAsync(string shellCommand) =>
        ContainerCli.RunAsync(CommandTimeout, CancellationToken.None, "exec", "-u", UserName, _container.Id, "sh", "-c", shellCommand);

    public SshClientOptions ZorgOptions() => new()
    {
        Host = Host,
        Port = Port,
        UserName = UserName,
        Credentials = [SshCredential.FromPassword(Password)],
        HostKeyPolicy = HostKeyPolicy.AcceptAnyUnsafe(),
    };

    /// <summary>SSH.NET accepts any host key unless told otherwise, the same check as the other two here.</summary>
    public ConnectionInfo SshNetInfo() => new(Host, Port, UserName, new PasswordAuthenticationMethod(UserName, Password));

    public SshNetClient SshNetClient() => new(SshNetInfo());

    public SshNetSftpClient SshNetSftpClient() => new(SshNetInfo());

    public TmdsSettings TmdsSettings() => new($"{UserName}@{Host}:{Port}")
    {
        Credentials = [new Tmds.Ssh.PasswordCredential(Password)],
        UserKnownHostsFilePaths = [],
        GlobalKnownHostsFilePaths = [],
        UpdateKnownHostsFileAfterAuthentication = false,
        HostAuthentication = static (_, _) => ValueTask.FromResult(true),
    };

    public TmdsClient TmdsClient() => new(TmdsSettings());

    public ValueTask DisposeAsync() => _container.DisposeAsync();
}

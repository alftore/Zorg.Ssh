using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Zorg.Ssh;
using Zorg.Ssh.Examples;
using Zorg.Ssh.Sftp;

// Modes:
//   --check-docs <repo root>                 checks that the docs hold only compiled samples; the build runs this
//   --run <host> <port> <user> <password>    runs the samples that need only a real server
//   (none)                                   runs a client against a server in this process
return args switch
{
    ["--check-docs", string root] => DocsCheck.Run(root),
    ["--run", string host, string port, string user, string password] => await RunAgainstAsync(host, int.Parse(port, System.Globalization.CultureInfo.InvariantCulture), user, password),
    _ => await RunInProcessAsync(),
};

static async Task<int> RunInProcessAsync()
{
    using CancellationTokenSource limit = new(TimeSpan.FromSeconds(30));
    CancellationToken token = limit.Token;

    using SshHostKey hostKey = SshHostKey.GenerateEd25519();
    await using SshServer server = await SshServer.StartAsync(new SshServerOptions
    {
        HostKeys = [hostKey],
        PasswordHandler = (request, ct) => ValueTask.FromResult(request.Password == "demo" ? SshAuthDecision.Accept : SshAuthDecision.Reject),
        SessionHandler = async (session, ct) =>
        {
            await session.Output.WriteAsync(Encoding.UTF8.GetBytes($"{session.Principal.UserName} ran {session.Command}\n"), ct);
            return 3;
        },
    }, token);

    await using SshClient client = await SshClient.ConnectAsync(new SshClientOptions
    {
        Host = "127.0.0.1",
        Port = server.LocalEndPoint.Port,
        UserName = "demo",
        Credentials = [SshCredential.FromPassword("demo")],
        HostKeyPolicy = HostKeyPolicy.Fingerprint(hostKey.Sha256Fingerprint),
    }, token);

    SshCommandResult result = await client.ExecuteAsync("anything", token);
    Console.Write(result.StandardOutput);
    Console.WriteLine($"Exit code {result.ExitCode}");
    return result.ExitCode == 3 ? 0 : 1;
}

static async Task<int> RunAgainstAsync(string host, int port, string user, string password)
{
    using CancellationTokenSource limit = new(TimeSpan.FromMinutes(2));
    CancellationToken token = limit.Token;

    SshClientOptions options = new()
    {
        Host = host,
        Port = port,
        UserName = user,
        Credentials = [SshCredential.FromPassword(password)],
        HostKeyPolicy = HostKeyPolicy.AcceptAnyUnsafe(),
    };

    await using SshClient client = await SshClient.ConnectAsync(options, token);
    await ClientExamples.Execute(client, token);
    await ClientExamples.Concurrent(client, token);
    await ClientExamples.Process(client, token);
    await ClientExamples.Stream(client, token);
    await ClientExamples.Environment(client, token);
    await ClientExamples.Shell(client, token);

    await File.WriteAllBytesAsync("report.pdf", new byte[1024 * 1024], token);
    await SftpExamples.Open(client, token);
    await using SftpClient sftp = await client.OpenSftpAsync(token);
    await SftpExamples.Transfer(sftp, token);
    await SftpExamples.SmallFiles(client, sftp, token);
    await SftpExamples.List(sftp, token);
    await SftpExamples.Tree(sftp, token);
    await SftpExamples.Streams(sftp, token);
    await SftpExamples.Attributes(sftp, token);
    await SftpExamples.Manage(sftp, token);
    await SftpExamples.Extensions(sftp, token);
    await SftpExamples.Errors(sftp, token);

    string[] copied = [.. Directory.GetFiles("local-reports").Select(Path.GetFileName)!];
    Console.WriteLine($"Tree download: {string.Join(", ", copied)}");
    return 0;
}

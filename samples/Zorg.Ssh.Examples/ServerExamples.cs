using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Zorg.Ssh.Sftp;
using System.Threading;
using System.Threading.Tasks;

namespace Zorg.Ssh.Examples;

/// <summary>The samples in docs/server.md.</summary>
internal static class ServerExamples
{
    public static async Task Echo(CancellationToken cancellationToken)
    {
        // doc:server-start
        // Make the key once, with: ssh-keygen -t ed25519 -N "" -f host_key
        using SshHostKey hostKey = SshHostKey.Load(await File.ReadAllTextAsync("host_key", cancellationToken));
        Console.WriteLine($"Host key: {hostKey.Sha256Fingerprint}");

        await using SshServer server = await SshServer.StartAsync(new SshServerOptions
        {
            Port = 2222,
            HostKeys = [hostKey],
            PasswordHandler = (request, ct) => ValueTask.FromResult(
                IsPasswordRight(request.UserName, request.Password) ? SshAuthDecision.Accept : SshAuthDecision.Reject),
            SessionHandler = async (session, ct) =>
            {
                await session.Output.WriteAsync(Encoding.UTF8.GetBytes($"Hello, {session.Principal.UserName}\n"), ct);
                return 0;
            },
        }, cancellationToken);

        Console.WriteLine($"Listening on {server.LocalEndPoint}");
        await Task.Delay(Timeout.Infinite, cancellationToken);
        // end-doc
    }

    public static SshServerOptions KeyOnly(SshHostKey hostKey, ISet<string> allowedKeys)
    {
        // doc:server-public-key
        SshServerOptions options = new()
        {
            Address = IPAddress.Any,
            Port = 2222,
            HostKeys = [hostKey],
            PublicKeyHandler = (request, ct) => ValueTask.FromResult(
                allowedKeys.Contains(request.Sha256Fingerprint) ? SshAuthDecision.Accept : SshAuthDecision.Reject),
            SessionHandler = RunSessionAsync,
        };
        // end-doc
        return options;
    }

    public static SshServerOptions TwoSteps(SshHostKey hostKey, ISet<string> allowedKeys)
    {
        // doc:server-two-factor
        SshServerOptions options = new()
        {
            HostKeys = [hostKey],
            RequiredAuthMethods = ["publickey", "password"],
            PublicKeyHandler = (request, ct) => ValueTask.FromResult(
                allowedKeys.Contains(request.Sha256Fingerprint) ? SshAuthDecision.Accept : SshAuthDecision.Reject),
            PasswordHandler = (request, ct) => ValueTask.FromResult(
                IsPasswordRight(request.UserName, request.Password) ? SshAuthDecision.Accept : SshAuthDecision.Reject),
            SessionHandler = RunSessionAsync,
        };
        // end-doc
        return options;
    }

    public static SshServerOptions SftpOnly(SshHostKey hostKey)
    {
        // doc:server-sftp
        SftpServerOptions sftp = new() { RootDirectory = "/srv/sftp", ReadOnly = true };
        SshServerOptions options = new()
        {
            HostKeys = [hostKey],
            PasswordHandler = (request, ct) => ValueTask.FromResult(
                IsPasswordRight(request.UserName, request.Password) ? SshAuthDecision.Accept : SshAuthDecision.Reject),
            SessionHandler = (session, ct) =>
                session.Kind == SshSessionKind.Subsystem && session.Command == "sftp"
                    ? SftpServer.ServeAsync(session, sftp, ct)
                    : Task.FromResult(1),
        };
        // end-doc
        return options;
    }

    public static SshServerOptions Limits(SshHostKey hostKey)
    {
        // doc:server-limits
        SshServerOptions options = new()
        {
            HostKeys = [hostKey],
            PasswordHandler = (request, ct) => ValueTask.FromResult(SshAuthDecision.Reject),
            SessionHandler = RunSessionAsync,
            Banner = "Authorised use only.\n",
            MaxConnections = 50,
            MaxUnauthenticatedConnections = 10,
            MaxUnauthenticatedPerAddress = 3,
            LoginGraceTime = TimeSpan.FromSeconds(15),
            IdleTimeout = TimeSpan.FromMinutes(10),
            MaxAuthAttempts = 3,
            MaxSessionsPerConnection = 4,
        };
        // end-doc
        return options;
    }

    // doc:server-session
    private static async Task<int> RunSessionAsync(SshServerSession session, CancellationToken cancellationToken)
    {
        switch (session.Kind)
        {
            case SshSessionKind.Exec when session.Command == "whoami":
                await session.Output.WriteAsync(Encoding.UTF8.GetBytes(session.Principal.UserName + "\n"), cancellationToken);
                return 0;

            case SshSessionKind.Exec:
                await session.Error.WriteAsync("Unknown command.\n"u8.ToArray(), cancellationToken);
                return 127;

            case SshSessionKind.Shell:
                // An echo service: runs until the client sends EOF.
                await session.Input.CopyToAsync(session.Output, cancellationToken);
                return 0;

            default:
                // Subsystems reach this handler too, so a request for sftp ends up here.
                await session.Error.WriteAsync("No subsystems here.\n"u8.ToArray(), cancellationToken);
                return 1;
        }
    }
    // end-doc

    // doc:server-password-check
    private static bool IsPasswordRight(string userName, string password)
    {
        // A sample only. Store a salted hash from a slow function such as PBKDF2, never the password.
        byte[] expected = LookUpHash(userName);
        byte[] actual = Rfc2898DeriveBytes.Pbkdf2(password, Salt(userName), 600_000, HashAlgorithmName.SHA256, expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }
    // end-doc

    private static byte[] LookUpHash(string userName) => SHA256.HashData(Encoding.UTF8.GetBytes(userName));

    private static byte[] Salt(string userName) => Encoding.UTF8.GetBytes(userName);
}

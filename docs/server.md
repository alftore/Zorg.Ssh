# Server

`SshServer` runs an SSH server inside your process. It doesn't run a shell or log people in to the machine: your handlers decide who gets in and what a session does.

The server is the newest and least tested part of the library. See [security.md](security.md#unverified) before you expose one to a network.

## Starting a server

```csharp
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
```

The server listens on loopback unless you set `Address`, so exposing it is a deliberate choice. A `Port` of zero, the default, picks a free port: read it from `LocalEndPoint`.

Disposing the server stops listening, closes every connection, cancels the handlers' tokens, and waits for the handlers to end. A handler that ignores its token holds up disposal.

## Host keys

`HostKeys` needs at least one key. `SshHostKey.Load` takes the text of a private key file in OpenSSH, PKCS#1, SEC1 or PKCS#8 form, with a passphrase if it's encrypted.

Clients pin the host key, so it has to stay the same between runs. `SshHostKey.GenerateEd25519` makes a new random key, but there's no way to save one, so it only suits tests and short-lived servers. For anything else, make the key with `ssh-keygen` and load it.

You own the keys: dispose them after the server has stopped. `using` before `await using`, as above, does that in the right order.

## Authentication

At least one of `PasswordHandler` and `PublicKeyHandler` is required. Only the methods with a handler are offered. The server has no keyboard-interactive login, and a client that tries to change a password is disconnected.

A handler returns `SshAuthDecision.Accept` or `Reject`. The user name in a request is unverified and chosen by the client.

### Passwords

Compare passwords in constant time, against a salted hash from a slow function.

```csharp
private static bool IsPasswordRight(string userName, string password)
{
    // A sample only. Store a salted hash from a slow function such as PBKDF2, never the password.
    byte[] expected = LookUpHash(userName);
    byte[] actual = Rfc2898DeriveBytes.Pbkdf2(password, Salt(userName), 600_000, HashAlgorithmName.SHA256, expected.Length);
    return CryptographicOperations.FixedTimeEquals(actual, expected);
}
```

`SshPasswordRequest.ToString` leaves the password out, so logging a request can't leak it. Don't log `request.Password` yourself. A slow check runs on the client's connection, so `LoginGraceTime` and `MaxUnauthenticatedConnections` bound how many can run at once.

### Public keys

```csharp
SshServerOptions options = new()
{
    Address = IPAddress.Any,
    Port = 2222,
    HostKeys = [hostKey],
    PublicKeyHandler = (request, ct) => ValueTask.FromResult(
        allowedKeys.Contains(request.Sha256Fingerprint) ? SshAuthDecision.Accept : SshAuthDecision.Reject),
    SessionHandler = RunSessionAsync,
};
```

The handler runs before the signature is checked, because a client may ask whether a key is acceptable before it signs anything. `Accept` takes effect only if the client then proves it holds the key. So the handler can run for keys the client doesn't hold: don't treat a call as a login.

### Two steps

`RequiredAuthMethods` lists methods that must all pass. The server enforces it, whatever the handlers return.

```csharp
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
```

A client can pass them in either order, and a password alone gets no further. `Principal.Methods` lists every method that passed, in order. `Principal.KeyFingerprints` lists every key the client proved, in order, and `KeyFingerprint` is the last. A method passes once, so a second key never counts as the second method. A login can prove at most eight keys.

## Sessions

`SessionHandler` runs once per exec, shell or subsystem request, and returns the exit code.

```csharp
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
```

| `SshServerSession` | Meaning |
|---|---|
| `Principal` | Who logged in: `UserName`, the `Methods` that passed, and `KeyFingerprint` (the last key proven) and `KeyFingerprints` (all of them). |
| `Kind` | `Exec`, `Shell` or `Subsystem`. |
| `Command` | The command line or subsystem name. Null for a shell. |
| `Pty` | The terminal the client asked for, if any. |
| `Environment` | The variables the client asked for. |
| `Input`, `Output`, `Error` | Streams for stdin, stdout and stderr. |

Everything in a session comes from an authenticated client, but it's still under the client's control:

- Never pass `Command` to a shell without thinking about what it can do.
- Don't apply `Environment` blindly. Variables such as `LD_PRELOAD` are dangerous.

What the server doesn't do for you:

- There's no shell, no process launching and no real terminal. `Pty` only tells you what was asked for. A later `window-change` is accepted, but your handler isn't told about it.
- There's no remote forwarding: `tcpip-forward` is refused. `direct-tcpip` channels are refused too, unless you set `DirectTcpHandler`. On allow, the server itself makes the connection, so decide on the target, not just the user.

The token cancels when the server stops, and when the client closes the session or goes away. Reads on `Input` then end or fail, and writes fail with an `SshException`, so a handler that does other long work has to watch for that itself.

If a handler throws, the error is logged, the client gets exit code 1, and it learns nothing about why.

## SFTP

`SftpServer.ServeAsync` serves one SFTP session from a directory. Call it from `SessionHandler` for the `sftp` subsystem.

```csharp
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
```

The client sees `RootDirectory` as `/`, and paths and symlinks that lead out of it are refused. That check can't be airtight against another process on the same machine changing the directory at the same moment, because .NET has no `openat`. Don't share a root with anyone you don't trust to write to it. Disk use isn't limited, and metadata requests run one at a time across the whole process.

## Limits

```csharp
SshServerOptions options = new()
{
    HostKeys = [hostKey],
    PasswordHandler = (request, ct) => ValueTask.FromResult(SshAuthDecision.Reject),
    SessionHandler = RunSessionAsync,
    Banner = "Authorised use only.\n",
    MaxConnections = 50,
    MaxUnauthenticatedConnections = 10,
    LoginGraceTime = TimeSpan.FromSeconds(15),
    MaxAuthAttempts = 3,
    MaxSessionsPerConnection = 4,
};
```

| Option | Default | Meaning |
|---|---|---|
| `MaxConnections` | 100 | The most connections at once. Past it, new ones are closed before a byte is read. |
| `MaxUnauthenticatedConnections` | 20 | The most connections not yet logged in, so idle ones can't crowd out real users. |
| `LoginGraceTime` | 30 seconds | The time allowed to log in. |
| `MaxAuthAttempts` | 6 | Failed attempts allowed per connection. |
| `MaxSessionsPerConnection` | 10 | The most sessions on one connection. |

`Banner` is text sent to clients before login. `LoggerFactory` takes a standard `ILoggerFactory`, and passwords and keys aren't logged.

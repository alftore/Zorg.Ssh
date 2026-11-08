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

`SshPasswordRequest.ToString` leaves the password out, so logging a request can't leak it. Don't log `request.Password` yourself. `RemoteEndPoint` on both requests is the client's address and port, for your own rate limits or audit log. It's null for a connection given to `ServeStreamAsync`. A slow check runs on the client's connection, so `LoginGraceTime` and `MaxUnauthenticatedConnections` bound how many can run at once.

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

A client can pass them in either order, and a password alone gets no further. `Principal.Methods` lists every method that passed, in order. `Principal.KeyFingerprints` lists every key the client proved, in order. A method passes once, so a second key never counts as the second method. A login can prove at most eight keys.

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
| `Principal` | Who logged in: `UserName`, the `Methods` that passed, and `KeyFingerprints` (every key proven, in order). |
| `RemoteEndPoint` | The client's address and port. Null for a connection given to `ServeStreamAsync`. |
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

The token cancels when the server stops, when the client closes the session's channel, and when the connection ends: the client disconnects or goes away, keepalive gives up on it, or the stream you passed to `ServeStreamAsync` is closed or its token cancelled. Reads on `Input` then end or fail, and writes fail with an `SshException`, so a handler that does other long work has to watch for that itself. `IdleTimeout` never cancels it: a running handler's channel is open, and an open channel stops the idle clock. The token says only that the session is over, not why. Its callbacks run on the thread pool, never in the connection's receive loop, but a slow one delays that session's cleanup, and a stopping server waits for it.

If a handler throws, the error is logged, the client gets exit code 1, and it learns nothing about why. The other handlers fail closed the same way: a password or public key handler that throws has rejected the attempt, and a `DirectTcpHandler` that throws has refused the channel. Each is logged at `Error`, with your exception attached, so keep secrets out of its message.

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

The client sees `RootDirectory` as `/`, and paths and symlinks that lead out of it are refused. That check can't be airtight against another process on the same machine changing the directory at the same moment, because .NET has no `openat`. Don't share a root with anyone you don't trust to write to it. A new symlink is stored in one shape. An absolute target means the client's root, and is stored relative to the link. `..` may only lead the target, and no further than the root. After the first name the target only goes down, so `m/..` is cancelled when the link is made. A target that leads nowhere, such as `.` or the link's own directory, is refused. Whatever links are made later, every link made through the server then ends inside the root. A rename keeps this true: a link can't be moved to a directory too shallow for its `..`, and a directory moved to a shallower place is checked for such links below it. The check looks at up to 10,000 entries, and a larger directory can't be moved up the tree (the client sees a plain failure). Disk use isn't limited, and metadata requests run one at a time across the whole process.

What a client sees comes from .NET's view of the directory (on Linux, listings come from the server's own reading of it), which differs from OpenSSH's in a few places:

- On Linux and macOS, a FIFO, socket or device is reported with its real type, so `IsRegularFile` is false, as OpenSSH reports it. On macOS the type comes from `lstat`, whose layout hasn't been run by the maintainers: it's used only when the permission bits read beside it match .NET's, and otherwise the entry is reported as a regular file, as before. On other Unix systems .NET can't tell them from files, and they're reported as regular files. Opening one can block, so the session ends after the open has waited 10 seconds.
- On Linux, a name that isn't valid UTF-8, such as one made on a Latin-1 system, is listed as the bytes the file system holds, in the name and the long name, with that entry's own attributes, as OpenSSH's `sftp-server` does. The server reads the directory itself (`getdents64`, then `statx` and `readlinkat` relative to the open directory), because .NET would turn the bad bytes into U+FFFD and then look up the wrong path. Our client reports such a name with `HasValidName` false. The entry still can't be reached through the server: every path a client sends must be UTF-8, so it can't be opened, renamed or removed over SFTP. The check before a directory moves up the tree reads directories the same way, so it sees a link with such a name, or below a directory with one.
- A symbolic link is described as itself in a listing and in `LSTAT`: its permission bits are 0777 on Unix, as Linux and OpenSSH have them, never its target's, which could be a file outside the root.
- A Windows name with an unpaired surrogate isn't Unicode, so it can't be sent as UTF-8. It's sent as the three bytes of the surrogate (WTF-8), which a client can't decode, as it can't decode a name that isn't UTF-8 from OpenSSH. Our client reports it with `HasValidName` false.
- **Known limit:** on other Unix systems, such as macOS and FreeBSD, .NET still reads the directory. So it does on Linux on an architecture other than x64, x86, Arm, Arm64, RISC-V and LoongArch, or with a C library that lacks `getdents64` (or musl's `getdents`), `statx` or `readlinkat`, such as glibc before 2.30 or musl before 1.2.5. There a name that isn't UTF-8 is listed with U+FFFD in place of the bad bytes: a valid-looking name that leads nowhere, or to another entry whose name really has U+FFFD in it, and without its own attributes. The check before a directory moves up can miss a link with such a name. Don't serve a tree that can hold such names there.
- Windows rules apply on Windows: names are case-insensitive, and a name with `:`, `*`, `?`, `"`, `<`, `>`, `|` or `\`, a trailing dot or space, or a device name such as `CON` or `aux.csv` is refused with a plain failure. There are no owners and no permission bits: the bits a client sees are made up from the read-only attribute, and setting them is accepted and ignored.
- Some answers differ from OpenSSH's `sftp-server` everywhere. `REALPATH` of a path that doesn't exist returns the path instead of `NoSuchFile`. A rename onto an existing empty directory fails. Listing or removing a file as if it were a directory gets `Failure` where OpenSSH says `NoSuchFile`. Attributes carry no owner or group. Only `posix-rename`, `fsync`, `limits` and `statvfs` are offered, so `CopyFileAsync` and `CreateHardLinkAsync` get `OperationUnsupported`.

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
    MaxUnauthenticatedPerAddress = 3,
    LoginGraceTime = TimeSpan.FromSeconds(15),
    IdleTimeout = TimeSpan.FromMinutes(10),
    MaxAuthAttempts = 3,
    MaxSessionsPerConnection = 4,
};
```

| Option | Default | Meaning |
|---|---|---|
| `MaxConnections` | 100 | The most connections at once. Past it, new ones are closed before a byte is read. |
| `MaxUnauthenticatedConnections` | 20 | The most connections not yet logged in, so idle ones can't crowd out real users. |
| `MaxUnauthenticatedPerAddress` | 5 | The most connections not yet logged in that one source address may hold, so one address can't take every unauthenticated slot. See below. |
| `LoginGraceTime` | 30 seconds | The time allowed to log in. |
| `IdleTimeout` | none | How long a logged-in connection may have no open channel before the server closes it. See below. |
| `KeepAliveInterval` | 5 minutes | How long a logged-in connection can be silent before a probe goes out. `TimeSpan.Zero` turns it off. |
| `KeepAliveCountMax` | 3 | How many more silent intervals end the connection. |
| `MaxAuthAttempts` | 6 | Failed attempts allowed per connection. |
| `MaxSessionsPerConnection` | 10 | The most sessions on one connection. |

`MaxUnauthenticatedPerAddress` counts by the source address of the accepted socket, before anything is read. An IPv4-mapped IPv6 address (`::ffff:192.0.2.7`) and a NAT64 address (`64:ff9b::192.0.2.7`) count as the IPv4 address inside them, and other IPv6 addresses count together by /64 prefix, because one host commonly owns a whole /64. A user who is delegated a /56 or /48 owns many /64 prefixes, so for IPv6 the limit raises the cost of an attack but doesn't stop it. A connection over the limit is closed at once, like one over `MaxConnections`. The count is given back when the connection logs in, fails to, runs out of `LoginGraceTime`, or ends, so a client that logs in leaves room for the next. Clients behind one NAT share an address, so raise the limit for a gateway that fronts many users. Behind a proxy, a TCP load balancer, or SNAT (for example a Kubernetes Service with `externalTrafficPolicy: Cluster`), every connection comes from the proxy's address. The limit then applies to that one address: with the default of 5, one client holding five idle sockets locks everyone else out until `LoginGraceTime`. Raise `MaxUnauthenticatedPerAddress` there, or set it to `int.MaxValue` to turn it off, and rely on `MaxUnauthenticatedConnections` and the proxy's own limits. It doesn't apply to `ServeStreamAsync`, which has no address, and there are no penalties for repeat failures or random early drop as in OpenSSH's `MaxStartups`: an attacker with many addresses is still bounded only by `MaxUnauthenticatedConnections`.

`IdleTimeout` is like OpenSSH's `UnusedConnectionTimeout`. It starts when the client logs in, and runs only while the connection has no open channel: a session or a direct-tcpip forward that is still open, including one whose handler is still running, stops the clock. Opening a channel resets it, and it starts again from zero when the last channel closes. Keepalive traffic doesn't count as activity, so a client that only answers keepalives is still closed. The server sends a polite DISCONNECT and logs the close at `Information` level. The server never accepts remote forwards, so there is no listener that could count as use. It must be above zero.

`Banner` is text sent to clients before login. `LoggerFactory` takes a standard `ILoggerFactory`, and passwords and keys aren't logged. `SshServerOptions` is a record, so `with` makes a changed copy, and its `ToString` shows only the address and port.

`Algorithms` narrows what the server offers, as on the client. For old clients, `SshAlgorithms.LegacyUnsafe` adds `ssh-rsa` (SHA-1) host key signatures, when a host key is RSA, `ssh-rsa` user signatures, and the `hmac-sha1` MACs. It doesn't add finite-field Diffie-Hellman: a client can make the server spend milliseconds of CPU per handshake on it before logging in, so the server offers `diffie-hellman-*` only when its `KeyExchange` list names them, as OpenSSH 10's sshd does. Name them on a copy of the preset: `Algorithms = SshAlgorithms.LegacyUnsafe with { KeyExchange = ["curve25519-sha256", "diffie-hellman-group14-sha256"] }`. A plain `new SshAlgorithms` refuses legacy names. [security.md](security.md#legacy-algorithms) has the details.

### Keepalive

Keepalive frees the slot of a client that has gone. It's on by default, and it starts after login. Before login, `LoginGraceTime` does that job.

- If nothing arrives for one interval, the server sends a `keepalive@openssh.com` request. Any packet counts as an answer, so a busy connection sends no probes. A client that doesn't know global requests can answer `UNIMPLEMENTED`, and that counts too.
- Only one probe is out at a time. After it, `KeepAliveCountMax` more silent intervals end the connection. With the defaults that's 20 minutes of silence. Set a shorter interval to notice sooner, at the cost of dropping a connection over a shorter network break. The default is the one Debian's OpenSSH uses for `BatchMode`, because upstream OpenSSH leaves it off and relies on TCP keepalive, which can't see a peer that stops reading.
- A client that keeps sending but has stopped reading is never silent. So one socket write that doesn't finish within the interval times the count also ends the connection. With the defaults that's 15 minutes, or up to one interval more.
- When the connection ends, each handler's token is cancelled, and its stream calls throw `SshConnectionException`. A handler that ignores both still holds its slot.
- A client that answers probes but grants no window is alive. The connection stays up, and a handler's write waits. Use the handler's token, and a timeout of your own if you need one.
- `TimeSpan.Zero` turns all of this off. The interval can be 1 second to 1 day, and the count 1 to 1000.

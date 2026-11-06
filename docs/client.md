# Client

## Connecting

`SshClient.ConnectAsync` opens the connection, exchanges keys, checks the host key, and logs in. It returns only when all of that has worked.

```csharp
await using SshClient client = await SshClient.ConnectAsync(new SshClientOptions
{
    Host = "example.com",
    UserName = "alice",
    Credentials = [SshCredential.FromPrivateKeyFile("~/.ssh/id_ed25519")],
    HostKeyPolicy = HostKeyPolicy.KnownHostsFile(),
}, cancellationToken);

SshCommandResult result = await client.ExecuteAsync("uname -a", cancellationToken);
Console.WriteLine(result.StandardOutput);

await using SftpClient sftp = await client.OpenSftpAsync(cancellationToken);
await using FileStream local = File.OpenRead("report.pdf");
await sftp.UploadFileAsync(local, "report.pdf", cancellationToken);
```

The client types are in the `Zorg.Ssh` namespace, and the SFTP types in `Zorg.Ssh.Sftp`.

`Host`, `UserName` and `HostKeyPolicy` are required. There's no default host key policy, so a connection can't be left unverified by accident.

All the options:

```csharp
SshClientOptions options = new()
{
    Host = "example.com",
    Port = 2222,
    UserName = "alice",
    Credentials = [SshCredential.FromPassword(password)],
    HostKeyPolicy = HostKeyPolicy.Fingerprint(fingerprint),
    ConnectTimeout = TimeSpan.FromSeconds(10),
    MaxCommandOutputBytes = 1024 * 1024,
    BannerHandler = banner => Console.WriteLine(banner),
    LoggerFactory = loggerFactory,
};
```

| Option | Default | Meaning |
|---|---|---|
| `Port` | 22 | The TCP port. |
| `Credentials` | none | Tried in order. See below. |
| `ConnectTimeout` | 30 seconds | One limit for TCP connect, key exchange and login together. |
| `KeepAliveInterval` | 5 minutes | How long the connection can be silent before a probe goes out. `TimeSpan.Zero` turns it off. See [Keepalive](#keepalive). |
| `KeepAliveCountMax` | 3 | How many more silent intervals end the connection. |
| `MaxCommandOutputBytes` | 64 MiB | The most `ExecuteAsync` keeps per stream before it fails. |
| `BannerHandler` | none | Receives the server's login banner. The server chooses that text. |
| `LoggerFactory` | none | A standard `ILoggerFactory`. Secrets aren't logged. |

Algorithms can't be chosen: see [security.md](security.md#algorithms).

`client.ServerVersion` holds the server's identification line, such as `SSH-2.0-OpenSSH_10.6`. The server chooses that too, so don't base a security decision on it.

Dispose the client to close the connection. Commands on one client can run at the same time.

### Connecting over your own stream

Use `ConnectOverStreamAsync` when you've already got a stream, such as a tunnel through a proxy.

```csharp
TcpClient tcp = new();
await tcp.ConnectAsync("jump.example.com", 10022, cancellationToken);

// The client owns the stream from here on. Host and Port in the options are what the host key check sees.
await using SshClient client = await SshClient.ConnectOverStreamAsync(tcp.GetStream(), options, cancellationToken);
```

### Through a jump host

Set `JumpHost` to a connected client. `Host` and `Port` are then as the jump host sees them, and `HostKeyPolicy` still checks this host: the jump host vouches for nothing.

```csharp
await using SshClient bastion = await SshClient.ConnectAsync(bastionOptions, cancellationToken);
await using SshClient inner = await SshClient.ConnectAsync(new SshClientOptions
{
    Host = "10.0.0.5",
    UserName = "alice",
    Credentials = [SshCredential.FromPassword(password)],
    HostKeyPolicy = HostKeyPolicy.Fingerprint(innerFingerprint),
    JumpHost = bastion,
}, cancellationToken);
```

## Port forwarding

```csharp
// ssh -L: a local port that leads to a target the server can reach. Null binds a free loopback port.
await using SshForward local = await client.ForwardLocalPortAsync(null, "db.internal", 5432, cancellationToken);

// ssh -D: a SOCKS5 proxy, CONNECT only, no login. SOCKS4 isn't supported.
await using SshForward proxy = await client.ForwardDynamicPortAsync(null, cancellationToken);

// ssh -R: a port on the server that leads back here. Port 0 lets the server choose.
await using SshRemoteForward remote = await client.ForwardRemotePortAsync("127.0.0.1", 0, "localhost", 8080, cancellationToken);

// No listener at all: one connection, as a stream.
await using Stream stream = await client.OpenTcpStreamAsync("db.internal", 5432, cancellationToken);
```

Anyone who can reach a local forward's port can use it with no login, so think before binding anything but loopback. Each forward carries at most `MaxForwardedConnections` at once, and disposing it closes its listener and its connections. A forward also closes when the SSH connection ends.

## Credentials

```csharp
SshCredential[] credentials =
[
    SshCredential.FromPrivateKeyFile("~/.ssh/id_ed25519", passphrase),
    SshCredential.FromPrivateKey(deployKey),
    SshCredential.FromPassword(password),
    SshCredential.FromKeyboardInteractive((prompts, ct) =>
        ValueTask.FromResult<IReadOnlyList<string>>([.. prompts.Select(_ => oneTimeCode)])),
];
```

Credentials are tried in the order you list them. A credential whose method the server doesn't offer is skipped. If the server asks for a second step after a partial success, the next credential answers it. With an empty list, the client still asks for `none`, which a few servers accept.

Public keys are offered before they're signed with, so a key the server doesn't know doesn't count as a failed login on OpenSSH.

| Key files | Supported |
|---|---|
| Key types | Ed25519, ECDSA on P-256, P-384 and P-521, RSA of 2048 to 16384 bits |
| Formats | OpenSSH, PKCS#1, SEC1, PKCS#8 and encrypted PKCS#8 |
| Not supported | Legacy encrypted PEM (`Proc-Type: 4,ENCRYPTED`). Convert it with `ssh-keygen -p -f <file>`. |

A key file is read when its turn comes. If it can't be loaded, for example because the passphrase is wrong, `ConnectAsync` fails with `SshKeyFileException` at that point, and later credentials aren't tried.

`~/` at the start of a path means the user's home directory.

A keyboard-interactive handler must return exactly one answer per prompt. `SshPrompt.Text` comes from the server, so treat it as untrusted, and `SshPrompt.Echo` says whether the answer may be shown as it's typed.

Passwords are .NET strings, so Zorg.Ssh can't zero them. See [security.md](security.md#secrets).

## Host key policies

The host key is what proves you've reached the right server. It's checked before any credential is sent.

```csharp
HostKeyPolicy usual = HostKeyPolicy.KnownHostsFile();
HostKeyPolicy ownFile = HostKeyPolicy.KnownHostsFile("/etc/myapp/known_hosts");
HostKeyPolicy pinned = HostKeyPolicy.Fingerprint("SHA256:n4cHVJ8c0vCpJiQJCbOgLEUxOkKrDhVJzcEKHnSSd9E");
```

- `KnownHostsFile` reads an OpenSSH `known_hosts` file, by default `~/.ssh/known_hosts`. It understands hashed host names, `[host]:port` entries and `@revoked`. An unknown host is refused, and so is a host whose key has changed. A file that doesn't exist counts as empty, so every host is unknown.
- `Fingerprint` trusts one key. It's the strictest policy when you know the key. Get the value on the server with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`. It's compared exactly, including the `SHA256:` prefix.
- `Custom` runs your own check, once, during connection.

```csharp
HostKeyPolicy policy = HostKeyPolicy.Custom((key, ct) =>
{
    Console.WriteLine($"{key.Host}:{key.Port} offers {key.KeyType} {key.Sha256Fingerprint}");
    return ValueTask.FromResult(trusted.Contains(key.Sha256Fingerprint));
});
```

Return false to refuse the key. Don't throw from the check: an exception from it ends the connection with an `SshException` that calls itself a bug in Zorg.Ssh.

Two choices weaken the check, so they carry `Unsafe` in their names.

```csharp
HostKeyPolicy trustOnFirstUse = HostKeyPolicy.KnownHostsFile(addUnknownHostsUnsafe: true);
HostKeyPolicy noCheckAtAll = HostKeyPolicy.AcceptAnyUnsafe();
```

`addUnknownHostsUnsafe` trusts a host the first time it's seen and records it, as `ssh -o StrictHostKeyChecking=accept-new` does. A first connection can be intercepted without anyone noticing, but a changed key is still refused. `AcceptAnyUnsafe` removes the protection entirely. Use it only in tests against a machine you control.

## Running a command

`ExecuteAsync` runs a command to the end and returns its output.

```csharp
SshCommandResult result = await client.ExecuteAsync("df -h /", cancellationToken);

if (result.ExitCode == 0)
{
    Console.WriteLine(result.StandardOutput);
}
else if (result.ExitSignal is not null)
{
    Console.Error.WriteLine($"Killed by {result.ExitSignal}");
}
else
{
    Console.Error.WriteLine($"Exit code {result.ExitCode}: {result.StandardError}");
}
```

- `ExitCode` is null if the command ended on a signal or the server sent no status.
- Output is decoded as UTF-8. For binary output, use `StartProcessAsync`.
- The server's shell interprets the command line, so quote anything that comes from a user. A NUL character in a command throws `ArgumentException`.
- If either stream passes `MaxCommandOutputBytes`, the call fails with `SshException`. Use `StartProcessAsync` to stream it instead.

Each command gets its own channel, so they can run side by side.

```csharp
Task<SshCommandResult> uptime = client.ExecuteAsync("uptime", cancellationToken);
Task<SshCommandResult> disk = client.ExecuteAsync("df -h /", cancellationToken);
await Task.WhenAll(uptime, disk);
```

### Cancellation

```csharp
using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(30));

try
{
    await client.ExecuteAsync("sleep 3600", timeout.Token);
}
catch (OperationCanceledException)
{
    Console.WriteLine("Gave up. The channel is closed, and the connection is still usable.");
}
```

Closing a channel doesn't reliably stop a remote command. What happens to it is up to the server.

### Keepalive

Keepalive notices a server that has gone, so a call with no token doesn't wait for ever. It's on by default, and it starts after login.

```csharp
SshClientOptions options = new()
{
    Host = "example.com",
    UserName = "alice",
    Credentials = [SshCredential.FromPassword(password)],
    HostKeyPolicy = HostKeyPolicy.Fingerprint(knownFingerprint),
    KeepAliveInterval = TimeSpan.FromSeconds(15),
    KeepAliveCountMax = 4,
};
```

- If nothing arrives for one interval, the client sends a `keepalive@openssh.com` request. Any packet counts as an answer, so a busy connection sends no probes. A server that doesn't know global requests can answer `UNIMPLEMENTED`, and that counts too.
- Only one probe is out at a time. After it, `KeepAliveCountMax` more silent intervals end the connection. With the defaults that's 20 minutes of silence. Set a shorter interval to notice sooner, at the cost of dropping a connection over a shorter network break. The default is the one Debian's OpenSSH uses for `BatchMode`, because upstream OpenSSH leaves it off and relies on TCP keepalive, which can't see a peer that stops reading.
- A server that keeps sending but has stopped reading is never silent. So one socket write that doesn't finish within the interval times the count also ends the connection. With the defaults that's 90 seconds, or up to one interval more.
- No probe goes out during a rekey, because nothing but the rekey can. Silence still counts. A live rekey sends packets, and each one restarts the count.
- The connection fails with `SshConnectionException`, and everything waiting on it wakes: commands, stream reads and writes, SFTP calls and forwards. Connect again to continue.
- `TimeSpan.Zero` turns all of this off. The interval can be 1 second to 1 day, and the count 1 to 1000.

A zero window isn't a dead server. If the server answers probes but grants no window, the connection stays up, and a write waits. Pass that writer its own token.

Keepalive doesn't limit a command either: `sleep 3600` runs for an hour while the server answers. And a server that sends a packet in every interval stays connected, whatever else it's doing.

The probe waits behind data already queued. On a very slow link that's busy sending, it might not get through in time, so raise the interval there.

## Processes

`StartProcessAsync` gives you streams, for long-running commands, large or binary output, and input.

```csharp
await using SshProcess process = await client.StartProcessAsync("sort", null, cancellationToken);

// Both output streams share one flow-control window, so read them both while you write.
using StreamReader output = new(process.StandardOutput);
using StreamReader errors = new(process.StandardError);
Task<string> sorted = output.ReadToEndAsync(cancellationToken);
Task<string> problems = errors.ReadToEndAsync(cancellationToken);

await process.StandardInput.WriteAsync("pear\napple\n"u8.ToArray(), cancellationToken);
await process.StandardInput.DisposeAsync(); // Sends EOF, so sort can finish.

Console.WriteLine(await sorted);
Console.Error.WriteLine(await problems);
await process.WaitForExitAsync(cancellationToken);
Console.WriteLine($"Exit code {process.ExitCode}");
```

Read `StandardOutput` and `StandardError` together. They share a flow-control window, so if you read only one, a server writing to the other stalls when the window fills.

Disposing `StandardInput` doesn't wait. EOF goes out behind everything already written, including a write still running, and it reaches the server when the connection has room. A write that starts after the dispose fails.

To follow output as it comes:

```csharp
await using SshProcess process = await client.StartProcessAsync("for i in 1 2 3; do echo $i; sleep 1; done", null, cancellationToken);
using StreamReader reader = new(process.StandardOutput);

while (await reader.ReadLineAsync(cancellationToken) is { } line)
{
    Console.WriteLine(line);
}
```

`WaitForExitAsync` waits for the process to end and the channel to close. Its token stops the waiting and leaves the process running. `ExitCode` and `ExitSignal` are set once the process has ended.

Disposing the process closes the channel. If it's still running, the server decides what happens to it.

Ask for a terminal or environment variables with `SshProcessOptions`.

```csharp
SshProcessOptions options = new()
{
    Pty = new SshPtyOptions { Terminal = "xterm-256color", Columns = 120, Rows = 40 },
    Environment = new Dictionary<string, string> { ["LANG"] = "C.UTF-8" },
};

await using SshProcess process = await client.StartProcessAsync("top -b -n 1", options, cancellationToken);
```

Servers usually accept only a few environment variables, and ignore the rest without saying so. OpenSSH's `AcceptEnv` setting controls this.

## Shells

`StartShellAsync` starts the user's login shell. With `null` options it asks for a default terminal: `xterm-256color`, 80 by 24.

```csharp
await using SshProcess shell = await client.StartShellAsync(null, cancellationToken);

await shell.ResizeAsync(120, 40, cancellationToken);
await shell.StandardInput.WriteAsync("echo hello; exit\n"u8.ToArray(), cancellationToken);

// With a terminal, stdout and stderr both arrive on StandardOutput.
using StreamReader reader = new(shell.StandardOutput);
Console.WriteLine(await reader.ReadToEndAsync(cancellationToken));
await shell.WaitForExitAsync(cancellationToken);
```

Output from a shell with a terminal holds prompts and control sequences. To run a known command, use `ExecuteAsync` instead.

## What's not here

The client has no SSH agent, certificates or `~/.ssh/config` parsing. See [security.md](security.md#out-of-scope).

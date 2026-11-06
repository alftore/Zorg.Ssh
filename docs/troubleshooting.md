# Troubleshooting

Every failure a peer causes is an `SshException` or a derived type. Messages say what failed and what to try. Your own mistakes, such as a null argument, are the usual .NET exceptions, and cancelling through your token gives `OperationCanceledException`.

```csharp
try
{
    await using SshClient client = await SshClient.ConnectAsync(options, cancellationToken);
    await client.ExecuteAsync("uptime", cancellationToken);
}
catch (SshHostKeyException ex)
{
    // Never retry this one automatically. Show it to a person.
    Console.Error.WriteLine(ex.Message);
}
catch (SshAuthenticationException ex)
{
    Console.Error.WriteLine($"Tried {string.Join(", ", ex.AttemptedMethods)}. The server accepts {string.Join(", ", ex.AllowedMethods)}.");
}
catch (SshNegotiationException ex)
{
    Console.Error.WriteLine($"No common {ex.Family}. The server offers {string.Join(", ", ex.PeerAlgorithms)}.");
}
catch (SshDisconnectedException ex)
{
    Console.Error.WriteLine($"The server hung up: {ex.ReasonCode} {ex.Description}");
}
catch (SshConnectionException ex)
{
    Console.Error.WriteLine($"Network failure, safe to reconnect: {ex.Message}");
}
catch (SshException ex)
{
    Console.Error.WriteLine(ex.Message);
}
```

Catch the most derived type first. The hierarchy:

```text
SshException
  SshConnectionException
    SshDisconnectedException
  SshProtocolException
    SshNegotiationException
  SshHostKeyException
  SshAuthenticationException
  SshKeyFileException
  SftpException
    SftpFileNotFoundException
    SftpPermissionDeniedException
    SftpUnsafeNameException
```

Text from a peer, such as `SshDisconnectedException.Description`, `SftpUnsafeNameException.EntryName` and the login banner, is under that peer's control. Treat it as untrusted when you display or log it.

## SshHostKeyException

The host key wasn't trusted, or the server didn't prove it holds that key. **This can mean an attack, so don't retry it automatically or work around it.**

| Message says | What to do |
|---|---|
| The host isn't in the file | Check the fingerprint in the message with the server's administrator, then add the host, for example by connecting once with `ssh`. |
| The host key has changed | Ask the administrator whether it was replaced. Update `known_hosts` only if they confirm it. A different key type counts as a change too. |
| The key is marked revoked | Don't connect until the administrator has replaced it. |
| The key isn't trusted | A `Fingerprint` or `Custom` policy refused it. Compare the fingerprint exactly, including `SHA256:`. |
| The signature is invalid, or the key doesn't match the negotiated type | Treat it as an attack until you know otherwise. |
| The server changed its host key during a rekey | The same. The connection was closed. |

If a server is on a port other than 22, `known_hosts` needs a `[host]:port` entry. The host name is compared as you wrote it in `SshClientOptions.Host`, so an address and a name are different entries.

## SshAuthenticationException

The server refused every credential. `AttemptedMethods` lists what was tried, and `AllowedMethods` what the server last said it accepts.

- Check the user name, and that the credential matches an allowed method. A credential for a method the server doesn't offer is skipped, so it won't appear in `AttemptedMethods`.
- If the server allows only `keyboard-interactive`, a password credential won't work. Use `FromKeyboardInteractive`.
- `publickey` tried but refused: check that the public key is in the account's `authorized_keys`, and that the file's permissions satisfy the server.
- "The password has expired": change it some other way, then connect again. The client can't change it.
- On OpenSSH, the server's log says why. Run `sshd` with `LogLevel VERBOSE`.

## SshKeyFileException

A private key file couldn't be loaded. It stops the login at that credential, so later credentials aren't tried.

| Message says | What to do |
|---|---|
| The file is encrypted | Pass the passphrase. |
| The passphrase is wrong, or the file is damaged | Check the passphrase. |
| Couldn't read the key file | Check the path and permissions. |
| Legacy encrypted PEM format | Convert it: `ssh-keygen -p -f <file>`. |
| The key isn't supported | Use Ed25519, ECDSA on P-256, P-384 or P-521, or RSA of 2048 to 16384 bits. |
| Malformed, or the public key doesn't match | The file is incomplete or altered. Restore it, or make a new key. |

## SshConnectionException

The network failed or the connection closed. Connect again to continue: a client doesn't reconnect by itself.

- "Couldn't connect": check the host, the port and any firewall.
- "Timed out": `ConnectTimeout` covers TCP connect, key exchange and login together. Raise it for a slow server, or a slow keyboard-interactive login with a person at the keyboard.
- "The peer closed the connection" during login: a server can drop connections at its own limits, such as OpenSSH's `MaxStartups`, or its `PerSourcePenalties` after repeated failures.
- "The key exchange timed out": the peer stopped answering. Check that it's a working SSH server.
- "The peer stopped answering keepalives": nothing arrived for `KeepAliveInterval` and then `KeepAliveCountMax` more intervals. The peer or the path has gone. Raise both for a link that drops out for a while, and check that nothing between you drops idle connections.
- "The peer went silent during a key exchange": the same, during a rekey. No probe can go out then, so only the peer's own packets count.
- "The peer stopped reading": one socket write stayed unfinished for `KeepAliveInterval` times `KeepAliveCountMax`. The peer may still be sending. Check whether it's stuck, and raise both if it's only very slow.
- "The channel is closed": this one process has ended, or you've used its stream after disposing it. The client may still work.

## SshDisconnectedException

The server ended the connection on purpose. It derives from `SshConnectionException`. `ReasonCode` is from RFC 4253 section 11.1, and `Description` is the server's text. Common causes are too many authentication failures, an idle timeout, and a server shutting down.

## SshNegotiationException

The two sides share no algorithm in one family. `Family` names it, and `LocalAlgorithms` and `PeerAlgorithms` list both sides. Usually the server is old and offers only algorithms that aren't supported here. You can't change the client's lists, so enable a shared algorithm on the server: see [security.md](security.md#algorithms). If the server can't change, Zorg.Ssh can't connect to it yet.

## SshProtocolException

The peer broke the SSH protocol, so the connection can't continue.

- "Check that the port runs SSH", or a bad identification line: you've probably reached something other than an SSH server.
- "Failed authentication" on a packet: the data was corrupted or tampered with. Reconnect, and check the network path if it repeats.
- Other messages: if the peer is a real server, this may be a bug in either side. Report it with the server's version string, and a log from `LoggerFactory` if you can. See [SECURITY.md](../SECURITY.md) if it looks exploitable.

## SshException

The base type is thrown directly in a few cases:

| Message says | What to do |
|---|---|
| The command wrote more than N bytes | Use `StartProcessAsync` to stream it, or raise `MaxCommandOutputBytes`. |
| The server refused the exec or shell request | The account may be restricted, for example by a `ForceCommand` or a restricted shell. |
| The server refused to allocate a terminal | Leave `Pty` out, or check the server's `PermitTTY`. |
| The server refused the sftp subsystem | SFTP isn't enabled there. On OpenSSH, check the `Subsystem sftp` line. |
| The server refused to open the channel | It may have reached a session limit, such as OpenSSH's `MaxSessions`. Close something first. |
| Too many channels are open | The same limit on this side. Close a process or SFTP session first. |
| This is a bug in Zorg.Ssh | Something unexpected escaped. An exception from your own `HostKeyPolicy.Custom` check also arrives this way: see `InnerException`. Otherwise please report it. |

## SftpException

The server refused an SFTP request. The session stays usable unless the message says otherwise. `StatusCode` holds the server's status, and `Path` the path involved.

| `StatusCode` | Meaning |
|---|---|
| `Failure` | The server failed, and version 3 has no better code. The target may already exist, or a limit in this library was reached: read the message. |
| `OperationUnsupported` | The server lacks this operation or extension. Check `ServerExtensions` first. |
| `BadMessage` | The server didn't understand the request. |
| `NoConnection`, `ConnectionLost` | Open a new session. |

`SftpFileNotFoundException` means nothing exists at the path, and `SftpPermissionDeniedException` means the account isn't allowed. Check the path, and the account's rights on it. With a relative path, remember that it starts from the home directory on OpenSSH: `GetFullPathAsync(".")` shows it.

Limits reached in the library also arrive as `SftpException`: raise `MaxReadAllBytes`, `MaxDirectoryEntries` or `maxTotalBytes` if the size is expected.

`CreateDirectoryAsync` on an existing directory usually gives `Failure`. Check with `ExistsAsync` first.

## SftpUnsafeNameException

During `DownloadDirectoryAsync`, a name from the server couldn't safely become a local path, or collided with something already in the destination. `EntryName` holds the name.

- If the destination already held files, for example from an earlier run, clear it and try again.
- Otherwise the server sent a name that tries to leave the destination. Don't trust that server.

## SFTP calls that end with SshConnectionException

"The SFTP session has ended" means an earlier failure closed the session. The message includes the cause. A malformed reply first raises `SshProtocolException`, and every later call raises this. Open a new session with `OpenSftpAsync`. If the `SshClient` is still connected, you don't need to reconnect.

## Calls that seem to hang

- **A process makes no progress.** You may be reading only one of `StandardOutput` and `StandardError`. They share a window, so read both at once.
- **A process doesn't exit.** Many commands wait for the end of stdin. Dispose `StandardInput` to send EOF. EOF follows the data, so a write that is still waiting for the server delays it, and so does a server that has stopped reading.
- **`ExecuteAsync` never returns.** The command is still running, or a background process it started kept stdout open. Pass a token with a timeout. `ExecuteAsync` closes stdin for you.
- **A write never finishes, and the connection stays up.** The peer answers keepalives but grants no window. That's a live peer, not a dead one, so keepalive leaves it alone. Pass the write a token.
- **No time limit on a live peer.** Keepalive ends a connection to a peer that has gone. Apart from that and `ConnectTimeout`, nothing limits how long a command or transfer takes. Use a `CancellationToken`.

## Logging

Pass an `ILoggerFactory` as `LoggerFactory`. At `Debug` level the logs show the peer's identification, the negotiated algorithms and why a connection ended. They aren't meant to hold secrets. On the server, `A session handler failed` at `Error` level carries the exception your handler threw.

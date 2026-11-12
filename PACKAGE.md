# Zorg.Ssh

An async SSH client and server library for .NET 10, with SFTP, written in C# only. It aims for secure defaults, correct behaviour against hostile peers, and interop with the SSH servers people actually run.

This is a 0.x release, so the API can still change before 1.0. Breaking changes are listed in the [changelog](https://github.com/alftore/Zorg.Ssh/blob/main/CHANGELOG.md). It has had internal reviews, fuzzing and interop tests, but no external security audit.

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

There's no default host key policy, so a connection can't trust a server by accident.

## What it does

- **Client:** password, public key (also through ssh-agent, and with user certificates) and keyboard-interactive login, `known_hosts` with `@revoked` and `@cert-authority` host certificates, pinned host keys, a subset of `ssh_config`, jump hosts, port forwarding, commands, processes with streams, and shells.
- **SFTP version 3 client:** pipelined transfers with progress, file streams, directory listing, safe recursive download, and the OpenSSH extensions.
- **Server:** password and public key login, your own handlers for exec, shell and subsystem sessions, and an SFTP server rooted at a directory.
- **Current algorithms only,** including ML-KEM and sntrup761 hybrid key exchange, and strict key exchange against Terrapin. `SshAlgorithms` narrows the lists, and `SshAlgorithms.LegacyUnsafe` reaches old equipment.
- **Native AOT and trimming** work.

No SCP, compression or agent forwarding, and the server has no remote forwarding or user certificates.

## Safe against a hostile peer

- **Four guarantees, each with tests:** no message is acted on in a state that doesn't allow it; nothing proceeds on an unverified host key or unauthenticated user, and insecure bypasses carry `Unsafe` in their name; a hostile peer can't cause unbounded memory, a hang or an unhandled exception type; secrets never reach logs or exception messages, and are zeroed after use.
- **Published advisories** in other SSH and SFTP implementations each have a named regression test, or a stated reason they can't apply.
- **Untrusted names** from an SFTP listing are checked, and recursive downloads can be capped in size.
- **Every failure a peer causes** is an `SshException` or a derived type, and a dead or stalled peer is noticed through keepalives.

**Don't put the server on the public internet, or in front of users you don't trust.**

## Tested with

Interop tests run against real OpenSSH, Dropbear, AsyncSSH and Paramiko on every change, and the unit tests run on Windows, Linux and macOS, and again on the .NET 11 runtime. The package targets .NET 10 and also runs on .NET 11. Against SSH.NET and Tmds.Ssh it is ahead in login, level in exec, and behind in some transfers: the [benchmarks](https://github.com/alftore/Zorg.Ssh/blob/main/docs/benchmarks.md) show the wins and the losses.

## Documentation

- [Client](https://github.com/alftore/Zorg.Ssh/blob/main/docs/client.md): connecting, credentials, host keys, commands, processes, shells and forwarding
- [SFTP](https://github.com/alftore/Zorg.Ssh/blob/main/docs/sftp.md): transfers, listings, file streams and file management
- [Server](https://github.com/alftore/Zorg.Ssh/blob/main/docs/server.md): running an SSH server in your own process, and where not to run it
- [Security](https://github.com/alftore/Zorg.Ssh/blob/main/docs/security.md): guarantees, defaults, algorithms, advisories, what's out of scope and what's unverified
- [Troubleshooting](https://github.com/alftore/Zorg.Ssh/blob/main/docs/troubleshooting.md): each exception, and what to do
- [Changelog](https://github.com/alftore/Zorg.Ssh/blob/main/CHANGELOG.md)
- [Report a security problem](https://github.com/alftore/Zorg.Ssh/security/advisories/new)

## How this is built

Zorg.Ssh is written with the help of AI agents, mainly Claude Code from Anthropic. The maintainer sets the direction and makes the design decisions, and agents do most of the implementation. This note covers the whole project, so individual commits don't carry a co-author line.

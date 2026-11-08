# Zorg.Ssh

An async SSH client and server library for .NET 10, with an SFTP client, written in C# only. It aims for secure defaults, correct behaviour against hostile peers, and interop with the SSH servers people actually run.

**Status: pre-release, and it hasn't had an external security review. Don't use it in production.** Nothing has been published yet, and the public API can still change. [docs/security.md](docs/security.md) lists what's been tested and what hasn't.

## What it does

- Client: password, public key (also through ssh-agent, and with user certificates) and keyboard-interactive login, `known_hosts` with `@revoked` and `@cert-authority` host certificates, pinned host keys, a subset of `ssh_config`, commands, processes with streams, and shells.
- SFTP version 3 client: pipelined transfers, file streams, directory listing, safe recursive download, and the OpenSSH extensions.
- Server: password and public key login, your own handlers for exec, shell and subsystem sessions, and an SFTP server rooted at a directory. The server is for tests, local tools and trusted networks, not the public internet: see [docs/server.md](docs/server.md#where-to-run-it).
- Current algorithms only, including ML-KEM and sntrup761 hybrid key exchange, and strict key exchange against Terrapin. `SshAlgorithms` narrows the lists.

It has no SCP, compression or agent forwarding. See [what's out of scope](docs/security.md#out-of-scope).

## Sample

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

## Documentation

- [Client](docs/client.md): connecting, credentials, host keys, commands, processes and shells
- [SFTP](docs/sftp.md)
- [Server](docs/server.md)
- [Security](docs/security.md): guarantees, defaults, algorithms, what's out of scope, what's unverified
- [Troubleshooting](docs/troubleshooting.md): each exception, and what to do
- [Benchmarks](docs/benchmarks.md): measured against SSH.NET and Tmds.Ssh, wins and losses

## Guarantees

1. No message is acted on in a state that doesn't allow it.
2. Nothing proceeds on an unverified host key or unauthenticated user. Insecure bypasses carry `Unsafe` in their name.
3. A hostile peer can't cause unbounded memory, a hang or an unhandled exception type.
4. Secrets never reach logs or exception messages, and are zeroed after use.

Each has tests, but no outside party has checked them. [docs/security.md](docs/security.md) gives the limits, including what .NET strings mean for the fourth.

## How this is built

Zorg.Ssh is written with the help of AI agents, mainly Claude Code from Anthropic. The maintainer sets the direction and makes the design decisions, and agents do most of the implementation. This note covers the whole project, so individual commits don't carry a co-author line.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Report security problems as [SECURITY.md](SECURITY.md) describes. Local scratch files go in `.tmp/`, which is gitignored.

## License

MIT. See [LICENSE](LICENSE). Package choices are recorded in [docs/dependencies.md](docs/dependencies.md).

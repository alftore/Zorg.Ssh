# Zorg.Ssh

An async SSH client and server library for .NET 10, with SFTP, written in C# only. It aims for secure defaults, correct behaviour against hostile peers, and interop with the SSH servers people actually run.

Status: early, version 0.1. The public API can still change before 1.0. It has had internal reviews and tests, not an external security audit: see [Status and security](#status-and-security).

```
dotnet add package Zorg.Ssh
```

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

There's no default host key policy, so a connection can't trust a server by accident. [docs/client.md](docs/client.md) shows the others.

## What's in it

- **Client:** password, public key (also through ssh-agent, and with user certificates) and keyboard-interactive login, `known_hosts` with `@revoked` and `@cert-authority` host certificates, pinned host keys, a subset of `ssh_config`, jump hosts, port forwarding, commands, processes with streams, and shells.
- **SFTP version 3 client:** pipelined transfers with progress, file streams, directory listing, safe recursive download, and the OpenSSH extensions.
- **Server:** password and public key login, your own handlers for exec, shell and subsystem sessions, and an SFTP server rooted at a directory. The server is for tests, local tools and trusted networks, not the public internet: see [docs/server.md](docs/server.md#where-to-run-it).
- **Current algorithms only,** including ML-KEM and sntrup761 hybrid key exchange, and strict key exchange against Terrapin. `SshAlgorithms` narrows the lists, and `SshAlgorithms.LegacyUnsafe` reaches old equipment.
- **Native AOT and trimming** work, checked by a smoke test in CI.

## What's not in it

No SCP, compression or agent forwarding, and the server has no remote forwarding or user certificates. [docs/security.md](docs/security.md#out-of-scope) has the full list, and [what's unverified](docs/security.md#unverified) says what hasn't been tested.

## Documentation

- [Client](docs/client.md): connecting, credentials, host keys, commands, processes, shells and forwarding
- [SFTP](docs/sftp.md): transfers, listings, file streams and file management
- [Server](docs/server.md): running an SSH server in your own process, and where not to run it
- [Security](docs/security.md): guarantees, defaults, algorithms, what's out of scope, what's unverified
- [Troubleshooting](docs/troubleshooting.md): each exception, and what to do
- [Benchmarks](docs/benchmarks.md): measured against SSH.NET and Tmds.Ssh, wins and losses
- [Changelog](CHANGELOG.md)

## Guarantees

1. No message is acted on in a state that doesn't allow it.
2. Nothing proceeds on an unverified host key or unauthenticated user. Insecure bypasses carry `Unsafe` in their name.
3. A hostile peer can't cause unbounded memory, a hang or an unhandled exception type.
4. Secrets never reach logs or exception messages, and are zeroed after use.

Each has tests, but no outside party has checked them. [docs/security.md](docs/security.md) gives the limits, including what .NET strings mean for the fourth.

## Status and security

Zorg.Ssh has had internal reviews only: reviews by the AI agents that build it, a pre-audit by a separate AI model, hostile-input tests, a fuzzer on every decoder and on live encrypted connections, and interop tests against real OpenSSH, Dropbear, AsyncSSH and Paramiko on every push. It hasn't had an external security audit or a penetration test, and none is planned. [docs/security.md](docs/security.md#unverified) lists what has and hasn't been checked, so you can judge whether it fits your use.

**Don't put the server on the public internet, or in front of users you don't trust.** That doesn't change with a version number. [docs/server.md](docs/server.md#where-to-run-it) says where it fits.

Report a vulnerability privately, as [SECURITY.md](SECURITY.md) describes.

## How this is built

Zorg.Ssh is written with the help of AI agents, mainly Claude Code from Anthropic. The maintainer sets the direction and makes the design decisions, and agents do most of the implementation. This note covers the whole project, so individual commits don't carry a co-author line.

## Contributing

Issues are welcome. Pull requests are open to collaborators only. See [CONTRIBUTING.md](CONTRIBUTING.md) for why, and for how to build and test. Local scratch files go in `.tmp/`, which is gitignored.

## License

MIT. See [LICENSE](LICENSE). Package choices are recorded in [docs/dependencies.md](docs/dependencies.md).

# Zorg.Ssh

An async-first SSH client and server library for .NET 10, written in C# only. It aims for secure defaults, correct behaviour against hostile peers, and interop with the SSH servers people actually run.

**Status: early development. Don't use it in production.** The first preview ships after the client and SFTP work is done.

## Planned shape

```csharp
await using SshClient client = await SshClient.ConnectAsync(new SshClientOptions
{
    Host = "example.com",
    UserName = "alice",
    HostKeyPolicy = HostKeyPolicy.KnownHostsFile(),
}, cancellationToken);

SshCommandResult result = await client.ExecuteAsync("uname -a", cancellationToken);
```

## Guarantees

1. No message is acted on in a state that doesn't allow it.
2. Nothing proceeds on an unverified host key or unauthenticated user. Insecure bypasses carry `Unsafe` in their name.
3. A hostile peer can't cause unbounded memory, a hang or an unhandled exception type.
4. Secrets never reach logs or exception messages, and are zeroed after use.

## How this is built

Zorg.Ssh is written with the help of AI agents, mainly Claude Code from Anthropic. The maintainer sets the direction and makes the design decisions, and agents do most of the implementation. This note covers the whole project, so individual commits don't carry a co-author line.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Report security problems as [SECURITY.md](SECURITY.md) describes. Local scratch files go in `.tmp/`, which is gitignored.

## License

MIT. See [LICENSE](LICENSE). Package choices are recorded in [docs/dependencies.md](docs/dependencies.md).

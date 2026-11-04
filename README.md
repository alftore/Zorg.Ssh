# Zorg.Ssh

A modern, async-first SSH client library for .NET. Supports several SSH servers, follows the SSH RFCs, and uses secure crypto by default.

Status: research phase. No public API yet.

```csharp
// Planned shape (not implemented yet)
await using var session = await Zorg.Ssh.ConnectAsync("example.com", auth);
var output = await session.RunAsync("uname -a");
```

## Scratch space

Local scratch and temporary files go in `.tmp/`. That folder is gitignored.

## License

MIT. See [LICENSE](LICENSE).

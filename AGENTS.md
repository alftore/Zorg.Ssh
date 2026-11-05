# Using and working on Zorg.Ssh

## Writing code that uses Zorg.Ssh

- Start with `SshClient.ConnectAsync(new SshClientOptions { ... }, ct)`. `Host`, `UserName` and `HostKeyPolicy` are required, and `await using` closes the connection.
- There's no default host key policy. Use `HostKeyPolicy.KnownHostsFile()` or `.Fingerprint("SHA256:...")`. `AcceptAnyUnsafe()` is for tests against a machine you control, never for a fix to a connection error.
- Never catch `SshHostKeyException` to retry or to switch policy. It can mean an attack, so show it to a person.
- `Credentials = [...]` are tried in order: `SshCredential.FromPrivateKeyFile`, `.FromPrivateKey`, `.FromPassword`, `.FromKeyboardInteractive`.
- `client.ExecuteAsync(command, ct)` returns `SshCommandResult`. Check `ExitCode`, which is null after a signal. A non-zero exit doesn't throw.
- For large, binary or long-running output, use `StartProcessAsync`, and read `StandardOutput` and `StandardError` at the same time: they share a window. Dispose `StandardInput` to send EOF.
- The command line goes through the server's shell, so quote anything from a user.
- `await using SftpClient sftp = await client.OpenSftpAsync(ct)`. Use `UploadFileAsync` and `DownloadFileAsync` for files. `SftpFile` reads can be short, and its sync methods block.
- Names from a listing are untrusted. Check `SftpEntry.IsSafeName`, and pass `maxTotalBytes` to `DownloadDirectoryAsync`.
- Catch `SshException` and its subtypes. A connection that has failed stays failed: connect again.
- Nothing times out except `ConnectTimeout`, so pass a `CancellationToken`.
- For SFTP on a server, call `SftpServer.ServeAsync` from the `SessionHandler`, with `SftpServerOptions.RootDirectory`.
- `SshServer.StartAsync` needs a host key, a `PasswordHandler` or `PublicKeyHandler`, and a `SessionHandler`. Load the key with `SshHostKey.Load`, because a generated one can't be saved.
- These don't exist, so don't call them: SCP, compression, port forwarding, an agent, certificates, `~/.ssh/config`. `src/Zorg.Ssh/PublicAPI.Unshipped.txt` is the full API.
- It's pre-release and unreviewed. `docs/` has the details, and `docs/troubleshooting.md` covers each exception.

## Working on the repo

```bash
dotnet build Zorg.Ssh.slnx -nologo -v q
```

```bash
dotnet test --solution Zorg.Ssh.slnx --no-build
```

- `CONTRIBUTING.md` has the conventions. The build fails on any warning.
- Commits are signed through `commit.gpgsign`. Never bypass it. If signing fails, stop and tell the maintainer.
- Commit messages and pull requests have no `Co-Authored-By` or "Generated with" lines. The README states that agents help build the library.
- `.tmp/design/` holds the agreed design, where it exists on your machine. `01-implementation-plan.md` wins over older notes.
- Before adding a package, read `docs/dependencies.md`, check the licence in the `.nuspec`, and add a row in the same change.
- Read other SSH libraries for ideas, but don't copy their code.

## The four guarantees

Each has tests. A change that weakens one needs a design decision, not a test edit.

1. **No message is acted on in a state that doesn't allow it.** `Transport/MessagePolicy` is the single table. Default is deny.
2. **Nothing proceeds on an unverified host key or unauthenticated user.** Insecure bypasses carry `Unsafe` in their name.
3. **A hostile peer can't cause unbounded memory, a hang or an unhandled exception type.** Every buffer, queue and count has a limit, and every wait has cancellation. Peer-caused failures are `SshException` types only.
4. **Secrets never reach logs or exception messages, and are zeroed after use.**

Published SSH advisories each get a named regression test. Keep them when refactoring.

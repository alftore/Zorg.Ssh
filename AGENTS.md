# Working on Zorg.Ssh

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

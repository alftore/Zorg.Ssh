# Documentation

Zorg.Ssh is an async SSH client and server library for .NET 10. It has had internal reviews and tests, but no external security audit. Read [security.md](security.md) before you depend on it.

- [Client](client.md): connecting, credentials, host key policies, forwarding, commands, processes and shells.
- [SFTP](sftp.md): file transfer and file management over SFTP.
- [Server](server.md): running an SSH server in your own process, and where not to run it.
- [Security](security.md): the four guarantees, defaults, algorithms, what's out of scope and what's unverified.
- [Troubleshooting](troubleshooting.md): each exception, and what to do about it.
- [Benchmarks](benchmarks.md): measured results against SSH.NET and Tmds.Ssh, and their limits.
- [Dependencies](dependencies.md): every third-party package, and why it's there.
- [.NET versions](dotnet-versions.md): what each .NET release means for the library, and what to check at the next one.

## Known limits

These pages say what doesn't work, or works differently than you might expect:

- [Out of scope](security.md#out-of-scope): what isn't implemented, such as SCP, compression and agent forwarding.
- [Unverified](security.md#unverified): what hasn't been tested, such as some platforms, servers and long-running connections.
- [Where to run the server](server.md#where-to-run-it): not on the public internet, and not in front of users you don't trust.
- [SFTP limits](sftp.md#telling-the-librarys-limits-from-the-servers-answers): telling a refusal by the library from the server's answer.
- [Defaults](security.md#defaults) and [server limits](server.md#limits): the sizes, counts and timeouts that bound each connection.
- [Known issues](troubleshooting.md#known-issues): occasional delays over loopback on Windows.

## The samples

Every C# block in these pages, and in the README, is a region of the `samples/Zorg.Ssh.Examples` project. Each region sits between a `// doc:name` line and a `// end-doc` line. The project compiles with the solution, and its build fails if a block in a document differs from its region, or if a region is no longer used.

Run the project with no arguments to see a client talk to a server in the same process. Pass `--run <host> <port> <user> <password>` to run most of the client and SFTP samples against a real server. That mode accepts any host key and writes files in the server account's home directory and the current directory, so use a throwaway server.

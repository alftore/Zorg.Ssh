# Documentation

Zorg.Ssh is an async SSH client and server library for .NET 10. It's pre-release and hasn't had an external security review. Read [security.md](security.md) before you depend on it.

| Page | What it covers |
|---|---|
| [client.md](client.md) | Connecting, credentials, host key policies, commands, processes and shells |
| [sftp.md](sftp.md) | File transfer and file management over SFTP |
| [server.md](server.md) | Running an SSH server in your own process |
| [security.md](security.md) | The four guarantees, defaults, algorithms, what's out of scope, what's unverified |
| [troubleshooting.md](troubleshooting.md) | Each exception, and what to do about it |
| [benchmarks.md](benchmarks.md) | Measured results against SSH.NET and Tmds.Ssh, and their limits |
| [dependencies.md](dependencies.md) | Every third-party package, and why it's there |

## The samples

Every C# block in these pages, and in the README, is a region of the `samples/Zorg.Ssh.Examples` project. Each region sits between a `// doc:name` line and a `// end-doc` line. The project compiles with the solution, and its build fails if a block in a document differs from its region, or if a region is no longer used.

Run the project with no arguments to see a client talk to a server in the same process. Pass `--run <host> <port> <user> <password>` to run most of the client and SFTP samples against a real server. That mode accepts any host key and writes files in the server account's home directory and the current directory, so use a throwaway server.

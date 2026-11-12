# Zorg.Ssh

An async SSH client and server library for .NET 10, with SFTP, written in C# only. It also runs on .NET 11, where the same tests run on every change.

Status: early, version 0.1. The public API can still change before 1.0. It has had internal reviews, fuzzing and interop tests against real OpenSSH and Dropbear, but no external security audit. The repository's `docs/security.md` lists what has and hasn't been checked.

**Don't put the server on the public internet, or in front of users you don't trust.**

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

No SCP, compression or agent forwarding. See the [repository](https://github.com/alftore/Zorg.Ssh) for documentation, the security notes, the changelog and benchmarks. Report vulnerabilities privately, as its `SECURITY.md` describes.

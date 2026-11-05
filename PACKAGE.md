# Zorg.Ssh

An async SSH client and server library for .NET 10, with an SFTP client, written in C# only.

**Pre-release. It hasn't had an external security review, so don't use it in production.** The public API can still change.

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

See the [repository](https://github.com/alftore/Zorg.Ssh) for documentation, security notes and benchmarks.

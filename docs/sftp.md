# SFTP

Zorg.Ssh speaks SFTP version 3, the version OpenSSH uses. A session runs on its own channel, and several can share one `SshClient`. Calls on one session can run at the same time.

```csharp
SftpClient sftp = await client.OpenSftpAsync(cancellationToken);
string home = await sftp.GetFullPathAsync(".", cancellationToken);
```

Dispose the session when you've finished. That closes its channel and leaves the `SshClient` connected. If the server refuses the subsystem, `OpenSftpAsync` throws `SshException`, and SFTP may not be enabled there.

Paths are sent as you write them. With OpenSSH, a relative path starts from the home directory, as in these samples.

## Transferring files

`UploadFileAsync` and `DownloadFileAsync` work on any stream, and keep many requests in flight.

```csharp
if (!await sftp.ExistsAsync("reports", cancellationToken))
{
    await sftp.CreateDirectoryAsync("reports", cancellationToken);
}

await using (FileStream source = File.OpenRead("report.pdf"))
{
    await sftp.UploadFileAsync(source, "reports/report.pdf", cancellationToken);
}

await using (FileStream destination = File.Create("copy.pdf"))
{
    await sftp.DownloadFileAsync("reports/report.pdf", destination, cancellationToken);
}
```

- An upload creates the file, or replaces what it holds. It's finished when the server has confirmed every write and closed the file, because some file systems only report failure on close.
- Your stream is left open.
- Cancelling an upload can leave an incomplete file behind. To replace a file safely, upload to a temporary name, then use `RenameAsync` with `overwrite: true`.
- `DownloadFileAsync` has no size limit. To bound a transfer from a server you don't trust, cancel it, or count the bytes in the stream you pass.
- There's no resume and no recursive upload.

For small files:

```csharp
await sftp.WriteAllBytesAsync("reports/settings.json", "{}"u8.ToArray(), cancellationToken);
byte[] settings = await sftp.ReadAllBytesAsync("reports/settings.json", cancellationToken);

// ReadAllBytesAsync refuses anything over this limit. The default is 256 MiB.
sftp.MaxReadAllBytes = 1024L * 1024 * 1024;
```

## Listing directories

`ListDirectoryAsync` reads the directory as you enumerate it.

```csharp
await foreach (SftpEntry entry in sftp.ListDirectoryAsync("reports", cancellationToken))
{
    string kind = entry.Attributes.IsDirectory ? "dir" : "file";
    Console.WriteLine($"{kind} {entry.Attributes.Size} {entry.Attributes.ModifiedTime:u} {entry.Name}");

    if (!entry.IsSafeName)
    {
        Console.WriteLine("Don't use that name as a local path.");
    }
}
```

Names come back exactly as the server sent them, including `.` and `..`, and they can be hostile. Check `IsSafeName` before you build a local path from one. A listing that passes `MaxDirectoryEntries`, by default 1,000,000, fails with `SftpException`.

## Downloading a tree

```csharp
await sftp.DownloadDirectoryAsync("reports", "local-reports", maxTotalBytes: 10L * 1024 * 1024 * 1024, cancellationToken);
```

`DownloadDirectoryAsync` treats the server as hostile:

- Regular files and directories are copied. Symbolic links and special files are skipped.
- `.` and `..` are never used. A name holding a slash, a backslash or NUL, or anything this machine would resolve to something other than a direct child, stops the download with `SftpUnsafeNameException` before that name touches the disk.
- Existing files are never overwritten and existing links are never followed. A second download into the same directory therefore fails with `SftpUnsafeNameException`: clear the destination first.
- `maxTotalBytes` bounds the bytes across all files, and `MaxDirectoryEntries` bounds the entries across the tree. It stops at 64 levels of nesting.
- If it fails or you cancel, the files already written stay.

Set `maxTotalBytes` for any server you don't fully trust. The default is no limit.

## Files as streams

`OpenAsync` returns an `SftpFile`, a `Stream` with the same `FileMode` and `FileAccess` meanings as `FileStream`.

```csharp
await using SftpFile file = await sftp.OpenAsync("reports/log.txt", FileMode.OpenOrCreate, FileAccess.ReadWrite, cancellationToken);

file.Position = await file.GetLengthAsync(cancellationToken);
await file.WriteAsync("one more line\n"u8.ToArray(), cancellationToken);
await file.SyncAsync(cancellationToken);

file.Position = 0;
byte[] start = new byte[1024];
int read = await file.ReadAsync(start, cancellationToken); // Can be less than you asked for.
```

- Use the async methods. The sync ones block a thread on the network, and so does `Length`, so prefer `GetLengthAsync`.
- Each read asks the server once. `CopyToAsync` keeps many reads in flight, so it's the fast way to read a lot.
- Each `WriteAsync` returns once the server has confirmed it. For bulk writes, `UploadFileAsync` is faster.
- One `SftpFile` isn't safe for use by several tasks at once.
- `SyncAsync` needs the `fsync@openssh.com` extension.

## Attributes

```csharp
SftpAttributes attributes = await sftp.GetAttributesAsync("reports/log.txt", cancellationToken: cancellationToken);
Console.WriteLine($"{attributes.Size} bytes, {attributes.Permissions}");

await sftp.SetAttributesAsync(
    "reports/log.txt",
    new SftpAttributes { Permissions = UnixFileMode.UserRead | UnixFileMode.UserWrite },
    cancellationToken);
```

A property is null if the server didn't send it, and `SetAttributesAsync` changes only the properties you set. Set `Uid` with `Gid`, and `ModifiedTime` with `AccessTime`, because the protocol sends them in pairs. Times have a resolution of one second.

`GetAttributesAsync` follows symbolic links unless you pass `followSymbolicLinks: false`.

## Managing files

```csharp
await sftp.RenameAsync("reports/log.txt", "reports/old.txt", overwrite: true, cancellationToken);
await sftp.CreateSymbolicLinkAsync("reports/latest", "old.txt", cancellationToken);
string target = await sftp.ReadLinkAsync("reports/latest", cancellationToken);

await sftp.DeleteFileAsync("reports/latest", cancellationToken);
await sftp.DeleteFileAsync("reports/old.txt", cancellationToken);
```

- `RenameAsync` with `overwrite: true` replaces the target atomically through `posix-rename@openssh.com`. A server without that extension can only rename to a free name.
- `CreateSymbolicLinkAsync` takes the link first, then the target. OpenSSH reverses the arguments on the wire compared with the draft, and Zorg.Ssh handles that.
- `DeleteDirectoryAsync` removes an empty directory. `CreateDirectoryAsync` needs the parent to exist.
- `ExistsAsync` counts a symbolic link as existing, even if its target is missing. It throws `SftpPermissionDeniedException` if the account can't look there, because the answer is then unknown.

## Server extensions

`ServerExtensions` lists what the server advertised.

```csharp
SftpFileSystemInfo disk = await sftp.GetFileSystemInfoAsync(".", cancellationToken);
Console.WriteLine($"{disk.AvailableBytes} bytes free");

await sftp.WriteAllBytesAsync("a.bin", new byte[16], cancellationToken);
await sftp.CreateHardLinkAsync("b.bin", "a.bin", cancellationToken);

if (sftp.ServerExtensions.ContainsKey("copy-data"))
{
    await sftp.CopyFileAsync("a.bin", "c.bin", overwrite: true, cancellationToken);
}
```

| Method | Extension |
|---|---|
| `GetFileSystemInfoAsync` | `statvfs@openssh.com` |
| `CreateHardLinkAsync` | `hardlink@openssh.com` |
| `CopyFileAsync` | `copy-data`. The bytes stay on the server. |
| `SftpFile.SyncAsync` | `fsync@openssh.com` |

Without the extension, these fail with `SftpException` and `SftpStatusCode.OperationUnsupported`. Zorg.Ssh also respects `limits@openssh.com` when a server sends it.

## Errors

```csharp
try
{
    await sftp.ReadAllBytesAsync("no-such-file", cancellationToken);
}
catch (SftpFileNotFoundException ex)
{
    Console.WriteLine($"Nothing at {ex.Path}");
}
catch (SftpPermissionDeniedException ex)
{
    Console.WriteLine($"No access to {ex.Path}");
}
catch (SftpException ex) when (ex.StatusCode == SftpStatusCode.OperationUnsupported)
{
    Console.WriteLine("This server can't do that.");
}
```

A refusal from the server is an `SftpException` and leaves the session usable. A malformed response, or one that matches no outstanding request, ends the session with `SshProtocolException`, and later calls fail with `SshConnectionException`. See [troubleshooting.md](troubleshooting.md).

SFTP version 3 has few status codes. Most servers report an existing directory or target as `SftpStatusCode.Failure`, so the code alone won't tell you why.

SCP isn't supported. See [security.md](security.md#out-of-scope).

# SFTP

Zorg.Ssh speaks SFTP version 3, the version OpenSSH uses. A session runs on its own channel, and several can share one `SshClient`. Calls on one session can run at the same time.

```csharp
await using SftpClient sftp = await client.OpenSftpAsync(cancellationToken);
string home = await sftp.GetFullPathAsync(".", cancellationToken);
```

Disposing the session closes its channel and leaves the `SshClient` connected. `OpenSftpAsync` also takes `SftpClientOptions`, which holds the session's limits: `MaxReadAllBytes` and `MaxDirectoryEntries`. If the server refuses the subsystem, `OpenSftpAsync` throws `SshException`, and SFTP may not be enabled there.

Paths are sent as you write them. With OpenSSH, a relative path starts from the home directory, as in these samples.

## Transferring files

`UploadFileAsync` and `DownloadFileAsync` work on any stream, and keep many requests in flight.

```csharp
await sftp.CreateDirectoryAsync("reports", recursive: true, cancellationToken);

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

### Progress

Each transfer method has an overload that takes `SftpTransferOptions`. Set `Progress` to see how far it has got.

```csharp
SftpTransferOptions options = new()
{
    Progress = new Progress<SftpTransferProgress>(p =>
    {
        string of = p.TotalBytes is long total ? $" of {total}" : string.Empty;
        Console.WriteLine($"{p.RemotePath}: {p.BytesTransferred}{of} bytes, {p.FilesCompleted} files done");
    }),
};

await using (FileStream source = File.OpenRead("report.pdf"))
{
    await sftp.UploadFileAsync(source, "reports/report.pdf", options, cancellationToken);
}

await sftp.DownloadDirectoryAsync("reports", "progress-reports", maxTotalBytes: 10L * 1024 * 1024 * 1024, options, cancellationToken);
```

- A call reports when its first file starts, with 0 bytes, and when it finishes, with the final counts. In between, a report goes out at most every 100 ms, so a fast transfer doesn't flood your handler.
- `TotalBytes` is the file's size when it's known: the rest of a stream that can seek, for an upload, and the size the server gives for a download. It's null otherwise. The server's size is a claim, and a file that changes during the transfer can end above or below it.
- An upload counts bytes as they're sent. Its last report comes after the server has confirmed every write and closed the file.
- With progress on, `DownloadFileAsync` asks the server for the size first, which costs one round trip.
- `DownloadDirectoryAsync` reports each file with its `LocalPath` and its size from the listing. `FilesCompleted` and `OverallBytesTransferred` count across the tree. There's no total for the tree, because it's listed as it's copied. A tree with no regular files reports nothing.
- `Report` runs on the transfer's own flow, and the transfer waits for it. `Progress<T>` posts each report to the context it was made on, such as a UI thread, so its handler can run after the method returns, but no report is made after it.
- If your handler throws, the transfer stops, the remote file is closed, and your exception comes out of the transfer method unchanged. The session stays usable.

For small files:

```csharp
await sftp.WriteAllBytesAsync("reports/settings.json", "{}"u8.ToArray(), cancellationToken);
byte[] settings = await sftp.ReadAllBytesAsync("reports/settings.json", cancellationToken);

// ReadAllBytesAsync refuses anything over this limit. The default is 256 MiB.
await using SftpClient large = await client.OpenSftpAsync(new SftpClientOptions { MaxReadAllBytes = 1024L * 1024 * 1024 }, cancellationToken);
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

Names come back exactly as the server sent them, including `.` and `..`, and they can be hostile. Check `IsSafeName` before you build a local path from one. A listing that passes `SftpClientOptions.MaxDirectoryEntries`, by default 1,000,000, fails with `SftpException`. That failure has `IsLocalLimit` set: see below.

What a listing gives you:

- OpenSSH includes `.` and `..` as entries. Skip them (`IsSafeName` is false for both), and don't count them as files.
- The order is the server's. OpenSSH sends the directory order of its file system, which isn't sorted and can change. Sort the entries yourself if the order matters.
- Each entry carries the attributes from the listing: `Size`, the type (`IsRegularFile`, `IsDirectory`, `IsSymbolicLink`), permissions and `ModifiedTime`. You don't need a `GetAttributesAsync` call per file. `ModifiedTime` has a resolution of one second.
- A symbolic link is reported as a link, with the link's own attributes, not those of its target. A link to a directory has `IsSymbolicLink` true and `IsDirectory` false.
- The `longname` text that servers send for `ls -l` is ignored. Use the attributes.
- Anything that isn't a regular file or a directory, such as a FIFO or a device, is listed too. Check `Attributes.IsRegularFile` before you open it: see [Special files](#special-files).

### Name encodings

SFTP version 3 doesn't say how a name is encoded. OpenSSH sends the raw bytes the file system holds, so a name made on a Latin-1 system isn't valid UTF-8.

- A name that is valid UTF-8 is decoded as it is. Zorg.Ssh doesn't normalise it, so `Å` as one character (NFC) and `A` plus a combining ring (NFD) are two different files that look the same. Compare and build paths with the string you got from the listing, not one you typed.
- A name that isn't valid UTF-8 is shown with U+FFFD in place of each bad byte, and `HasValidName` is false. `IsSafeName` is false too. Such a name can't be used as a path, because it would encode to different bytes, and two different bad names can show the same text. Skip them, or tell a person.
- A name that holds a real U+FFFD character is valid, and has `HasValidName` true.
- `DownloadDirectoryAsync` treats a name with `HasValidName` false like any other unsafe name: it stops with `SftpUnsafeNameException`.
- A path you pass in is encoded as UTF-8. A string with an unpaired surrogate can't be, so it throws `ArgumentException` instead of being sent as U+FFFD.

## Special files

Opening or downloading a FIFO (a named pipe) or a device can block inside the server's `open()`, because the open waits for a writer that never comes. Cancelling the token returns your call, but it doesn't stop the server. OpenSSH's `sftp-server` handles the requests of a session one at a time, so the blocked open holds up everything behind it, and that session can stay unresponsive.

- Check `Attributes.IsRegularFile` from the listing before you open or download a path. `DownloadDirectoryAsync` already skips everything that isn't a regular file or a directory.
- After you cancel such an open, don't reuse the session. Dispose it and call `OpenSftpAsync` again. The `SshClient` can stay connected.

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

`maxTotalBytes` is required, so every download says how much it will take. Pass `long.MaxValue` only for a server you fully trust.

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
SftpAttributes attributes = await sftp.GetAttributesAsync("reports/log.txt", cancellationToken);
Console.WriteLine($"{attributes.Size} bytes, {attributes.Permissions}");

await sftp.SetAttributesAsync(
    "reports/log.txt",
    new SftpAttributes { Permissions = UnixFileMode.UserRead | UnixFileMode.UserWrite },
    cancellationToken);
```

A property is null if the server didn't send it, and `SetAttributesAsync` changes only the properties you set. Set `Uid` with `Gid`, and `ModifiedTime` with `AccessTime`, because the protocol sends them in pairs. Times have a resolution of one second.

`GetAttributesAsync` follows symbolic links. `GetLinkAttributesAsync` reports on a link itself.

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
- `DeleteDirectoryAsync` removes an empty directory. `CreateDirectoryAsync` needs the parent to exist, unless you pass `recursive: true`.
- `CreateDirectoryAsync(path, recursive: true)` creates the missing parents too. It succeeds if the directory is already there, and it throws `SftpException` if the path or one of its parents exists and isn't a directory. A symbolic link to a directory counts as one. If another client makes the same directories at the same moment, a create that fails is checked again, and it succeeds if a directory is now there. Directories already made stay if you cancel or a later one fails.
- SFTP version 3 has no "already exists" status. A `RenameAsync` with `overwrite: false` that finds the target taken fails with `SftpStatusCode.Failure`, and so does a `CreateDirectoryAsync` on an existing path. To tell why, ask afterwards with `ExistsAsync` or `GetAttributesAsync`. `CreateDirectoryAsync(path, recursive: true)` does this for you.
- `ExistsAsync` counts a symbolic link as existing, even if its target is missing. It throws `SftpPermissionDeniedException` if the account can't look there, because the answer is then unknown.

### Claiming a file by renaming it

When several clients take files from one folder, each can claim a file by renaming it to a name of its own. The file leaves the folder, so only one client's rename of it succeeds. The others fail, with `SftpFileNotFoundException` or `SftpStatusCode.Failure` depending on the server and the timing. Use `overwrite: false`, so that a claim can never replace a file that is already at the target.

```csharp
try
{
    await sftp.RenameAsync("inbox/0001.csv", "work/0001.csv.7f3a", overwrite: false, cancellationToken);
    // This client owns the file now.
}
catch (SftpException ex) when (ex.StatusCode is SftpStatusCode.Failure or SftpStatusCode.NoSuchFile)
{
    // Another client took it first, or it is gone. Look at the next file.
}
```

Give each client a target name that only it would pick, such as one with a unique suffix, so that a failure can't be someone else's claim. On OpenSSH the rename of a regular file is a hard link followed by removing the old name, and the link is undone if the removal fails, so two clients can't both win. Another server may check and rename in two steps, so test the one you use before you rely on this.

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
| `CopyFileAsync` | `copy-data`. The bytes stay on the server. Without `overwrite`, the destination must be new. A server that ignores that and opens an existing file gets a size check first: a file that isn't empty is left alone and the call throws. |
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

## Telling the library's limits from the server's answers

`SftpException` covers both a status the server sent and a limit Zorg.Ssh applies on its own side. `SftpException.IsLocalLimit` separates them. It is true for a listing or tree past `MaxDirectoryEntries`, a file past `MaxReadAllBytes` or a directory download past `maxTotalBytes`, a tree nested more than 64 levels, and an unsafe name (`SftpUnsafeNameException`). In those cases `StatusCode` is `Failure` as a stand-in, and the same call on the same server fails the same way until you raise the limit. It is false for anything the server said and for local disk errors.

```csharp
try
{
    await sftp.DownloadDirectoryAsync("/srv/reports", "reports", maxTotalBytes: 1L << 30, cancellationToken);
}
catch (SftpException ex) when (ex.IsLocalLimit)
{
    Console.WriteLine($"Stopped here, not by the server: {ex.Message}");
}
```

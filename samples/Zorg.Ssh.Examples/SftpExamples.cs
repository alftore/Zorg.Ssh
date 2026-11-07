using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Zorg.Ssh.Sftp;

namespace Zorg.Ssh.Examples;

/// <summary>The samples in docs/sftp.md. Paths are relative, so OpenSSH resolves them from the home directory.</summary>
internal static class SftpExamples
{
    public static async Task Open(SshClient client, CancellationToken cancellationToken)
    {
        // doc:sftp-open
        await using SftpClient sftp = await client.OpenSftpAsync(cancellationToken);
        string home = await sftp.GetFullPathAsync(".", cancellationToken);
        // end-doc
        Console.WriteLine(home);
    }

    public static async Task Transfer(SftpClient sftp, CancellationToken cancellationToken)
    {
        // doc:sftp-transfer
        await sftp.CreateDirectoryAsync("reports", recursive: true, cancellationToken);

        await using (FileStream source = File.OpenRead("report.pdf"))
        {
            await sftp.UploadFileAsync(source, "reports/report.pdf", cancellationToken);
        }

        await using (FileStream destination = File.Create("copy.pdf"))
        {
            await sftp.DownloadFileAsync("reports/report.pdf", destination, cancellationToken);
        }
        // end-doc
    }

    public static async Task Progress(SftpClient sftp, CancellationToken cancellationToken)
    {
        // doc:sftp-progress
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
        // end-doc
    }

    public static async Task ClaimByRename(SftpClient sftp, CancellationToken cancellationToken)
    {
        // doc:sftp-claim
        try
        {
            await sftp.RenameAsync("inbox/0001.csv", "work/0001.csv.7f3a", overwrite: false, cancellationToken);
            // This client owns the file now.
        }
        catch (SftpException ex) when (ex.StatusCode is SftpStatusCode.Failure or SftpStatusCode.NoSuchFile)
        {
            // Another client took it first, or it is gone. Look at the next file.
        }
        // end-doc
    }

    public static async Task SmallFiles(SshClient client, SftpClient sftp, CancellationToken cancellationToken)
    {
        // doc:sftp-small-files
        await sftp.WriteAllBytesAsync("reports/settings.json", "{}"u8.ToArray(), cancellationToken);
        byte[] settings = await sftp.ReadAllBytesAsync("reports/settings.json", cancellationToken);

        // ReadAllBytesAsync refuses anything over this limit. The default is 256 MiB.
        await using SftpClient large = await client.OpenSftpAsync(new SftpClientOptions { MaxReadAllBytes = 1024L * 1024 * 1024 }, cancellationToken);
        // end-doc
        Console.WriteLine(settings.Length);
    }

    public static async Task List(SftpClient sftp, CancellationToken cancellationToken)
    {
        // doc:sftp-list
        await foreach (SftpEntry entry in sftp.ListDirectoryAsync("reports", cancellationToken))
        {
            string kind = entry.Attributes.IsDirectory ? "dir" : "file";
            Console.WriteLine($"{kind} {entry.Attributes.Size} {entry.Attributes.ModifiedTime:u} {entry.Name}");

            if (!entry.IsSafeName)
            {
                Console.WriteLine("Don't use that name as a local path.");
            }
        }
        // end-doc
    }

    public static async Task Tree(SftpClient sftp, CancellationToken cancellationToken)
    {
        // doc:sftp-tree
        await sftp.DownloadDirectoryAsync("reports", "local-reports", maxTotalBytes: 10L * 1024 * 1024 * 1024, cancellationToken);
        // end-doc
    }

    public static async Task Streams(SftpClient sftp, CancellationToken cancellationToken)
    {
        // doc:sftp-stream
        await using SftpFile file = await sftp.OpenAsync("reports/log.txt", FileMode.OpenOrCreate, FileAccess.ReadWrite, cancellationToken);

        file.Position = await file.GetLengthAsync(cancellationToken);
        await file.WriteAsync("one more line\n"u8.ToArray(), cancellationToken);
        await file.SyncAsync(cancellationToken);

        file.Position = 0;
        byte[] start = new byte[1024];
        int read = await file.ReadAsync(start, cancellationToken); // Can be less than you asked for.
        // end-doc
        Console.WriteLine(read);
    }

    public static async Task Attributes(SftpClient sftp, CancellationToken cancellationToken)
    {
        // doc:sftp-attributes
        SftpAttributes attributes = await sftp.GetAttributesAsync("reports/log.txt", cancellationToken);
        Console.WriteLine($"{attributes.Size} bytes, {attributes.Permissions}");

        await sftp.SetAttributesAsync(
            "reports/log.txt",
            new SftpAttributes { Permissions = UnixFileMode.UserRead | UnixFileMode.UserWrite },
            cancellationToken);
        // end-doc
    }

    public static async Task Manage(SftpClient sftp, CancellationToken cancellationToken)
    {
        // doc:sftp-manage
        await sftp.RenameAsync("reports/log.txt", "reports/old.txt", overwrite: true, cancellationToken);
        await sftp.CreateSymbolicLinkAsync("reports/latest", "old.txt", cancellationToken);
        string target = await sftp.ReadLinkAsync("reports/latest", cancellationToken);

        await sftp.DeleteFileAsync("reports/latest", cancellationToken);
        await sftp.DeleteFileAsync("reports/old.txt", cancellationToken);
        // end-doc
        Console.WriteLine(target);
    }

    public static async Task Extensions(SftpClient sftp, CancellationToken cancellationToken)
    {
        // doc:sftp-extensions
        SftpFileSystemInfo disk = await sftp.GetFileSystemInfoAsync(".", cancellationToken);
        Console.WriteLine($"{disk.AvailableBytes} bytes free");

        await sftp.WriteAllBytesAsync("a.bin", new byte[16], cancellationToken);
        await sftp.CreateHardLinkAsync("b.bin", "a.bin", cancellationToken);

        if (sftp.ServerExtensions.ContainsKey("copy-data"))
        {
            await sftp.CopyFileAsync("a.bin", "c.bin", overwrite: true, cancellationToken);
        }
        // end-doc
    }

    public static async Task Errors(SftpClient sftp, CancellationToken cancellationToken)
    {
        // doc:sftp-errors
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
        // end-doc
    }
}

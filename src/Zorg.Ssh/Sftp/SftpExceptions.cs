using System;

namespace Zorg.Ssh.Sftp;

/// <summary>The status codes of SFTP version 3. A server may send others, which keep their number.</summary>
/// <example>
/// <code>
/// catch (SftpException ex) when (ex.StatusCode == SftpStatusCode.OperationUnsupported)
/// {
///     Console.WriteLine("This server can't do that.");
/// }
/// </code>
/// </example>
public enum SftpStatusCode
{
    /// <summary>The operation worked.</summary>
    /// <example>
    /// <code>
    /// bool matches = ex.StatusCode == SftpStatusCode.Ok;
    /// </code>
    /// </example>
    Ok = 0,

    /// <summary>The end of a file or directory was reached.</summary>
    /// <example>
    /// <code>
    /// bool matches = ex.StatusCode == SftpStatusCode.EndOfFile;
    /// </code>
    /// </example>
    EndOfFile = 1,

    /// <summary>The file or directory doesn't exist.</summary>
    /// <example>
    /// <code>
    /// bool matches = ex.StatusCode == SftpStatusCode.NoSuchFile;
    /// </code>
    /// </example>
    NoSuchFile = 2,

    /// <summary>The account isn't allowed to do this.</summary>
    /// <example>
    /// <code>
    /// bool matches = ex.StatusCode == SftpStatusCode.PermissionDenied;
    /// </code>
    /// </example>
    PermissionDenied = 3,

    /// <summary>The server failed, and version 3 has no more specific code. The target may already exist, for example.</summary>
    /// <example>
    /// <code>
    /// bool matches = ex.StatusCode == SftpStatusCode.Failure;
    /// </code>
    /// </example>
    Failure = 4,

    /// <summary>The server couldn't understand the request.</summary>
    /// <example>
    /// <code>
    /// bool matches = ex.StatusCode == SftpStatusCode.BadMessage;
    /// </code>
    /// </example>
    BadMessage = 5,

    /// <summary>There is no connection. Only a client should report this.</summary>
    /// <example>
    /// <code>
    /// bool matches = ex.StatusCode == SftpStatusCode.NoConnection;
    /// </code>
    /// </example>
    NoConnection = 6,

    /// <summary>The connection was lost. Only a client should report this.</summary>
    /// <example>
    /// <code>
    /// bool matches = ex.StatusCode == SftpStatusCode.ConnectionLost;
    /// </code>
    /// </example>
    ConnectionLost = 7,

    /// <summary>The server doesn't support this operation.</summary>
    /// <example>
    /// <code>
    /// bool matches = ex.StatusCode == SftpStatusCode.OperationUnsupported;
    /// </code>
    /// </example>
    OperationUnsupported = 8,
}

/// <summary>The server refused an SFTP request. The session is still usable, unless the failure says otherwise.</summary>
/// <example>
/// <code>
/// try
/// {
///     await sftp.CreateDirectoryAsync("/srv/data", cancellationToken);
/// }
/// catch (SftpException ex)
/// {
///     Console.WriteLine($"{ex.StatusCode}: {ex.Message}");
/// }
/// </code>
/// </example>
public class SftpException : SshException
{
    /// <summary>Creates an exception with a default message.</summary>
    public SftpException()
        : base("The SFTP request failed. Check the path and the account's permissions on the server.")
    {
        StatusCode = SftpStatusCode.Failure;
    }

    /// <summary>Creates an exception with a message.</summary>
    /// <param name="message">What failed and what to do next.</param>
    public SftpException(string message)
        : base(message)
    {
        StatusCode = SftpStatusCode.Failure;
    }

    /// <summary>Creates an exception with a message and a cause.</summary>
    /// <param name="message">What failed and what to do next.</param>
    /// <param name="innerException">The underlying failure.</param>
    public SftpException(string message, Exception innerException)
        : base(message, innerException)
    {
        StatusCode = SftpStatusCode.Failure;
    }

    /// <summary>Creates an exception from a server's status.</summary>
    /// <param name="message">What failed and what to do next.</param>
    /// <param name="statusCode">The status the server sent.</param>
    /// <param name="path">The remote path involved, if any.</param>
    public SftpException(string message, SftpStatusCode statusCode, string? path)
        : base(message)
    {
        StatusCode = statusCode;
        Path = path;
    }

    /// <summary>Gets the status the server sent.</summary>
    /// <example>
    /// <code>
    /// if (ex.StatusCode == SftpStatusCode.Failure)
    /// {
    ///     Console.WriteLine("The target may already exist.");
    /// }
    /// </code>
    /// </example>
    public SftpStatusCode StatusCode { get; }

    /// <summary>Gets the remote path involved, if there was one.</summary>
    /// <example>
    /// <code>
    /// Console.WriteLine($"Failed on {ex.Path}");
    /// </code>
    /// </example>
    public string? Path { get; }

    /// <summary>
    /// Gets a value saying whether Zorg.Ssh refused this itself, on its own side, and the server did not.
    /// It's true for the limits and checks the library applies to what a server sends: more entries than
    /// <see cref="SftpClientOptions.MaxDirectoryEntries"/> in a listing or a tree, a file over
    /// <see cref="SftpClientOptions.MaxReadAllBytes"/> or over the <c>maxTotalBytes</c> of a directory download, a
    /// tree nested too deep, and a name that isn't safe locally (<see cref="SftpUnsafeNameException"/>). Then
    /// <see cref="StatusCode"/> is a stand-in (<see cref="SftpStatusCode.Failure"/>), not something the server sent,
    /// and retrying the same call on the same server gives the same answer until the limit is raised or the server changes.
    /// It's false for every status a server sent, and for failures of the local disk, which carry an
    /// <see cref="Exception.InnerException"/>.
    /// </summary>
    /// <example>
    /// <code>
    /// catch (SftpException ex) when (ex.IsLocalLimit)
    /// {
    ///     Console.WriteLine($"Zorg.Ssh stopped this, not the server: {ex.Message}");
    /// }
    /// </code>
    /// </example>
    public bool IsLocalLimit { get; internal init; }
}

/// <summary>The remote file or directory doesn't exist.</summary>
/// <example>
/// <code>
/// try
/// {
///     byte[] data = await sftp.ReadAllBytesAsync("/etc/app.conf", cancellationToken);
/// }
/// catch (SftpFileNotFoundException)
/// {
///     Console.WriteLine("Using the default configuration.");
/// }
/// </code>
/// </example>
public sealed class SftpFileNotFoundException : SftpException
{
    /// <summary>Creates an exception with a default message.</summary>
    /// <example>
    /// <code>
    /// throw new SftpFileNotFoundException();
    /// </code>
    /// </example>
    public SftpFileNotFoundException()
        : base("The remote file or directory doesn't exist. Check the path.", SftpStatusCode.NoSuchFile, null)
    {
    }

    /// <summary>Creates an exception with a message.</summary>
    /// <param name="message">What failed and what to do next.</param>
    /// <example>
    /// <code>
    /// throw new SftpFileNotFoundException("What failed, and what to do next.");
    /// </code>
    /// </example>
    public SftpFileNotFoundException(string message)
        : base(message, SftpStatusCode.NoSuchFile, null)
    {
    }

    /// <summary>Creates an exception with a message and a cause.</summary>
    /// <param name="message">What failed and what to do next.</param>
    /// <param name="innerException">The underlying failure.</param>
    /// <example>
    /// <code>
    /// throw new SftpFileNotFoundException("What failed, and what to do next.", ioException);
    /// </code>
    /// </example>
    public SftpFileNotFoundException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Creates an exception naming the path.</summary>
    /// <param name="message">What failed and what to do next.</param>
    /// <param name="path">The remote path.</param>
    /// <example>
    /// <code>
    /// throw new SftpFileNotFoundException("What failed, and what to do next.", "/srv/data");
    /// </code>
    /// </example>
    public SftpFileNotFoundException(string message, string? path)
        : base(message, SftpStatusCode.NoSuchFile, path)
    {
    }
}

/// <summary>The account isn't allowed to do this on the server.</summary>
/// <example>
/// <code>
/// catch (SftpPermissionDeniedException ex)
/// {
///     Console.WriteLine($"Ask the administrator for access to {ex.Path}.");
/// }
/// </code>
/// </example>
public sealed class SftpPermissionDeniedException : SftpException
{
    /// <summary>Creates an exception with a default message.</summary>
    /// <example>
    /// <code>
    /// throw new SftpPermissionDeniedException();
    /// </code>
    /// </example>
    public SftpPermissionDeniedException()
        : base("The server denied permission. Check the account's rights on the path.", SftpStatusCode.PermissionDenied, null)
    {
    }

    /// <summary>Creates an exception with a message.</summary>
    /// <param name="message">What failed and what to do next.</param>
    /// <example>
    /// <code>
    /// throw new SftpPermissionDeniedException("What failed, and what to do next.");
    /// </code>
    /// </example>
    public SftpPermissionDeniedException(string message)
        : base(message, SftpStatusCode.PermissionDenied, null)
    {
    }

    /// <summary>Creates an exception with a message and a cause.</summary>
    /// <param name="message">What failed and what to do next.</param>
    /// <param name="innerException">The underlying failure.</param>
    /// <example>
    /// <code>
    /// throw new SftpPermissionDeniedException("What failed, and what to do next.", ioException);
    /// </code>
    /// </example>
    public SftpPermissionDeniedException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Creates an exception naming the path.</summary>
    /// <param name="message">What failed and what to do next.</param>
    /// <param name="path">The remote path.</param>
    /// <example>
    /// <code>
    /// throw new SftpPermissionDeniedException("What failed, and what to do next.", "/srv/data");
    /// </code>
    /// </example>
    public SftpPermissionDeniedException(string message, string? path)
        : base(message, SftpStatusCode.PermissionDenied, path)
    {
    }
}

/// <summary>
/// A server sent a file name that isn't safe as a local path, during a recursive download. This can be an
/// attempt to write outside the destination, so the download stops at once and writes nothing for that name.
/// </summary>
/// <example>
/// <code>
/// catch (SftpUnsafeNameException ex)
/// {
///     logger.LogWarning("Don't trust this server: it sent the name {Name}", ex.EntryName);
/// }
/// </code>
/// </example>
public sealed class SftpUnsafeNameException : SftpException
{
    /// <summary>Creates an exception with a default message.</summary>
    /// <example>
    /// <code>
    /// throw new SftpUnsafeNameException();
    /// </code>
    /// </example>
    public SftpUnsafeNameException()
        : base("The server sent a file name that isn't safe to use locally. Don't trust this server's listing.")
    {
        IsLocalLimit = true;
    }

    /// <summary>Creates an exception with a message.</summary>
    /// <param name="message">What failed and what to do next.</param>
    /// <example>
    /// <code>
    /// throw new SftpUnsafeNameException("What failed, and what to do next.");
    /// </code>
    /// </example>
    public SftpUnsafeNameException(string message)
        : base(message)
    {
        IsLocalLimit = true;
    }

    /// <summary>Creates an exception with a message and a cause.</summary>
    /// <param name="message">What failed and what to do next.</param>
    /// <param name="innerException">The underlying failure.</param>
    /// <example>
    /// <code>
    /// throw new SftpUnsafeNameException("What failed, and what to do next.", ioException);
    /// </code>
    /// </example>
    public SftpUnsafeNameException(string message, Exception innerException)
        : base(message, innerException)
    {
        IsLocalLimit = true;
    }

    /// <summary>Creates an exception naming the entry.</summary>
    /// <param name="message">What failed and what to do next.</param>
    /// <param name="entryName">The name the server sent. It's untrusted.</param>
    /// <param name="path">The remote directory that held it.</param>
    /// <example>
    /// <code>
    /// throw new SftpUnsafeNameException("What failed, and what to do next.", "../evil", "/srv");
    /// </code>
    /// </example>
    public SftpUnsafeNameException(string message, string entryName, string? path)
        : base(message, SftpStatusCode.Failure, path)
    {
        IsLocalLimit = true;
        EntryName = entryName;
    }

    /// <summary>Gets the name the server sent. It's untrusted, and can hold control characters.</summary>
    /// <example>
    /// <code>
    /// logger.LogWarning("Rejected {Name}", ex.EntryName);
    /// </code>
    /// </example>
    public string? EntryName { get; }
}

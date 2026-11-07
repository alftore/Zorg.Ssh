using System;

namespace Zorg.Ssh;

/// <summary>
/// A private key file couldn't be loaded: it's malformed, it's in an unsupported format, or the passphrase is missing
/// or wrong. The message says which, and what to do next. It never holds key material or the passphrase.
/// </summary>
/// <example>
/// <code>
/// try
/// {
///     using var key = LoadKey(path, passphrase);
/// }
/// catch (SshKeyFileException ex)
/// {
///     logger.LogError("Can't use the key at {Path}: {Reason}", path, ex.Message);
/// }
/// </code>
/// </example>
public sealed class SshKeyFileException : SshException
{
    /// <summary>Creates an exception with a default message.</summary>
    public SshKeyFileException()
        : base("The private key file couldn't be loaded. Check that it's a complete, unmodified private key file.")
    {
    }

    /// <summary>Creates an exception with a message.</summary>
    /// <param name="message">What failed and what to do next. It must not hold key material or the passphrase.</param>
    public SshKeyFileException(string message)
        : base(message)
    {
    }

    /// <summary>Creates an exception with a message and a cause.</summary>
    /// <param name="message">What failed and what to do next. It must not hold key material or the passphrase.</param>
    /// <param name="innerException">The underlying failure.</param>
    public SshKeyFileException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

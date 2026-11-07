using System;

namespace Zorg.Ssh;

/// <summary>
/// A config file can't be used. It's unreadable or too large, a keyword this library handles has a bad value, or it
/// asks for something that needs the caller's say-so. The message gives the file and line where it can.
/// </summary>
/// <example>
/// <code>
/// catch (SshConfigException ex)
/// {
///     Console.Error.WriteLine(ex.Message);
/// }
/// </code>
/// </example>
public sealed class SshConfigException : SshException
{
    /// <summary>Creates an exception with a default message.</summary>
    public SshConfigException()
        : base("The SSH config file can't be used. Check it with: ssh -G <host>")
    {
    }

    /// <summary>Creates an exception with a message.</summary>
    /// <param name="message">What failed and what to do next.</param>
    public SshConfigException(string message)
        : base(message)
    {
    }

    /// <summary>Creates an exception with a message and a cause.</summary>
    /// <param name="message">What failed and what to do next.</param>
    /// <param name="innerException">The underlying failure.</param>
    public SshConfigException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

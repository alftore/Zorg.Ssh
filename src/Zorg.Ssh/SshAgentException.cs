using System;

namespace Zorg.Ssh;

/// <summary>
/// The ssh-agent couldn't be reached, or it did something wrong. A failed login reports this in its own message;
/// this type is what you see if you catch it around agent calls directly, and as the cause in logs.
/// </summary>
/// <example>
/// <code>
/// catch (SshAgentException ex)
/// {
///     logger.LogWarning("The agent failed: {Reason}", ex.Message);
/// }
/// </code>
/// </example>
public sealed class SshAgentException : SshException
{
    /// <summary>Creates an exception with a default message.</summary>
    public SshAgentException()
        : base("The ssh-agent failed. Check that it's running and that SSH_AUTH_SOCK points at it.")
    {
    }

    /// <summary>Creates an exception with a message.</summary>
    /// <param name="message">What failed and what to do next.</param>
    public SshAgentException(string message)
        : base(message)
    {
    }

    /// <summary>Creates an exception with a message and a cause.</summary>
    /// <param name="message">What failed and what to do next.</param>
    /// <param name="innerException">The underlying failure.</param>
    public SshAgentException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

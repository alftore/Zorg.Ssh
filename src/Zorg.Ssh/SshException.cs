using System;

namespace Zorg.Ssh;

/// <summary>The base type of every failure this library reports. Failures caused by a peer only ever surface as this type or a derived one.</summary>
/// <example>
/// <code>
/// try
/// {
///     await client.ExecuteAsync("uname -a", cancellationToken);
/// }
/// catch (SshException ex)
/// {
///     logger.LogError(ex, "SSH failed");
/// }
/// </code>
/// </example>
public class SshException : Exception
{
    /// <summary>Creates an exception with a default message.</summary>
    public SshException()
        : base("The SSH operation failed.")
    {
    }

    /// <summary>Creates an exception with a message.</summary>
    /// <param name="message">What failed and what to do next.</param>
    public SshException(string message)
        : base(message)
    {
    }

    /// <summary>Creates an exception with a message and a cause.</summary>
    /// <param name="message">What failed and what to do next.</param>
    /// <param name="innerException">The underlying failure.</param>
    public SshException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>The peer broke the SSH protocol, so the connection can't continue.</summary>
/// <example>
/// <code>
/// catch (SshProtocolException ex)
/// {
///     logger.LogWarning("Peer broke the protocol: {Reason}", ex.Message);
/// }
/// </code>
/// </example>
public class SshProtocolException : SshException
{
    /// <summary>Creates an exception with a default message.</summary>
    public SshProtocolException()
        : base("The peer broke the SSH protocol. Check that it is a real SSH implementation, then retry.")
    {
    }

    /// <summary>Creates an exception with a message.</summary>
    /// <param name="message">What the peer did wrong.</param>
    public SshProtocolException(string message)
        : base(message)
    {
    }

    /// <summary>Creates an exception with a message and a cause.</summary>
    /// <param name="message">What the peer did wrong.</param>
    /// <param name="innerException">The underlying failure.</param>
    public SshProtocolException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

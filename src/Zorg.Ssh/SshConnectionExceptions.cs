using System;
using System.Collections.Generic;

namespace Zorg.Ssh;

/// <summary>The connection failed or closed. Connect again to continue.</summary>
/// <example>
/// <code>
/// catch (SshConnectionException)
/// {
///     client = await SshClient.ConnectAsync(options, cancellationToken);
/// }
/// </code>
/// </example>
public class SshConnectionException : SshException
{
    /// <summary>Creates an exception with a default message.</summary>
    public SshConnectionException()
        : base("The SSH connection closed. Connect again to continue.")
    {
    }

    /// <summary>Creates an exception with a message.</summary>
    /// <param name="message">What failed and what to do next.</param>
    public SshConnectionException(string message)
        : base(message)
    {
    }

    /// <summary>Creates an exception with a message and a cause.</summary>
    /// <param name="message">What failed and what to do next.</param>
    /// <param name="innerException">The underlying failure.</param>
    public SshConnectionException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>The peer ended the connection with an SSH_MSG_DISCONNECT.</summary>
/// <example>
/// <code>
/// catch (SshDisconnectedException ex)
/// {
///     logger.LogWarning("Server closed the connection: {Code} {Text}", ex.ReasonCode, ex.Description);
/// }
/// </code>
/// </example>
public class SshDisconnectedException : SshConnectionException
{
    /// <summary>Creates an exception with no reason.</summary>
    public SshDisconnectedException()
        : base("The peer disconnected.")
    {
        Description = string.Empty;
    }

    /// <summary>Creates an exception with a message.</summary>
    /// <param name="message">What happened.</param>
    public SshDisconnectedException(string message)
        : base(message)
    {
        Description = string.Empty;
    }

    /// <summary>Creates an exception with a message and a cause.</summary>
    /// <param name="message">What happened.</param>
    /// <param name="innerException">The underlying failure.</param>
    public SshDisconnectedException(string message, Exception innerException)
        : base(message, innerException)
    {
        Description = string.Empty;
    }

    /// <summary>Creates an exception from a disconnect message.</summary>
    /// <param name="reasonCode">The reason code from RFC 4253 section 11.1.</param>
    /// <param name="description">The peer's text, already sanitised.</param>
    public SshDisconnectedException(uint reasonCode, string description)
        : base($"The peer disconnected (reason {reasonCode}): {description}")
    {
        ReasonCode = reasonCode;
        Description = description;
    }

    /// <summary>Gets the reason code from RFC 4253 section 11.1.</summary>
    public uint ReasonCode { get; }

    /// <summary>Gets the peer's text, with control characters removed and its length capped. It's still peer-controlled.</summary>
    public string Description { get; }
}

/// <summary>The two sides share no algorithm in one family.</summary>
/// <example>
/// <code>
/// catch (SshNegotiationException ex)
/// {
///     Console.WriteLine($"No common {ex.Family}. Ours: {string.Join(',', ex.LocalAlgorithms)}");
/// }
/// </code>
/// </example>
public class SshNegotiationException : SshProtocolException
{
    /// <summary>Creates an exception with a default message.</summary>
    public SshNegotiationException()
        : this("The two sides have no algorithm in common.")
    {
    }

    /// <summary>Creates an exception with a message.</summary>
    /// <param name="message">What failed.</param>
    public SshNegotiationException(string message)
        : base(message)
    {
        Family = string.Empty;
        LocalAlgorithms = [];
        PeerAlgorithms = [];
    }

    /// <summary>Creates an exception with a message and a cause.</summary>
    /// <param name="message">What failed.</param>
    /// <param name="innerException">The underlying failure.</param>
    public SshNegotiationException(string message, Exception innerException)
        : base(message, innerException)
    {
        Family = string.Empty;
        LocalAlgorithms = [];
        PeerAlgorithms = [];
    }

    /// <summary>Creates an exception naming both lists, so the mismatch can be fixed from the message alone.</summary>
    /// <param name="family">The family, for example <c>key exchange</c>.</param>
    /// <param name="localAlgorithms">What this side offered.</param>
    /// <param name="peerAlgorithms">What the peer offered.</param>
    public SshNegotiationException(string family, IReadOnlyList<string> localAlgorithms, IReadOnlyList<string> peerAlgorithms)
        : base($"No common {family} algorithm. This side offers [{string.Join(", ", localAlgorithms)}]; the peer offers [{string.Join(", ", peerAlgorithms)}]. Enable a shared algorithm on either side.")
    {
        Family = family;
        LocalAlgorithms = localAlgorithms;
        PeerAlgorithms = peerAlgorithms;
    }

    /// <summary>Gets the algorithm family that failed.</summary>
    public string Family { get; }

    /// <summary>Gets what this side offered.</summary>
    public IReadOnlyList<string> LocalAlgorithms { get; }

    /// <summary>Gets what the peer offered.</summary>
    public IReadOnlyList<string> PeerAlgorithms { get; }
}

/// <summary>The server's host key was rejected, or it didn't prove it holds that key. This can mean an attack.</summary>
/// <example>
/// <code>
/// catch (SshHostKeyException ex)
/// {
///     logger.LogError(ex, "Refusing to connect: host key not trusted");
/// }
/// </code>
/// </example>
public class SshHostKeyException : SshException
{
    /// <summary>Creates an exception with a default message.</summary>
    public SshHostKeyException()
        : base("The server's host key isn't trusted. Check the key with the server's administrator before trusting it.")
    {
    }

    /// <summary>Creates an exception with a message.</summary>
    /// <param name="message">What failed and what to do next.</param>
    public SshHostKeyException(string message)
        : base(message)
    {
    }

    /// <summary>Creates an exception with a message and a cause.</summary>
    /// <param name="message">What failed and what to do next.</param>
    /// <param name="innerException">The underlying failure.</param>
    public SshHostKeyException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

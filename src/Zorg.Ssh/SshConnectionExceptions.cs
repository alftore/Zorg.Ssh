using System;
using System.Collections.Generic;
using System.Linq;

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

/// <summary>Why a peer disconnected: the reason codes of RFC 4253 section 11.1. A code outside the list keeps its number.</summary>
/// <example>
/// <code>
/// if (ex.Reason == SshDisconnectReason.TooManyConnections)
/// {
///     await Task.Delay(TimeSpan.FromSeconds(30), cancellationToken);
/// }
/// </code>
/// </example>
#pragma warning disable CA1028 // The wire value is a uint32, and an unknown one must pass through unchanged.
public enum SshDisconnectReason : uint
#pragma warning restore CA1028
{
    /// <summary>Zero, which RFC 4253 doesn't define.</summary>
    None = 0,

    /// <summary>The host isn't allowed to connect.</summary>
    HostNotAllowedToConnect = 1,

    /// <summary>A protocol error.</summary>
    ProtocolError = 2,

    /// <summary>The key exchange failed.</summary>
    KeyExchangeFailed = 3,

    /// <summary>A packet failed its MAC check.</summary>
    MacError = 5,

    /// <summary>A compression error.</summary>
    CompressionError = 6,

    /// <summary>The service isn't available.</summary>
    ServiceNotAvailable = 7,

    /// <summary>The protocol version isn't supported.</summary>
    ProtocolVersionNotSupported = 8,

    /// <summary>The host key couldn't be verified.</summary>
    HostKeyNotVerifiable = 9,

    /// <summary>The connection was lost.</summary>
    ConnectionLost = 10,

    /// <summary>The application closed the connection, the usual reason for an orderly end.</summary>
    ByApplication = 11,

    /// <summary>The peer has too many connections.</summary>
    TooManyConnections = 12,

    /// <summary>The user cancelled authentication.</summary>
    AuthCancelledByUser = 13,

    /// <summary>No more authentication methods are available.</summary>
    NoMoreAuthMethodsAvailable = 14,

    /// <summary>The user name isn't allowed.</summary>
    IllegalUserName = 15,
}

/// <summary>The peer ended the connection with an SSH_MSG_DISCONNECT.</summary>
/// <example>
/// <code>
/// catch (SshDisconnectedException ex)
/// {
///     logger.LogWarning("Server closed the connection: {Reason} {Text}", ex.Reason, ex.Description);
/// }
/// </code>
/// </example>
public sealed class SshDisconnectedException : SshConnectionException
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
    /// <param name="reason">The reason code from RFC 4253 section 11.1.</param>
    /// <param name="description">The peer's text, already sanitised.</param>
    public SshDisconnectedException(SshDisconnectReason reason, string description)
        : base($"The peer disconnected (reason {(uint)reason}, {reason}): {description}")
    {
        Reason = reason;
        Description = description;
    }

    /// <summary>Gets the reason code from RFC 4253 section 11.1. A code outside <see cref="SshDisconnectReason"/>'s names keeps its number.</summary>
    public SshDisconnectReason Reason { get; }

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
public sealed class SshNegotiationException : SshProtocolException
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
        : base($"No common {family} algorithm. This side offers [{Summarise(localAlgorithms)}]; the peer offers [{Summarise(peerAlgorithms)}]. Enable a shared algorithm on either side.{LegacyHint(localAlgorithms, peerAlgorithms)}")
    {
        Family = family;
        LocalAlgorithms = localAlgorithms;
        PeerAlgorithms = peerAlgorithms;
    }

    /// <summary>Points at LegacyUnsafe when the peer offers a legacy algorithm this side doesn't. Names only, from a fixed list.</summary>
    private static string LegacyHint(IReadOnlyList<string> localAlgorithms, IReadOnlyList<string> peerAlgorithms) =>
        peerAlgorithms.FirstOrDefault(name => Crypto.LegacyAlgorithms.IsLegacy(name) && !localAlgorithms.Contains(name)) is { } legacy
            ? $" The peer offers {legacy}, which SshAlgorithms.LegacyUnsafe enables: read docs/security.md before using it."
            : string.Empty;

    private static string Summarise(IReadOnlyList<string> names)
    {
        const int MaxNames = 32;
        const int MaxLength = 64;
        IEnumerable<string> shown = names.Take(MaxNames).Select(static n => n.Length <= MaxLength ? n : n[..MaxLength] + "...");
        string more = names.Count > MaxNames ? $", and {names.Count - MaxNames} more" : string.Empty;
        return string.Join(", ", shown) + more;
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
public sealed class SshHostKeyException : SshException
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

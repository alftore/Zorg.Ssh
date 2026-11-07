using System;
using System.Collections.Generic;

namespace Zorg.Ssh;

/// <summary>The server refused every credential.</summary>
/// <example>
/// <code>
/// catch (SshAuthenticationException ex)
/// {
///     Console.WriteLine($"Tried {string.Join(", ", ex.AttemptedMethods)}; server accepts {string.Join(", ", ex.AllowedMethods)}");
/// }
/// </code>
/// </example>
public sealed class SshAuthenticationException : SshException
{
    /// <summary>Creates an exception with a default message.</summary>
    public SshAuthenticationException()
        : this("Authentication failed. Check the user name and credentials.")
    {
    }

    /// <summary>Creates an exception with a message.</summary>
    /// <param name="message">What failed and what to do next.</param>
    public SshAuthenticationException(string message)
        : base(message)
    {
        AttemptedMethods = [];
        AllowedMethods = [];
    }

    /// <summary>Creates an exception with a message and a cause.</summary>
    /// <param name="message">What failed and what to do next.</param>
    /// <param name="innerException">The underlying failure.</param>
    public SshAuthenticationException(string message, Exception innerException)
        : base(message, innerException)
    {
        AttemptedMethods = [];
        AllowedMethods = [];
    }

    /// <summary>Creates an exception that lists what was tried.</summary>
    /// <param name="message">What failed and what to do next.</param>
    /// <param name="attemptedMethods">The methods tried.</param>
    /// <param name="allowedMethods">The methods the server last said it accepts.</param>
    public SshAuthenticationException(string message, IReadOnlyList<string> attemptedMethods, IReadOnlyList<string> allowedMethods)
        : base(message)
    {
        AttemptedMethods = attemptedMethods;
        AllowedMethods = allowedMethods;
    }

    /// <summary>Gets the methods tried.</summary>
    public IReadOnlyList<string> AttemptedMethods { get; }

    /// <summary>Gets the methods the server last said it accepts.</summary>
    public IReadOnlyList<string> AllowedMethods { get; }
}

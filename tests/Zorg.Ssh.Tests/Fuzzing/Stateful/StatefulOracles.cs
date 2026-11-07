#pragma warning disable CA1031 // The oracles catch everything on purpose: an exception of any type is a finding.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Crypto.KeyFiles;

namespace Zorg.Ssh.Tests.Fuzzing.Stateful;

/// <summary>A finding the stateful oracles raise. The runner reports any exception that is not an allowed type, and this is never allowed.</summary>
internal sealed class StatefulFindingException(string kind, string message) : Exception(kind + ": " + message)
{
    public string Kind { get; } = kind;
}

internal static class StatefulFindings
{
    /// <summary>Runs one input and puts the readable ops of the input on any finding, so that the report shows the sequence that caused it.</summary>
    public static T Run<T>(byte[] input, Func<T> run)
    {
        try
        {
            return run();
        }
        catch (StatefulFindingException finding)
        {
            throw new StatefulFindingException(finding.Kind, finding.Message[(finding.Kind.Length + 2)..] + Environment.NewLine + "The ops of the input:" + Environment.NewLine + FuzzOpCodec.Describe(input));
        }
    }
}

/// <summary>Keeps every log entry of a run, with its exception in full, so the oracles can read what the library said.</summary>
internal sealed class CaptureLoggerFactory : ILoggerFactory
{
    private readonly ConcurrentQueue<string> _entries = new();
    private readonly ConcurrentQueue<Exception> _exceptions = new();

    public string[] Entries => [.. _entries];

    public Exception[] Exceptions => [.. _exceptions];

    /// <summary>Forgets what was captured so far, so the next input starts clean.</summary>
    public void Clear()
    {
        while (_entries.TryDequeue(out _))
        {
        }

        while (_exceptions.TryDequeue(out _))
        {
        }
    }

    public void AddProvider(ILoggerProvider provider)
    {
    }

    public ILogger CreateLogger(string categoryName) => new CaptureLogger(this, categoryName);

    public void Dispose()
    {
    }

    private sealed class CaptureLogger(CaptureLoggerFactory owner, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            StringBuilder text = new();
            text.Append(CultureInfo.InvariantCulture, $"[{logLevel}] {category}: {formatter(state, exception)}");
            if (exception is not null)
            {
                text.AppendLine().Append(exception);
                owner._exceptions.Enqueue(exception);
            }

            owner._entries.Enqueue(text.ToString());
        }
    }
}

/// <summary>Watches for faulted tasks nobody observed. A background loop that loses its failure shows up here once the task is collected.</summary>
internal static class UnobservedTasks
{
    private static readonly ConcurrentQueue<Exception> Seen = new();
    private static int _installed;

    public static void Install()
    {
        if (Interlocked.Exchange(ref _installed, 1) == 0)
        {
            TaskScheduler.UnobservedTaskException += (_, e) =>
            {
                foreach (Exception inner in e.Exception.Flatten().InnerExceptions)
                {
                    Seen.Enqueue(inner);
                }

                e.SetObserved();
            };
        }
    }

    /// <summary>Collects garbage so that finalizers of dropped tasks run, then returns what was unobserved since the last call.</summary>
    public static List<Exception> Drain()
    {
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        List<Exception> found = [];
        while (Seen.TryDequeue(out Exception? exception))
        {
            found.Add(exception);
        }

        return found;
    }
}

/// <summary>The judgement of what an exception that left the SUT means.</summary>
internal static class SutExceptions
{
    /// <summary>Gets the library's own marker for a bug that its catch-alls turned into an <see cref="SshException"/>.</summary>
    public const string BugMarker = "This is a bug in Zorg.Ssh";

    /// <summary>
    /// Returns why an exception that escaped or was logged is not what guarantee 3 allows, or null if it is fine. Only
    /// <see cref="SshException"/> types are fine, with the I/O and cancellation a closed stream or token causes. An
    /// <see cref="SshException"/> that says it is a bug is the library's catch-all hiding a failure.
    /// </summary>
    public static string? Judge(Exception exception)
    {
        for (Exception? e = exception; e is not null; e = e.InnerException)
        {
            if (e.Message.Contains(BugMarker, StringComparison.Ordinal))
            {
                return $"a catch-all in the library turned an unexpected failure into SshException (\"{BugMarker}\"): {e.InnerException?.GetType().FullName ?? "no inner exception"}: {e.InnerException?.Message}";
            }
        }

        // An SshException may carry the exception that caused it (a UTF-8 decoder failure inside SshProtocolException, say): that is wrapping, and the
        // outer type is what a caller catches. Only the library's own catch-all, found above by its message, is a hidden failure.
        return Allowed(exception) ? null : $"{exception.GetType().FullName} is not an SshException type: {exception.Message}";
    }

    private static bool Allowed(Exception e) => e switch
    {
        SshException => true,
        OperationCanceledException => true,
        ObjectDisposedException => true,

        // A stream that closes under a reader or writer: the transport turns it into SshConnectionException, but the pipes below it say IOException.
        IOException => true,
        SocketException => true,
        AggregateException aggregate => aggregate.InnerExceptions.All(Allowed),
        _ => false,
    };
}

/// <summary>Guarantee 4: the secrets of a run, and a search of everything the library wrote for them.</summary>
internal sealed class SecretScan
{
    private readonly List<string> _secrets = [];

    public SecretScan Add(string secret)
    {
        _secrets.Add(secret);
        return this;
    }

    /// <summary>Adds slices of a private key file, so a key that reached a log in any piece is found.</summary>
    public SecretScan AddKeyFile(string keyText)
    {
        string body = string.Concat(keyText.Split('\n').Where(line => !line.StartsWith("-----", StringComparison.Ordinal)).Select(line => line.Trim()));
        for (int at = 0; at + 24 <= body.Length; at += 24)
        {
            _secrets.Add(body.Substring(at, 24));
        }

        return this;
    }

    public string? Find(IEnumerable<string> texts)
    {
        foreach (string text in texts)
        {
            foreach (string secret in _secrets)
            {
                if (text.Contains(secret, StringComparison.Ordinal))
                {
                    return $"the secret \"{(secret.Length > 6 ? secret[..3] + "..." : "?")}\" ({secret.Length} chars) appears in: {Excerpt(text, secret)}";
                }
            }
        }

        return null;
    }

    private static string Excerpt(string text, string secret)
    {
        int at = text.IndexOf(secret, StringComparison.Ordinal);
        int start = Math.Max(0, at - 60);
        return text.Substring(start, Math.Min(text.Length - start, 160)).Replace(secret, "<SECRET>", StringComparison.Ordinal);
    }
}

/// <summary>Secrets the fuzz setup uses, which must never appear in a log or an exception.</summary>
internal static class FuzzSecrets
{
    public static SecretScan Scan() => new SecretScan().Add(Wire.Secret).AddKeyFile(FuzzKeys.Ed25519OpenSsh);

    public static string PrivateKeyForClient => FuzzKeys.Ed25519OpenSsh;

    /// <summary>The Ed25519 key the scripted peer logs in with. Generated at test time: nothing is stored.</summary>
    public static SshPrivateKey PeerKey { get; } = SshKeyFile.Load(FuzzKeys.Ed25519OpenSsh);
}

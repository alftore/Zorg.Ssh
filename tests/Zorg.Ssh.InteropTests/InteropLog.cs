using System;
using System.Collections.Concurrent;
using System.Linq;
using Microsoft.Extensions.Logging;

namespace Zorg.Ssh.InteropTests;

/// <summary>Keeps every log line, so a test can check what was negotiated from the library's own debug log.</summary>
internal sealed class InteropLog : ILoggerFactory
{
    private readonly ConcurrentQueue<string> _lines = new();

    public string Text => string.Join(Environment.NewLine, _lines);

    public bool Contains(string text) => _lines.Any(line => line.Contains(text, StringComparison.Ordinal));

    public void AddProvider(ILoggerProvider provider)
    {
    }

    public ILogger CreateLogger(string categoryName) => new Logger(this);

    public void Dispose()
    {
    }

    private sealed class Logger(InteropLog log) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            log._lines.Enqueue($"[{logLevel}] {formatter(state, exception)}");
    }
}

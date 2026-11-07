using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Zorg.Ssh.Auth;
using Zorg.Ssh.Connection;
using Zorg.Ssh.Forwarding;
using Zorg.Ssh.Sftp;
using Zorg.Ssh.Transport;

namespace Zorg.Ssh;

/// <summary>What a finished command produced.</summary>
/// <example>
/// <code>
/// SshCommandResult result = await client.ExecuteAsync("uname -a", cancellationToken);
/// Console.WriteLine(result.StandardOutput);
/// </code>
/// </example>
public sealed record SshCommandResult
{
    /// <summary>Gets the exit code, or null if the command ended on a signal or the server sent none.</summary>
    public int? ExitCode { get; init; }

    /// <summary>Gets the name of the signal that ended the command, if any.</summary>
    public string? ExitSignal { get; init; }

    /// <summary>Gets everything on stdout, as UTF-8.</summary>
    public required string StandardOutput { get; init; }

    /// <summary>Gets everything on stderr, as UTF-8.</summary>
    public required string StandardError { get; init; }
}

/// <summary>Terminal settings for <see cref="SshProcessOptions.Pty"/>.</summary>
/// <example>
/// <code>
/// SshPtyOptions pty = new() { Terminal = "xterm-256color", Columns = 120, Rows = 40 };
/// </code>
/// </example>
public sealed class SshPtyOptions
{
    /// <summary>Gets the terminal type. The default is <c>xterm-256color</c>.</summary>
    public string Terminal { get; init; } = "xterm-256color";

    private readonly int _columns = 80;
    private readonly int _rows = 24;

    /// <summary>Gets the width in characters. The default is 80.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is zero or less.</exception>
    public int Columns
    {
        get => _columns;
        init
        {
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(value);
            _columns = value;
        }
    }

    /// <summary>Gets the height in characters. The default is 24.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is zero or less.</exception>
    public int Rows
    {
        get => _rows;
        init
        {
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(value);
            _rows = value;
        }
    }
}

/// <summary>Settings for <see cref="SshClient.StartProcessAsync"/>.</summary>
/// <example>
/// <code>
/// SshProcessOptions options = new() { Pty = new SshPtyOptions(), Environment = new Dictionary&lt;string, string&gt; { ["LANG"] = "C" } };
/// </code>
/// </example>
public sealed class SshProcessOptions
{
    /// <summary>Gets the terminal to allocate. Null, the default, allocates none.</summary>
    public SshPtyOptions? Pty { get; init; }

    /// <summary>Gets environment variables to ask for. Servers usually allow only a few, and ignore the rest.</summary>
    public IReadOnlyDictionary<string, string>? Environment { get; init; }
}

/// <summary>An SSH connection. Start with <see cref="ConnectAsync"/>. Commands on one client may run at the same time.</summary>
/// <example>
/// <code>
/// await using SshClient client = await SshClient.ConnectAsync(new SshClientOptions
/// {
///     Host = "example.com",
///     UserName = "alice",
///     Credentials = [SshCredential.FromPassword(password)],
///     HostKeyPolicy = HostKeyPolicy.Fingerprint(knownFingerprint),
/// }, cancellationToken);
///
/// SshCommandResult result = await client.ExecuteAsync("uname -a", cancellationToken);
/// </code>
/// </example>
public sealed partial class SshClient : IAsyncDisposable
{
    private readonly SshConnection _connection;
    private readonly SshClientOptions _options;
    private readonly RemoteForwardTable _remoteForwards;
    private readonly ILogger _logger;
    private int _disposed;

    private SshClient(SshConnection connection, SshClientOptions options, RemoteForwardTable remoteForwards, ILogger logger)
    {
        _connection = connection;
        _options = options;

        // The key exchange that ConnectAsync waited for checked this key. A rekey must present the same one, or the
        // transport ends the connection, so it can't change while the client lives.
        HostKey = SshHostKeyInfo.From(options.Host, options.Port, connection.Transport.PeerHostKey!);
        _remoteForwards = remoteForwards;
        _logger = logger;
        _ = CloseForwardsWhenEndedAsync();
    }

    /// <summary>Gets the server's identification string, for example <c>SSH-2.0-OpenSSH_10.6</c>. It's chosen by the server.</summary>
    public string ServerVersion => _connection.Transport.PeerIdentification;

    /// <summary>
    /// Gets the host key the server proved it holds when this connection was made, and that
    /// <see cref="SshClientOptions.HostKeyPolicy"/> accepted. It's what a <see cref="HostKeyPolicy.Custom"/> check is
    /// given: <see cref="SshClientOptions.Host"/> and <see cref="SshClientOptions.Port"/> as you passed them, the key
    /// type, the fingerprint and the key itself. A server that sent a host certificate is described by the certificate.
    /// </summary>
    /// <remarks>
    /// It never changes: a rekey that offers another key ends the connection with <see cref="SshHostKeyException"/>.
    /// Through a <see cref="SshClientOptions.JumpHost"/>, each client has its own server's key.
    /// </remarks>
    /// <example>
    /// <code>
    /// await using SshClient client = await SshClient.ConnectAsync(options with { HostKeyPolicy = HostKeyPolicy.KnownHostsFile() }, cancellationToken);
    /// Console.WriteLine($"Connected to {client.HostKey.Host}, {client.HostKey.KeyType} {client.HostKey.Sha256Fingerprint}");
    /// </code>
    /// </example>
    public SshHostKeyInfo HostKey { get; }

    /// <summary>Connects, checks the server's host key, and logs in. With <see cref="SshClientOptions.JumpHost"/> set, the connection goes through that client.</summary>
    /// <param name="options">Where to connect, and how to log in.</param>
    /// <param name="cancellationToken">Cancels the connection attempt.</param>
    /// <returns>A connected client.</returns>
    /// <exception cref="SshHostKeyException">The host key wasn't trusted, or your <see cref="HostKeyPolicy.Custom"/> check threw. Show it to a person: it can mean an attack.</exception>
    /// <exception cref="SshAuthenticationException">The server refused every credential, or a banner or keyboard-interactive handler of yours threw. An agent that failed is named in the message, not thrown as <see cref="SshAgentException"/>.</exception>
    /// <exception cref="SshKeyFileException">A private key file couldn't be read, or its passphrase is wrong. An identity file that <see cref="SshClientOptions.FromConfig"/> added is passed over instead.</exception>
    /// <exception cref="SshNegotiationException">The two sides share no algorithm in one family.</exception>
    /// <exception cref="SshDisconnectedException">The server ended the connection, with a reason code.</exception>
    /// <exception cref="SshConnectionException">The network failed, or the connection timed out.</exception>
    /// <exception cref="SshProtocolException">The server broke the protocol.</exception>
    /// <exception cref="ArgumentException">An option is out of range, or <see cref="SshClientOptions.Algorithms"/> names an algorithm that isn't supported.</exception>
    /// <example>
    /// <code>
    /// await using SshClient client = await SshClient.ConnectAsync(options, cancellationToken);
    /// </code>
    /// </example>
    public static async Task<SshClient> ConnectAsync(SshClientOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Algorithms.Validate();
        TransportOptions.ValidateKeepAlive(options.KeepAliveInterval, options.KeepAliveCountMax);
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(options.ConnectTimeout);

#pragma warning disable CA2000 // Ownership passes to the transport, which closes the stream on every path.
        if (options.JumpHost is { } jumpHost)
        {
            Stream tunnel;
            try
            {
                tunnel = await jumpHost.OpenTcpStreamAsync(options.Host, options.Port, timeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
            {
                throw new SshConnectionException($"Connecting to {options.Host}:{options.Port} through the jump host timed out. Check the host and port, or raise ConnectTimeout.", ex);
            }

            return await ConnectCoreAsync(tunnel, options, timeout.Token, cancellationToken).ConfigureAwait(false);
        }

        Socket socket = new(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        NetworkStream stream;
        try
        {
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            await socket.ConnectAsync(options.Host, options.Port, timeout.Token).ConfigureAwait(false);
            stream = new NetworkStream(socket, ownsSocket: true);
        }
        catch (SocketException ex)
        {
            socket.Dispose();
            throw new SshConnectionException($"Couldn't connect to {options.Host}:{options.Port}: {ex.Message}. Check the host, port and network.", ex);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            socket.Dispose();
            throw new SshConnectionException($"Connecting to {options.Host}:{options.Port} timed out. Check the host and port, or raise ConnectTimeout.", ex);
        }
        catch
        {
            socket.Dispose();
            throw;
        }

        return await ConnectCoreAsync(stream, options, timeout.Token, cancellationToken).ConfigureAwait(false);
#pragma warning restore CA2000
    }

    /// <summary>Connects over a stream you've already opened, such as a proxy tunnel. The client owns the stream from here on.</summary>
    /// <param name="stream">The connected stream.</param>
    /// <param name="options">How to log in. <see cref="SshClientOptions.Host"/> is still used for the host key check. <see cref="SshClientOptions.JumpHost"/> is ignored: the stream is the route.</param>
    /// <param name="cancellationToken">Cancels the connection attempt.</param>
    /// <returns>A connected client.</returns>
    /// <example>
    /// <code>
    /// await using SshClient client = await SshClient.ConnectOverStreamAsync(tunnelStream, options, cancellationToken);
    /// </code>
    /// </example>
    public static async Task<SshClient> ConnectOverStreamAsync(Stream stream, SshClientOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(options);
        options.Algorithms.Validate();
        TransportOptions.ValidateKeepAlive(options.KeepAliveInterval, options.KeepAliveCountMax);
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(options.ConnectTimeout);
        return await ConnectCoreAsync(stream, options, timeout.Token, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Runs a command to the end, and returns its output. For long or large output, use <see cref="StartProcessAsync"/>.</summary>
    /// <param name="command">The command line. The server's shell interprets it, so quote anything that comes from a user.</param>
    /// <param name="cancellationToken">Stops waiting and closes the channel.</param>
    /// <returns>The exit status and output.</returns>
    /// <example>
    /// <code>
    /// SshCommandResult result = await client.ExecuteAsync("uname -a", cancellationToken);
    /// if (result.ExitCode != 0)
    /// {
    ///     Console.Error.WriteLine(result.StandardError);
    /// }
    /// </code>
    /// </example>
    public Task<SshCommandResult> ExecuteAsync(string command, CancellationToken cancellationToken) =>
        ExecuteAsync(command, null, cancellationToken);

    /// <summary>Runs a command to the end with environment or terminal settings, and returns its output.</summary>
    /// <param name="command">The command line. The server's shell interprets it, so quote anything that comes from a user.</param>
    /// <param name="options">Terminal and environment settings, as for <see cref="StartProcessAsync"/>. With a terminal, stderr arrives in <see cref="SshCommandResult.StandardOutput"/>.</param>
    /// <param name="cancellationToken">Stops waiting and closes the channel.</param>
    /// <returns>The exit status and output.</returns>
    /// <example>
    /// <code>
    /// SshProcessOptions options = new() { Environment = new Dictionary&lt;string, string&gt; { ["LANG"] = "C" } };
    /// SshCommandResult result = await client.ExecuteAsync("locale", options, cancellationToken);
    /// </code>
    /// </example>
    public async Task<SshCommandResult> ExecuteAsync(string command, SshProcessOptions? options = null, CancellationToken cancellationToken = default)
    {
        SshProcess process = await StartProcessAsync(command, options, cancellationToken).ConfigureAwait(false);
        await using (process.ConfigureAwait(false))
        {
            await process.StandardInput.DisposeAsync().ConfigureAwait(false);

            // Both streams share the channel window, so both must be read at once or the server stalls. And when
            // one fails, the other stops too, or it would wait for output the full window now holds back.
            using CancellationTokenSource reading = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
#pragma warning disable CA2025 // Both are awaited below, before the source is disposed.
            Task<string> output = ReadAllAsync(process.StandardOutput, reading);
            Task<string> error = ReadAllAsync(process.StandardError, reading);
#pragma warning restore CA2025
            await Task.WhenAll(output, error).ConfigureAwait(false);
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
            return new SshCommandResult
            {
                ExitCode = process.ExitCode,
                ExitSignal = process.ExitSignal,
                StandardOutput = await output.ConfigureAwait(false),
                StandardError = await error.ConfigureAwait(false),
            };
        }
    }

    /// <summary>Starts a command, with streams for its input and output.</summary>
    /// <param name="command">The command line. The server's shell interprets it, so quote anything that comes from a user.</param>
    /// <param name="options">Terminal and environment settings.</param>
    /// <param name="cancellationToken">Cancels the start. It doesn't affect a process that has started.</param>
    /// <returns>The running process. Read both of its output streams, because they share one flow-control window.</returns>
    /// <example>
    /// <code>
    /// await using SshProcess process = await client.StartProcessAsync("tail -f /var/log/syslog", null, cancellationToken);
    /// using StreamReader reader = new(process.StandardOutput);
    /// string? line = await reader.ReadLineAsync(cancellationToken);
    /// </code>
    /// </example>
    public Task<SshProcess> StartProcessAsync(string command, SshProcessOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (command.Contains('\0', StringComparison.Ordinal))
        {
            throw new ArgumentException("A command can't contain a NUL character: servers end the connection over it.", nameof(command));
        }

        return StartAsync("exec", command, options, cancellationToken);
    }

    /// <summary>Starts the user's login shell, with a terminal unless the options say otherwise.</summary>
    /// <param name="options">Terminal and environment settings. Null asks for a default terminal.</param>
    /// <param name="cancellationToken">Cancels the start.</param>
    /// <returns>The running shell.</returns>
    /// <example>
    /// <code>
    /// await using SshProcess shell = await client.StartShellAsync(null, cancellationToken);
    /// </code>
    /// </example>
    public Task<SshProcess> StartShellAsync(SshProcessOptions? options = null, CancellationToken cancellationToken = default) =>
        StartAsync("shell", null, options ?? new SshProcessOptions { Pty = new SshPtyOptions() }, cancellationToken);

    /// <summary>Starts an SFTP session on a new channel, with the default limits. Several sessions can share one client.</summary>
    /// <param name="cancellationToken">Cancels the start. It doesn't affect a session that has started.</param>
    /// <returns>The session. Disposing it closes its channel, and leaves this client connected.</returns>
    /// <exception cref="SshException">The server refused the subsystem, so SFTP may not be enabled there.</exception>
    /// <example>
    /// <code>
    /// await using SftpClient sftp = await client.OpenSftpAsync(cancellationToken);
    /// byte[] config = await sftp.ReadAllBytesAsync("/etc/app.conf", cancellationToken);
    /// </code>
    /// </example>
    public Task<SftpClient> OpenSftpAsync(CancellationToken cancellationToken) =>
        OpenSftpAsync(null, cancellationToken);

    /// <summary>Starts an SFTP session on a new channel, with limits of your own. Several sessions can share one client.</summary>
    /// <param name="options">The session's limits. Null uses the defaults.</param>
    /// <param name="cancellationToken">Cancels the start. It doesn't affect a session that has started.</param>
    /// <returns>The session. Disposing it closes its channel, and leaves this client connected.</returns>
    /// <exception cref="SshException">The server refused the subsystem, so SFTP may not be enabled there.</exception>
    /// <example>
    /// <code>
    /// await using SftpClient sftp = await client.OpenSftpAsync(new SftpClientOptions { MaxReadAllBytes = 1024L * 1024 * 1024 }, cancellationToken);
    /// </code>
    /// </example>
    public async Task<SftpClient> OpenSftpAsync(SftpClientOptions? options = null, CancellationToken cancellationToken = default)
    {
        options ??= SftpClientOptions.Default;
        SshChannel channel = await OpenSubsystemAsync("sftp", cancellationToken).ConfigureAwait(false);
        return await SftpClient.OpenOverChannelAsync(channel, ServerVersion, options, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Closes every forward, and then the connection. A client that used this one as a jump host loses its connection too.</summary>
    /// <returns>A task that completes when the connection is closed.</returns>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            await CloseForwardsAsync().ConfigureAwait(false);
            await _connection.DisposeAsync().ConfigureAwait(false);
        }
    }

    /// <summary>Opens a session channel and starts a subsystem on it, such as <c>sftp</c>.</summary>
    internal async Task<SshChannel> OpenSubsystemAsync(string name, CancellationToken cancellationToken)
    {
        SshChannel channel = await _connection.OpenChannelAsync("session", cancellationToken).ConfigureAwait(false);
        try
        {
            if (!await channel.SendRequestAsync("subsystem", Encode(w => w.String(name)), cancellationToken).ConfigureAwait(false))
            {
                throw new SshException($"The server refused the {name} subsystem. It may not be enabled there.");
            }

            return channel;
        }
        catch
        {
            await channel.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>Test hook: starts a rekey now.</summary>
    internal void RequestRekey() => _connection.Transport.RequestRekey();

    internal int CompletedKeyExchanges => _connection.Transport.CompletedKeyExchanges;

    /// <summary>Gets the connection, for tests.</summary>
    internal SshConnection Connection => _connection;

    private static async Task<SshClient> ConnectCoreAsync(Stream stream, SshClientOptions options, CancellationToken timeoutToken, CancellationToken callerToken)
    {
        ILogger logger = options.LoggerFactory?.CreateLogger<SshClient>() ?? NullLogger<SshClient>.Instance;
        TransportOptions transportOptions = new()
        {
            Role = SshRole.Client,
            Logger = logger,
            HandshakeTimeout = options.ConnectTimeout,
            KeepAliveInterval = options.KeepAliveInterval,
            KeepAliveCountMax = options.KeepAliveCountMax,
            TimeProvider = options.TimeProvider,
            KexAlgorithms = options.Algorithms.KeyExchange,
            KeyExchangeExtension = options.Algorithms.KeyExchangeExtension,

            // An explicit list is the caller's. Otherwise the policy can put certificate algorithms first, and a preset's
            // legacy names (ssh-rsa in LegacyUnsafe) follow everything else.
            HostKeyAlgorithms = options.Algorithms.ClientHostKeys(() => options.HostKeyPolicy.HostKeyAlgorithmsFor(options.Host, options.Port)),
            Ciphers = options.Algorithms.Ciphers,
            Macs = options.Algorithms.Macs,
            HostKeyValidator = (key, ct) => options.HostKeyPolicy.CheckAsync(options.Host, options.Port, key, ct),
        };

#pragma warning disable CA2000 // On success both belong to the client, and the catch blocks release the transport otherwise.
        SshTransport? transport = null;
        try
        {
            transport = await SshTransport.StartAsync(stream, transportOptions, timeoutToken).ConfigureAwait(false);
            ClientAuthenticator authenticator = new(transport, options.UserName, options.BannerHandler, options.Algorithms.AllowsRsaSha1);
            await authenticator.AuthenticateAsync(options.Credentials, timeoutToken).ConfigureAwait(false);
            RemoteForwardTable remoteForwards = new();
            SshConnection connection = new(transport) { ForwardedChannelHandler = remoteForwards.HandleOpen };
            connection.Start();
            return new SshClient(connection, options, remoteForwards, logger);
        }
        catch (OperationCanceledException ex) when (!callerToken.IsCancellationRequested)
        {
            if (transport is not null)
            {
                await transport.DisposeAsync().ConfigureAwait(false);
            }

            throw new SshConnectionException($"Connecting to {options.Host} timed out during login. Raise ConnectTimeout if the server is slow.", ex);
        }
        catch
        {
            if (transport is not null)
            {
                await transport.DisposeAsync().ConfigureAwait(false);
            }

            throw;
        }
    }

#pragma warning restore CA2000

    private static byte[] Encode(Action<SshRequestWriter> build)
    {
        SshRequestWriter writer = new();
        build(writer);
        return writer.ToArray();
    }

    private async Task<string> ReadAllAsync(Stream stream, CancellationTokenSource reading)
    {
        CancellationToken cancellationToken = reading.Token;
        using MemoryStream all = new();
        byte[] buffer = ArrayPool<byte>.Shared.Rent(32 * 1024);
        try
        {
            while (true)
            {
                int read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    return Encoding.UTF8.GetString(all.GetBuffer(), 0, (int)all.Length);
                }

                if (all.Length + read > _options.MaxCommandOutputBytes)
                {
                    await reading.CancelAsync().ConfigureAwait(false);
                    throw new SshException($"The command wrote more than {_options.MaxCommandOutputBytes} bytes. Use StartProcessAsync to stream it, or raise MaxCommandOutputBytes.");
                }

                await all.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    private async Task<SshProcess> StartAsync(string requestType, string? command, SshProcessOptions? options, CancellationToken cancellationToken)
    {
        SshChannel channel = await _connection.OpenChannelAsync("session", cancellationToken).ConfigureAwait(false);
        try
        {
            if (options?.Environment is { } environment)
            {
                foreach ((string name, string value) in environment)
                {
                    await channel.SendRequestNoReplyAsync(
                        "env",
                        Encode(w =>
                        {
                            w.String(name);
                            w.String(value);
                        }),
                        cancellationToken).ConfigureAwait(false);
                }
            }

            if (options?.Pty is { } pty)
            {
                byte[] request = Encode(w =>
                {
                    w.String(pty.Terminal);
                    w.UInt32((uint)pty.Columns);
                    w.UInt32((uint)pty.Rows);
                    w.UInt32(0);
                    w.UInt32(0);
                    w.Bytes([0]);
                });
                if (!await channel.SendRequestAsync("pty-req", request, cancellationToken).ConfigureAwait(false))
                {
                    throw new SshException("The server refused to allocate a terminal.");
                }
            }

            byte[] start = command is null ? [] : Encode(w => w.String(command));
            if (!await channel.SendRequestAsync(requestType, start, cancellationToken).ConfigureAwait(false))
            {
                throw new SshException($"The server refused the {requestType} request. The account may be restricted.");
            }

            return new SshProcess(channel);
        }
        catch
        {
            await channel.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }
}

/// <summary>A running remote command or shell.</summary>
/// <example>
/// <code>
/// await using SshProcess process = await client.StartProcessAsync("cat", null, cancellationToken);
/// await process.StandardInput.WriteAsync(data, cancellationToken);
/// await process.StandardInput.DisposeAsync();
/// await process.WaitForExitAsync(cancellationToken);
/// </code>
/// </example>
public sealed class SshProcess : IAsyncDisposable
{
    private readonly SshChannel _channel;

    internal SshProcess(SshChannel channel) => _channel = channel;

    /// <summary>Gets the process's stdin. Disposing it sends EOF.</summary>
    public Stream StandardInput => _channel.Input;

    /// <summary>Gets the process's stdout.</summary>
    public Stream StandardOutput => _channel.Output;

    /// <summary>Gets the process's stderr. With a terminal it's empty, because everything arrives on stdout.</summary>
    public Stream StandardError => _channel.ErrorOutput;

    /// <summary>Gets the exit code, once the process has ended and if the server sent one.</summary>
    public int? ExitCode => _channel.ExitCode;

    /// <summary>Gets the signal that ended the process, if any.</summary>
    public string? ExitSignal => _channel.ExitSignal;

    /// <summary>Waits for the process to end and the channel to close.</summary>
    /// <param name="cancellationToken">Stops waiting. The process keeps running.</param>
    /// <returns>A task that completes when the process has ended.</returns>
    /// <example>
    /// <code>
    /// await process.WaitForExitAsync(cancellationToken);
    /// Console.WriteLine(process.ExitCode);
    /// </code>
    /// </example>
    /// <exception cref="SshConnectionException">The connection was lost, so how the process ended isn't known.</exception>
    public async Task WaitForExitAsync(CancellationToken cancellationToken = default)
    {
        await _channel.Closed.WaitAsync(cancellationToken).ConfigureAwait(false);
        if (_channel.ConnectionFailure is { } failure && ExitCode is null && ExitSignal is null)
        {
            throw new SshConnectionException("The connection was lost before the process ended. It may still be running.", failure);
        }
    }

    /// <summary>Tells the terminal its new size.</summary>
    /// <param name="columns">The width in characters.</param>
    /// <param name="rows">The height in characters.</param>
    /// <param name="cancellationToken">Cancels the send.</param>
    /// <returns>A task that completes when the request is queued.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="columns"/> or <paramref name="rows"/> is zero or less.</exception>
    /// <example>
    /// <code>
    /// await shell.ResizeAsync(120, 40, cancellationToken);
    /// </code>
    /// </example>
    public async Task ResizeAsync(int columns, int rows, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(columns);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(rows);
        SshRequestWriter writer = new();
        writer.UInt32((uint)columns);
        writer.UInt32((uint)rows);
        writer.UInt32(0);
        writer.UInt32(0);
        await _channel.SendRequestNoReplyAsync("window-change", writer.ToArray(), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Closes the channel. If the process is still running, the server decides what happens to it.</summary>
    /// <returns>A task that completes when the channel is released.</returns>
    public ValueTask DisposeAsync() => _channel.DisposeAsync();
}

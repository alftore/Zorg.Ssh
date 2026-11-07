#pragma warning disable CA1031 // The rig catches everything on purpose: what escapes the SUT is judged by the oracles.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Zorg.Ssh.Sftp;
using Zorg.Ssh.Tests.Transport;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Tests.Fuzzing.Stateful;

/// <summary>The SSH client under test, driven by a small application whose actions the fuzz input starts, against a scripted hostile server.</summary>
internal sealed class ClientRig(Depth depth = Depth.Channel) : IDisposable
{
    private readonly Lock _inputGate = new();
    private int _inputs;

    /// <summary>Gets or sets what a probe op runs. For tests that measure the connection while it is busy.</summary>
    public Func<SshClient?, Task>? Probe { get; set; }

    /// <summary>Gets what the peer saw at the end of the last input.</summary>
    public string LastDescription { get; private set; } = string.Empty;

    public void Dispose()
    {
    }

    public FuzzOutcome Run(byte[] input)
    {
        lock (_inputGate)
        {
            StatefulNotes notes = new();
            try
            {
                return StatefulFindings.Run(input, () => RunAsync(input, notes).GetAwaiter().GetResult());
            }
            finally
            {
                notes.Flush();
            }
        }
    }

    private static string HostFingerprint() => HostKeyPolicy.ComputeFingerprint(TransportHarness.HostKey.PublicKey.Blob.Span);

    private async Task<FuzzOutcome> RunAsync(byte[] input, StatefulNotes notes)
    {
        Stopwatch watch = Stopwatch.StartNew();
        (byte variant, List<FuzzOp> ops) = FuzzOpCodec.Decode(input);
        _inputs++;
        CaptureLoggerFactory logs = new();
        SshClientOptions options = new()
        {
            Host = "fuzz.test",
            Port = 22,
            UserName = Wire.UserName,
            HostKeyPolicy = HostKeyPolicy.Fingerprint(HostFingerprint()),
            Algorithms = StatefulLimits.FastAlgorithms,
            LoggerFactory = logs,
            Credentials =
            [
                SshCredential.FromPrivateKey(FuzzSecrets.PrivateKeyForClient),
                SshCredential.FromKeyboardInteractive((prompts, _) => ValueTask.FromResult<IReadOnlyList<string>>([.. prompts.Select(_ => Wire.Secret)])),
                SshCredential.FromPassword(Wire.Secret),
            ],
        };

        (Stream peerStream, Stream sutStream) = DuplexStream.CreatePair();
        Task<SshClient> connect = SshClient.ConnectOverStreamAsync(sutStream, options);
        ConcurrentQueue<(string Name, Task Task)> apps = new();
        ConcurrentQueue<string> appFailures = new();
        StatefulPeer? peer = null;
        SequenceExecutor? executor = null;
        string? memory = null;
        bool survived = false;
        try
        {
            using CancellationTokenSource handshake = new(TimeSpan.FromSeconds(20));
            try
            {
                (string suiteName, string[]? ciphers, string[]? macs) = StatefulLimits.PeerSuite(variant);
                notes.Reached("cipher: " + suiteName);
                peer = await StatefulPeer.StartAsync(peerStream, TransportHarness.ServerOptions(kex: ["curve25519-sha256"], ciphers: ciphers, macs: macs), handshake.Token).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                throw new StatefulFindingException("Harness", "The unfuzzed key exchange with the SUT failed, which is a bug in the setup or the library: " + ex.GetType().Name + ": " + ex.Message);
            }

            notes.Milliseconds["handshake"] = watch.Elapsed.TotalMilliseconds;
            watch.Restart();
            executor = new SequenceExecutor(peer, action => StartAppAsync(connect, action, apps, appFailures), Probe is null ? null : async () => await Probe(connect.IsCompletedSuccessfully ? await connect.ConfigureAwait(false) : null).ConfigureAwait(false))
            {
                SutRekey = async () => (await connect.WaitAsync(StatefulLimits.AwaitLimit * 2).ConfigureAwait(false)).RequestRekey(),
            };
            await executor.RunAsync(ops).ConfigureAwait(false);
            survived = await executor.BarrierAsync().ConfigureAwait(false);
            await executor.RequireCanariesEndedAsync().ConfigureAwait(false);
            if (survived && connect.IsCompletedSuccessfully)
            {
                memory = ServerRig.CheckBounds((await connect.ConfigureAwait(false)).Connection, 256);
            }

            notes.Record(peer, survived);
            notes.RecordKex(executor, peer);
            notes.Milliseconds["ops and barrier"] = watch.Elapsed.TotalMilliseconds;
            watch.Restart();
        }
        finally
        {
            peer?.Vanish();
        }

        // The peer has gone. The connect call, every application call and the dispose must now end by themselves, with no token.
        string? hang = null;
        string description = StatefulNotes.Describe(peer!);
        LastDescription = description;
        Exception? connectFailure = null;
        SshClient? client = null;
        try
        {
            client = await connect.WaitAsync(StatefulLimits.EndLimit).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            hang = $"ConnectOverStreamAsync did not complete within {StatefulLimits.EndLimit.TotalSeconds:0} s of the peer vanishing.";
        }
        catch (Exception ex)
        {
            connectFailure = ex;
        }

        try
        {
            await Task.WhenAll(apps.Select(a => a.Task)).WaitAsync(StatefulLimits.EndLimit).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            hang ??= $"{apps.Count(a => !a.Task.IsCompleted)} application calls were still pending {StatefulLimits.EndLimit.TotalSeconds:0} s after the peer vanished and the connection was lost: {string.Join(", ", apps.Where(a => !a.Task.IsCompleted).Select(a => a.Name))}. Connection ended: {client?.Connection.Ended.IsCompleted}.";
        }
        catch (Exception ex)
        {
            appFailures.Enqueue("application task: " + ex);
        }

        if (client is not null)
        {
            try
            {
                await client.Connection.Ended.WaitAsync(StatefulLimits.EndLimit).ConfigureAwait(false);
                await client.DisposeAsync().AsTask().WaitAsync(StatefulLimits.EndLimit).ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                hang ??= $"The connection did not end, or DisposeAsync did not complete, within {StatefulLimits.EndLimit.TotalSeconds:0} s of the peer vanishing.";
            }
            catch (Exception ex)
            {
                appFailures.Enqueue("dispose: " + ex);
            }
        }

        await executor!.StopAsync().ConfigureAwait(false);
        string[] entries = logs.Entries;
        Exception[] logged = logs.Exceptions;
        LastDescription += " | logged: " + string.Join("; ", logged.Select(e => e.GetType().Name + ": " + e.Message));
        bool authenticated = peer!.SentAuthSuccess;
        string? peerEnd = peer.EndedBy?.Message;
        bool clientSentConnectionMessageBeforeAuth = !authenticated && peer.Snapshot().Any(m => m.Number is >= 80 and <= 127);
        bool stalled = peer.SendStalled;
        List<PeerMessage> received = peer.Snapshot();
        bool openedChannel = peer.Snapshot().Any(m => m.Number == MessageNumber.ChannelOpen);
        await peer.DisposeAsync().ConfigureAwait(false);

        // A message that policy forbids during the peer's key exchange was queued right behind its KEXINIT. The SUT must end the connection over it. An
        // answer that names it (a confirmation or a refusal of the open) means it was acted on, which is the first guarantee broken.
        if (executor is not null && received.FirstOrDefault(m => m.Number is MessageNumber.ChannelOpenConfirmation or MessageNumber.ChannelOpenFailure && m.Payload.Length >= 5 && executor.Canaries.Contains(System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(m.Payload.AsSpan(1)))) is { } answered)
        {
            throw new StatefulFindingException("GUARANTEE 1 BREACH", $"The SUT answered ({StatefulLimits.Name(answered.Number)}) a message that was sent in the middle of the peer's key exchange, which policy forbids. It acted on it. {description}");
        }

        if (clientSentConnectionMessageBeforeAuth)
        {
            throw new StatefulFindingException("GUARANTEE 2 BREACH", $"The client sent a connection-layer message before the server had logged it in. {description}");
        }

        // The scripted server changes its own phase when it sends a message, so a message the client had already sent can arrive in the new
        // phase and be refused by the peer. That is the race of any real server. Only a connection-layer message with no login behind it is a breach.
        if (peerEnd is not null && peerEnd.Contains("isn't allowed in this state", StringComparison.Ordinal) && !authenticated
            && System.Text.RegularExpressions.Regex.Match(peerEnd, @"message (\d+)") is { Success: true } refused && int.Parse(refused.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture) >= 80)
        {
            throw new StatefulFindingException("GUARANTEE 1", $"The client sent a message that the message policy forbids in the state it was in: {peerEnd} {description}");
        }

        if (stalled)
        {
            throw new StatefulFindingException("Hang", $"A send waited more than {StatefulPeer.SendStallLimit.TotalSeconds:0} s: the client stopped reading from the connection. {description}");
        }

        if (hang is not null)
        {
            throw new StatefulFindingException("Hang", hang + " " + description);
        }

        if (connectFailure is not null && SutExceptions.Judge(connectFailure) is { } why)
        {
            throw new StatefulFindingException("Exception", $"ConnectOverStreamAsync failed with something other than an SshException type: {why}{Environment.NewLine}{connectFailure}");
        }

        if (appFailures.TryDequeue(out string? failure))
        {
            throw new StatefulFindingException("Exception", failure);
        }

        foreach (Exception exception in logged)
        {
            if (SutExceptions.Judge(exception) is { } reason)
            {
                throw new StatefulFindingException("Exception", $"{reason}{Environment.NewLine}{exception}");
            }
        }

        List<string> texts = [.. entries, .. logged.Select(e => e.ToString())];
        if (connectFailure is not null)
        {
            texts.Add(connectFailure.ToString());
        }

        if (FuzzSecrets.Scan().Find(texts) is { } leak)
        {
            throw new StatefulFindingException("GUARANTEE 4", leak);
        }

        if (memory is not null)
        {
            throw new StatefulFindingException("Memory bound", memory + " " + description);
        }

        if (FuzzSettings.UnobservedTaskCheck && _inputs % 20 == 0)
        {
            foreach (Exception unobserved in UnobservedTasks.Drain())
            {
                throw new StatefulFindingException("Unobserved task exception", $"A background task of type {unobserved.Data["task"]} faulted and nobody awaited it (within the last 20 inputs): {unobserved.GetType().FullName}: {unobserved.Message}{Environment.NewLine}{unobserved}");
            }
        }

        notes.Milliseconds["teardown and verdict"] = watch.Elapsed.TotalMilliseconds;
        bool deep = depth switch
        {
            Depth.Authenticated => authenticated,
            Depth.Rekeyed => authenticated && peer.Transport.CompletedKeyExchanges >= 2,
            _ => authenticated && openedChannel,
        };
        if (!deep)
        {
            notes.Refuse(authenticated ? "logged in, no channel opened" : "not logged in");
        }

        return deep ? FuzzOutcome.Accepted : FuzzOutcome.Rejected;
    }

    private static string AppName(byte action) => (action % 10) switch
    {
        0 => "ExecuteAsync",
        1 => "StartProcessAsync",
        2 => "OpenSftpAsync and operations",
        3 => "ForwardRemotePortAsync",
        4 => "OpenTcpStreamAsync",
        5 => "StartShellAsync",
        6 => "ForwardRemotePortAsync fixed port",
        7 => "two ExecuteAsync calls",
        8 => "SFTP files and streams",
        _ => "SFTP metadata",
    };

    private static async Task DrainAsync(Stream stream)
    {
        byte[] buffer = new byte[4096];
        while (await stream.ReadAsync(buffer).ConfigureAwait(false) > 0)
        {
        }
    }

    private async Task StartAppAsync(Task<SshClient> connect, byte action, ConcurrentQueue<(string Name, Task Task)> apps, ConcurrentQueue<string> failures)
    {
        if (apps.Count >= 12)
        {
            return;
        }

        SshClient client;
        try
        {
            client = await connect.WaitAsync(StatefulLimits.AwaitLimit * 2).ConfigureAwait(false);
        }
        catch (Exception)
        {
            return;
        }

        apps.Enqueue((AppName(action), Task.Run(async () =>
        {
            try
            {
                await RunAppAsync(client, action).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                if (SutExceptions.Judge(ex) is { } why)
                {
                    failures.Enqueue($"An application call ({AppName(action)}) failed with something other than an SshException type: {why}{Environment.NewLine}{ex}");
                }
            }
        })));
    }

    private async Task RunAppAsync(SshClient client, byte action)
    {
        switch (action % 10)
        {
            case 0:
                await client.ExecuteAsync("echo hi").ConfigureAwait(false);
                break;
            case 1:
                SshProcess process = await client.StartProcessAsync("cat").ConfigureAwait(false);
                await using (process.ConfigureAwait(false))
                {
                    await process.StandardInput.WriteAsync(new byte[3000]).ConfigureAwait(false);
                    await process.StandardInput.DisposeAsync().ConfigureAwait(false);
                    Task output = DrainAsync(process.StandardOutput);
                    Task error = DrainAsync(process.StandardError);
                    await Task.WhenAll(output, error).ConfigureAwait(false);
                    await process.WaitForExitAsync().ConfigureAwait(false);
                }

                break;
            case 2:
                SftpClient sftp = await client.OpenSftpAsync().ConfigureAwait(false);
                await using (sftp.ConfigureAwait(false))
                {
                    await foreach (SftpEntry entry in sftp.ListDirectoryAsync(".").ConfigureAwait(false))
                    {
                        _ = entry.Name;
                    }

                    await sftp.GetAttributesAsync("a.txt").ConfigureAwait(false);
                    await sftp.ReadAllBytesAsync("a.txt").ConfigureAwait(false);
                    await sftp.WriteAllBytesAsync("b.txt", new byte[100]).ConfigureAwait(false);
                    await sftp.CreateDirectoryAsync("d").ConfigureAwait(false);
                    await sftp.RenameAsync("b.txt", "d/c.txt").ConfigureAwait(false);
                    await sftp.GetFullPathAsync(".").ConfigureAwait(false);
                    await sftp.DeleteFileAsync("d/c.txt").ConfigureAwait(false);
                }

                break;
            case 3 or 6:
                SshRemoteForward forward = await client.ForwardRemotePortAsync(action % 10 == 3 ? "127.0.0.1" : "0.0.0.0", action % 10 == 3 ? 0 : 8022, "127.0.0.1", SharedSink.Port).ConfigureAwait(false);
                await using (forward.ConfigureAwait(false))
                {
                    // Stays registered while the scripted server opens connections to it, until the connection ends or a moment has passed.
                    await Task.WhenAny(client.Connection.Ended, Task.Delay(1500)).ConfigureAwait(false);
                }

                break;
            case 4:
                Stream tcp = await client.OpenTcpStreamAsync("127.0.0.1", 80).ConfigureAwait(false);
                await using (tcp.ConfigureAwait(false))
                {
                    await tcp.WriteAsync(new byte[200]).ConfigureAwait(false);
                    byte[] buffer = new byte[1024];
                    await tcp.ReadAsync(buffer).ConfigureAwait(false);
                }

                break;
            case 5:
                SshProcess shell = await client.StartShellAsync().ConfigureAwait(false);
                await using (shell.ConfigureAwait(false))
                {
                    await shell.StandardInput.WriteAsync("ls\n"u8.ToArray()).ConfigureAwait(false);
                    await shell.ResizeAsync(100, 30).ConfigureAwait(false);
                    byte[] buffer = new byte[1024];
                    await shell.StandardOutput.ReadAsync(buffer).ConfigureAwait(false);
                }

                break;
            case 7:
                await client.ExecuteAsync("one").ConfigureAwait(false);
                await client.ExecuteAsync("two").ConfigureAwait(false);
                break;
            case 8:
                SftpClient files = await client.OpenSftpAsync().ConfigureAwait(false);
                await using (files.ConfigureAwait(false))
                {
                    SftpFile file = await files.OpenAsync("a.txt").ConfigureAwait(false);
                    await using (file.ConfigureAwait(false))
                    {
                        byte[] buffer = new byte[100];
                        await file.ReadAsync(buffer, CancellationToken.None).ConfigureAwait(false);
                    }

                    using MemoryStream download = new();
                    await files.DownloadFileAsync("a.txt", download).ConfigureAwait(false);
                    using MemoryStream upload = new(new byte[500]);
                    await files.UploadFileAsync(upload, "up.bin").ConfigureAwait(false);
                    await files.DownloadDirectoryAsync(".", Path.Combine(Path.GetTempPath(), "zorg-fuzz-down-" + Guid.NewGuid().ToString("N")), maxTotalBytes: 4096).ConfigureAwait(false);
                }

                break;
            default:
                SftpClient meta = await client.OpenSftpAsync().ConfigureAwait(false);
                await using (meta.ConfigureAwait(false))
                {
                    await meta.ExistsAsync("a.txt").ConfigureAwait(false);
                    await meta.SetAttributesAsync("a.txt", new SftpAttributes { Permissions = UnixFileMode.UserRead | UnixFileMode.UserWrite }).ConfigureAwait(false);
                    await meta.CreateSymbolicLinkAsync("l", "a.txt").ConfigureAwait(false);
                    await meta.ReadLinkAsync("l").ConfigureAwait(false);
                    await meta.GetFileSystemInfoAsync(".").ConfigureAwait(false);
                    await meta.CopyFileAsync("a.txt", "b.txt").ConfigureAwait(false);
                    await meta.CreateHardLinkAsync("h", "a.txt").ConfigureAwait(false);
                    await meta.DeleteDirectoryAsync("d").ConfigureAwait(false);
                }

                break;
        }
    }
}

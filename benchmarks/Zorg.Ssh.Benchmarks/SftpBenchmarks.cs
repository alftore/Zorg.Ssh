using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using Zorg.Ssh.Sftp;
using SshNetSftpClient = Renci.SshNet.SftpClient;
using TmdsClient = Tmds.Ssh.SshClient;
using TmdsSftpClient = Tmds.Ssh.SftpClient;

namespace Zorg.Ssh.Benchmarks;

/// <summary>
/// One large file over a session that's already open, from and to memory so the client's disk plays no part. Each
/// library runs on its defaults: its own chunk size and requests in flight are part of what's measured.
/// </summary>
[Config(typeof(TransferConfig))]
public class SftpBenchmarks
{
    public const int FileSize = 128 * 1024 * 1024;

    private const string RemoteSource = "/tmp/bench-source.bin";
    private const string RemoteTarget = "/tmp/bench-target.bin";

    private Peer _peer = null!;
    private byte[] _data = null!;

    private SshClient? _zorg;
    private SftpClient? _zorgSftp;
    private SshNetSftpClient? _sshNet;
    private TmdsClient? _tmds;
    private TmdsSftpClient? _tmdsSftp;

    [Params("aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com")]
    public string Cipher { get; set; } = Peer.DefaultCipher;

    [GlobalSetup(Targets = [nameof(ZorgUpload), nameof(ZorgDownload)])]
    public async Task SetupZorg()
    {
        await StartPeerAsync();
        _zorg = await SshClient.ConnectAsync(_peer.ZorgOptions());
        _zorgSftp = await _zorg.OpenSftpAsync();

        await ZorgUpload();
        using MemoryStream copy = new(FileSize);
        await _zorgSftp.DownloadFileAsync(RemoteTarget, copy);
        await CheckAsync(copy);
    }

    [GlobalSetup(Targets = [nameof(SshNetUpload), nameof(SshNetDownload)])]
    public async Task SetupSshNet()
    {
        await StartPeerAsync();
        _sshNet = _peer.SshNetSftpClient();
        await _sshNet.ConnectAsync(CancellationToken.None);

        await SshNetUpload();
        using MemoryStream copy = new(FileSize);
        await _sshNet.DownloadFileAsync(RemoteTarget, copy);
        await CheckAsync(copy);
    }

    [GlobalSetup(Targets = [nameof(TmdsUpload), nameof(TmdsDownload)])]
    public async Task SetupTmds()
    {
        await StartPeerAsync();
        _tmds = _peer.TmdsClient();
        await _tmds.ConnectAsync();
        _tmdsSftp = await _tmds.OpenSftpClientAsync();

        await TmdsUpload();
        using MemoryStream copy = new(FileSize);
        await _tmdsSftp.DownloadFileAsync(RemoteTarget, copy);
        await CheckAsync(copy);
    }

    [GlobalCleanup]
    public async Task Cleanup()
    {
        if (_zorgSftp is not null)
        {
            await _zorgSftp.DisposeAsync();
        }

        if (_zorg is not null)
        {
            await _zorg.DisposeAsync();
        }

        _sshNet?.Dispose();
        _tmdsSftp?.Dispose();
        _tmds?.Dispose();
        await _peer.DisposeAsync();
    }

    [Benchmark(Baseline = true)]
    [BenchmarkCategory("Upload")]
    public async Task ZorgUpload()
    {
        using MemoryStream source = new(_data, writable: false);
        await _zorgSftp!.UploadFileAsync(source, RemoteTarget);
    }

    [Benchmark]
    [BenchmarkCategory("Upload")]
    public async Task SshNetUpload()
    {
        using MemoryStream source = new(_data, writable: false);
        await _sshNet!.UploadFileAsync(source, RemoteTarget);
    }

    [Benchmark]
    [BenchmarkCategory("Upload")]
    public async Task TmdsUpload()
    {
        using MemoryStream source = new(_data, writable: false);
        await _tmdsSftp!.UploadFileAsync(source, RemoteTarget, overwrite: true);
    }

    [Benchmark(Baseline = true)]
    [BenchmarkCategory("Download")]
    public async Task ZorgDownload() => await _zorgSftp!.DownloadFileAsync(RemoteSource, Stream.Null);

    [Benchmark]
    [BenchmarkCategory("Download")]
    public async Task SshNetDownload() => await _sshNet!.DownloadFileAsync(RemoteSource, Stream.Null);

    [Benchmark]
    [BenchmarkCategory("Download")]
    public async Task TmdsDownload() => await _tmdsSftp!.DownloadFileAsync(RemoteSource, Stream.Null);

    private async Task StartPeerAsync()
    {
        _peer = await Peer.StartAsync(Cipher);
        await _peer.RunInContainerAsync($"head -c {FileSize} /dev/urandom > {RemoteSource}");

        _data = new byte[FileSize];
        RandomNumberGenerator.Fill(_data);
    }

    /// <summary>A transfer that's fast because it's wrong doesn't count: the setup checks a round trip first.</summary>
    private async Task CheckAsync(MemoryStream copy)
    {
        if (!copy.GetBuffer().AsSpan(0, (int)copy.Length).SequenceEqual(_data))
        {
            throw new InvalidOperationException("The file that came back isn't the one that was sent.");
        }

        string size = await _peer.RunInContainerAsync($"wc -c < {RemoteSource}");
        if (long.Parse(size.Trim(), System.Globalization.CultureInfo.InvariantCulture) != FileSize)
        {
            throw new InvalidOperationException($"The source file has {size} bytes.");
        }
    }
}

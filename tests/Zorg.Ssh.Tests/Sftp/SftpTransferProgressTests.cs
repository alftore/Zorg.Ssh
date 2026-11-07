#pragma warning disable xUnit1069 // Tests reach the token through the Ct property, which the analyzer can't see.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Zorg.Ssh.Sftp;
using Zorg.Ssh.Tests.Transport;

namespace Zorg.Ssh.Tests.Sftp;

/// <summary>
/// <see cref="SftpTransferOptions.Progress"/>: a first and a final report, counts that only grow, totals when they're
/// known, at most one report per interval in between, and nothing after the call has returned.
/// </summary>
[Collection(SftpSerialTests.Name)]
public sealed class SftpTransferProgressTests : IDisposable
{
    private const int Limit = 30_000;
    private const uint DirectoryMode = 0x41ED;
    private const uint RegularFile = 0x81A4;

    private readonly string _sandbox = Path.Combine(Path.GetTempPath(), "zorg-sftp-progress-" + Guid.NewGuid().ToString("N"));

    public SftpTransferProgressTests() => Directory.CreateDirectory(_sandbox);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => Directory.Delete(_sandbox, recursive: true);

    private static byte[] Pattern(int length)
    {
        byte[] data = new byte[length];
        new Random(length).NextBytes(data);
        return data;
    }

    private static SftpTransferOptions Options(Recorder recorder, StepClock clock) => new() { Progress = recorder, TimeProvider = clock };

    /// <summary>The checks every sequence of reports for one file must pass.</summary>
    private static void AssertWellFormedSingleFile(IReadOnlyList<SftpTransferProgress> reports, string remotePath, long length, long? total)
    {
        Assert.True(reports.Count >= 2);
        Assert.Equal(new SftpTransferProgress { RemotePath = remotePath, BytesTransferred = 0, TotalBytes = total, FilesCompleted = 0, OverallBytesTransferred = 0 }, reports[0]);
        Assert.Equal(new SftpTransferProgress { RemotePath = remotePath, BytesTransferred = length, TotalBytes = total, FilesCompleted = 1, OverallBytesTransferred = length }, reports[^1]);
        foreach (SftpTransferProgress report in reports)
        {
            Assert.Equal(remotePath, report.RemotePath);
            Assert.Null(report.LocalPath);
            Assert.Equal(total, report.TotalBytes);
            Assert.Equal(report.BytesTransferred, report.OverallBytesTransferred);
        }

        for (int i = 1; i < reports.Count; i++)
        {
            Assert.True(reports[i].BytesTransferred >= reports[i - 1].BytesTransferred, $"Report {i} went backwards.");
        }
    }

    [Fact(Timeout = Limit)]
    public async Task An_upload_from_a_seekable_stream_reports_its_total_first_and_its_count_last()
    {
        FakeFiles files = new();
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(files.HandleAsync);
        byte[] data = Pattern(1_000_000);
        Recorder recorder = new();

        // A clock that never moves lets only the first and the last report through.
        using MemoryStream source = new(data);
        await fake.Client.UploadFileAsync(source, "f", Options(recorder, StepClock.Frozen()), Ct);

        Assert.Equal(data, files.Files["f"]);
        Assert.Equal(2, recorder.Reports.Count);
        AssertWellFormedSingleFile(recorder.Reports, "f", data.Length, data.Length);
    }

    [Fact(Timeout = Limit)]
    public async Task An_upload_counts_only_what_is_left_of_the_stream()
    {
        FakeFiles files = new();
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(files.HandleAsync);
        byte[] data = Pattern(10_000);
        Recorder recorder = new();

        using MemoryStream source = new(data) { Position = 4000 };
        await fake.Client.UploadFileAsync(source, "f", Options(recorder, StepClock.Frozen()), Ct);

        Assert.Equal(data[4000..], files.Files["f"]);
        AssertWellFormedSingleFile(recorder.Reports, "f", 6000, 6000);
    }

    [Fact(Timeout = Limit)]
    public async Task An_upload_from_a_stream_that_cant_seek_has_no_total()
    {
        FakeFiles files = new();
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(files.HandleAsync);
        byte[] data = Pattern(300_000);
        Recorder recorder = new();

        using NonSeekableStream source = new(data);
        await fake.Client.UploadFileAsync(source, "f", Options(recorder, StepClock.Every(TimeSpan.FromSeconds(1))), Ct);

        Assert.Equal(data, files.Files["f"]);
        Assert.True(recorder.Reports.Count > 2, "Every chunk should have been reported on a clock this fast.");
        AssertWellFormedSingleFile(recorder.Reports, "f", data.Length, null);
    }

    [Fact(Timeout = Limit)]
    public async Task A_download_asks_for_the_size_only_when_progress_is_wanted()
    {
        FakeFiles files = new() { Files = { ["f"] = Pattern(500_000) } };
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(files.HandleAsync);
        Recorder recorder = new();

        using (MemoryStream plain = new())
        {
            await fake.Client.DownloadFileAsync("f", plain, Ct);
            await fake.Client.DownloadFileAsync("f", plain, new SftpTransferOptions(), Ct);
        }

        Assert.DoesNotContain(fake.Requests, r => r.Type == SftpMessage.Fstat);

        using MemoryStream received = new();
        await fake.Client.DownloadFileAsync("f", received, Options(recorder, StepClock.Frozen()), Ct);

        Assert.Equal(files.Files["f"], received.ToArray());
        Assert.Single(fake.Requests, r => r.Type == SftpMessage.Fstat);
        Assert.Equal(2, recorder.Reports.Count);
        AssertWellFormedSingleFile(recorder.Reports, "f", 500_000, 500_000);
    }

    [Fact(Timeout = Limit)]
    public async Task A_download_from_a_server_that_wont_give_the_size_has_no_total()
    {
        FakeFiles files = new() { Files = { ["f"] = Pattern(200_000) } };
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync((server, request) =>
            request.Type == SftpMessage.Fstat ? server.SendStatusAsync(request.Id, FakeSftpServer.StatusFailure, "no") : files.HandleAsync(server, request));
        Recorder recorder = new();

        using MemoryStream received = new();
        await fake.Client.DownloadFileAsync("f", received, Options(recorder, StepClock.Frozen()), Ct);

        Assert.Equal(files.Files["f"], received.ToArray());
        AssertWellFormedSingleFile(recorder.Reports, "f", 200_000, null);
    }

    [Fact(Timeout = Limit)]
    public async Task An_empty_file_still_gets_a_first_and_a_final_report()
    {
        FakeFiles files = new() { Files = { ["f"] = [] } };
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(files.HandleAsync);
        Recorder up = new();
        Recorder down = new();

        using (MemoryStream empty = new())
        {
            await fake.Client.UploadFileAsync(empty, "g", Options(up, StepClock.Frozen()), Ct);
        }

        using MemoryStream received = new();
        await fake.Client.DownloadFileAsync("f", received, Options(down, StepClock.Frozen()), Ct);

        AssertWellFormedSingleFile(up.Reports, "g", 0, 0);
        AssertWellFormedSingleFile(down.Reports, "f", 0, 0);
        Assert.Equal(2, up.Reports.Count);
        Assert.Equal(2, down.Reports.Count);
    }

    [Theory(Timeout = Limit)]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Reports_between_the_first_and_the_last_are_at_least_an_interval_apart(bool upload)
    {
        byte[] data = Pattern(2_000_000);
        FakeFiles files = new() { Files = { ["f"] = data } };
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(files.HandleAsync);

        // Each look at the clock moves it 30 ms, so a report can go out on every fourth chunk at most.
        StepClock clock = StepClock.Every(TimeSpan.FromMilliseconds(30));
        Recorder recorder = new(clock);
        if (upload)
        {
            using MemoryStream source = new(data);
            await fake.Client.UploadFileAsync(source, "g", Options(recorder, clock), Ct);
        }
        else
        {
            using MemoryStream received = new();
            await fake.Client.DownloadFileAsync("f", received, Options(recorder, clock), Ct);
        }

        int count = recorder.Reports.Count;
        AssertWellFormedSingleFile(recorder.Reports, upload ? "g" : "f", data.Length, data.Length);
        Assert.True(count > 3, $"Only {count} reports for a transfer the clock saw as long.");
        Assert.True(count <= (clock.Reads / 3) + 2, $"{count} reports for {clock.Reads} clock reads: the throttle let too many through.");

        // Every report but the last waited for the interval since the one before.
        for (int i = 1; i < count - 1; i++)
        {
            Assert.True(recorder.Times[i] - recorder.Times[i - 1] >= SftpTransferReporter.Interval, $"Report {i} came {recorder.Times[i] - recorder.Times[i - 1]} after the last.");
        }

        // Nothing arrives once the call has returned.
        await Task.Delay(100, Ct);
        Assert.Equal(count, recorder.Reports.Count);
    }

    [Theory(Timeout = Limit)]
    [InlineData(true)]
    [InlineData(false)]
    public async Task A_callback_that_throws_stops_the_transfer_with_its_own_exception_and_the_session_carries_on(bool upload)
    {
        byte[] data = Pattern(1_000_000);
        FakeFiles files = new() { Files = { ["f"] = data } };
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(files.HandleAsync);
        InvalidOperationException bug = new("bug in the progress callback");
        Recorder recorder = new() { OnReport = p => ThrowAfterTheFirst(p, bug) };
        SftpTransferOptions options = Options(recorder, StepClock.Every(TimeSpan.FromSeconds(1)));

        InvalidOperationException thrown = upload
            ? await Assert.ThrowsAsync<InvalidOperationException>(() => fake.Client.UploadFileAsync(new MemoryStream(data), "g", options, Ct))
            : await Assert.ThrowsAsync<InvalidOperationException>(() => fake.Client.DownloadFileAsync("f", Stream.Null, options, Ct));

        Assert.Same(bug, thrown);
        Assert.Equal(0, recorder.Reports[0].BytesTransferred);
        Assert.Equal(2, recorder.Reports.Count);

        // The file was closed, and the session still works.
        await WaitForAsync(() => files.OpenHandles == 0);
        Assert.Equal(data, await fake.Client.ReadAllBytesAsync("f", Ct));
    }

    [Fact(Timeout = Limit)]
    public async Task A_callback_that_throws_on_the_first_report_stops_the_transfer_before_any_data()
    {
        FakeFiles files = new() { Files = { ["f"] = Pattern(100_000) } };
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(files.HandleAsync);
        Recorder recorder = new() { OnReport = _ => throw new FormatException("first") };

        await Assert.ThrowsAsync<FormatException>(() => fake.Client.DownloadFileAsync("f", Stream.Null, Options(recorder, StepClock.Frozen()), Ct));

        Assert.Single(recorder.Reports);
        Assert.DoesNotContain(fake.Requests, r => r.Type == SftpMessage.Read);
        await WaitForAsync(() => files.OpenHandles == 0);
    }

    [Theory(Timeout = Limit)]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Cancelling_from_the_callback_stops_the_transfer_and_nothing_is_reported_after(bool upload)
    {
        byte[] data = Pattern(4_000_000);
        FakeFiles files = new() { Files = { ["f"] = data } };
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(files.HandleAsync);
        using CancellationTokenSource cancel = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        Recorder recorder = new()
        {
            OnReport = p =>
            {
                if (p.BytesTransferred > 0)
                {
                    cancel.Cancel();
                }
            },
        };
        SftpTransferOptions options = Options(recorder, StepClock.Every(TimeSpan.FromSeconds(1)));

        if (upload)
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fake.Client.UploadFileAsync(new MemoryStream(data), "g", options, cancel.Token));
        }
        else
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fake.Client.DownloadFileAsync("f", Stream.Null, options, cancel.Token));
        }

        int count = recorder.Reports.Count;
        Assert.True(recorder.Reports[^1].BytesTransferred < data.Length);
        Assert.Equal(0, recorder.Reports[^1].FilesCompleted);
        await Task.Delay(200, Ct);
        Assert.Equal(count, recorder.Reports.Count);
        await WaitForAsync(() => files.OpenHandles == 0);
    }

    [Fact(Timeout = Limit)]
    public async Task A_directory_download_reports_each_file_and_running_totals()
    {
        byte[] small = Pattern(100);
        byte[] large = Pattern(300_000);
        FakeFiles files = new();
        files.Directories["/d"] = [("a.txt", RegularFile), ("sub", DirectoryMode), ("empty", DirectoryMode)];
        files.Directories["/d/sub"] = [("b.bin", RegularFile)];
        files.Directories["/d/empty"] = [];
        files.Files["/d/a.txt"] = small;
        files.Files["/d/sub/b.bin"] = large;
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(files.HandleAsync);
        Recorder recorder = new();
        string destination = Path.Combine(_sandbox, "dest");

        // A clock this fast lets every report through, so the whole sequence can be checked.
        await fake.Client.DownloadDirectoryAsync("/d", destination, long.MaxValue, Options(recorder, StepClock.Every(TimeSpan.FromSeconds(1))), Ct);

        Assert.Equal(large, await File.ReadAllBytesAsync(Path.Combine(destination, "sub", "b.bin"), Ct));
        IReadOnlyList<SftpTransferProgress> reports = recorder.Reports;

        // The listing of this fake carries no sizes, so there are no totals.
        Assert.All(reports, r => Assert.Null(r.TotalBytes));
        Assert.Equal(new SftpTransferProgress { RemotePath = "/d/a.txt", LocalPath = Path.Combine(destination, "a.txt"), BytesTransferred = 0, FilesCompleted = 0, OverallBytesTransferred = 0 }, reports[0]);
        Assert.Contains(new SftpTransferProgress { RemotePath = "/d/a.txt", LocalPath = Path.Combine(destination, "a.txt"), BytesTransferred = 100, FilesCompleted = 1, OverallBytesTransferred = 100 }, reports);
        Assert.Contains(new SftpTransferProgress { RemotePath = "/d/sub/b.bin", LocalPath = Path.Combine(destination, "sub", "b.bin"), BytesTransferred = 0, FilesCompleted = 1, OverallBytesTransferred = 100 }, reports);
        Assert.Equal(new SftpTransferProgress { RemotePath = "/d/sub/b.bin", LocalPath = Path.Combine(destination, "sub", "b.bin"), BytesTransferred = 300_000, FilesCompleted = 2, OverallBytesTransferred = 300_100 }, reports[^1]);
        for (int i = 1; i < reports.Count; i++)
        {
            Assert.True(reports[i].OverallBytesTransferred >= reports[i - 1].OverallBytesTransferred);
            Assert.True(reports[i].FilesCompleted >= reports[i - 1].FilesCompleted);
        }
    }

    [Fact(Timeout = Limit)]
    public async Task A_throttled_directory_download_still_ends_on_the_final_counts()
    {
        FakeFiles files = new();
        files.Directories["/d"] = [.. Enumerable.Range(0, 20).Select(i => ($"f{i}", RegularFile))];
        for (int i = 0; i < 20; i++)
        {
            files.Files[$"/d/f{i}"] = Pattern(1000 + i);
        }

        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(files.HandleAsync);
        Recorder recorder = new();

        await fake.Client.DownloadDirectoryAsync("/d", Path.Combine(_sandbox, "dest"), long.MaxValue, Options(recorder, StepClock.Frozen()), Ct);

        Assert.Equal(2, recorder.Reports.Count);
        Assert.Equal("/d/f0", recorder.Reports[0].RemotePath);
        Assert.Equal(0, recorder.Reports[0].OverallBytesTransferred);
        Assert.Equal(new SftpTransferProgress { RemotePath = "/d/f19", LocalPath = Path.Combine(_sandbox, "dest", "f19"), BytesTransferred = 1019, FilesCompleted = 20, OverallBytesTransferred = Enumerable.Range(0, 20).Sum(i => 1000L + i) }, recorder.Reports[1]);
    }

    [Fact(Timeout = Limit)]
    public async Task A_directory_download_takes_the_totals_from_the_listing()
    {
        using SftpServerSandbox sandbox = new();
        Directory.CreateDirectory(sandbox.InRoot("tree/inner"));
        await File.WriteAllBytesAsync(sandbox.InRoot("tree/one.bin"), Pattern(70_000), Ct);
        await File.WriteAllBytesAsync(sandbox.InRoot("tree/inner/two.bin"), Pattern(5), Ct);
        (Stream client, Stream server) = DuplexStream.CreatePair();
        Task<int> serving = Task.Run(() => SftpServer.ServeStreamsAsync(server, server, new SftpServerOptions { RootDirectory = sandbox.Root }, CancellationToken.None), Ct);
        Recorder recorder = new();

        await using (SftpClient sftp = await SftpClient.StartAsync(client, client, client, null, SftpLimits.Default, Ct))
        {
            await sftp.DownloadDirectoryAsync("tree", Path.Combine(_sandbox, "dest"), long.MaxValue, Options(recorder, StepClock.Every(TimeSpan.FromSeconds(1))), Ct);
        }

        await serving;
        Assert.Equal(70_000, Assert.Single(recorder.Reports, r => r.RemotePath == "tree/one.bin" && r.BytesTransferred == 0).TotalBytes);
        Assert.Equal(5, Assert.Single(recorder.Reports, r => r.RemotePath == "tree/inner/two.bin" && r.BytesTransferred == 0).TotalBytes);
        Assert.Equal(2, recorder.Reports[^1].FilesCompleted);
        Assert.Equal(70_005, recorder.Reports[^1].OverallBytesTransferred);
    }

    [Fact(Timeout = Limit)]
    public async Task A_tree_with_no_files_reports_nothing()
    {
        FakeFiles files = new();
        files.Directories["/d"] = [("empty", DirectoryMode)];
        files.Directories["/d/empty"] = [];
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(files.HandleAsync);
        Recorder recorder = new();

        await fake.Client.DownloadDirectoryAsync("/d", Path.Combine(_sandbox, "dest"), long.MaxValue, Options(recorder, StepClock.Frozen()), Ct);

        Assert.Empty(recorder.Reports);
    }

    [Fact(Timeout = Limit)]
    public async Task A_directory_download_passes_a_callback_exception_through_even_when_it_is_an_IOException()
    {
        FakeFiles files = new();
        files.Directories["/d"] = [("a", RegularFile)];
        files.Files["/d/a"] = Pattern(50_000);
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(files.HandleAsync);
        IOException bug = new("the callback's own I/O failed");
        Recorder recorder = new() { OnReport = p => ThrowAfterTheFirst(p, bug) };

        // The download turns a failed local write into SftpException. A callback's exception must not be mistaken for one.
        IOException thrown = await Assert.ThrowsAsync<IOException>(
            () => fake.Client.DownloadDirectoryAsync("/d", Path.Combine(_sandbox, "dest"), long.MaxValue, Options(recorder, StepClock.Every(TimeSpan.FromSeconds(1))), Ct));

        Assert.Same(bug, thrown);
        await WaitForAsync(() => files.OpenHandles == 0);
    }

    [Fact(Timeout = Limit)]
    public async Task A_directory_download_still_stops_at_its_byte_limit_with_progress_on()
    {
        FakeFiles files = new();
        files.Directories["/d"] = [("a", RegularFile), ("b", RegularFile)];
        files.Files["/d/a"] = Pattern(60_000);
        files.Files["/d/b"] = Pattern(60_000);
        await using FakeSftpServer fake = await FakeSftpServer.StartAsync(files.HandleAsync);
        Recorder recorder = new();

        await Assert.ThrowsAsync<SftpException>(
            () => fake.Client.DownloadDirectoryAsync("/d", Path.Combine(_sandbox, "dest"), 100_000, Options(recorder, StepClock.Every(TimeSpan.FromSeconds(1))), Ct));

        Assert.True(recorder.Reports[^1].OverallBytesTransferred <= 100_000);
        Assert.Equal(1, recorder.Reports[^1].FilesCompleted);
    }

    [Fact]
    public void Options_are_a_record_that_prints_without_trouble()
    {
        Recorder recorder = new();
        SftpTransferOptions options = new() { Progress = recorder };

        Assert.Equal(options, options with { });
        Assert.NotEqual(options, new SftpTransferOptions());
        Assert.Null(new SftpTransferOptions().Progress);
        Assert.StartsWith("SftpTransferOptions { Progress = ", options.ToString(), StringComparison.Ordinal);
    }

    private static void ThrowAfterTheFirst(SftpTransferProgress progress, Exception bug)
    {
        if (progress.BytesTransferred > 0)
        {
            throw bug;
        }
    }

    private static async Task WaitForAsync(Func<bool> condition)
    {
        using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        limit.CancelAfter(TimeSpan.FromSeconds(20));
        while (!condition())
        {
            await Task.Delay(5, limit.Token);
        }
    }

    /// <summary>Records each report as it's made, on the transfer's own flow, with the clock's time.</summary>
    private sealed class Recorder(StepClock? clock = null) : IProgress<SftpTransferProgress>
    {
        private readonly List<SftpTransferProgress> _reports = [];
        private readonly List<TimeSpan> _times = [];
        private readonly Lock _gate = new();

        public Action<SftpTransferProgress>? OnReport { get; init; }

        public IReadOnlyList<SftpTransferProgress> Reports
        {
            get
            {
                lock (_gate)
                {
                    return [.. _reports];
                }
            }
        }

        public IReadOnlyList<TimeSpan> Times
        {
            get
            {
                lock (_gate)
                {
                    return [.. _times];
                }
            }
        }

        public void Report(SftpTransferProgress value)
        {
            lock (_gate)
            {
                _reports.Add(value);
                _times.Add(clock?.Now ?? TimeSpan.Zero);
            }

            OnReport?.Invoke(value);
        }
    }

    /// <summary>A clock that moves a fixed step each time it's read, so throttling can be tested without waiting.</summary>
    private sealed class StepClock(TimeSpan step) : TimeProvider
    {
        private long _now = TimeSpan.TicksPerDay;
        private int _reads;

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;

        public TimeSpan Now => TimeSpan.FromTicks(Volatile.Read(ref _now));

        public int Reads => Volatile.Read(ref _reads);

        public static StepClock Frozen() => new(TimeSpan.Zero);

        public static StepClock Every(TimeSpan step) => new(step);

        public override long GetTimestamp()
        {
            Interlocked.Increment(ref _reads);
            return Interlocked.Add(ref _now, step.Ticks);
        }
    }

    private sealed class NonSeekableStream(byte[] data) : MemoryStream(data)
    {
        public override bool CanSeek => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }
    }
}

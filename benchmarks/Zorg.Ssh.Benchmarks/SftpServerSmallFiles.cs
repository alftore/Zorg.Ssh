using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Zorg.Ssh.Sftp;

namespace Zorg.Ssh.Benchmarks;

/// <summary>
/// Many small files through Zorg.Ssh's own SFTP server, in process, on loopback, with the Zorg.Ssh client. The server's
/// root is a new directory in the temp directory, so the local disk is part of every number. Run it with
/// <c>--sftp-server</c>. Each request waits for its reply before the next goes, as most applications do, so this
/// measures a round trip through both ends and the file system. Optional: <c>--files N</c> (2,000), <c>--rounds N</c>
/// (5, after one warmup round), <c>--size N</c> (bytes per file, 1,024), <c>--lists N</c> (listings per round, 10).
/// </summary>
internal static class SftpServerSmallFiles
{
    private const string Directory1 = "bench/a/b/c";

    private static readonly string[] Phases = ["create", "stat", "read", "list", "remove"];

    public static async Task RunAsync(string[] args)
    {
        int files = Option(args, "--files", 2000);
        int rounds = Option(args, "--rounds", 5);
        int size = Option(args, "--size", 1024);
        int lists = Option(args, "--lists", 10);

        string root = Directory.CreateTempSubdirectory("zorg-bench-sftp-").FullName;
        using SshHostKey hostKey = SshHostKey.GenerateEd25519();
        try
        {
            await using SshServer server = await SshServer.StartAsync(new SshServerOptions
            {
                Address = IPAddress.Loopback,
                Port = 0,
                HostKeys = [hostKey],
                PasswordHandler = (_, _) => ValueTask.FromResult(SshAuthDecision.Accept),
                SessionHandler = (session, ct) => session is { Kind: SshSessionKind.Subsystem, Command: "sftp" }
                    ? SftpServer.ServeAsync(session, new SftpServerOptions { RootDirectory = root }, ct)
                    : Task.FromResult(1),
            });
            await using SshClient client = await SshClient.ConnectAsync(new SshClientOptions
            {
                Host = "127.0.0.1",
                Port = server.LocalEndPoint.Port,
                UserName = "bench",
                Credentials = [SshCredential.FromPassword("bench")],
                HostKeyPolicy = HostKeyPolicy.Fingerprint(hostKey.Sha256Fingerprint),
            });
            await using SftpClient sftp = await client.OpenSftpAsync();
            await sftp.CreateDirectoryAsync(Directory1, recursive: true);

            byte[] data = new byte[size];
            new Random(1).NextBytes(data);
            Console.WriteLine(string.Create(CultureInfo.InvariantCulture, $"SFTP server, small files: {files} files of {size} bytes in /{Directory1}/rN, {lists} listings, {rounds} rounds after 1 warmup, root {root}"));
            Console.WriteLine(string.Create(CultureInfo.InvariantCulture, $"Process: server GC {System.Runtime.GCSettings.IsServerGC}, {Environment.ProcessorCount} logical CPUs"));

            Dictionary<string, List<double>> rates = Phases.ToDictionary(p => p, _ => new List<double>());
            Dictionary<string, List<double>> bytes = Phases.ToDictionary(p => p, _ => new List<double>());
            for (int round = 0; round <= rounds; round++)
            {
                string directory = string.Create(CultureInfo.InvariantCulture, $"/{Directory1}/r{round}");
                await sftp.CreateDirectoryAsync(directory);
                string[] paths = [.. Enumerable.Range(0, files).Select(i => string.Create(CultureInfo.InvariantCulture, $"{directory}/file-{i:D5}.dat"))];

                (double Rate, double Bytes)[] results =
                [
                    await MeasureAsync(files, async () =>
                    {
                        foreach (string path in paths)
                        {
                            await sftp.WriteAllBytesAsync(path, data);
                        }
                    }),
                    await MeasureAsync(files, async () =>
                    {
                        foreach (string path in paths)
                        {
                            _ = await sftp.GetAttributesAsync(path);
                        }
                    }),
                    await MeasureAsync(files, async () =>
                    {
                        foreach (string path in paths)
                        {
                            if ((await sftp.ReadAllBytesAsync(path)).Length != size)
                            {
                                throw new InvalidOperationException("A file came back the wrong size.");
                            }
                        }
                    }),
                    await MeasureAsync(lists, async () =>
                    {
                        for (int i = 0; i < lists; i++)
                        {
                            int count = 0;
                            await foreach (SftpEntry entry in sftp.ListDirectoryAsync(directory))
                            {
                                count++;
                            }

                            if (count < files)
                            {
                                throw new InvalidOperationException("The listing came back short.");
                            }
                        }
                    }),
                    await MeasureAsync(files, async () =>
                    {
                        foreach (string path in paths)
                        {
                            await sftp.DeleteFileAsync(path);
                        }
                    }),
                ];
                await sftp.DeleteDirectoryAsync(directory);

                string label = round == 0 ? "warmup" : string.Create(CultureInfo.InvariantCulture, $"round {round}");
                Console.WriteLine(label + ": " + string.Join(", ", Phases.Select((p, i) => string.Create(CultureInfo.InvariantCulture, $"{p} {results[i].Rate:F0}/s {results[i].Bytes / 1024:F1} KB/op"))));
                if (round > 0)
                {
                    for (int i = 0; i < Phases.Length; i++)
                    {
                        rates[Phases[i]].Add(results[i].Rate);
                        bytes[Phases[i]].Add(results[i].Bytes);
                    }
                }
            }

            Console.WriteLine();
            Console.WriteLine("| Operation | Median ops/s | Lowest | Highest | Allocated per op (client and server) |");
            Console.WriteLine("|---|---:|---:|---:|---:|");
            foreach (string phase in Phases)
            {
                List<double> r = [.. rates[phase].Order()];
                string unit = phase == "list" ? $"listings of {files}" : "files";
                Console.WriteLine(string.Create(CultureInfo.InvariantCulture, $"| {phase} ({unit}) | {Median(r):F1} | {r[0]:F1} | {r[^1]:F1} | {Median([.. bytes[phase].Order()]) / 1024:F1} KB |"));
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static async Task<(double Rate, double Bytes)> MeasureAsync(int operations, Func<Task> run)
    {
        long allocated = GC.GetTotalAllocatedBytes(precise: true);
        Stopwatch watch = Stopwatch.StartNew();
        await run();
        watch.Stop();
        long used = GC.GetTotalAllocatedBytes(precise: true) - allocated;
        return (operations / watch.Elapsed.TotalSeconds, (double)used / operations);
    }

    private static double Median(List<double> sorted) =>
        sorted.Count % 2 == 1 ? sorted[sorted.Count / 2] : (sorted[(sorted.Count / 2) - 1] + sorted[sorted.Count / 2]) / 2;

    private static int Option(string[] args, string name, int fallback)
    {
        int index = Array.IndexOf(args, name);
        return index >= 0 && index + 1 < args.Length ? int.Parse(args[index + 1], CultureInfo.InvariantCulture) : fallback;
    }
}

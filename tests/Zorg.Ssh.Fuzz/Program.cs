using System;
using System.IO;
using SharpFuzz;

namespace Zorg.Ssh.Fuzz;

/// <summary>
/// Entry point for the coverage-guided fuzz targets. Under libFuzzer (scripts/fuzz.sh) it loops on inputs
/// from shared memory. With a file path it runs that one input, which reproduces a crash.
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length >= 2 && args[0] == "--seed")
        {
            SeedCorpus.Write(args[1]);
            return 0;
        }

        if (args.Length < 1 || !Targets.TryGet(args[0], out ReadOnlySpanAction? target))
        {
            Console.Error.WriteLine("Usage: Zorg.Ssh.Fuzz <packet-reader|packet-reader-ctr-eam|kex-init|sftp-response> [input-file]");
            Console.Error.WriteLine("       Zorg.Ssh.Fuzz --seed <directory>");
            return 2;
        }

        if (args.Length >= 2)
        {
            target(File.ReadAllBytes(args[1]));
            return 0;
        }

        Fuzzer.LibFuzzer.Run(target);
        return 0;
    }
}

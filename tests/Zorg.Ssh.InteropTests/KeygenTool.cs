using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Zorg.Ssh.InteropTests;

/// <summary>Real <c>ssh-keygen</c> into a temporary directory. Nothing it writes outlives the test.</summary>
internal sealed class KeygenTool : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("zorg-ssh-m5").FullName;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    public static string Base64(string path) => Convert.ToBase64String(File.ReadAllBytes(path));

    public string PathOf(string name) => Path.Combine(_directory, name);

    /// <summary>Makes a key and returns its private file's path. The public half is beside it, ending <c>.pub</c>.</summary>
    public async Task<string> GenerateAsync(string type, string bits)
    {
        string path = PathOf($"key-{type}-{bits}-{Guid.NewGuid():N}");
        await RunAsync("-q", "-t", type, "-b", bits, "-N", string.Empty, "-f", path);
        return path;
    }

    /// <summary>Has a CA sign a key, and returns the certificate's path.</summary>
    public async Task<string> SignAsync(string ca, string key, params string[] options)
    {
        List<string> arguments = ["-q", "-s", ca, "-I", "zorg-interop"];
        arguments.AddRange(options);
        arguments.Add(key + ".pub");
        await RunAsync([.. arguments]);
        return key + "-cert.pub";
    }

    private static string KeygenPath()
    {
        string ssh = PeerTools.RequireSshClient();
        return Path.Combine(Path.GetDirectoryName(ssh)!, OperatingSystem.IsWindows() ? "ssh-keygen.exe" : "ssh-keygen");
    }

    private static async Task RunAsync(params string[] arguments)
    {
        ProcessStartInfo start = new(KeygenPath())
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (string argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using Process process = Process.Start(start)!;
        Task<string> error = process.StandardError.ReadToEndAsync(Ct);
        await process.StandardOutput.ReadToEndAsync(Ct);
        await process.WaitForExitAsync(Ct);
        Assert.True(process.ExitCode == 0, await error);
    }
}

/// <summary>Makes a shell line that writes a file from the host into a container, through the command line.</summary>
internal static class ContainerScript
{
    public static string WriteFile(string source, string target, string mode = "644")
    {
        return $"echo {KeygenTool.Base64(source)} | base64 -d > {target} && chmod {mode} {target} && ";
    }
}

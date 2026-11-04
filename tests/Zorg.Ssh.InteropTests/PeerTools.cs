using System;
using System.IO;
using System.Linq;
using System.Reflection;
using Xunit;

namespace Zorg.Ssh.InteropTests;

/// <summary>
/// Finds the real peers. A missing peer skips a local run but fails in CI, because an interop
/// test that passes by skipping proves nothing.
/// </summary>
internal static class PeerTools
{
    public const string SshClientVariable = "ZORG_SSH_CLIENT";

    private static bool InCi => Environment.GetEnvironmentVariable("CI") == "true";

    public static string PeersPath { get; } = typeof(PeerTools).Assembly
        .GetCustomAttributes<AssemblyMetadataAttribute>()
        .Single(a => a.Key == "PeersPath").Value!;

    public static string RequireSshClient()
    {
        string[] candidates =
        [
            Environment.GetEnvironmentVariable(SshClientVariable) ?? string.Empty,
            @"C:\Program Files\Git\usr\bin\ssh.exe",
            "/usr/bin/ssh",
        ];
        string? found = candidates.FirstOrDefault(c => c.Length != 0 && File.Exists(c));
        return found ?? Missing<string>("an OpenSSH ssh client");
    }

    public static void RequireContainers()
    {
        if (!ContainerCli.IsAvailable)
        {
            Missing<bool>("podman or docker");
        }
    }

    private static T Missing<T>(string what)
    {
        if (InCi)
        {
            throw new InvalidOperationException($"CI must have {what}.");
        }

        Assert.Skip($"Needs {what}.");
        return default!;
    }
}

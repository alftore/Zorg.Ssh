using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Xunit;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.Tests.Crypto;

/// <summary>
/// Finds and runs the real OpenSSH tools. A missing tool skips locally. It fails when <c>CI</c> is set or
/// <c>ZORG_REQUIRE_PEERS=1</c>, because a test that passes by skipping proves nothing.
/// </summary>
internal static class OpenSshTools
{
    /// <summary>Returns the full path of a tool, or stops the test.</summary>
    public static string Require(string name)
    {
        string? path = Find(name);
        if (path is not null)
        {
            return path;
        }

        if (Environment.GetEnvironmentVariable("CI") is not null || Environment.GetEnvironmentVariable("ZORG_REQUIRE_PEERS") == "1")
        {
            Assert.Fail($"{name} is missing. CI and ZORG_REQUIRE_PEERS=1 must not pass by skipping an interop test.");
        }

        Assert.Skip($"{name} isn't installed here.");
        return string.Empty;
    }

    /// <summary>Runs a tool to its end, and returns the exit code with all its output.</summary>
    public static (int ExitCode, string Output) Run(string tool, IEnumerable<string> arguments, byte[]? input = null)
    {
        using Process process = Start(tool, arguments);
        if (input is not null)
        {
            process.StandardInput.BaseStream.Write(input);
        }

        process.StandardInput.Close();
        var error = process.StandardError.ReadToEndAsync();
        string output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        return (process.ExitCode, output + error.GetAwaiter().GetResult());
    }

    /// <summary>Starts a tool with every stream redirected.</summary>
    public static Process Start(string tool, IEnumerable<string> arguments)
    {
        ProcessStartInfo start = new(tool)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        foreach (string argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        return Process.Start(start) ?? throw new InvalidOperationException("The process didn't start.");
    }

    private static string? Find(string name)
    {
        bool windows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        string file = windows ? name + ".exe" : name;

        // Git's copy first on Windows: it's much newer than the one in the OS.
        IEnumerable<string> directories = windows ? [@"C:\Program Files\Git\usr\bin"] : [];
        directories = directories.Concat((Environment.GetEnvironmentVariable("PATH") ?? string.Empty).Split(Path.PathSeparator));
        return directories
            .Where(static directory => directory.Length != 0)
            .Select(directory => Path.Combine(directory, file))
            .FirstOrDefault(File.Exists);
    }
}

/// <summary>A temporary directory, removed with everything in it.</summary>
internal sealed class TempDirectory : IDisposable
{
    public string Path { get; } = Directory.CreateTempSubdirectory("zorg-ssh-test-").FullName;

    public void Dispose() => Directory.Delete(Path, recursive: true);
}

/// <summary>
/// The SSHSIG format (OpenSSH's PROTOCOL.sshsig), which is the one thing <c>ssh-keygen</c> will sign and
/// check. Its inner signature blob is the same one SSH uses, so it exercises real signatures both ways.
/// </summary>
internal static class Sshsig
{
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("SSHSIG");

    public static (byte[] PublicKey, string Namespace, string Hash, byte[] Signature) Parse(string armored)
    {
        string base64 = string.Concat(armored.Split('\n').Select(static line => line.Trim()).Where(static line => !line.StartsWith("-----", StringComparison.Ordinal)));
        byte[] raw = Convert.FromBase64String(base64);
        SshReader reader = new(raw);
        Assert.Equal(Magic, reader.ReadRaw(6).ToArray());
        Assert.Equal(1u, reader.ReadUInt32());
        byte[] publicKey = reader.ReadBinary().ToArray();
        string space = reader.ReadUtf8String();
        reader.ReadBinary();
        string hash = reader.ReadUtf8String();
        byte[] signature = reader.ReadBinary().ToArray();
        reader.EnsureEnd();
        return (publicKey, space, hash, signature);
    }

    /// <summary>Returns the name inside a signature blob.</summary>
    public static string SignatureAlgorithm(byte[] signature)
    {
        SshReader reader = new(signature);
        return reader.ReadUtf8String();
    }

    /// <summary>Returns the bytes an SSHSIG signature actually covers.</summary>
    public static byte[] SignedData(string space, ReadOnlySpan<byte> message)
    {
        SshWriter writer = new();
        try
        {
            writer.WriteRaw(Magic);
            writer.WriteUtf8String(space);
            writer.WriteBinary([]);
            writer.WriteUtf8String("sha512");
            writer.WriteBinary(SHA512.HashData(message));
            return writer.ToArray();
        }
        finally
        {
            writer.Dispose();
        }
    }

    /// <summary>Wraps our key and signature so that <c>ssh-keygen</c> can check them.</summary>
    public static string Armor(ReadOnlySpan<byte> publicKey, string space, byte[] signature)
    {
        SshWriter writer = new();
        try
        {
            writer.WriteRaw(Magic);
            writer.WriteUInt32(1);
            writer.WriteBinary(publicKey);
            writer.WriteUtf8String(space);
            writer.WriteBinary([]);
            writer.WriteUtf8String("sha512");
            writer.WriteBinary(signature);
            string base64 = Convert.ToBase64String(writer.Written);
            StringBuilder text = new("-----BEGIN SSH SIGNATURE-----\n");
            for (int i = 0; i < base64.Length; i += 70)
            {
                text.Append(base64, i, Math.Min(70, base64.Length - i)).Append('\n');
            }

            return text.Append("-----END SSH SIGNATURE-----\n").ToString();
        }
        finally
        {
            writer.Dispose();
        }
    }

    /// <summary>Gives the public key in a .pub line as a blob.</summary>
    public static byte[] PublicKeyLine(string line) => Convert.FromBase64String(line.Split(' ')[1]);
}

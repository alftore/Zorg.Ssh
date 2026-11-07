using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Xunit;

namespace Zorg.Ssh.Tests;

/// <summary>
/// Tests listen on loopback only. Anything wider makes Windows Defender Firewall ask whether to allow testhost, and
/// nobody may be there to answer, which stalls the run.
/// </summary>
public sealed partial class ListenAddressGuardTests
{
    // Files that may name a wildcard address because it never reaches a real listener.
    private static readonly string[] AllowedFiles =
    [
        // Documentation sample, compiled but not run by any test.
        "samples/Zorg.Ssh.Examples/ServerExamples.cs",
    ];

    // Folders whose "0.0.0.0" and "::" strings are payloads for a scripted peer (tcpip-forward and the like) or mutation seeds.
    private static readonly string[] ScriptedPeerFolders =
    [
        "tests/Zorg.Ssh.Tests/Fuzzing/",
    ];

    [GeneratedRegex(@"IPAddress\s*\.\s*(Any|IPv6Any)\b")]
    private static partial Regex WildcardProperty();

    [GeneratedRegex("\"(0\\.0\\.0\\.0|::)\"")]
    private static partial Regex WildcardString();

    [Fact]
    public void No_test_listens_on_a_wildcard_address()
    {
        string root = FindRoot();
        string self = nameof(ListenAddressGuardTests) + ".cs";
        string[] offences =
        [
            .. Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories)
                .Select(path => (Path: path, Relative: System.IO.Path.GetRelativePath(root, path).Replace('\\', '/')))
                .Where(f => (f.Relative.StartsWith("tests/", StringComparison.Ordinal) || f.Relative.StartsWith("samples/", StringComparison.Ordinal))
                    && !f.Relative.Contains("/obj/", StringComparison.Ordinal)
                    && !f.Relative.Contains("/bin/", StringComparison.Ordinal)
                    && !f.Relative.EndsWith(self, StringComparison.Ordinal)
                    && !AllowedFiles.Contains(f.Relative))
                .SelectMany(f => File.ReadAllLines(f.Path).Select((line, i) => (f.Relative, Line: i + 1, Text: line))
                    .Where(l => WildcardProperty().IsMatch(l.Text)
                        || (WildcardString().IsMatch(l.Text) && !ScriptedPeerFolders.Any(d => l.Relative.StartsWith(d, StringComparison.Ordinal))))
                    .Select(l => $"{l.Relative}:{l.Line}")),
        ];

        Assert.True(offences.Length == 0, "Listen on IPAddress.Loopback, not a wildcard, or the Windows firewall prompts: " + string.Join(", ", offences));
    }

    private static string FindRoot()
    {
        for (DirectoryInfo? dir = new(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(System.IO.Path.Combine(dir.FullName, "Zorg.Ssh.slnx")))
            {
                return dir.FullName;
            }
        }

        throw new InvalidOperationException("Zorg.Ssh.slnx not found above the test output folder.");
    }
}

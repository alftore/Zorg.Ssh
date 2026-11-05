using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Zorg.Ssh.Examples;

/// <summary>
/// Proves that the C# in the docs compiles: every <c>csharp</c> block in a Markdown file must equal a region of this
/// project between <c>// doc:name</c> and <c>// end-doc</c>, apart from indentation. Every region must be used too.
/// </summary>
internal static class DocsCheck
{
    private const string Fence = "```";
    private const string Start = "// doc:";
    private const string End = "// end-doc";

    public static int Run(string root)
    {
        Dictionary<string, string> regions = ReadRegions(Path.Combine(root, "samples", "Zorg.Ssh.Examples"));
        HashSet<string> used = [];
        List<string> errors = [];
        int blocks = 0;

        foreach (string file in MarkdownFiles(root))
        {
            foreach ((int line, string code) in ReadBlocks(file))
            {
                blocks++;
                string? name = regions.FirstOrDefault(r => r.Value == code).Key;
                if (name is null)
                {
                    errors.Add($"{file}:{line}: this C# block matches no region in samples/Zorg.Ssh.Examples.");
                }
                else
                {
                    used.Add(name);
                }
            }
        }

        errors.AddRange(regions.Keys.Except(used).Select(name => $"The region '{name}' isn't used by any document."));
        foreach (string error in errors)
        {
            Console.Error.WriteLine(error);
        }

        Console.WriteLine($"Docs check: {blocks} C# blocks, {regions.Count} regions, {errors.Count} errors.");
        return errors.Count == 0 ? 0 : 1;
    }

    private static IEnumerable<string> MarkdownFiles(string root) =>
        new[] { "README.md", "PACKAGE.md" }.Select(name => Path.Combine(root, name))
            .Concat(Directory.GetFiles(Path.Combine(root, "docs"), "*.md"));

    private static IEnumerable<(int Line, string Code)> ReadBlocks(string file)
    {
        string[] lines = File.ReadAllLines(file);
        for (int i = 0; i < lines.Length; i++)
        {
            if (lines[i].Trim() != Fence + "csharp")
            {
                continue;
            }

            int start = i + 1;
            int end = Array.FindIndex(lines, start, line => line.Trim() == Fence);
            yield return (start, Normalise(lines[start..end]));
            i = end;
        }
    }

    private static Dictionary<string, string> ReadRegions(string directory)
    {
        Dictionary<string, string> regions = [];
        foreach (string file in Directory.GetFiles(directory, "*Examples.cs"))
        {
            string[] lines = File.ReadAllLines(file);
            for (int i = 0; i < lines.Length; i++)
            {
                string trimmed = lines[i].Trim();
                if (trimmed.StartsWith(Start, StringComparison.Ordinal))
                {
                    int end = Array.FindIndex(lines, i, line => line.Trim() == End);
                    regions.Add(trimmed[Start.Length..], Normalise(lines[(i + 1)..end]));
                    i = end;
                }
            }
        }

        return regions;
    }

    private static string Normalise(string[] lines)
    {
        int indent = lines.Where(line => line.Length != 0).Min(line => line.Length - line.TrimStart().Length);
        return string.Join('\n', lines.Select(line => line.Length == 0 ? line : line[indent..].TrimEnd()));
    }
}

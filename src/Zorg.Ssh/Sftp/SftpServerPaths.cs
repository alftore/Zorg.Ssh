using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Zorg.Ssh.Sftp;

/// <summary>A request that can't go ahead. Only the status reaches the client, so this carries no text.</summary>
#pragma warning disable CA1032, CA1064 // Never leaves the session: it's turned into a status there.
internal sealed class SftpServerRefusedException(SftpStatusCode status) : Exception
#pragma warning restore CA1032, CA1064
{
    public SftpStatusCode Status { get; } = status;
}

/// <summary>What to do when the last component of a path is a link.</summary>
internal enum SftpServerFinalLink
{
    /// <summary>Resolve it, as STAT and OPEN do.</summary>
    Follow,

    /// <summary>Stop at the link itself, as LSTAT and REMOVE do.</summary>
    Keep,
}

/// <summary>
/// Where a path leads, inside the root. Every component before the last is a real directory, or missing.
/// </summary>
/// <param name="RealPath">The path on this machine. Never send this to the client.</param>
/// <param name="VirtualPath">The same place as the client sees it.</param>
/// <param name="Parts">The components below the root.</param>
/// <param name="Attributes">What the last component is, or null if it doesn't exist.</param>
/// <param name="IsLink">Whether the last component is a link, which only <see cref="SftpServerFinalLink.Keep"/> can give.</param>
/// <param name="ParentMissing">Whether the directory holding the last component doesn't exist either.</param>
internal readonly record struct SftpServerResolved(
    string RealPath,
    string VirtualPath,
    IReadOnlyList<string> Parts,
    FileAttributes? Attributes,
    bool IsLink,
    bool ParentMissing)
{
    public bool Exists => Attributes is not null;

    public bool IsRoot => Parts.Count == 0;

    /// <summary>Gets a value saying whether this is a directory. A link to a directory counts on both Windows and Unix.</summary>
    public bool IsDirectory => Attributes is { } attributes && attributes.HasFlag(FileAttributes.Directory);
}

/// <summary>
/// The virtual root. This is the security boundary of the SFTP server: every path from a client goes through
/// <see cref="Resolve"/>, and no other code turns a client's path into a real one.
/// </summary>
/// <remarks>
/// A client's <c>..</c> is removed lexically and stops at the root. After that the path is walked from the root one
/// component at a time, with <c>lstat</c>. A link is read, not followed: its target goes back on the list of components
/// to walk, so the check applies to each step of it. In a link's target, <c>..</c> above the root or an absolute path
/// outside it is a refusal, not a clamp. The walk therefore never touches anything outside the root, so a client can't
/// even learn whether something outside exists.
/// </remarks>
internal sealed class SftpServerPaths
{
    private const int MaxPathLength = 4096;
    private const int MaxLinkHops = 32;

    private static readonly StringComparison RootComparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
    private static readonly char[] LinkSeparators = OperatingSystem.IsWindows() ? ['/', '\\'] : ['/'];

    private readonly string _root;

    public SftpServerPaths(string rootDirectory) => _root = Canonicalise(rootDirectory);

    /// <summary>Gets the root, with every link in it resolved.</summary>
    public string Root => _root;

    /// <summary>Turns a client's path into the place it leads, or refuses.</summary>
    public SftpServerResolved Resolve(string clientPath, SftpServerFinalLink finalLink)
    {
        Stack<string> pending = new();
        PushReversed(pending, Normalise(clientPath));
        return Walk([], pending, finalLink);
    }

    /// <summary>
    /// Works out what to store for a new link at <paramref name="link"/>. The target must stay inside the root from
    /// where the link is. An absolute target means the client's root, so it's stored relative to the link: a real
    /// absolute path would point outside. A relative target is stored in one shape only: <c>..</c> as a leading run
    /// that goes no higher than the root, then plain names that only go down.
    /// </summary>
    /// <remarks>
    /// The shape is what keeps a link inside the root whatever links are made later. Take the link's directory: it is
    /// a real directory below the root, with no link in its path, because <see cref="Resolve"/> walked it. The leading
    /// <c>..</c> run is no longer than its depth, so it ends at one of its ancestors, and that is inside the root. The
    /// names only descend from there. A name can be another link, but that link was made under the same rule, so by
    /// induction it ends inside the root too, wherever it sits. Nothing after a name can climb, so no later link can
    /// change where <c>..</c> goes, which a check made against the disk at one moment could not promise (<c>m/..</c>
    /// with <c>m</c> missing, then <c>m</c> made a link to <c>.</c>). The walk below still refuses names that pass
    /// through a link the host planted that leads out. A move keeps the rule true: <see cref="CheckMove"/> refuses one
    /// that would leave a leading run longer than the depth of its new directory.
    /// </remarks>
    public string PrepareLinkTarget(string target, SftpServerResolved link)
    {
        if (target.Length is 0 or > MaxPathLength || target.Contains('\0', StringComparison.Ordinal))
        {
            throw Invalid();
        }

        List<string> directory = [.. link.Parts.Take(link.Parts.Count - 1)];
        List<string> raw;
        if (target[0] == '/')
        {
            raw = RelativeTo(directory, Normalise(target));
        }
        else
        {
            raw = [.. target.Split('/', StringSplitOptions.RemoveEmptyEntries)];
            if (raw.Exists(static c => c is not ("." or "..") && !IsPlainName(c)))
            {
                throw Invalid();
            }
        }

        // Lexically: "." goes, "name/.." goes, and ".." that has no name before it stays, in front.
        List<string> components = [];
        foreach (string component in raw)
        {
            if (component == ".")
            {
                continue;
            }

            if (component == ".." && components.Count != 0 && components[^1] != "..")
            {
                components.RemoveAt(components.Count - 1);
                continue;
            }

            components.Add(component);
        }

        int climbs = components.TakeWhile(static c => c == "..").Count();
        if (climbs > directory.Count)
        {
            throw Escape();
        }

        // Empty, ".", or a way back to the link's own directory: a link that leads nowhere.
        List<string> place = [.. directory.Take(directory.Count - climbs), .. components.Skip(climbs)];
        if (components.Count == 0 || place.SequenceEqual(directory, StringComparer.FromComparison(RootComparison)))
        {
            throw Invalid();
        }

        Stack<string> pending = new();
        PushReversed(pending, components);
        Walk([.. directory], pending, SftpServerFinalLink.Follow);
        return string.Join(Path.DirectorySeparatorChar, components);
    }

    /// <summary>The most entries <see cref="CheckMove"/> looks at below a directory before it refuses the move.</summary>
    internal const int MaxMoveScanEntries = 10_000;

    /// <summary>
    /// Refuses a rename that would break the shape <see cref="PrepareLinkTarget"/> gives a link. A link moved to a
    /// directory too shallow for its leading <c>..</c> run would lead out of the root for any other program. A
    /// directory moved to a shallower place needs every link below it checked the same way, without following any.
    /// If there are too many entries to check, the move is refused. Run this under the namespace gate, before the move.
    /// </summary>
    public static void CheckMove(SftpServerResolved source, SftpServerResolved target)
    {
        List<string> newDirectory = [.. target.Parts.Take(target.Parts.Count - 1)];
        if (source.IsLink)
        {
            string? stored = new FileInfo(source.RealPath).LinkTarget;
            if (stored is not null && ClimbsOutOf(stored, newDirectory.Count, newDirectory))
            {
                throw Escape();
            }

            return;
        }

        if (!source.IsDirectory || target.Parts.Count >= source.Parts.Count)
        {
            return;
        }

        int budget = MaxMoveScanEntries;
        if (SftpServerLinux.IsSupported)
        {
            // .NET would decode a name that isn't UTF-8 with U+FFFD and then look for a path that isn't there, so a
            // link with such a name, or anything below a directory with one, would go unchecked.
            SftpServerLinux.ScanForClimbs(source.RealPath, target.Parts.Count, ref budget, static (stored, depth) => ClimbsOutOf(stored, depth, null));
            return;
        }

        ScanMoved(source.RealPath, target.Parts.Count, ref budget);
    }

    private static void ScanMoved(string directory, int depth, ref int budget)
    {
        foreach (string path in Directory.EnumerateFileSystemEntries(directory))
        {
            if (--budget < 0)
            {
                throw Invalid();
            }

            string? stored = new FileInfo(path).LinkTarget;
            if (stored is not null)
            {
                if (ClimbsOutOf(stored, depth, null))
                {
                    throw Escape();
                }
            }
            else if (Directory.Exists(path))
            {
                ScanMoved(path, depth + 1, ref budget);
            }
        }
    }

    /// <summary>Says whether a stored relative target has a leading <c>..</c> run longer than <paramref name="depth"/>, or comes back to <paramref name="directory"/>.</summary>
    private static bool ClimbsOutOf(string stored, int depth, List<string>? directory)
    {
        if (Path.IsPathRooted(stored))
        {
            return false;
        }

        string[] components = stored.Split(LinkSeparators, StringSplitOptions.RemoveEmptyEntries);
        int climbs = components.TakeWhile(static c => c == "..").Count();
        if (climbs > depth)
        {
            return true;
        }

        if (directory is null)
        {
            return false;
        }

        List<string> place = [.. directory.Take(directory.Count - climbs), .. components.Skip(climbs).Where(static c => c != ".")];
        return place.SequenceEqual(directory, StringComparer.FromComparison(RootComparison));
    }

    /// <summary>
    /// Turns a link's stored target into what a client may see: refused if it leads out of the root, otherwise
    /// relative as stored, or absolute in the client's terms.
    /// </summary>
    public string PresentLinkTarget(string target, SftpServerResolved link)
    {
        Stack<string> pending = new();
        List<string> parts = [.. link.Parts.Take(link.Parts.Count - 1)];
        PushLink(target, parts, pending);
        bool absolute = Path.IsPathRooted(target);
        string[] components = [.. pending];
        Walk(parts, pending, SftpServerFinalLink.Follow);
        if (absolute)
        {
            return "/" + string.Join('/', components);
        }

        return OperatingSystem.IsWindows() ? target.Replace('\\', '/') : target;
    }

    /// <summary>The refusal for a path that leads out of the root. It looks the same whatever was out there.</summary>
    private static SftpServerRefusedException Escape() => new(SftpStatusCode.PermissionDenied);

    private static SftpServerRefusedException Invalid() => new(SftpStatusCode.Failure);

    private static void PushReversed(Stack<string> pending, IReadOnlyList<string> components)
    {
        for (int i = components.Count - 1; i >= 0; i--)
        {
            pending.Push(components[i]);
        }
    }

    /// <summary>Splits a client's path and removes <c>.</c> and <c>..</c>. Absolute or not, it's relative to the root.</summary>
    private static List<string> Normalise(string path)
    {
        if (path.Length > MaxPathLength)
        {
            throw Invalid();
        }

        List<string> components = [];
        foreach (string component in path.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            if (component == ".")
            {
                continue;
            }

            if (component == "..")
            {
                if (components.Count != 0)
                {
                    components.RemoveAt(components.Count - 1);
                }

                continue;
            }

            // Checked even if a later ".." removes it, so that nothing odd is ever accepted.
            if (!IsPlainName(component))
            {
                throw Invalid();
            }

            components.Add(component);
        }

        return components;
    }

    /// <summary>
    /// Says whether this is one plain name here. On Windows that rules out colons (drives and alternate data
    /// streams), backslashes, device names, and trailing dots and spaces, which Win32 would strip.
    /// </summary>
    private static bool IsPlainName(string component) =>
        !component.Contains('\0', StringComparison.Ordinal) && (!OperatingSystem.IsWindows() || SftpLocalPath.IsSafeName(component));

    /// <summary>Writes <paramref name="target"/> as a path relative to <paramref name="directory"/>, both below the root.</summary>
    private static List<string> RelativeTo(List<string> directory, List<string> target)
    {
        int common = 0;
        while (common < directory.Count && common < target.Count && directory[common] == target[common])
        {
            common++;
        }

        List<string> relative = [.. Enumerable.Repeat("..", directory.Count - common)];
        relative.AddRange(target.Skip(common));
        return relative;
    }

    /// <summary>
    /// Resolves every link in the configured root. This is the one walk that may leave it, because the root is the
    /// host's choice and not the client's.
    /// </summary>
    private static string Canonicalise(string directory)
    {
        string full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory));
        string current = Path.GetPathRoot(full)!;
        Stack<string> pending = new();
        PushReversed(pending, full[current.Length..].Split(LinkSeparators, StringSplitOptions.RemoveEmptyEntries));
        int hops = 0;
        while (pending.TryPop(out string? component))
        {
            if (component == "..")
            {
                current = Path.GetDirectoryName(current) ?? current;
                continue;
            }

            if (component == ".")
            {
                continue;
            }

            string next = Path.Join(current, component);
            string? target = new FileInfo(next).LinkTarget;
            if (target is null)
            {
                current = next;
                continue;
            }

            if (++hops > MaxLinkHops)
            {
                throw new IOException("RootDirectory goes through too many symbolic links. Point it at the real directory.");
            }

            if (Path.IsPathRooted(target))
            {
                target = Path.GetFullPath(target);
                current = Path.GetPathRoot(target)!;
                target = target[current.Length..];
            }

            PushReversed(pending, target.Split(LinkSeparators, StringSplitOptions.RemoveEmptyEntries));
        }

        return Path.TrimEndingDirectorySeparator(current);
    }

    private string Join(List<string> parts) => parts.Count == 0 ? _root : Path.Join(_root, string.Join(Path.DirectorySeparatorChar, parts));

    /// <summary>
    /// The walk. <paramref name="parts"/> is a place already known to be inside the root, and
    /// <paramref name="pending"/> holds what's left to walk, in order. A <c>..</c> here came from a link.
    /// </summary>
    private SftpServerResolved Walk(List<string> parts, Stack<string> pending, SftpServerFinalLink finalLink)
    {
        int hops = 0;
        int missing = 0;
        while (pending.TryPop(out string? component))
        {
            if (component == "..")
            {
                if (parts.Count == 0)
                {
                    throw Escape();
                }

                parts.RemoveAt(parts.Count - 1);
                missing = Math.Max(0, missing - 1);
                continue;
            }

            parts.Add(component);
            if (missing > 0)
            {
                missing++;
                continue;
            }

            FileInfo info = new(Join(parts));
            FileAttributes attributes = info.Attributes;
            if ((int)attributes == -1)
            {
                missing = 1;
                continue;
            }

            string? target = ReadLinkTarget(info, attributes);
            if (target is null)
            {
                if (OperatingSystem.IsWindows() && attributes.HasFlag(FileAttributes.ReparsePoint))
                {
                    // Not a link .NET can read, so there's no telling where it leads.
                    throw Escape();
                }

                continue;
            }

            if (pending.Count == 0 && finalLink == SftpServerFinalLink.Keep)
            {
                break;
            }

            if (++hops > MaxLinkHops)
            {
                throw Invalid();
            }

            parts.RemoveAt(parts.Count - 1);
            PushLink(target, parts, pending);
        }

        return Finish(parts, missing);
    }

    private SftpServerResolved Finish(List<string> parts, int missing)
    {
        string real = Join(parts);
        FileInfo info = new(real);
        FileAttributes attributes = info.Attributes;
        bool exists = (int)attributes != -1;
        return new SftpServerResolved(
            real,
            "/" + string.Join('/', parts),
            parts,
            exists ? attributes : null,
            exists && ReadLinkTarget(info, attributes) is not null,
            missing > 1);
    }

    /// <summary>
    /// Reads where a link leads, or null if <paramref name="info"/> isn't one. .NET marks a link with
    /// <see cref="FileAttributes.ReparsePoint"/> on every platform (on Unix from the same <c>lstat</c> that gave
    /// <paramref name="attributes"/>), and <see cref="FileSystemInfo.LinkTarget"/> is null for anything without it, so
    /// only an entry with the flag costs the second call. The answer is the same as asking every time: it describes
    /// the entry as <paramref name="attributes"/> found it, a moment earlier.
    /// </summary>
    internal static string? ReadLinkTarget(FileSystemInfo info, FileAttributes attributes) =>
        attributes.HasFlag(FileAttributes.ReparsePoint) ? info.LinkTarget : null;

    /// <summary>Puts a link's target on the list. An absolute target has to name the root, and restarts the walk there.</summary>
    private void PushLink(string target, List<string> parts, Stack<string> pending)
    {
        string relative = target;
        if (Path.IsPathRooted(target))
        {
            // Rooted but not fully qualified, like \x or C:x on Windows, depends on the process's current directory.
            if (!Path.IsPathFullyQualified(target) || !target.StartsWith(_root, RootComparison))
            {
                throw Escape();
            }

            relative = target[_root.Length..];
            if (relative.Length != 0 && !Path.EndsInDirectorySeparator(_root) && !LinkSeparators.Contains(relative[0]))
            {
                throw Escape();
            }

            parts.Clear();
        }

        string[] components = relative.Split(LinkSeparators, StringSplitOptions.RemoveEmptyEntries);
        for (int i = components.Length - 1; i >= 0; i--)
        {
            string component = components[i];
            if (component == ".")
            {
                continue;
            }

            if (component != ".." && !IsPlainName(component))
            {
                throw Escape();
            }

            pending.Push(component);
        }
    }
}

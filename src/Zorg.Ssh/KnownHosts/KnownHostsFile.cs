using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Zorg.Ssh.Crypto;
using Zorg.Ssh.Protocol;

namespace Zorg.Ssh.KnownHosts;

/// <summary>What a known_hosts file says about a host and key.</summary>
internal enum KnownHostStatus
{
    /// <summary>The file has no key for this host.</summary>
    Unknown,

    /// <summary>The file lists this exact key for this host.</summary>
    Trusted,

    /// <summary>The file lists keys for this host, and this isn't one of them. This can mean an attack.</summary>
    Changed,

    /// <summary>The file marks this key as revoked for this host. This wins over any other line.</summary>
    Revoked,
}

/// <summary>The marker at the start of a known_hosts line.</summary>
internal enum KnownHostMarker
{
    /// <summary>A plain host key.</summary>
    None,

    /// <summary><c>@revoked</c>: the key must never be accepted.</summary>
    Revoked,

    /// <summary><c>@cert-authority</c>: the key signs host certificates. It isn't a host key itself.</summary>
    CertificateAuthority,
}

/// <summary>
/// The text of an OpenSSH known_hosts file, as <c>sshd(8)</c> describes it. Malformed lines are skipped, as OpenSSH
/// does. Keys are kept as raw blobs rather than parsed, so a line for a key type this library lacks still says the
/// host is known, and comparison is byte-exact.
/// </summary>
internal sealed class KnownHostsFile
{
    /// <summary>The largest file accepted, in characters or bytes. Real files are well under a megabyte.</summary>
    public const int MaxFileLength = 16 * 1024 * 1024;

    /// <summary>The longest line accepted, in characters. A longer one is skipped as malformed.</summary>
    public const int MaxLineLength = 64 * 1024;

    private const int DefaultPort = 22;
    private const int HashLength = 20;
    private const string HashMagic = "|1|";

    private readonly List<KnownHostsEntry> _entries;

    private KnownHostsFile(List<KnownHostsEntry> entries) => _entries = entries;

    /// <summary>Gets the lines that parsed, in file order.</summary>
    public IReadOnlyList<KnownHostsEntry> Entries => _entries;

    /// <summary>
    /// Reads known_hosts text. A file over <see cref="MaxFileLength"/> throws <see cref="SshHostKeyException"/>
    /// rather than reading part of it, because a dropped <c>@revoked</c> line would make a revoked key look unknown.
    /// </summary>
    public static KnownHostsFile Parse(ReadOnlySpan<char> text)
    {
        EnsureSize(text.Length);
        if (!text.IsEmpty && text[0] == '﻿')
        {
            text = text[1..];
        }

        List<KnownHostsEntry> entries = [];
        while (!text.IsEmpty)
        {
            int end = text.IndexOf('\n');
            ReadOnlySpan<char> line = end < 0 ? text : text[..end];
            text = end < 0 ? default : text[(end + 1)..];
            if (line.Length <= MaxLineLength && KnownHostsEntry.TryParse(line, out KnownHostsEntry? entry))
            {
                entries.Add(entry);
            }
        }

        return new KnownHostsFile(entries);
    }

    /// <summary>Reads a file. A file that doesn't exist reads as empty, so every host is unknown.</summary>
    public static KnownHostsFile Load(string path)
    {
        try
        {
            using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            EnsureSize(stream.Length);
            byte[] bytes = new byte[(int)stream.Length];
            int read = stream.ReadAtLeast(bytes, bytes.Length, throwOnEndOfStream: false);
            return Parse(Encoding.UTF8.GetString(bytes, 0, read));
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return new KnownHostsFile([]);
        }
    }

    /// <summary>
    /// Makes a line for a newly trusted host, without a line ending. The host name is hashed by default, so a stolen
    /// file doesn't list where the user connects.
    /// </summary>
    public static string FormatLine(string host, int port, SshPublicKey key, bool hashed = true)
    {
        ArgumentNullException.ThrowIfNull(key);
        EnsureWritableHost(host);
        string name = LookupName(host, port);
        string field = hashed ? HashedField(name) : name;
        return $"{field} {key.KeyType} {Convert.ToBase64String(key.Blob.Span)}";
    }

    /// <summary>Appends a line for a newly trusted host, creating the file if needed. The directory must exist.</summary>
    public static void Append(string path, string host, int port, SshPublicKey key, bool hashed = true)
    {
        byte[] line = Encoding.UTF8.GetBytes(FormatLine(host, port, key, hashed) + "\n");
        using FileStream stream = new(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read);
        if (stream.Length > 0)
        {
            // A last line with no ending would otherwise swallow this one.
            stream.Seek(-1, SeekOrigin.End);
            if (stream.ReadByte() != '\n')
            {
                stream.WriteByte((byte)'\n');
            }
        }

        stream.Write(line);
    }

    /// <summary>
    /// Checks a key for a host. <c>@cert-authority</c> lines play no part: a CA key isn't a host key. A host with
    /// keys of other types only is <see cref="KnownHostStatus.Changed"/>, where <c>ssh</c> would ask, because
    /// otherwise an attacker could turn a mismatch into a first connection by offering another key type.
    /// </summary>
    public KnownHostStatus Lookup(string host, int port, SshPublicKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        string name = LookupName(host, port);
        byte[] nameBytes = Encoding.UTF8.GetBytes(name);
        ReadOnlySpan<byte> blob = key.Blob.Span;

        bool trusted = false;
        bool otherKey = false;
        foreach (KnownHostsEntry entry in _entries)
        {
            if (entry.Marker == KnownHostMarker.CertificateAuthority || !entry.MatchesHost(name, nameBytes))
            {
                continue;
            }

            bool sameKey = blob.SequenceEqual(entry.Blob.Span);
            if (entry.Marker == KnownHostMarker.Revoked)
            {
                if (sameKey)
                {
                    return KnownHostStatus.Revoked;
                }
            }
            else if (sameKey)
            {
                trusted = true;
            }
            else
            {
                otherKey = true;
            }
        }

        if (trusted)
        {
            return KnownHostStatus.Trusted;
        }

        return otherKey ? KnownHostStatus.Changed : KnownHostStatus.Unknown;
    }

    /// <summary>
    /// The HMAC-SHA1 of a host name, keyed with the salt. The name is what the file hashes: lower case, in
    /// <c>[host]:port</c> form unless the port is 22.
    /// </summary>
    internal static byte[] HashName(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> name)
    {
#pragma warning disable CA5350 // SHA-1 is fixed by the known_hosts format. It hides names and guards no trust decision.
        return HMACSHA1.HashData(salt, name);
#pragma warning restore CA5350
    }

    /// <summary>The name OpenSSH looks a host up by, which is also what it hashes.</summary>
    private static string LookupName(string host, int port)
    {
        ArgumentException.ThrowIfNullOrEmpty(host);
        ArgumentOutOfRangeException.ThrowIfLessThan(port, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, 65535);

        // ssh lower-cases the name before looking it up, and a hash can't be compared any other way.
        string name = string.Create(host.Length, host, static (span, source) =>
        {
            for (int i = 0; i < span.Length; i++)
            {
                span[i] = KnownHostsEntry.Fold(source[i]);
            }
        });
        return port == DefaultPort ? name : $"[{name}]:{port}";
    }

    private static string HashedField(string name)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(HashLength);
        byte[] hash = HashName(salt, Encoding.UTF8.GetBytes(name));
        return $"{HashMagic}{Convert.ToBase64String(salt)}|{Convert.ToBase64String(hash)}";
    }

    /// <summary>
    /// Refuses a name that would mean something else in the file. A host often comes from a config file or a URL, so
    /// without this a line break would add a line of the caller's choosing, and a wildcard would trust other hosts.
    /// </summary>
    private static void EnsureWritableHost(string host)
    {
        ArgumentException.ThrowIfNullOrEmpty(host);
        foreach (char c in host)
        {
            if (char.IsWhiteSpace(c) || char.IsControl(c) || c is ',' or '*' or '?' or '!' or '|' or '#' or '@' or '[' or ']')
            {
                throw new ArgumentException("The host name holds a character that known_hosts can't store.", nameof(host));
            }
        }
    }

    private static void EnsureSize(long length)
    {
        if (length > MaxFileLength)
        {
            throw new SshHostKeyException("The known_hosts file is too large to read, so no host in it can be checked. Remove stale entries from it.");
        }
    }
}

/// <summary>One parsed line of a known_hosts file.</summary>
internal sealed class KnownHostsEntry
{
    private const int HashLength = 20;
    private const string HashMagic = "|1|";
    private const string Blanks = " \t";

    private readonly string _patterns;
    private readonly byte[]? _salt;
    private readonly byte[]? _hash;

    private KnownHostsEntry(KnownHostMarker marker, string patterns, byte[]? salt, byte[]? hash, string keyType, byte[] blob)
    {
        Marker = marker;
        _patterns = patterns;
        _salt = salt;
        _hash = hash;
        KeyType = keyType;
        Blob = blob;
    }

    /// <summary>Gets the line's marker.</summary>
    public KnownHostMarker Marker { get; }

    /// <summary>Gets whether the host field is hashed.</summary>
    public bool IsHashed => _hash is not null;

    /// <summary>Gets the key type field.</summary>
    public string KeyType { get; }

    /// <summary>Gets the public key blob.</summary>
    public ReadOnlyMemory<byte> Blob { get; }

    /// <summary>Reads a line. Returns false for blanks, comments, and anything malformed.</summary>
    internal static bool TryParse(ReadOnlySpan<char> line, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out KnownHostsEntry? entry)
    {
        entry = null;
        line = line.Trim(" \t\r");
        if (line.IsEmpty || line[0] == '#')
        {
            return false;
        }

        ReadOnlySpan<char> field = NextField(ref line);
        KnownHostMarker marker = KnownHostMarker.None;
        if (field[0] == '@')
        {
            if (field.SequenceEqual("@revoked"))
            {
                marker = KnownHostMarker.Revoked;
            }
            else if (field.SequenceEqual("@cert-authority"))
            {
                marker = KnownHostMarker.CertificateAuthority;
            }
            else
            {
                return false;
            }

            field = NextField(ref line);
        }

        ReadOnlySpan<char> hosts = field;
        ReadOnlySpan<char> keyType = NextField(ref line);
        ReadOnlySpan<char> encodedKey = NextField(ref line);
        if (hosts.IsEmpty || keyType.IsEmpty || encodedKey.IsEmpty)
        {
            return false;
        }

        byte[]? salt = null;
        byte[]? hash = null;
        if (hosts[0] == '|' && !TryParseHashedField(hosts, out salt, out hash))
        {
            return false;
        }

        byte[] blobBuffer = new byte[(encodedKey.Length / 4 * 3) + 3];
        if (!Convert.TryFromBase64Chars(encodedKey, blobBuffer, out int written))
        {
            return false;
        }

        byte[] blob = blobBuffer.AsSpan(0, written).ToArray();
        string keyTypeText = keyType.ToString();
        if (!BlobHasType(blob, keyTypeText))
        {
            return false;
        }

        entry = new KnownHostsEntry(marker, hash is null ? hosts.ToString() : string.Empty, salt, hash, keyTypeText, blob);
        return true;
    }

    /// <summary>Lower-cases an ASCII letter, as OpenSSH does for host names. Other characters stay as they are.</summary>
    internal static char Fold(char c) => c is >= 'A' and <= 'Z' ? (char)(c + ('a' - 'A')) : c;

    /// <summary>
    /// Matches a <c>*</c> and <c>?</c> pattern against a name, ignoring ASCII case. It backs up to the last star
    /// only, so its cost is at most the product of the two lengths. A recursive matcher can take exponential time in
    /// the number of stars, and here the pattern comes from a file.
    /// </summary>
    internal static bool MatchesGlob(ReadOnlySpan<char> pattern, ReadOnlySpan<char> name)
    {
        int p = 0;
        int n = 0;
        int star = -1;
        int resume = 0;
        while (n < name.Length)
        {
            if (p < pattern.Length && pattern[p] == '*')
            {
                star = p++;
                resume = n;
            }
            else if (p < pattern.Length && (pattern[p] == '?' || Fold(pattern[p]) == Fold(name[n])))
            {
                p++;
                n++;
            }
            else if (star >= 0)
            {
                p = star + 1;
                n = ++resume;
            }
            else
            {
                return false;
            }
        }

        while (p < pattern.Length && pattern[p] == '*')
        {
            p++;
        }

        return p == pattern.Length;
    }

    /// <summary>
    /// Matches a comma list. One matching negated pattern rules the name out, wherever it stands in the list.
    /// A list of negated patterns alone matches nothing.
    /// </summary>
    internal static bool MatchesList(ReadOnlySpan<char> patterns, ReadOnlySpan<char> name)
    {
        bool matched = false;
        foreach (Range range in patterns.Split(','))
        {
            ReadOnlySpan<char> pattern = patterns[range];
            bool negated = !pattern.IsEmpty && pattern[0] == '!';
            if (negated)
            {
                pattern = pattern[1..];
            }

            if (MatchesGlob(pattern, name))
            {
                if (negated)
                {
                    return false;
                }

                matched = true;
            }
        }

        return matched;
    }

    /// <summary>Gets whether this line applies to a host, given its lookup name as text and as UTF-8.</summary>
    internal bool MatchesHost(string name, ReadOnlySpan<byte> nameBytes)
    {
        if (_salt is null || _hash is null)
        {
            return MatchesList(_patterns, name);
        }

        return CryptographicOperations.FixedTimeEquals(KnownHostsFile.HashName(_salt, nameBytes), _hash);
    }

    private static ReadOnlySpan<char> NextField(ref ReadOnlySpan<char> line)
    {
        line = line.TrimStart(Blanks);
        int end = line.IndexOfAny(Blanks);
        ReadOnlySpan<char> field = end < 0 ? line : line[..end];
        line = end < 0 ? default : line[end..];
        return field;
    }

    /// <summary>Reads <c>|1|salt|hash</c>. OpenSSH requires both to be the 20 bytes of a SHA-1 output.</summary>
    private static bool TryParseHashedField(ReadOnlySpan<char> field, out byte[]? salt, out byte[]? hash)
    {
        salt = null;
        hash = null;
        if (!field.StartsWith(HashMagic, StringComparison.Ordinal))
        {
            return false;
        }

        ReadOnlySpan<char> rest = field[HashMagic.Length..];
        int separator = rest.IndexOf('|');
        if (separator < 0)
        {
            return false;
        }

        byte[] saltBytes = new byte[HashLength + 3];
        byte[] hashBytes = new byte[HashLength + 3];
        if (!Convert.TryFromBase64Chars(rest[..separator], saltBytes, out int saltLength) || saltLength != HashLength
            || !Convert.TryFromBase64Chars(rest[(separator + 1)..], hashBytes, out int hashLength) || hashLength != HashLength)
        {
            return false;
        }

        salt = saltBytes[..HashLength];
        hash = hashBytes[..HashLength];
        return true;
    }

    /// <summary>A key blob starts with its own type. A line where the two differ isn't a key of that type.</summary>
    private static bool BlobHasType(ReadOnlySpan<byte> blob, string keyType)
    {
        try
        {
            SshReader reader = new(blob);
            return reader.ReadUtf8String() == keyType;
        }
        catch (SshProtocolException)
        {
            return false;
        }
    }
}

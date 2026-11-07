using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace Zorg.Ssh.Tests.Fuzzing;

/// <summary>One seed input of a corpus: bytes for a binary format, or text for a text format.</summary>
/// <param name="Name">What it is, for reports.</param>
/// <param name="Data">The bytes. For text, UTF-16 code units copied as they are, so a lone surrogate survives.</param>
/// <param name="IsText">Whether the mutator should treat the input as text.</param>
internal sealed record FuzzSeed(string Name, byte[] Data, bool IsText = false)
{
    public static FuzzSeed Binary(string name, byte[] data) => new(name, data);

    public static FuzzSeed Text(string name, string text) => new(name, FuzzText.Encode(text), IsText: true);

    /// <summary>Gets the text of a text seed or input.</summary>
    public string AsText() => FuzzText.Decode(Data);
}

/// <summary>Moves text in and out of the byte arrays the runner handles, without validating it.</summary>
internal static class FuzzText
{
    public static byte[] Encode(string text) => MemoryMarshal.AsBytes(text.AsSpan()).ToArray();

    public static string Decode(ReadOnlySpan<byte> bytes) => new(MemoryMarshal.Cast<byte, char>(bytes[..(bytes.Length & ~1)]));

    /// <summary>Shows text on one line, with every control or odd character escaped, to put in a message or a test.</summary>
    public static string Escape(string text, int max = 600)
    {
        StringBuilder builder = new();
        foreach (char c in text)
        {
            if (builder.Length >= max)
            {
                builder.Append("...");
                break;
            }

            switch (c)
            {
                case '\n':
                    builder.Append("\\n");
                    break;
                case '\r':
                    builder.Append("\\r");
                    break;
                case '\t':
                    builder.Append("\\t");
                    break;
                case '"':
                    builder.Append("\\\"");
                    break;
                case '\\':
                    builder.Append("\\\\");
                    break;
                case < ' ' or > '~':
                    builder.Append($"\\u{(int)c:x4}");
                    break;
                default:
                    builder.Append(c);
                    break;
            }
        }

        return builder.ToString();
    }
}

/// <summary>
/// Finds the length fields in SSH-encoded bytes. The format is length-prefixed strings inside length-prefixed strings,
/// and nothing in the bytes says where the prefixes are, so this walks chains: a 4-byte count that fits in what's left,
/// then the next count after the string it names, and so on. A chain of two or more, or one that ends exactly at the end,
/// is taken as real, and the strings inside are searched the same way. It can be wrong. A wrong guess costs the mutator
/// one wasted change, and the corpus builders can name offsets they know.
/// </summary>
internal static class FuzzLengthFields
{
    private const int MaxDepth = 4;
    private const int TopLevelStarts = 1536;

    public static List<int> Find(ReadOnlySpan<byte> data, IReadOnlyList<int>? known = null)
    {
        SortedSet<int> found = [];
        if (known is not null)
        {
            foreach (int offset in known)
            {
                if (offset >= 0 && offset + 4 <= data.Length)
                {
                    found.Add(offset);
                }
            }
        }

        Scan(data, 0, data.Length, TopLevelStarts, 0, found);
        return [.. found];
    }

    private static void Scan(ReadOnlySpan<byte> data, int start, int end, int starts, int depth, SortedSet<int> found)
    {
        if (depth > MaxDepth)
        {
            return;
        }

        int last = Math.Min(start + starts, end - 4);
        for (int s = start; s <= last; s++)
        {
            List<(int Offset, int Length)> members = [];
            int p = s;
            while (p + 4 <= end)
            {
                uint value = BinaryPrimitives.ReadUInt32BigEndian(data[p..]);
                if (value > (uint)(end - p - 4))
                {
                    break;
                }

                members.Add((p, (int)value));
                p += 4 + (int)value;
                if (p == end)
                {
                    break;
                }
            }

            bool real = members.Count > 0 && members[0].Length > 0 && (members.Count >= 2 || p == end);
            if (!real)
            {
                continue;
            }

            foreach ((int offset, int length) in members)
            {
                if (found.Add(offset) && length >= 8)
                {
                    Scan(data, offset + 4, offset + 4 + length, 1, depth + 1, found);
                }
            }
        }
    }
}

/// <summary>
/// Turns a seed into a hostile input. Binary seeds are changed by bit flips, truncation, splices and boundary values, and
/// above all by changes to length fields, because in this format a wrong length is what a parser has most to get right.
/// Text seeds are changed by character, token, line and number edits. The same seed number always gives the same input.
/// </summary>
internal static class FuzzMutator
{
    /// <summary>Inputs never grow past this, so a mutation can't make the run itself slow.</summary>
    public const int MaxBinaryLength = 1 << 17;

    private const int MaxTextLength = 1 << 17;

    private static readonly uint[] Boundaries =
    [
        0, 1, 2, 3, 4, 5, 7, 8, 15, 16, 17, 31, 32, 33, 64, 127, 128, 129, 255, 256, 257, 511, 512, 1023, 1024, 2047, 2048, 2049, 2050, 4095, 4096, 4097,
        8191, 8192, 16383, 16384, 16385, 32767, 32768, 65535, 65536, 65537, 131071, 131072, 131073, 262143, 262144, 262145, 0xFFFFFF, 0x1000000,
        0x3FFFFFFF, 0x40000000, 0x7FFFFFFE, 0x7FFFFFFF, 0x80000000, 0x80000001, 0xFFFFFFFE, 0xFFFFFFFF,
    ];

    /// <summary>The values that decide whether a length check uses the right integer type: signed overflow and unsigned wrap.</summary>
    private static readonly uint[] ExtremeLengths = [0, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0xFFFFFFFE, 0x7FFFFFFE, 0x01000000, 0x00FFFFFF];

    private static readonly string[] InterestingText =
    [
        string.Empty, " ", "\t", "\n", "\r\n", "\r", "\0", "#", "*", "?", "!", "!*", "*,!*", "@", "@revoked", "@cert-authority", "|1|", "|1||", "|", ",", ",,", "=", "%", "%%", "%h", "%z", "\"", "\\", "'", "/",
        "~", "~/", "..", "../", ":", "::", "[", "]", "[::1]:22", "-", "0", "-1", "00", "0x10", "1e9", "65535", "65536", "99999999999999999999", "2147483647", "2147483648", "4294967295", "4294967296",
        "\u0080", "é", "\ud800", "\udc00", "𐀀", "￿", "﻿", "‮", "\u0000\u0000", "é", "yes", "no", "ask", "accept-new", "none", "localhost", "*.example.com", "a", "aa", "ssh-ed25519",
        "ssh-rsa", "ecdsa-sha2-nistp256", "ssh-ed25519-cert-v01@openssh.com", "AAAA", "AAAAB3NzaC1yc2E=", "====", "-----BEGIN OPENSSH PRIVATE KEY-----", "-----END OPENSSH PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----",
    ];

    private static readonly int[] RepeatCounts = [2, 3, 8, 16, 100, 255, 256, 257, 1000, 4096, 16383, 16384, 16385, 40000, 65535, 65536, 65537];

    /// <summary>Makes the input for one seed number.</summary>
    /// <param name="random">Generator for this input only.</param>
    /// <param name="corpus">All seeds of the target. One is chosen, and others are spliced into it.</param>
    /// <param name="tokens">Words the target's format is made of, tried in place of tokens in a text input.</param>
    /// <param name="knownLengthOffsets">Per seed, offsets the corpus builder knows are length fields.</param>
    public static byte[] Next(FuzzRandom random, IReadOnlyList<FuzzSeed> corpus, IReadOnlyList<string>? tokens = null, IReadOnlyDictionary<string, int[]>? knownLengthOffsets = null)
    {
        FuzzSeed seed = corpus[random.Next(corpus.Count)];
        int[]? known = null;
        knownLengthOffsets?.TryGetValue(seed.Name, out known);
        return seed.IsText ? MutateText(random, seed, corpus, tokens ?? []) : MutateBinary(random, seed, corpus, known);
    }

    public static byte[] MutateBinary(FuzzRandom random, FuzzSeed seed, IReadOnlyList<FuzzSeed> corpus, int[]? knownLengthOffsets = null)
    {
        // A few inputs are not mutations at all: nothing, noise, or all ones. They check the first thing a parser does.
        int roll = random.Next(1000);
        if (roll < 6)
        {
            return [];
        }

        if (roll < 12)
        {
            return NoiseOf(random, random.Next(80));
        }

        List<byte> data = [.. seed.Data];
        int changes = 1 + random.Next(3);
        if (random.Chance(15))
        {
            changes += random.Next(6);
        }

        for (int i = 0; i < changes && data.Count <= MaxBinaryLength; i++)
        {
            ApplyBinary(random, data, corpus, knownLengthOffsets);
        }

        if (data.Count > MaxBinaryLength)
        {
            data.RemoveRange(MaxBinaryLength, data.Count - MaxBinaryLength);
        }

        return [.. data];
    }

    /// <summary>Returns a length value chosen from the boundary values, the old value and what's left to read.</summary>
    public static uint BoundaryLength(FuzzRandom random, uint old, int remaining)
    {
        return random.Next(12) switch
        {
            0 => old + 1,
            1 => old - 1,
            2 => (uint)remaining,
            3 => (uint)remaining + 1,
            4 => (uint)Math.Max(0, remaining - 1),
            5 => old * 2,
            6 => (uint)random.NextUInt64(),
            7 or 8 => ExtremeLengths[random.Next(ExtremeLengths.Length)],
            _ => Boundaries[random.Next(Boundaries.Length)],
        };
    }

    private static void ApplyBinary(FuzzRandom random, List<byte> data, IReadOnlyList<FuzzSeed> corpus, int[]? known)
    {
        int roll = random.Next(100);
        if (data.Count == 0)
        {
            data.AddRange(NoiseOf(random, 1 + random.Next(32)));
            return;
        }

        if (roll < 22)
        {
            SetLengthField(random, data, known);
        }
        else if (roll < 34)
        {
            ResizeInsideField(random, data, known);
        }
        else if (roll < 44)
        {
            FlipBits(random, data);
        }
        else if (roll < 52)
        {
            SetByte(random, data);
        }
        else if (roll < 59)
        {
            Truncate(random, data, known);
        }
        else if (roll < 67)
        {
            Splice(random, data, corpus);
        }
        else if (roll < 73)
        {
            InsertBytes(random, data);
        }
        else if (roll < 79)
        {
            DeleteBytes(random, data);
        }
        else if (roll < 85)
        {
            AddToWord(random, data);
        }
        else if (roll < 91)
        {
            DuplicateChunk(random, data);
        }
        else if (roll < 96)
        {
            SwapFields(random, data, known);
        }
        else
        {
            AppendTail(random, data);
        }
    }

    /// <summary>Writes a boundary value over one length field. The bytes the field described stay where they were.</summary>
    private static void SetLengthField(FuzzRandom random, List<byte> data, int[]? known)
    {
        int offset = PickLengthOffset(random, data, known);
        if (offset < 0)
        {
            return;
        }

        uint old = ReadWord(data, offset);
        WriteWord(data, offset, BoundaryLength(random, old, data.Count - offset - 4));
    }

    /// <summary>
    /// Adds or removes bytes inside a string and keeps its length, and the length of every string around it, right. The
    /// input stays well formed, so it goes deeper than a wrong length does before something rejects it.
    /// </summary>
    private static void ResizeInsideField(FuzzRandom random, List<byte> data, int[]? known)
    {
        int offset = PickLengthOffset(random, data, known);
        if (offset < 0)
        {
            return;
        }

        // Remember every field before the change, with the range it covered.
        List<(int Offset, uint Length)> before = [];
        foreach (int field in FuzzLengthFields.Find(CollectionsMarshal.AsSpan(data), known))
        {
            before.Add((field, ReadWord(data, field)));
        }

        uint length = ReadWord(data, offset);
        if (length > int.MaxValue || offset + 4 + (long)length > data.Count)
        {
            return;
        }

        int contentStart = offset + 4;
        int at = contentStart + random.Next((int)length + 1);
        int removed = 0;
        int inserted = 0;
        if (length > 0 && random.Chance(40))
        {
            at = Math.Min(at, contentStart + (int)length - 1);
            removed = Math.Min(1 + random.Next(16), contentStart + (int)length - at);
            data.RemoveRange(at, removed);
        }
        else
        {
            inserted = 1 + random.Next(random.Chance(10) ? 4096 : 24);
            byte[] filler = random.Chance(50) ? NoiseOf(random, inserted) : Enumerable.Repeat(random.Chance(50) ? (byte)'a' : (byte)0, inserted).ToArray();
            data.InsertRange(at, filler);
        }

        // Every field whose string held the changed bytes grows or shrinks with them, so the input stays well formed.
        int delta = inserted - removed;
        foreach ((int field, uint fieldLength) in before)
        {
            long fieldStart = (long)field + 4;
            if (fieldStart <= at && (long)at + removed <= fieldStart + fieldLength)
            {
                WriteWord(data, field, (uint)((long)fieldLength + delta));
            }
        }
    }

    private static void FlipBits(FuzzRandom random, List<byte> data)
    {
        int flips = 1 + random.Next(3);
        for (int i = 0; i < flips; i++)
        {
            int index = random.Next(data.Count);
            data[index] ^= (byte)(1 << random.Next(8));
        }
    }

    private static void SetByte(FuzzRandom random, List<byte> data)
    {
        ReadOnlySpan<byte> interesting = [0, 1, 0x7F, 0x80, 0xFF, (byte)',', (byte)' ', 0x0A, 0x20, 0x7E];
        data[random.Next(data.Count)] = random.Chance(70) ? random.Pick(interesting) : random.NextByte();
    }

    private static void Truncate(FuzzRandom random, List<byte> data, int[]? known)
    {
        List<int> fields = FuzzLengthFields.Find(CollectionsMarshal.AsSpan(data), known);
        int newLength;
        if (fields.Count > 0 && random.Chance(60))
        {
            // At a field edge, or one byte either side of it: the places a parser's bounds check can be off by one.
            newLength = fields[random.Next(fields.Count)] + random.Pick<int>([0, 1, 2, 3, 4, 5, 6]);
        }
        else
        {
            newLength = random.Next(data.Count);
        }

        if (newLength < data.Count)
        {
            data.RemoveRange(newLength, data.Count - newLength);
        }
    }

    private static void Splice(FuzzRandom random, List<byte> data, IReadOnlyList<FuzzSeed> corpus)
    {
        FuzzSeed donor = corpus[random.Next(corpus.Count)];
        if (donor.IsText || donor.Data.Length == 0)
        {
            return;
        }

        int from = random.Next(donor.Data.Length);
        int count = 1 + random.Next(Math.Min(donor.Data.Length - from, random.Chance(20) ? 512 : 48));
        ReadOnlySpan<byte> chunk = donor.Data.AsSpan(from, count);
        int at = random.Next(data.Count + 1);
        if (random.Chance(50) && at < data.Count)
        {
            data.RemoveRange(at, Math.Min(count, data.Count - at));
        }

        data.InsertRange(at, chunk.ToArray());
    }

    private static void InsertBytes(FuzzRandom random, List<byte> data)
    {
        int count = 1 + random.Next(random.Chance(10) ? 1024 : 16);
        byte[] bytes = random.Next(3) switch
        {
            0 => NoiseOf(random, count),
            1 => new byte[count],
            _ => Enumerable.Repeat((byte)0xFF, count).ToArray(),
        };
        data.InsertRange(random.Next(data.Count + 1), bytes);
    }

    private static void DeleteBytes(FuzzRandom random, List<byte> data)
    {
        int at = random.Next(data.Count);
        data.RemoveRange(at, 1 + random.Next(Math.Min(data.Count - at, 16)));
    }

    /// <summary>Adds a small number to a 1, 2, 4 or 8 byte word, the change that moves a value across a limit by one.</summary>
    private static void AddToWord(FuzzRandom random, List<byte> data)
    {
        int size = random.Pick<int>([1, 2, 4, 8]);
        if (data.Count < size)
        {
            return;
        }

        int at = random.Next(data.Count - size + 1);
        long delta = random.Next(35) - 17;
        int carry = (int)delta;
        for (int i = size - 1; i >= 0 && carry != 0; i--)
        {
            int sum = data[at + i] + carry;
            data[at + i] = (byte)sum;
            carry = sum >> 8;
        }
    }

    private static void DuplicateChunk(FuzzRandom random, List<byte> data)
    {
        int from = random.Next(data.Count);
        int count = 1 + random.Next(Math.Min(data.Count - from, 64));
        byte[] chunk = data.GetRange(from, count).ToArray();
        int copies = random.Chance(10) ? 1 + random.Next(300) : 1;
        for (int i = 0; i < copies && data.Count <= MaxBinaryLength; i++)
        {
            data.InsertRange(from + count, chunk);
        }
    }

    /// <summary>Swaps two whole strings, so each field gets another field's contents under its own type.</summary>
    private static void SwapFields(FuzzRandom random, List<byte> data, int[]? known)
    {
        List<int> fields = FuzzLengthFields.Find(CollectionsMarshal.AsSpan(data), known);
        if (fields.Count < 2)
        {
            return;
        }

        int a = fields[random.Next(fields.Count)];
        int b = fields[random.Next(fields.Count)];
        if (a == b)
        {
            return;
        }

        (a, b) = (Math.Min(a, b), Math.Max(a, b));
        long endA = (long)a + 4 + ReadWord(data, a);
        if (endA > b)
        {
            return;
        }

        long endB = (long)b + 4 + ReadWord(data, b);
        if (endB > data.Count)
        {
            return;
        }

        byte[] first = data.GetRange(a, (int)(endA - a)).ToArray();
        byte[] second = data.GetRange(b, (int)(endB - b)).ToArray();
        byte[] middle = data.GetRange((int)endA, b - (int)endA).ToArray();
        data.RemoveRange(a, (int)(endB - a));
        data.InsertRange(a, [.. second, .. middle, .. first]);
    }

    private static void AppendTail(FuzzRandom random, List<byte> data)
    {
        int count = 1 + random.Next(random.Chance(10) ? 300 : 12);
        data.AddRange(random.Chance(50) ? new byte[count] : NoiseOf(random, count));
    }

    private static int PickLengthOffset(FuzzRandom random, List<byte> data, int[]? known)
    {
        List<int> fields = FuzzLengthFields.Find(CollectionsMarshal.AsSpan(data), known);
        if (fields.Count > 0)
        {
            return fields[random.Next(fields.Count)];
        }

        // No structure found. Any 4 bytes may be a length, and the guess costs nothing.
        return data.Count >= 4 ? random.Next(data.Count - 3) : -1;
    }

    private static byte[] NoiseOf(FuzzRandom random, int count)
    {
        byte[] noise = new byte[count];
        for (int i = 0; i < noise.Length; i++)
        {
            noise[i] = random.NextByte();
        }

        return noise;
    }

    private static uint ReadWord(List<byte> data, int offset) =>
        ((uint)data[offset] << 24) | ((uint)data[offset + 1] << 16) | ((uint)data[offset + 2] << 8) | data[offset + 3];

    private static void WriteWord(List<byte> data, int offset, uint value)
    {
        data[offset] = (byte)(value >> 24);
        data[offset + 1] = (byte)(value >> 16);
        data[offset + 2] = (byte)(value >> 8);
        data[offset + 3] = (byte)value;
    }

    // Text.

    public static byte[] MutateText(FuzzRandom random, FuzzSeed seed, IReadOnlyList<FuzzSeed> corpus, IReadOnlyList<string> tokens)
    {
        int roll = random.Next(1000);
        if (roll < 5)
        {
            return [];
        }

        string text = seed.AsText();
        int changes = 1 + random.Next(3);
        if (random.Chance(15))
        {
            changes += random.Next(5);
        }

        for (int i = 0; i < changes && text.Length <= MaxTextLength; i++)
        {
            text = ApplyText(random, text, corpus, tokens);
        }

        if (text.Length > MaxTextLength)
        {
            text = text[..MaxTextLength];
        }

        return FuzzText.Encode(text);
    }

    private static string ApplyText(FuzzRandom random, string text, IReadOnlyList<FuzzSeed> corpus, IReadOnlyList<string> tokens)
    {
        int roll = random.Next(100);
        if (text.Length == 0)
        {
            return random.Chance(50) && tokens.Count > 0 ? tokens[random.Next(tokens.Count)] : InterestingText[random.Next(InterestingText.Length)];
        }

        if (roll < 12)
        {
            return ReplaceChar(random, text);
        }

        if (roll < 26)
        {
            return ReplaceToken(random, text, tokens);
        }

        if (roll < 36)
        {
            return ReplaceNumber(random, text);
        }

        if (roll < 46)
        {
            return EditLines(random, text);
        }

        if (roll < 56)
        {
            return Insert(random, text, InterestingText[random.Next(InterestingText.Length)]);
        }

        if (roll < 64)
        {
            return Repeat(random, text);
        }

        if (roll < 72)
        {
            return text[..random.Next(text.Length)];
        }

        if (roll < 80)
        {
            return DeleteRange(random, text);
        }

        if (roll < 90)
        {
            return MutateBase64Token(random, text, corpus);
        }

        if (roll < 95 && tokens.Count > 0)
        {
            return Insert(random, text, tokens[random.Next(tokens.Count)]);
        }

        return SpliceText(random, text, corpus);
    }

    private static string ReplaceChar(FuzzRandom random, string text)
    {
        int at = random.Next(text.Length);
        string replacement = InterestingText[random.Next(InterestingText.Length)];
        char c = replacement.Length > 0 && random.Chance(80) ? replacement[random.Next(replacement.Length)] : (char)(text[at] ^ (1 << random.Next(8)));
        return string.Concat(text.AsSpan(0, at), c.ToString(), text.AsSpan(at + 1));
    }

    private static string ReplaceToken(FuzzRandom random, string text, IReadOnlyList<string> tokens)
    {
        List<(int Start, int Length)> spans = TokenSpans(text);
        if (spans.Count == 0)
        {
            return text;
        }

        (int start, int length) = spans[random.Next(spans.Count)];
        string replacement = tokens.Count > 0 && random.Chance(50) ? tokens[random.Next(tokens.Count)] : InterestingText[random.Next(InterestingText.Length)];
        return string.Concat(text.AsSpan(0, start), replacement, text.AsSpan(start + length));
    }

    private static string ReplaceNumber(FuzzRandom random, string text)
    {
        List<(int Start, int Length)> digits = [];
        for (int i = 0; i < text.Length; i++)
        {
            if (char.IsAsciiDigit(text[i]))
            {
                int start = i;
                while (i < text.Length && char.IsAsciiDigit(text[i]))
                {
                    i++;
                }

                digits.Add((start, i - start));
            }
        }

        if (digits.Count == 0)
        {
            return Insert(random, text, Boundaries[random.Next(Boundaries.Length)].ToString(System.Globalization.CultureInfo.InvariantCulture));
        }

        (int s, int l) = digits[random.Next(digits.Count)];
        string number = random.Next(4) == 0
            ? (-1 - random.Next(3)).ToString(System.Globalization.CultureInfo.InvariantCulture)
            : Boundaries[random.Next(Boundaries.Length)].ToString(System.Globalization.CultureInfo.InvariantCulture);
        return string.Concat(text.AsSpan(0, s), number, text.AsSpan(s + l));
    }

    private static string EditLines(FuzzRandom random, string text)
    {
        List<string> lines = [.. text.Split('\n')];
        if (lines.Count == 0)
        {
            return text;
        }

        int a = random.Next(lines.Count);
        switch (random.Next(5))
        {
            case 0:
                lines.RemoveAt(a);
                break;
            case 1:
                lines.Insert(a, lines[a]);
                break;
            case 2:
                int b = random.Next(lines.Count);
                (lines[a], lines[b]) = (lines[b], lines[a]);
                break;
            case 3:
                if (a + 1 < lines.Count)
                {
                    lines[a] += " " + lines[a + 1];
                    lines.RemoveAt(a + 1);
                }

                break;
            default:
                int cut = random.Next(lines[a].Length + 1);
                lines[a] = lines[a][..cut];
                break;
        }

        return string.Join('\n', lines);
    }

    private static string Insert(FuzzRandom random, string text, string piece) =>
        text.Insert(random.Next(text.Length + 1), piece);

    private static string Repeat(FuzzRandom random, string text)
    {
        string unit = random.Chance(50) ? InterestingText[1 + random.Next(InterestingText.Length - 1)] : text.Substring(random.Next(text.Length), 1);
        if (unit.Length == 0)
        {
            return text;
        }

        int count = RepeatCounts[random.Next(RepeatCounts.Length)];
        return Insert(random, text, string.Concat(Enumerable.Repeat(unit, count)));
    }

    private static string DeleteRange(FuzzRandom random, string text)
    {
        int at = random.Next(text.Length);
        int count = 1 + random.Next(Math.Min(text.Length - at, 24));
        return text.Remove(at, count);
    }

    /// <summary>
    /// Finds a long base64 word, such as a public key in a known_hosts line, decodes it, changes the bytes the way a binary
    /// input is changed, and encodes it again. Without this, a changed key is almost always bad base64 and stops at once.
    /// </summary>
    private static string MutateBase64Token(FuzzRandom random, string text, IReadOnlyList<FuzzSeed> corpus)
    {
        List<(int Start, int Length)> spans = TokenSpans(text).Where(s => s.Length >= 16).ToList();
        if (spans.Count == 0)
        {
            return text;
        }

        (int start, int length) = spans[random.Next(spans.Count)];
        string token = text.Substring(start, length);
        byte[] raw;
        try
        {
            raw = Convert.FromBase64String(token);
        }
        catch (FormatException)
        {
            return text;
        }

        byte[] changed = MutateBinary(random, FuzzSeed.Binary("token", raw), [FuzzSeed.Binary("token", raw)]);
        _ = corpus;
        return string.Concat(text.AsSpan(0, start), Convert.ToBase64String(changed), text.AsSpan(start + length));
    }

    private static string SpliceText(FuzzRandom random, string text, IReadOnlyList<FuzzSeed> corpus)
    {
        FuzzSeed donor = corpus[random.Next(corpus.Count)];
        if (!donor.IsText)
        {
            return text;
        }

        string other = donor.AsText();
        if (other.Length == 0)
        {
            return text;
        }

        int from = random.Next(other.Length);
        int count = 1 + random.Next(Math.Min(other.Length - from, 200));
        return Insert(random, text, other.Substring(from, count));
    }

    private static List<(int Start, int Length)> TokenSpans(string text)
    {
        List<(int Start, int Length)> spans = [];
        int i = 0;
        while (i < text.Length)
        {
            while (i < text.Length && text[i] is ' ' or '\t' or '\n' or '\r')
            {
                i++;
            }

            int start = i;
            while (i < text.Length && text[i] is not (' ' or '\t' or '\n' or '\r'))
            {
                i++;
            }

            if (i > start)
            {
                spans.Add((start, i - start));
            }
        }

        return spans;
    }
}

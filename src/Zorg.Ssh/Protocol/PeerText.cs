using System;
using System.Globalization;
using System.Text;

namespace Zorg.Ssh.Protocol;

/// <summary>Cleans text a peer chose, before it reaches exceptions, logs or callers.</summary>
internal static class PeerText
{
    /// <summary>Removes control and invisible formatting characters and caps the length, so the text can't forge log lines or hide what it says.</summary>
    public static string Clean(string text, int maxLength)
    {
        StringBuilder clean = new(Math.Min(text.Length, maxLength));
        foreach (char c in text)
        {
            if (clean.Length == maxLength)
            {
                break;
            }

            if (char.GetUnicodeCategory(c) is not (UnicodeCategory.Control or UnicodeCategory.Format
                or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator or UnicodeCategory.Surrogate))
            {
                clean.Append(c);
            }
        }

        return clean.ToString();
    }
}

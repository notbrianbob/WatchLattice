using System.Globalization;
using System.Text;

namespace WatchLattice.Fuzz.Tests.Harness;

/// <summary>
/// The random source for one fuzz case. Everything a case generates comes
/// from one seed, so a failure is reproduced by its seed alone.
/// </summary>
public sealed class FuzzRandom
{
    /// <summary>
    /// Text that parsers tend to get wrong: empty and blank text, control
    /// characters, lone surrogates, look-alike digits and dots, path and
    /// quoting syntax, numbers at the edge of their type.
    /// </summary>
    public static readonly string[] Nasty =
    {
        "", " ", "  ", "\t", "\r", "\n", "\r\n", "\0", "\u000b", "\u000c", "\u0085", "\u00a0", "\u2028", "\u2029", "\u200b",
        "\u202e", "\ufeff", "\ud800", "\udc00", "\ud83d\ude00", "\u00e9", "\u0130", "\u0131", "\u00df", "\u0661\u0662\u0663", "\uff0e", "\u3002",
        "%", "%%", "%TEMP%", "%SystemRoot%", "%USERPROFILE%", ".", "..", "...", "../", "..\\", "/", "\\", "\\\\", "\\\\?\\", "\\\\.\\",
        "\\??\\", "\\\\?\\UNC\\", "\\\\server\\share\\", "C:", "C:\\", "c:/", "C:\\Windows\\System32\\", ":", "::", "::$DATA",
        "\"", "\"\"", "'", "`", "```", "~~~", "|", "||", "<", ">", "&", "&#124;", "#", ";", "=", "==", "@", "+", "-", "--", "*", "?",
        "{", "}", "[", "]", "(", ")", ",", "$", "^", "!", "\\n", "\\u0000", "\\ud800", "{0}", "%s", "%n",
        "0", "1", "-1", "00", "01", "2147483647", "2147483648", "-2147483649", "4294967296", "9223372036854775808",
        "99999999999999999999999999", "1e309", "-0", "0.0", "1.", ".5", "NaN", "Infinity", "null", "true", "false", "{}", "[]",
        "nul", "CON", "aux.txt", "a", "A", "aa", "exe", ".exe", ".dll", "x.exe", "localhost", "127.0.0.1", "0.0.0.0", "::1",
    };

    private const string Printable = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
    private const string Word = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    private readonly Random _random;

    public FuzzRandom(int seed) => _random = new Random(seed);

    public int Next(int exclusiveMax) => _random.Next(exclusiveMax);

    public int Next(int min, int exclusiveMax) => _random.Next(min, exclusiveMax);

    public bool Chance(double probability) => _random.NextDouble() < probability;

    public T Pick<T>(IReadOnlyList<T> items) => items[_random.Next(items.Count)];

    public T Pick<T>(params T[] items) => items[_random.Next(items.Length)];

    /// <summary>Usually small, sometimes large: most bugs need few elements, some need many.</summary>
    public int Count(int usualMax, int rareMax) => Chance(0.9) ? Next(usualMax + 1) : Next(rareMax + 1);

    /// <summary>Letters and digits only, never empty: a stand-in for a name that is not itself an edge case.</summary>
    public string Identifier(int minLength = 1, int maxLength = 12)
    {
        var length = Next(minLength, maxLength + 1);
        var text = new StringBuilder(length);
        for (var i = 0; i < length; i++) text.Append(Word[Next(Word.Length)]);
        return text.ToString();
    }

    /// <summary>Printable ASCII of the given length.</summary>
    public string Ascii(int maxLength = 24)
    {
        var length = Next(maxLength + 1);
        var text = new StringBuilder(length);
        for (var i = 0; i < length; i++) text.Append(Printable[Next(Printable.Length)]);
        return text.ToString();
    }

    /// <summary>Any UTF-16 code unit, including control characters and surrogates.</summary>
    public char AnyChar() => Next(4) switch
    {
        0 => (char)Next(0x20),
        1 => (char)Next(0x80),
        2 => (char)Next(0x80, 0x800),
        _ => (char)Next(0x10000),
    };

    /// <summary>
    /// Hostile text: pieces from <see cref="Nasty"/>, the target's own
    /// <paramref name="dictionary"/> (its keywords and separators), plain runs
    /// and arbitrary characters, glued together.
    /// </summary>
    public string Text(IReadOnlyList<string>? dictionary = null, int usualParts = 6, int rareParts = 40)
    {
        var parts = Count(usualParts, rareParts);
        var text = new StringBuilder();
        for (var i = 0; i < parts; i++)
        {
            switch (Next(dictionary is { Count: > 0 } ? 6 : 4))
            {
                case 0: text.Append(Pick(Nasty)); break;
                case 1: text.Append(Ascii(12)); break;
                case 2: text.Append(Identifier()); break;
                case 3: text.Append(AnyChar()); break;
                default: text.Append(Pick(dictionary!)); break;
            }
        }
        return text.ToString();
    }

    /// <summary>One piece of text: usually from the dictionary or the nasty list, otherwise generated.</summary>
    public string Token(IReadOnlyList<string>? dictionary = null) => Next(4) switch
    {
        0 => Pick(Nasty),
        1 => Text(dictionary, 3, 8),
        2 => Identifier(),
        _ => dictionary is { Count: > 0 } ? Pick(dictionary) : Ascii(12),
    };

    public byte[] Bytes(int usualMax = 64, int rareMax = 4096)
    {
        var bytes = new byte[Count(usualMax, rareMax)];
        _random.NextBytes(bytes);
        return bytes;
    }

    /// <summary>
    /// A changed copy of valid input, which reaches code that random text never
    /// gets to: pieces inserted, removed, repeated, swapped or cut short.
    /// </summary>
    public string Mutate(string seed, IReadOnlyList<string>? dictionary = null, int maxChanges = 4)
    {
        var text = new StringBuilder(seed);
        var changes = Next(1, maxChanges + 1);
        for (var i = 0; i < changes; i++)
        {
            var at = Next(text.Length + 1);
            switch (Next(9))
            {
                case 0: text.Insert(at, Token(dictionary)); break;
                case 1: text.Insert(at, Pick(Nasty)); break;
                case 2 when text.Length > 0: text.Remove(Math.Min(at, text.Length - 1), Math.Min(Next(1, 9), text.Length - Math.Min(at, text.Length - 1))); break;
                case 3 when text.Length > 0: text[Math.Min(at, text.Length - 1)] = AnyChar(); break;
                case 4 when text.Length > 0:
                {
                    // Repeat a piece, sometimes very many times, to stress loops and backtracking.
                    var start = Math.Min(at, text.Length - 1);
                    var piece = text.ToString(start, Math.Min(Next(1, 12), text.Length - start));
                    var times = Chance(0.9) ? Next(1, 4) : Next(50, 400);
                    text.Insert(start, string.Concat(Enumerable.Repeat(piece, times)));
                    break;
                }
                case 5: text.Length = at; break;
                case 6 when text.Length > 0:
                {
                    var index = Math.Min(at, text.Length - 1);
                    text[index] = char.IsUpper(text[index]) ? char.ToLowerInvariant(text[index]) : char.ToUpperInvariant(text[index]);
                    break;
                }
                case 7 when text.Length > 1:
                {
                    // Move a piece somewhere else.
                    var start = Next(text.Length);
                    var length = Math.Min(Next(1, 16), text.Length - start);
                    var piece = text.ToString(start, length);
                    text.Remove(start, length);
                    text.Insert(Next(text.Length + 1), piece);
                    break;
                }
                default: text.Insert(at, AnyChar()); break;
            }
        }
        return text.ToString();
    }

    public byte[] Mutate(byte[] seed, int maxChanges = 4)
    {
        var bytes = new List<byte>(seed);
        var changes = Next(1, maxChanges + 1);
        for (var i = 0; i < changes; i++)
        {
            var at = Next(bytes.Count + 1);
            switch (Next(6))
            {
                case 0 when bytes.Count > 0: bytes[Math.Min(at, bytes.Count - 1)] ^= (byte)(1 << Next(8)); break;
                case 1 when bytes.Count > 0: bytes[Math.Min(at, bytes.Count - 1)] = Pick<byte>(0, 1, 0x7f, 0x80, 0xff); break;
                case 2 when bytes.Count > 0: bytes.RemoveRange(Math.Min(at, bytes.Count - 1), Math.Min(Next(1, 9), bytes.Count - Math.Min(at, bytes.Count - 1))); break;
                case 3: bytes.InsertRange(at, Bytes(8, 64)); break;
                case 4: bytes.RemoveRange(at, bytes.Count - at); break;
                default:
                    // A length field set to an extreme value.
                    bytes.InsertRange(at, BitConverter.GetBytes(Pick(-1, 0, 1, int.MaxValue, int.MinValue, 0x7fff, 0x8000, 0xffff, 0x10000)));
                    break;
            }
        }
        return bytes.ToArray();
    }

    /// <summary>A JSON string literal, with every character that needs it escaped; lone surrogates become \uXXXX escapes.</summary>
    public static string JsonString(string value)
    {
        var text = new StringBuilder(value.Length + 2).Append('"');
        for (var i = 0; i < value.Length; i++)
        {
            var c = value[i];
            var paired = (char.IsHighSurrogate(c) && i + 1 < value.Length && char.IsLowSurrogate(value[i + 1]))
                || (char.IsLowSurrogate(c) && i > 0 && char.IsHighSurrogate(value[i - 1]));
            if (c is '"' or '\\') text.Append('\\').Append(c);
            else if (c < 0x20 || (char.IsSurrogate(c) && !paired) || c is '\u2028' or '\u2029')
                text.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
            else text.Append(c);
        }
        return text.Append('"').ToString();
    }

    /// <summary>
    /// A random JSON value. Property names come mostly from <paramref name="keys"/>
    /// and string values from <paramref name="strings"/>, so the shapes a parser
    /// looks for turn up often, holding values of every other kind.
    /// </summary>
    public string Json(IReadOnlyList<string> keys, IReadOnlyList<string> strings, int depth = 4)
    {
        var text = new StringBuilder();
        WriteJson(text, keys, strings, depth);
        return text.ToString();
    }

    private void WriteJson(StringBuilder text, IReadOnlyList<string> keys, IReadOnlyList<string> strings, int depth)
    {
        switch (depth <= 0 ? Next(2, 8) : Next(8))
        {
            case 0:
            case 1:
            {
                text.Append('{');
                var count = Count(5, 12);
                for (var i = 0; i < count; i++)
                {
                    if (i > 0) text.Append(',');
                    // Keys repeat on purpose now and then: duplicate names are legal JSON that many readers mishandle.
                    text.Append(JsonString(Chance(0.85) ? Pick(keys) : Token(keys))).Append(':');
                    WriteJson(text, keys, strings, depth - 1);
                }
                text.Append('}');
                break;
            }
            case 2 when depth > 0:
            {
                text.Append('[');
                var count = Count(3, 10);
                for (var i = 0; i < count; i++)
                {
                    if (i > 0) text.Append(',');
                    WriteJson(text, keys, strings, depth - 1);
                }
                text.Append(']');
                break;
            }
            case 3: text.Append(Pick("0", "1", "2", "3", "4", "5", "7", "8", "9", "10", "-1", "1.5", "1e3", "2147483648", "-9223372036854775809", "1e400", "0.0000001")); break;
            case 4: text.Append(Pick("true", "false", "null")); break;
            case 5: text.Append(JsonString(Token(strings))); break;
            default: text.Append(JsonString(Pick(strings))); break;
        }
    }
}

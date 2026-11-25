using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace WatchLattice.Updater;

/// <summary>Reads <c>sha256sum</c>-style checksum files and compares hashes.</summary>
public static class Sha256Sums
{
    private static readonly Regex Line = new(@"^([0-9A-Fa-f]{64}) [ *](.+)$", RegexOptions.CultureInvariant);

    /// <summary>File name to lowercase hex hash. Malformed or conflicting lines make the whole file invalid.</summary>
    public static IReadOnlyDictionary<string, string> Parse(string text)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.Trim().Length == 0 || line.StartsWith('#')) continue;
            var match = Line.Match(line);
            if (!match.Success) throw new InvalidDataException("The checksum file has a malformed line.");
            var name = match.Groups[2].Value.Trim();
            if (name.StartsWith("./", StringComparison.Ordinal)) name = name[2..];
            if (name.Length == 0) throw new InvalidDataException("The checksum file has a line that names no file.");
            var hash = match.Groups[1].Value.ToLowerInvariant();
            if (result.TryGetValue(name, out var existing) && existing != hash)
                throw new InvalidDataException($"The checksum file lists {name} twice with different hashes.");
            result[name] = hash;
        }
        return result;
    }

    public static string Compute(Stream stream) => Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();

    /// <summary>True when both are the same SHA-256 in hex, in either case. Anything that is not 64 hex digits matches nothing.</summary>
    public static bool Matches(string actualHex, string expectedHex) =>
        IsHash(actualHex) && IsHash(expectedHex)
        && CryptographicOperations.FixedTimeEquals(Convert.FromHexString(actualHex), Convert.FromHexString(expectedHex));

    private static bool IsHash(string text) => text.Length == 64 && text.All(char.IsAsciiHexDigit);
}

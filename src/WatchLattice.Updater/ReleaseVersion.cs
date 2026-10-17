using System.Reflection;
using System.Text.RegularExpressions;

namespace WatchLattice.Updater;

/// <summary>A semantic version (major.minor.patch[-prerelease]) as used by release tags.</summary>
public sealed record ReleaseVersion(int Major, int Minor, int Patch, string? Prerelease = null) : IComparable<ReleaseVersion>
{
    private static readonly Regex Pattern = new(
        @"^v?(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?$",
        RegexOptions.CultureInvariant);

    public static ReleaseVersion Development { get; } = new(0, 0, 0, "dev");

    /// <summary>True for builds that did not come from the release workflow.</summary>
    public bool IsDevelopmentBuild => Prerelease is not null
        && Prerelease.Split('.').Contains("dev", StringComparer.OrdinalIgnoreCase);

    public static bool TryParse(string? text, out ReleaseVersion version)
    {
        version = Development;
        if (text is null) return false;
        var match = Pattern.Match(text.Trim());
        if (!match.Success) return false;
        version = new(int.Parse(match.Groups[1].Value), int.Parse(match.Groups[2].Value), int.Parse(match.Groups[3].Value),
            match.Groups[4].Success ? match.Groups[4].Value : null);
        return true;
    }

    public static ReleaseVersion Parse(string text) =>
        TryParse(text, out var version) ? version : throw new FormatException($"'{text}' is not a release version.");

    /// <summary>The version the build stamped into an assembly; unknown builds count as development builds.</summary>
    public static ReleaseVersion FromAssembly(Assembly assembly)
    {
        var informational = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        return TryParse(informational, out var version) ? version : Development;
    }

    /// <summary>
    /// The version stamped into the assembly file now at <paramref name="path"/>,
    /// which after an update can differ from the copy a process loaded; null
    /// when the file is missing or carries no release version.
    /// </summary>
    public static ReleaseVersion? FromFile(string path)
    {
        if (!File.Exists(path)) return null;
        try
        {
            return TryParse(System.Diagnostics.FileVersionInfo.GetVersionInfo(path).ProductVersion, out var version) ? version : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    public int CompareTo(ReleaseVersion? other)
    {
        if (other is null) return 1;
        var result = Major.CompareTo(other.Major);
        if (result == 0) result = Minor.CompareTo(other.Minor);
        if (result == 0) result = Patch.CompareTo(other.Patch);
        if (result != 0) return result;
        if (Prerelease is null || other.Prerelease is null)
            return Prerelease is null ? (other.Prerelease is null ? 0 : 1) : -1;

        var left = Prerelease.Split('.');
        var right = other.Prerelease.Split('.');
        for (var i = 0; i < Math.Min(left.Length, right.Length); i++)
        {
            var leftNumeric = long.TryParse(left[i], out var leftNumber);
            var rightNumeric = long.TryParse(right[i], out var rightNumber);
            result = leftNumeric && rightNumeric ? leftNumber.CompareTo(rightNumber)
                : leftNumeric ? -1 : rightNumeric ? 1 : string.CompareOrdinal(left[i], right[i]);
            if (result != 0) return result;
        }
        return left.Length.CompareTo(right.Length);
    }

    public static bool operator >(ReleaseVersion left, ReleaseVersion right) => left.CompareTo(right) > 0;
    public static bool operator <(ReleaseVersion left, ReleaseVersion right) => left.CompareTo(right) < 0;
    public static bool operator >=(ReleaseVersion left, ReleaseVersion right) => left.CompareTo(right) >= 0;
    public static bool operator <=(ReleaseVersion left, ReleaseVersion right) => left.CompareTo(right) <= 0;

    public override string ToString() => $"{Major}.{Minor}.{Patch}" + (Prerelease is null ? "" : "-" + Prerelease);
}

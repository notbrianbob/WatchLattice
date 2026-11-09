using System.Text.Json;

namespace WatchLattice.Updater;

/// <summary>One shared .NET framework a framework-dependent app needs, from its runtimeconfig.json.</summary>
public sealed record FrameworkRequirement(string Name, Version Version, string RollForward)
{
    /// <summary>True when an installed version satisfies this requirement under the app's roll-forward policy.</summary>
    public bool IsSatisfiedBy(Version installed)
    {
        if (installed < Version) return false;
        return RollForward.ToLowerInvariant() switch
        {
            "disable" => installed == Version,
            "latestpatch" => installed.Major == Version.Major && installed.Minor == Version.Minor,
            "major" or "latestmajor" => true,
            _ => installed.Major == Version.Major, // "Minor" and "LatestMinor", .NET's default
        };
    }

    public override string ToString() => $"{Name} {Version.Major}.{Version.Minor}";
}

/// <summary>
/// Checks, before an update touches any installed file, that the .NET runtime
/// the new release needs is on this PC. A self-contained release carries its
/// own runtime and needs nothing. Without this check, an update to a release
/// built for a newer .NET would install a hub that cannot start.
/// </summary>
public static class RuntimeRequirements
{
    /// <summary>
    /// The shared frameworks an app needs, read from its runtimeconfig.json.
    /// A missing file or a self-contained app (<c>includedFrameworks</c>) needs none.
    /// </summary>
    public static IReadOnlyList<FrameworkRequirement> Read(string runtimeConfigPath)
    {
        if (!File.Exists(runtimeConfigPath)) return Array.Empty<FrameworkRequirement>();
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(File.ReadAllText(runtimeConfigPath),
                new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException(Path.GetFileName(runtimeConfigPath) + " is not valid JSON: " + ex.Message, ex);
        }
        using var disposeDocument = document;
        if (!document.RootElement.TryGetProperty("runtimeOptions", out var options) || options.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException(Path.GetFileName(runtimeConfigPath) + " has no runtimeOptions.");
        if (options.TryGetProperty("includedFrameworks", out _)) return Array.Empty<FrameworkRequirement>();

        var rollForward = options.TryGetProperty("rollForward", out var roll) && roll.ValueKind == JsonValueKind.String
            ? roll.GetString()! : "Minor";
        var frameworks = new List<JsonElement>();
        if (options.TryGetProperty("frameworks", out var many) && many.ValueKind == JsonValueKind.Array)
            frameworks.AddRange(many.EnumerateArray());
        if (options.TryGetProperty("framework", out var one) && one.ValueKind == JsonValueKind.Object)
            frameworks.Add(one);

        var result = new List<FrameworkRequirement>();
        foreach (var framework in frameworks)
        {
            var name = framework.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String ? n.GetString() : null;
            var text = framework.TryGetProperty("version", out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
            if (!IsFrameworkName(name) || !TryParseVersion(text, out var version))
                throw new InvalidDataException(Path.GetFileName(runtimeConfigPath) + " names a framework without a valid name and version.");
            result.Add(new FrameworkRequirement(name!, version, rollForward));
        }
        return result;
    }

    /// <summary>The requirements no installed version satisfies, one entry per framework.</summary>
    public static IReadOnlyList<FrameworkRequirement> FindMissing(IEnumerable<FrameworkRequirement> requirements,
        Func<string, IReadOnlyList<Version>> installedVersions)
    {
        return requirements
            .Where(r => !installedVersions(r.Name).Any(r.IsSatisfiedBy))
            .DistinctBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// The versions of a shared framework installed on this PC, from the
    /// <c>shared</c> folders of the machine-wide .NET install and of DOTNET_ROOT.
    /// </summary>
    public static IReadOnlyList<Version> InstalledVersions(string frameworkName)
    {
        var versions = new List<Version>();
        if (!IsFrameworkName(frameworkName)) return versions;
        foreach (var folder in DotnetRoots().Select(root => Path.Join(root, "shared", frameworkName)).Where(Directory.Exists))
        {
            try
            {
                versions.AddRange(Directory.EnumerateDirectories(folder)
                    .Select(dir => TryParseVersion(Path.GetFileName(dir), out var version) ? version : null)
                    .OfType<Version>());
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // An unreadable .NET folder counts as no versions there; other roots still count.
                continue;
            }
        }
        return versions;
    }

    /// <summary>A user-facing description of what is missing and how to install it.</summary>
    public static string Describe(IReadOnlyList<FrameworkRequirement> missing)
    {
        var major = missing.Max(m => m.Version.Major);
        var desktop = missing.Any(m => m.Name.Equals("Microsoft.WindowsDesktop.App", StringComparison.OrdinalIgnoreCase));
        var package = desktop ? $"Microsoft.DotNet.DesktopRuntime.{major}" : $"Microsoft.DotNet.Runtime.{major}";
        return $"this release needs {string.Join(", ", missing)}, which is not installed. "
            + $"Install it with: winget install {package} (or from https://dotnet.microsoft.com/download/dotnet/{major}.0), then install the update again.";
    }

    private static IEnumerable<string> DotnetRoots()
    {
        var roots = new List<string>();
        roots.AddRange(new[] { "DOTNET_ROOT_X64", "DOTNET_ROOT" }
            .Select(Environment.GetEnvironmentVariable)
            .Where(value => !string.IsNullOrWhiteSpace(value))!);
        if (OperatingSystem.IsWindows() && RegisteredInstallLocation() is { } location) roots.Add(location);
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (!string.IsNullOrEmpty(programFiles)) roots.Add(Path.Join(programFiles, "dotnet"));
        if (!OperatingSystem.IsWindows())
        {
            roots.Add("/usr/share/dotnet");
            roots.Add("/usr/lib/dotnet");
        }
        return roots.Distinct(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
    }

    /// <summary>Where the .NET installer says x64 .NET is, or null; the default folder is checked either way.</summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static string? RegisteredInstallLocation()
    {
        try
        {
            using var setup = Microsoft.Win32.RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine,
                Microsoft.Win32.RegistryView.Registry64).OpenSubKey(@"SOFTWARE\dotnet\Setup\InstalledVersions\x64");
            return setup?.GetValue("InstallLocation") is string location && !string.IsNullOrWhiteSpace(location) ? location : null;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            return null;
        }
    }

    /// <summary>A shared framework name such as Microsoft.NETCore.App: letters, digits and dots only, so it is never a path.</summary>
    private static bool IsFrameworkName(string? name) =>
        !string.IsNullOrEmpty(name) && name.Length <= 100 && name.All(c => char.IsAsciiLetterOrDigit(c) || c == '.')
        && !name.StartsWith('.') && !name.Contains("..", StringComparison.Ordinal);

    private static bool TryParseVersion(string? text, out Version version)
    {
        version = new Version(0, 0);
        if (string.IsNullOrWhiteSpace(text)) return false;
        var core = text.Split('-', '+')[0];
        if (!Version.TryParse(core, out var parsed)) return false;
        version = new Version(parsed.Major, parsed.Minor, Math.Max(0, parsed.Build));
        return true;
    }
}

using System.Text.Json;

namespace WatchLattice.BrowserExtensionWatchdog;

/// <summary>
/// Reads the extensions of every Firefox profile listed in
/// <c>profiles.ini</c>, from each profile's <c>extensions.json</c> (Firefox's
/// own add-on database). Themes, dictionaries and language packs are left
/// out, and so are the add-ons Firefox itself ships and updates. Read-only.
/// </summary>
public static class FirefoxProfileReader
{
    private static readonly HashSet<string> BuiltInLocations = new(StringComparer.OrdinalIgnoreCase)
    {
        "app-builtin", "app-builtin-addons", "app-system-defaults", "app-system-addons",
    };

    private static readonly HashSet<string> SideloadLocations = new(StringComparer.OrdinalIgnoreCase)
    {
        "app-global", "app-system-share", "app-system-local", "app-system-user", "winreg-app-user", "winreg-app-global",
    };

    private static readonly HashSet<string> StoreSources = new(StringComparer.OrdinalIgnoreCase)
    {
        "amo", "disco", "about:addons", "about:preferences",
    };

    /// <summary>
    /// The profiles in <paramref name="firefoxFolder"/> (the folder holding
    /// <c>profiles.ini</c>), or none when Firefox was never used by this
    /// account. Throws when <c>profiles.ini</c> exists but can't be read.
    /// </summary>
    public static IReadOnlyList<BrowserProfile> Read(string userId, string userName, string firefoxFolder,
        int maxFileBytes, CancellationToken cancellationToken)
    {
        var ini = Path.Join(firefoxFolder, "profiles.ini");
        if (!File.Exists(ini))
        {
            return Array.Empty<BrowserProfile>();
        }

        var profiles = new List<BrowserProfile>();
        foreach (var (name, relative, configuredPath) in ParseProfilesIni(ReadText(ini, maxFileBytes)))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var folderKey = configuredPath.Replace('\\', '/').TrimEnd('/');
            var path = relative
                ? Path.Join(firefoxFolder, configuredPath.Replace('/', Path.DirectorySeparatorChar).Replace('\\', Path.DirectorySeparatorChar))
                : configuredPath;
            if (!Directory.Exists(path))
            {
                // Listed but never created, or deleted by hand: nothing is installed there.
                continue;
            }
            var key = $"{Browsers.Firefox}|{userId}|{folderKey}";
            var folder = folderKey.Split('/').Last();
            try
            {
                profiles.Add(new BrowserProfile(key, Browsers.Firefox, userId, userName, folder, name ?? folder, path,
                    ReadExtensions(path, maxFileBytes)));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidDataException)
            {
                profiles.Add(new BrowserProfile(key, Browsers.Firefox, userId, userName, folder, name ?? folder, path, null, ex.Message));
            }
        }
        return profiles
            .GroupBy(p => p.Key, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .ToList();
    }

    /// <summary>The <c>[ProfileN]</c> sections: display name, whether the path is relative, and the path.</summary>
    public static IReadOnlyList<(string? Name, bool IsRelative, string Path)> ParseProfilesIni(string text)
    {
        var result = new List<(string?, bool, string)>();
        string? section = null;
        Dictionary<string, string> values = new(StringComparer.OrdinalIgnoreCase);

        void Flush()
        {
            if (section is not null && section.StartsWith("Profile", StringComparison.OrdinalIgnoreCase)
                && values.TryGetValue("Path", out var path) && !string.IsNullOrWhiteSpace(path))
            {
                values.TryGetValue("Name", out var name);
                result.Add((name, !values.TryGetValue("IsRelative", out var relative) || relative.Trim() != "0", path.Trim()));
            }
            values = new(StringComparer.OrdinalIgnoreCase);
        }

        foreach (var line in text.Split('\n').Select(l => l.Trim()))
        {
            if (line.Length == 0 || line[0] is ';' or '#')
            {
                continue;
            }
            if (line[0] == '[' && line[^1] == ']')
            {
                Flush();
                section = line[1..^1].Trim();
                continue;
            }
            var equals = line.IndexOf('=');
            if (equals > 0)
            {
                values[line[..equals].Trim()] = line[(equals + 1)..].Trim();
            }
        }
        Flush();
        return result;
    }

    private static IReadOnlyList<InstalledExtension> ReadExtensions(string profileFolder, int maxFileBytes)
    {
        using var document = BoundedJson.TryRead(Path.Join(profileFolder, "extensions.json"), maxFileBytes);
        if (document is null)
        {
            // Firefox writes the database on first start; until then nothing is installed.
            return Array.Empty<InstalledExtension>();
        }
        if (!document.RootElement.TryGetPath(out var addons, "addons") || addons.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException("extensions.json has no add-on list.");
        }

        var extensions = new Dictionary<string, InstalledExtension>(StringComparer.Ordinal);
        foreach (var addon in addons.EnumerateArray())
        {
            if (addon.GetStringOrNull("id") is not { Length: > 0 } id
                || !string.Equals(addon.GetStringOrNull("type"), "extension", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            var location = addon.GetStringOrNull("location") ?? "";
            if (BuiltInLocations.Contains(location))
            {
                continue;
            }

            var source = addon.TryGetPath(out var telemetry, "installTelemetryInfo", "source") && telemetry.ValueKind == JsonValueKind.String
                ? telemetry.GetString()
                : null;
            var (kind, detail) = (location, source) switch
            {
                (_, "enterprise-policy") => (ExtensionSource.Policy, "installed by policy"),
                ("temporary-addon", _) or (_, "temporary-addon") => (ExtensionSource.Unpacked, "loaded temporarily (about:debugging)"),
                _ when SideloadLocations.Contains(location) => (ExtensionSource.Sideloaded, $"placed in a shared folder or the registry by another program ({location})"),
                (_, "sideload") => (ExtensionSource.Sideloaded, "dropped into the profile by another program"),
                (_, { } s) when StoreSources.Contains(s) => (ExtensionSource.Store, "from addons.mozilla.org"),
                _ => (ExtensionSource.Other, source is null ? $"install location {location}" : $"installed from {source}"),
            };

            var name = addon.TryGetPath(out var locale, "defaultLocale", "name") && locale.ValueKind == JsonValueKind.String
                ? locale.GetString()
                : addon.GetStringOrNull("name");
            var enabled = addon.GetBoolOrNull("active") ?? addon.GetBoolOrNull("userDisabled") != true;
            extensions.TryAdd(id, new InstalledExtension(id, string.IsNullOrWhiteSpace(name) ? id : name.Trim(),
                addon.GetStringOrNull("version"), kind, enabled, detail));
        }
        return extensions.Values.OrderBy(e => e.Id, StringComparer.Ordinal).ToList();
    }

    private static string ReadText(string path, int maxBytes)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        if (stream.Length > maxBytes)
        {
            throw new InvalidDataException($"{path} is over the {maxBytes:N0}-byte MaxFileBytes limit.");
        }
        using var reader = new StreamReader(stream, detectEncodingFromByteOrderMarks: true);
        return reader.ReadToEnd();
    }
}

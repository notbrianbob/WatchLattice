using System.Text.Json;

namespace WatchLattice.BrowserExtensionWatchdog;

/// <summary>
/// Reads the extensions of every profile in a Chromium "User Data" folder
/// (Edge and Chrome): profile names from <c>Local State</c>, installs from
/// <c>extensions.settings</c> in each profile's <c>Preferences</c> and
/// <c>Secure Preferences</c>, and names and versions from the installed
/// <c>manifest.json</c> when the preferences don't carry them. Read-only.
/// </summary>
public static class ChromiumProfileReader
{
    // Chromium's ManifestLocation values, as stored in "location".
    private const int Internal = 1;
    private const int ExternalPref = 2;
    private const int ExternalRegistry = 3;
    private const int UnpackedLocation = 4;
    private const int Component = 5;
    private const int ExternalPrefDownload = 6;
    private const int ExternalPolicyDownload = 7;
    private const int CommandLine = 8;
    private const int ExternalPolicy = 9;
    private const int ExternalComponent = 10;

    private const int MaxManifestBytes = 1024 * 1024;

    private static readonly string[] StoreUpdateHosts =
    {
        "clients2.google.com/service/update2/crx",
        "edge.microsoft.com/extensionwebstorebase/",
    };

    /// <summary>
    /// The profiles in <paramref name="userDataFolder"/>, or none when it does
    /// not exist (the browser was never used by this account). Throws when the
    /// folder exists but can't be listed; a profile that can't be read is
    /// returned with its error.
    /// </summary>
    public static IReadOnlyList<BrowserProfile> Read(string browser, string userId, string userName, string userDataFolder,
        int maxFileBytes, CancellationToken cancellationToken)
    {
        if (!Directory.Exists(userDataFolder))
        {
            return Array.Empty<BrowserProfile>();
        }

        var names = ProfileNames(userDataFolder, maxFileBytes);
        var folders = Directory.EnumerateDirectories(userDataFolder)
            .Select(Path.GetFileName)
            .OfType<string>()
            .Where(f => names.ContainsKey(f)
                        || ((f == "Default" || f.StartsWith("Profile ", StringComparison.Ordinal))
                            && File.Exists(Path.Join(userDataFolder, f, "Preferences"))))
            .OrderBy(f => f, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var profiles = new List<BrowserProfile>();
        foreach (var folder in folders)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var path = Path.Join(userDataFolder, folder);
            var name = names.TryGetValue(folder, out var n) && !string.IsNullOrWhiteSpace(n) ? n.Trim() : folder;
            var key = $"{browser}|{userId}|{folder}";
            try
            {
                profiles.Add(new BrowserProfile(key, browser, userId, userName, folder, name, path, ReadExtensions(path, maxFileBytes)));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidDataException)
            {
                profiles.Add(new BrowserProfile(key, browser, userId, userName, folder, name, path, null, ex.Message));
            }
        }
        return profiles;
    }

    private static Dictionary<string, string?> ProfileNames(string userDataFolder, int maxFileBytes)
    {
        var names = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var localState = BoundedJson.TryRead(Path.Join(userDataFolder, "Local State"), maxFileBytes);
            if (localState?.RootElement.TryGetPath(out var cache, "profile", "info_cache") == true && cache.ValueKind == JsonValueKind.Object)
            {
                foreach (var profile in cache.EnumerateObject())
                {
                    names[profile.Name] = profile.Value.GetStringOrNull("name");
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidDataException)
        {
            // Names are only for display; the folders are still found below.
        }
        return names;
    }

    private static IReadOnlyList<InstalledExtension> ReadExtensions(string profileFolder, int maxFileBytes)
    {
        // Chromium keeps extensions.settings in Secure Preferences on most
        // Windows machines and in Preferences on others; read both, the
        // protected copy winning for an extension listed in each.
        var settings = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var file in new[] { "Preferences", "Secure Preferences" })
        {
            using var document = BoundedJson.TryRead(Path.Join(profileFolder, file), maxFileBytes);
            if (document?.RootElement.TryGetPath(out var entries, "extensions", "settings") == true && entries.ValueKind == JsonValueKind.Object)
            {
                foreach (var entry in entries.EnumerateObject().Where(e => e.Value.ValueKind == JsonValueKind.Object))
                {
                    // Cloned so the entry outlives its document.
                    settings[entry.Name] = entry.Value.Clone();
                }
            }
        }

        return settings
            .Select(s => ToExtension(profileFolder, s.Key, s.Value))
            .OfType<InstalledExtension>()
            .OrderBy(e => e.Id, StringComparer.Ordinal)
            .ToList();
    }

    private static InstalledExtension? ToExtension(string profileFolder, string id, JsonElement entry)
    {
        // Entries without a location are leftover preferences of an extension
        // that is not installed; component extensions are part of the browser.
        if (entry.GetIntOrNull("location") is not { } location || location is Component or ExternalComponent)
        {
            return null;
        }

        var manifest = entry.TryGetProperty("manifest", out var m) && m.ValueKind == JsonValueKind.Object ? m : (JsonElement?)null;
        using var installed = ReadInstalledManifest(profileFolder, id, entry.GetStringOrNull("path"));
        var name = Localize(manifest?.GetStringOrNull("name"), installed)
                   ?? Localize(installed?.Manifest.GetStringOrNull("name"), installed);
        var version = manifest?.GetStringOrNull("version") ?? installed?.Manifest.GetStringOrNull("version");
        var updateUrl = manifest?.GetStringOrNull("update_url") ?? installed?.Manifest.GetStringOrNull("update_url");

        var byDefault = entry.GetBoolOrNull("was_installed_by_default") == true || entry.GetBoolOrNull("was_installed_by_oem") == true;
        var (source, detail) = location switch
        {
            ExternalPolicy or ExternalPolicyDownload => (ExtensionSource.Policy, "installed by policy"),
            UnpackedLocation => (ExtensionSource.Unpacked, "loaded unpacked (developer mode)"),
            CommandLine => (ExtensionSource.Unpacked, "loaded from the command line"),
            ExternalPref or ExternalRegistry or ExternalPrefDownload when byDefault => (ExtensionSource.Default, "installed by default"),
            ExternalRegistry => (ExtensionSource.Sideloaded, "registered in the Windows registry by another program"),
            ExternalPref or ExternalPrefDownload => (ExtensionSource.Sideloaded, "registered by an external preferences file"),
            Internal when entry.GetBoolOrNull("from_webstore") == true || IsStoreUpdateUrl(updateUrl) => (ExtensionSource.Store, "from the store"),
            Internal => (ExtensionSource.Other, "installed from outside the store"),
            _ => (ExtensionSource.Other, $"install location {location}"),
        };

        var enabled = entry.GetIntOrNull("state") != 0 && !HasDisableReasons(entry);
        return new InstalledExtension(id, string.IsNullOrWhiteSpace(name) ? id : name.Trim(), version, source, enabled, detail);
    }

    /// <summary>Chromium records why an extension is disabled as a bit field (older versions) or a list.</summary>
    private static bool HasDisableReasons(JsonElement entry)
    {
        if (!entry.TryGetProperty("disable_reasons", out var reasons))
        {
            return false;
        }
        return reasons.ValueKind switch
        {
            JsonValueKind.Number => reasons.TryGetInt64(out var bits) && bits != 0,
            JsonValueKind.Array => reasons.GetArrayLength() > 0,
            _ => false,
        };
    }

    private static bool IsStoreUpdateUrl(string? url) =>
        url is not null && StoreUpdateHosts.Any(h => url.Contains(h, StringComparison.OrdinalIgnoreCase));

    private sealed class InstalledManifest : IDisposable
    {
        public required JsonDocument Document { get; init; }
        public required string Folder { get; init; }
        public JsonElement Manifest => Document.RootElement;
        public void Dispose() => Document.Dispose();
    }

    private static InstalledManifest? ReadInstalledManifest(string profileFolder, string id, string? path)
    {
        try
        {
            string? folder = null;
            if (!string.IsNullOrWhiteSpace(path))
            {
                folder = Path.IsPathRooted(path)
                    ? path
                    : Path.Join(profileFolder, "Extensions", path.Replace('\\', Path.DirectorySeparatorChar));
            }
            else if (BoundedJson.IsSafeName(id) && Directory.Exists(Path.Join(profileFolder, "Extensions", id)))
            {
                // Newest version folder; Chromium keeps one, briefly two during an update.
                folder = Directory.EnumerateDirectories(Path.Join(profileFolder, "Extensions", id))
                    .OrderByDescending(d => Path.GetFileName(d), StringComparer.Ordinal)
                    .FirstOrDefault();
            }
            if (folder is null)
            {
                return null;
            }
            var document = BoundedJson.TryRead(Path.Join(folder, "manifest.json"), MaxManifestBytes);
            return document is null ? null : new InstalledManifest { Document = document, Folder = folder };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidDataException or ArgumentException)
        {
            // Name and version are a nicety; the install is still reported.
            return null;
        }
    }

    /// <summary>Resolves a <c>__MSG_name__</c> placeholder from the extension's default locale.</summary>
    private static string? Localize(string? value, InstalledManifest? installed)
    {
        if (value is null || !value.StartsWith("__MSG_", StringComparison.Ordinal) || !value.EndsWith("__", StringComparison.Ordinal))
        {
            return value;
        }
        if (installed?.Manifest.GetStringOrNull("default_locale") is not { } locale || !BoundedJson.IsSafeName(locale))
        {
            return null;
        }

        var key = value[6..^2];
        try
        {
            using var messages = BoundedJson.TryRead(Path.Join(installed.Folder, "_locales", locale, "messages.json"), MaxManifestBytes);
            if (messages?.RootElement.ValueKind != JsonValueKind.Object)
            {
                return null;
            }
            foreach (var message in messages.RootElement.EnumerateObject())
            {
                if (string.Equals(message.Name, key, StringComparison.OrdinalIgnoreCase))
                {
                    return message.Value.GetStringOrNull("message");
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidDataException)
        {
            // An unreadable locale only costs the display name; the ID is used instead.
            return null;
        }
        return null;
    }
}

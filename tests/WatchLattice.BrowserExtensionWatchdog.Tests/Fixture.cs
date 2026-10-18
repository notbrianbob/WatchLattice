using System.Text.Json;
using System.Text.Json.Nodes;

namespace WatchLattice.BrowserExtensionWatchdog.Tests;

/// <summary>
/// Builds Windows-shaped user profile folders on disk, with Edge, Chrome and
/// Firefox profiles laid out the way the browsers write them, so the real
/// readers run against them on any OS.
/// </summary>
internal sealed class Fixture : IDisposable
{
    public const string StoreExtension = "aapbdbdomjkkjkaonfhkkikfgjllcleb";
    public const string SideloadedExtension = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    public const string PolicyExtension = "cccccccccccccccccccccccccccccccc";
    public const string ComponentExtension = "mhjfbmdgcfjbbpaeojofohoefgiehjai";

    public Fixture()
    {
        Directory.CreateDirectory(Root);
    }

    public string Root { get; } = Path.Join(Path.GetTempPath(), $"watchlattice-browserext-{Guid.NewGuid():N}");

    public string Home(string user = "alex") => Path.Join(Root, "Users", user);

    public string UserData(string browser, string user = "alex") =>
        BrowserExtensionProvider.ChromiumUserData(browser, Path.Join(Home(user), "AppData", "Local"));

    public string FirefoxFolder(string user = "alex") => Path.Join(Home(user), "AppData", "Roaming", "Mozilla", "Firefox");

    public string ProfilePath(string browser, string folder = "Default", string user = "alex") => Path.Join(UserData(browser, user), folder);

    /// <summary>Creates a Chromium profile if needed, and records its display name in Local State when one is given.</summary>
    public string ChromiumProfile(string browser, string folder = "Default", string? name = null, string user = "alex")
    {
        var path = ProfilePath(browser, folder, user);
        Directory.CreateDirectory(path);
        if (!File.Exists(Path.Join(path, "Preferences")))
        {
            Write(Path.Join(path, "Preferences"), new JsonObject { ["profile"] = new JsonObject { ["name"] = name ?? folder } });
        }

        var localStatePath = Path.Join(UserData(browser, user), "Local State");
        var localState = File.Exists(localStatePath) ? JsonNode.Parse(File.ReadAllText(localStatePath))!.AsObject() : new JsonObject();
        var cache = (localState["profile"] ??= new JsonObject())["info_cache"] ??= new JsonObject();
        if (name is not null || cache[folder] is null)
        {
            cache[folder] = new JsonObject { ["name"] = name ?? folder };
        }
        Write(localStatePath, localState);
        return path;
    }

    /// <summary>
    /// Adds an extension the way Chromium records it: an
    /// <c>extensions.settings</c> entry (in Secure Preferences when
    /// <paramref name="secure"/>) and, unless <paramref name="manifestInPrefs"/>,
    /// an installed copy under Extensions with its manifest.
    /// </summary>
    public void AddChromiumExtension(string browser, string id, string name, int location = 1, string folder = "Default",
        string user = "alex", bool fromWebstore = true, bool secure = true, bool manifestInPrefs = false, string version = "1.0.0",
        Action<JsonObject>? entry = null)
    {
        var profile = ChromiumProfile(browser, folder, user: user);
        var file = Path.Join(profile, secure ? "Secure Preferences" : "Preferences");
        var prefs = File.Exists(file) ? JsonNode.Parse(File.ReadAllText(file))!.AsObject() : new JsonObject();
        var settings = (prefs["extensions"] ??= new JsonObject())["settings"] ??= new JsonObject();
        var item = new JsonObject
        {
            ["location"] = location,
            ["from_webstore"] = fromWebstore,
            ["state"] = 1,
            ["path"] = $"{id}\\{version}_0",
        };
        if (manifestInPrefs)
        {
            item["manifest"] = new JsonObject { ["name"] = name, ["version"] = version };
        }
        else
        {
            var installed = Path.Join(profile, "Extensions", id, version + "_0");
            Directory.CreateDirectory(installed);
            Write(Path.Join(installed, "manifest.json"), new JsonObject { ["name"] = name, ["version"] = version, ["manifest_version"] = 3 });
        }
        entry?.Invoke(item);
        settings[id] = item;
        Write(file, prefs);
    }

    public void RemoveChromiumExtension(string browser, string id, string folder = "Default", string user = "alex")
    {
        foreach (var name in new[] { "Preferences", "Secure Preferences" })
        {
            var file = Path.Join(ProfilePath(browser, folder, user), name);
            if (!File.Exists(file))
            {
                continue;
            }
            var prefs = JsonNode.Parse(File.ReadAllText(file))!.AsObject();
            if (prefs["extensions"]?["settings"] is JsonObject settings)
            {
                settings.Remove(id);
            }
            Write(file, prefs);
        }
        var installed = Path.Join(ProfilePath(browser, folder, user), "Extensions", id);
        if (Directory.Exists(installed))
        {
            Directory.Delete(installed, recursive: true);
        }
    }

    /// <summary>Writes profiles.ini listing the given profiles (relative paths) and creates their folders.</summary>
    public void FirefoxProfiles(string user = "alex", params (string Name, string Path)[] profiles)
    {
        var lines = new List<string> { "[General]", "StartWithLastProfile=1", "Version=2", "" };
        for (var i = 0; i < profiles.Length; i++)
        {
            lines.AddRange(new[] { $"[Profile{i}]", $"Name={profiles[i].Name}", "IsRelative=1", $"Path={profiles[i].Path}", "" });
            Directory.CreateDirectory(Path.Join(FirefoxFolder(user), profiles[i].Path));
        }
        lines.AddRange(new[] { "[Install308046B0AF4A39CB]", "Default=" + (profiles.Length > 0 ? profiles[0].Path : ""), "Locked=1" });
        Directory.CreateDirectory(FirefoxFolder(user));
        File.WriteAllText(Path.Join(FirefoxFolder(user), "profiles.ini"), string.Join("\r\n", lines));
    }

    /// <summary>Writes a profile's extensions.json with the given add-ons.</summary>
    public void FirefoxAddons(string profilePath, string user = "alex", params JsonObject[] addons)
    {
        var folder = Path.Join(FirefoxFolder(user), profilePath);
        Directory.CreateDirectory(folder);
        var array = new JsonArray();
        foreach (var addon in addons)
        {
            array.Add(addon);
        }
        Write(Path.Join(folder, "extensions.json"), new JsonObject { ["schemaVersion"] = 36, ["addons"] = array });
    }

    public static JsonObject FirefoxAddon(string id, string name, string location = "app-profile", string? source = "amo",
        string type = "extension", bool active = true) => new()
    {
        ["id"] = id,
        ["type"] = type,
        ["location"] = location,
        ["version"] = "2.1",
        ["active"] = active,
        ["defaultLocale"] = new JsonObject { ["name"] = name },
        ["installTelemetryInfo"] = source is null ? null : new JsonObject { ["source"] = source },
    };

    public static void Write(string path, JsonNode node)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, node.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(Root, recursive: true);
        }
        catch (IOException)
        {
        }
    }
}

/// <summary>Policy entries the test controls, with the scopes it says were read.</summary>
internal sealed class FakePolicyReader : IExtensionPolicyReader
{
    public List<PolicyEntry> Entries { get; } = new();

    public List<string> Scopes { get; } = new() { "Machine" };

    public Exception? Failure { get; set; }

    public (IReadOnlyList<PolicyEntry> Entries, IReadOnlyList<string> Scopes) Read(
        IReadOnlyList<string> browsers, IReadOnlyList<(string Sid, string Name)> users, CancellationToken cancellationToken)
    {
        if (Failure is not null)
        {
            throw Failure;
        }
        return (Entries.Where(e => browsers.Contains(e.Browser)).ToList(), Scopes.ToList());
    }

    public static PolicyEntry ForceInstall(string browser, string id, string scope = "Machine") =>
        new(browser, scope, scope == "Machine" ? "this computer (all users)" : "user " + scope, WindowsExtensionPolicyReader.ForceInstallKind, id,
            "https://clients2.google.com/service/update2/crx");
}

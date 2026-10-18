using System.Text.Json.Nodes;
using Xunit;

namespace WatchLattice.BrowserExtensionWatchdog.Tests;

public sealed class ProfileReaderTests : IDisposable
{
    private readonly Fixture _fixture = new();

    private IReadOnlyList<BrowserProfile> ReadChromium(string browser = Browsers.Chrome) =>
        ChromiumProfileReader.Read(browser, "User:S-1-5-21-1", "PC\\alex", _fixture.UserData(browser), 1024 * 1024, default);

    private IReadOnlyList<BrowserProfile> ReadFirefox() =>
        FirefoxProfileReader.Read("User:S-1-5-21-1", "PC\\alex", _fixture.FirefoxFolder(), 1024 * 1024, default);

    [Fact]
    public void Chromium_NoUserDataFolder_MeansNoProfiles()
    {
        Assert.Empty(ReadChromium());
        Assert.Empty(ReadFirefox());
    }

    [Fact]
    public void Chromium_ReadsBothPreferenceFiles_NamesProfiles_AndSkipsComponents()
    {
        _fixture.ChromiumProfile(Browsers.Chrome, "Default", "Work");
        _fixture.AddChromiumExtension(Browsers.Chrome, Fixture.StoreExtension, "uBlock Origin Lite", secure: true);
        _fixture.AddChromiumExtension(Browsers.Chrome, Fixture.SideloadedExtension, "Search Helper", location: 3, fromWebstore: false,
            secure: false, manifestInPrefs: true);
        _fixture.AddChromiumExtension(Browsers.Chrome, Fixture.ComponentExtension, "PDF viewer", location: 5);
        _fixture.ChromiumProfile(Browsers.Chrome, "Profile 1", "Personal");

        var profiles = ReadChromium();

        Assert.Equal(new[] { "Default", "Profile 1" }, profiles.Select(p => p.ProfileFolder));
        var work = profiles[0];
        Assert.Equal("Work", work.ProfileName);
        Assert.Equal("Chrome|User:S-1-5-21-1|Default", work.Key);
        Assert.Null(work.Error);
        Assert.Equal(new[] { Fixture.StoreExtension, Fixture.SideloadedExtension }.Order(StringComparer.Ordinal), work.Extensions!.Select(e => e.Id));

        var store = work.Extensions!.Single(e => e.Id == Fixture.StoreExtension);
        Assert.Equal(("uBlock Origin Lite", "1.0.0", ExtensionSource.Store, true), (store.Name, store.Version, store.Source, store.Enabled));
        var sideloaded = work.Extensions!.Single(e => e.Id == Fixture.SideloadedExtension);
        Assert.Equal(ExtensionSource.Sideloaded, sideloaded.Source);
        Assert.Contains("registry", sideloaded.SourceDetail);
        Assert.Empty(profiles[1].Extensions!);
    }

    [Theory]
    [InlineData(1, true, ExtensionSource.Store)]
    [InlineData(1, false, ExtensionSource.Other)]
    [InlineData(2, false, ExtensionSource.Sideloaded)]
    [InlineData(4, false, ExtensionSource.Unpacked)]
    [InlineData(6, false, ExtensionSource.Sideloaded)]
    [InlineData(7, false, ExtensionSource.Policy)]
    [InlineData(8, false, ExtensionSource.Unpacked)]
    [InlineData(9, false, ExtensionSource.Policy)]
    [InlineData(42, false, ExtensionSource.Other)]
    public void Chromium_MapsInstallLocations(int location, bool fromWebstore, ExtensionSource expected)
    {
        _fixture.AddChromiumExtension(Browsers.Edge, Fixture.PolicyExtension, "Thing", location: location, fromWebstore: fromWebstore);

        var extension = Assert.Single(Assert.Single(ReadChromium(Browsers.Edge)).Extensions!);

        Assert.Equal(expected, extension.Source);
        Assert.Equal(expected == ExtensionSource.Policy, extension.ByPolicy);
    }

    [Fact]
    public void Chromium_DefaultInstalls_DisabledState_LocalizedNames_AndLeftoverEntries()
    {
        _fixture.AddChromiumExtension(Browsers.Chrome, Fixture.SideloadedExtension, "Docs", location: 6, fromWebstore: false,
            entry: e => e["was_installed_by_default"] = true);
        _fixture.AddChromiumExtension(Browsers.Chrome, Fixture.StoreExtension, "__MSG_appName__", entry: e => e["disable_reasons"] = 1);
        var installed = Path.Join(_fixture.ProfilePath(Browsers.Chrome), "Extensions", Fixture.StoreExtension, "1.0.0_0");
        Fixture.Write(Path.Join(installed, "manifest.json"), new JsonObject { ["name"] = "__MSG_appName__", ["version"] = "1.0.0", ["default_locale"] = "en" });
        Fixture.Write(Path.Join(installed, "_locales", "en", "messages.json"), new JsonObject { ["APPNAME"] = new JsonObject { ["message"] = "Localized Name" } });
        // Preferences an extension left behind after it was uninstalled: no location.
        var prefs = Path.Join(_fixture.ProfilePath(Browsers.Chrome), "Preferences");
        var node = JsonNode.Parse(File.ReadAllText(prefs))!.AsObject();
        node["extensions"] = new JsonObject { ["settings"] = new JsonObject { [Fixture.PolicyExtension] = new JsonObject { ["active_permissions"] = new JsonObject() } } };
        Fixture.Write(prefs, node);

        var extensions = Assert.Single(ReadChromium()).Extensions!;

        Assert.Equal(2, extensions.Count);
        Assert.Equal(ExtensionSource.Default, extensions.Single(e => e.Id == Fixture.SideloadedExtension).Source);
        var localized = extensions.Single(e => e.Id == Fixture.StoreExtension);
        Assert.Equal("Localized Name", localized.Name);
        Assert.False(localized.Enabled);
    }

    [Fact]
    public void Chromium_UnreadablePreferences_IsAProfileError_NotAnEmptyProfile()
    {
        var path = _fixture.ChromiumProfile(Browsers.Chrome);
        File.WriteAllText(Path.Join(path, "Secure Preferences"), "{ not json");

        var profile = Assert.Single(ReadChromium());

        Assert.Null(profile.Extensions);
        Assert.NotNull(profile.Error);
    }

    [Fact]
    public void Chromium_OversizedPreferences_IsAProfileError()
    {
        var path = _fixture.ChromiumProfile(Browsers.Chrome);
        File.WriteAllText(Path.Join(path, "Preferences"), "{\"pad\":\"" + new string('x', 200_000) + "\"}");

        var profile = Assert.Single(ChromiumProfileReader.Read(Browsers.Chrome, "u", "u", _fixture.UserData(Browsers.Chrome), 64 * 1024, default));

        Assert.Contains("MaxFileBytes", profile.Error);
    }

    [Fact]
    public void Firefox_ReadsEveryListedProfile_AndOnlyRealExtensions()
    {
        _fixture.FirefoxProfiles("alex", ("default-release", "Profiles/abcd.default-release"), ("dev", "Profiles/efgh.dev"), ("gone", "Profiles/never.created"));
        Directory.Delete(Path.Join(_fixture.FirefoxFolder(), "Profiles", "never.created"));
        _fixture.FirefoxAddons("Profiles/abcd.default-release", "alex",
            Fixture.FirefoxAddon("uBlock0@raymondhill.net", "uBlock Origin"),
            Fixture.FirefoxAddon("corp@example.com", "Corp Tool", source: "enterprise-policy"),
            Fixture.FirefoxAddon("helper@adware.test", "Helper", location: "winreg-app-global", source: null),
            Fixture.FirefoxAddon("dropped@adware.test", "Dropped", source: "sideload", active: false),
            Fixture.FirefoxAddon("dev@example.com", "Dev", location: "temporary-addon", source: "temporary-addon"),
            Fixture.FirefoxAddon("formautofill@mozilla.org", "Form Autofill", location: "app-builtin", source: null),
            Fixture.FirefoxAddon("screenshots@mozilla.org", "Screenshots", location: "app-system-defaults", source: null),
            Fixture.FirefoxAddon("dark@mozilla.org", "Dark", type: "theme"));

        var profiles = ReadFirefox();

        Assert.Equal(new[] { "default-release", "dev" }, profiles.Select(p => p.ProfileName));
        Assert.Equal("Firefox|User:S-1-5-21-1|Profiles/abcd.default-release", profiles[0].Key);
        Assert.Empty(profiles[1].Extensions!);
        var extensions = profiles[0].Extensions!.ToDictionary(e => e.Id);
        Assert.Equal(5, extensions.Count);
        Assert.Equal(ExtensionSource.Store, extensions["uBlock0@raymondhill.net"].Source);
        Assert.Equal("uBlock Origin", extensions["uBlock0@raymondhill.net"].Name);
        Assert.True(extensions["corp@example.com"].ByPolicy);
        Assert.Equal(ExtensionSource.Sideloaded, extensions["helper@adware.test"].Source);
        Assert.Equal(ExtensionSource.Sideloaded, extensions["dropped@adware.test"].Source);
        Assert.False(extensions["dropped@adware.test"].Enabled);
        Assert.Equal(ExtensionSource.Unpacked, extensions["dev@example.com"].Source);
    }

    [Fact]
    public void Firefox_ProfilesIni_HandlesAbsolutePaths_AndOtherSections()
    {
        var parsed = FirefoxProfileReader.ParseProfilesIni(
            "[General]\nStartWithLastProfile=1\n\n[Profile1]\nName=Other\nIsRelative=0\nPath=D:\\Firefox\\other\n\n; comment\n[Profile0]\nName=default\nIsRelative=1\nPath=Profiles/x.default\nDefault=1\n[InstallABC]\nDefault=Profiles/x.default\n");

        Assert.Equal(new (string?, bool, string)[] { ("Other", false, @"D:\Firefox\other"), ("default", true, "Profiles/x.default") }, parsed);
    }

    [Fact]
    public void Firefox_BrokenDatabase_IsAProfileError()
    {
        _fixture.FirefoxProfiles("alex", ("default", "Profiles/a.default"));
        File.WriteAllText(Path.Join(_fixture.FirefoxFolder(), "Profiles", "a.default", "extensions.json"), "{\"schemaVersion\":36}");

        var profile = Assert.Single(ReadFirefox());

        Assert.Null(profile.Extensions);
        Assert.Contains("add-on list", profile.Error);
    }

    [Theory]
    [InlineData("cccccccccccccccccccccccccccccccc;https://clients2.google.com/service/update2/crx", "cccccccccccccccccccccccccccccccc", "https://clients2.google.com/service/update2/crx")]
    [InlineData(" cccccccccccccccccccccccccccccccc ", "cccccccccccccccccccccccccccccccc", null)]
    public void Policy_ForcelistValues(string value, string id, string? url)
    {
        Assert.Equal((id, url), WindowsExtensionPolicyReader.ParseForcelistValue(value));
    }

    [Fact]
    public void Policy_ExtensionSettings_KeepsOnlyEntriesThatInstall()
    {
        var entries = WindowsExtensionPolicyReader.ParseExtensionSettings("""
            {
              "*": { "installation_mode": "blocked" },
              "aaaa,bbbb": { "installation_mode": "force_installed", "update_url": "https://evil.test/update.xml" },
              "cccc": { "installation_mode": "normal_installed" },
              "dddd": { "installation_mode": "allowed" },
              "update_url:https://x.test/*": { "installation_mode": "force_installed" },
            }
            """, Browsers.Chrome, "Machine", "this computer");

        Assert.Equal(new[] { "aaaa", "bbbb", "cccc" }, entries.Select(e => e.ExtensionId));
        Assert.Equal(WindowsExtensionPolicyReader.SettingsForceKind, entries[0].Kind);
        Assert.Equal("https://evil.test/update.xml", entries[1].Location);
        Assert.Equal(WindowsExtensionPolicyReader.SettingsNormalKind, entries[2].Kind);

        Assert.Single(WindowsExtensionPolicyReader.ParseExtensionSettings("{ broken", Browsers.Edge, "Machine", "this computer"));
    }

    public void Dispose() => _fixture.Dispose();
}

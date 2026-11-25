using System.Text;
using WatchLattice.BrowserExtensionWatchdog;
using WatchLattice.Fuzz.Tests.Harness;
using Xunit;

namespace WatchLattice.Fuzz.Tests;

/// <summary>
/// Browser profiles belong to the user, and an extension writes its own
/// manifest. The hub reads both as LocalSystem. Nothing in them may stop the
/// scan: one profile that can't be read is reported as that, and the rest
/// are still checked.
/// </summary>
public class BrowserExtensionFuzzTests
{
    private const string ExtensionId = "abcdefghijklmnopabcdefghijklmnop";

    private static readonly string[] Keys =
    {
        "extensions", "settings", "profile", "info_cache", "name", "location", "state", "path", "manifest", "version", "update_url",
        "from_webstore", "was_installed_by_default", "was_installed_by_oem", "disable_reasons", "default_locale", "message",
        "addons", "id", "type", "installTelemetryInfo", "source", "defaultLocale", "active", "userDisabled", "installation_mode",
        "install_url", "*", "Default", "Profile 1", ExtensionId, "appName", "appname",
    };

    private static readonly string[] Strings =
    {
        "__MSG_appName__", "__MSG_appname__", "__MSG__", "__MSG_", "__MSG___", "__MSG_missing__", "appName", "en", "en_US", "..", "../..",
        ExtensionId, "1.0_0", ExtensionId + "/1.0_0", "\\\\server\\share\\ext", "//server/share/ext", "\\\\?\\C:\\ext", "C:\\no-such-folder\\ext",
        "/no-such-folder/ext", "https://clients2.google.com/service/update2/crx", "https://example.test/updates.xml", "extension", "theme",
        "app-profile", "app-builtin", "app-system-user", "temporary-addon", "enterprise-policy", "sideload", "amo", "force_installed",
        "normal_installed", "blocked", "addon@example.test", "{11111111-2222-3333-4444-555555555555}", "Default", "Profile 1", "",
    };

    [Fact]
    public void ChromiumProfile_AnyFiles_AreReadWithoutThrowing()
    {
        using var temp = new TempFolder();
        Fuzzer.Run(400, r => new[]
        {
            ("Local State", Document(r, LocalState)),
            ("Default/Preferences", Document(r, Preferences)),
            ("Default/Secure Preferences", Document(r, Preferences)),
            ("Profile 1/Preferences", Document(r, Preferences)),
            ($"Default/Extensions/{ExtensionId}/1.0_0/manifest.json", Document(r, Manifest)),
            ($"Default/Extensions/{ExtensionId}/1.0_0/_locales/en/messages.json", Document(r, Messages)),
        }, files =>
        {
            temp.Clear();
            foreach (var (name, content) in files) temp.Write(name, content);

            var profiles = ChromiumProfileReader.Read(Browsers.Chrome, "user", "User", temp.Path, 1024 * 1024, CancellationToken.None);

            Assert.Equal(new[] { "Default", "Profile 1" }, profiles.Select(p => p.ProfileFolder));
            foreach (var profile in profiles) AssertUsable(profile);
        }, ShowFiles);
    }

    [Fact]
    public void FirefoxProfile_AnyFiles_AreReadWithoutThrowing()
    {
        using var temp = new TempFolder();
        Fuzzer.Run(400, r => new[]
        {
            ("profiles.ini", Encoding.UTF8.GetBytes(r.Chance(0.7)
                ? "[Profile0]\nName=default\nIsRelative=1\nPath=Profiles/abc.default\n\n[Profile1]\nName=" + r.Token(Strings).ReplaceLineEndings(" ")
                    + "\nIsRelative=" + r.Pick("0", "1", "") + "\nPath=" + r.Token(Strings).ReplaceLineEndings(" ") + "\n"
                : r.Mutate("[Profile0]\nName=default\nIsRelative=1\nPath=Profiles/abc.default\n", Strings))),
            ("Profiles/abc.default/extensions.json", Document(r, Addons)),
        }, files =>
        {
            temp.Clear();
            foreach (var (name, content) in files) temp.Write(name, content);

            foreach (var profile in FirefoxProfileReader.Read("user", "User", temp.Path, 1024 * 1024, CancellationToken.None)) AssertUsable(profile);
        }, ShowFiles);
    }

    [Fact]
    public void ProfilesIni_AnyText_NeverThrows_AndEveryProfileHasAPath()
    {
        const string sample = "[Install4F96D1932A9F858E]\nDefault=Profiles/abc.default-release\nLocked=1\n\n[Profile1]\nName=default\nIsRelative=1\nPath=Profiles/xyz.default\nDefault=1\n\n[Profile0]\nName=work\nIsRelative=0\nPath=D:\\Firefox\\work\n\n[General]\nStartWithLastProfile=1\nVersion=2\n";
        var words = new[] { "[", "]", "[]", "[Profile", "=", "Path=", "Name=", "IsRelative=0", ";", "#", "\n", "\r\n", " " };
        Fuzzer.RunText(3000, r => r.Chance(0.3) ? r.Text(words, 10, 60) : r.Mutate(sample, words), text =>
        {
            foreach (var (_, _, path) in FirefoxProfileReader.ParseProfilesIni(text))
            {
                Assert.False(string.IsNullOrWhiteSpace(path));
                Assert.Equal(path.Trim(), path);
            }
        });
    }

    [Fact]
    public void ProfilesIni_WrittenAsFirefoxWritesIt_ReadsBackExactly()
    {
        Fuzzer.Run(1000, r => Enumerable.Range(0, r.Count(3, 12))
            .Select(i => (Name: r.Chance(0.2) ? null : r.Identifier(), Relative: r.Chance(0.7), Path: "Profiles/" + r.Identifier() + ".default", LineEnd: r.Pick("\n", "\r\n")))
            .ToArray(), profiles =>
        {
            var ini = new StringBuilder("[General]\nStartWithLastProfile=1\n\n; a comment\n");
            for (var i = 0; i < profiles.Length; i++)
            {
                var (name, relative, path, end) = profiles[i];
                ini.Append($"[Profile{i}]{end}");
                if (name is not null) ini.Append($"Name={name}{end}");
                ini.Append($"IsRelative={(relative ? 1 : 0)}{end}Path={path}{end}{end}");
            }

            var parsed = FirefoxProfileReader.ParseProfilesIni(ini.ToString());

            Assert.Equal(profiles.Select(p => (p.Name, p.Relative, p.Path)), parsed.Select(p => (p.Name, p.IsRelative, p.Path)));
        }, profiles => string.Join("; ", profiles.Select(p => $"{p.Name} {p.Relative} {p.Path}")));
    }

    [Fact]
    public void ExtensionPolicy_AnyValue_NeverThrows_AndEveryEntryNamesAnExtension()
    {
        var sample = "{\"*\":{\"installation_mode\":\"blocked\"},\"" + ExtensionId + "\":{\"installation_mode\":\"force_installed\",\"update_url\":\"https://example.test/u.xml\"},"
            + "\"addon@example.test, other@example.test\":{\"installation_mode\":\"normal_installed\",\"install_url\":\"https://example.test/a.xpi\"}}";
        Fuzzer.RunText(3000, r => r.Next(3) switch
        {
            0 => r.Json(Keys, Strings),
            1 => "{" + FuzzRandom.JsonString(r.Token(Strings)) + ":" + r.Json(Keys, Strings, 2) + "}",
            _ => r.Mutate(sample, Strings),
        }, json =>
        {
            foreach (var entry in WindowsExtensionPolicyReader.ParseExtensionSettings(json, Browsers.Edge, "Machine", "this computer"))
            {
                Assert.False(string.IsNullOrEmpty(entry.ExtensionId));
                Assert.NotNull(entry.Key);
                entry.Describe();
            }
            if (WindowsExtensionPolicyReader.ParseForcelistValue(json) is var (id, _)) Assert.NotEqual("", id);
        });
    }

    private static void AssertUsable(BrowserProfile profile)
    {
        // Either the extensions, or why they could not be read: never neither, and never an exception.
        Assert.True(profile.Extensions is null != profile.Error is null, "A profile has either extensions or an error.");
        Assert.False(string.IsNullOrWhiteSpace(profile.ProfileName));
        foreach (var extension in profile.Extensions ?? Array.Empty<InstalledExtension>())
        {
            // The ID is whatever the file says, even an empty one: hiding an odd entry would hide tampering.
            Assert.NotNull(extension.Id);
            Assert.False(string.IsNullOrWhiteSpace(extension.Name));
            Assert.Equal(extension.Name.Trim(), extension.Name);
            Assert.False(string.IsNullOrWhiteSpace(extension.SourceDetail));
        }
        profile.Describe();
    }

    /// <summary>
    /// A file as a browser might leave it: usually the right shape with odd
    /// values, sometimes any JSON at all, sometimes damaged text or bytes.
    /// </summary>
    private static byte[] Document(FuzzRandom r, Func<FuzzRandom, string> shape)
    {
        var text = r.Next(10) switch
        {
            0 => r.Json(Keys, Strings),
            1 => r.Mutate(shape(r), Strings),
            _ => shape(r),
        };
        var bytes = Encoding.UTF8.GetBytes(text);
        if (r.Chance(0.1)) bytes = r.Mutate(bytes);
        return r.Chance(0.1) ? Encoding.UTF8.GetPreamble().Concat(bytes).ToArray() : bytes;
    }

    /// <summary>The expected kind of value most of the time, anything else the rest.</summary>
    private static string Or(FuzzRandom r, string usual) => r.Chance(0.8) ? usual : r.Json(Keys, Strings, 2);

    private static string Str(FuzzRandom r, params string[] usual) =>
        Or(r, FuzzRandom.JsonString(r.Chance(0.7) ? r.Pick(usual) : r.Token(Strings)));

    private static string LocalState(FuzzRandom r) =>
        "{\"profile\":{\"info_cache\":" + Or(r, "{\"Default\":{\"name\":" + Str(r, "Person 1", " ") + "},\"Profile 1\":" + Or(r, "{\"name\":" + Str(r, "Work") + "}") + "}") + "}}";

    private static string Preferences(FuzzRandom r)
    {
        var entries = Enumerable.Range(0, r.Next(4)).Select(i =>
            FuzzRandom.JsonString(i == 0 ? ExtensionId : r.Token(Strings)) + ":" + Or(r, "{"
            + "\"location\":" + Or(r, r.Next(12).ToString()) + ","
            + "\"state\":" + Or(r, r.Next(2).ToString()) + ","
            + (r.Chance(0.5) ? "\"path\":" + Str(r, ExtensionId + "/1.0_0", "..", "\\\\server\\share\\ext", "C:\\no-such-folder\\ext") + "," : "")
            + (r.Chance(0.5) ? "\"manifest\":" + Or(r, Manifest(r)) + "," : "")
            + (r.Chance(0.3) ? "\"disable_reasons\":" + Or(r, r.Pick("0", "1", "[]", "[1]")) + "," : "")
            + "\"from_webstore\":" + Or(r, r.Pick("true", "false")) + "}"));
        return "{\"extensions\":" + Or(r, "{\"settings\":" + Or(r, "{" + string.Join(",", entries) + "}") + "}") + "}";
    }

    private static string Manifest(FuzzRandom r) =>
        "{\"name\":" + Str(r, "__MSG_appName__", "__MSG__", "My extension") + ",\"version\":" + Str(r, "1.0", "2.3.4")
        + ",\"default_locale\":" + Str(r, "en", "..", "en_US") + ",\"update_url\":" + Str(r, "https://clients2.google.com/service/update2/crx") + "}";

    private static string Messages(FuzzRandom r) =>
        "{" + FuzzRandom.JsonString(r.Pick("appName", "appname", "APPNAME", "other")) + ":" + Or(r, "{\"message\":" + Str(r, "My extension", " ") + "}") + "}";

    private static string Addons(FuzzRandom r)
    {
        var addons = Enumerable.Range(0, r.Next(5)).Select(_ => Or(r, "{"
            + "\"id\":" + Str(r, "addon@example.test", "{11111111-2222-3333-4444-555555555555}") + ","
            + "\"type\":" + Str(r, "extension", "theme") + ","
            + "\"location\":" + Str(r, "app-profile", "app-builtin", "app-system-user", "temporary-addon") + ","
            + (r.Chance(0.6) ? "\"installTelemetryInfo\":" + Or(r, "{\"source\":" + Str(r, "amo", "sideload", "enterprise-policy") + "}") + "," : "")
            + (r.Chance(0.6) ? "\"defaultLocale\":" + Or(r, "{\"name\":" + Str(r, "My add-on", " ") + "}") + "," : "")
            + "\"version\":" + Str(r, "1.0") + ",\"active\":" + Or(r, r.Pick("true", "false")) + ",\"userDisabled\":" + Or(r, r.Pick("true", "false")) + "}"));
        return "{\"schemaVersion\":36,\"addons\":" + Or(r, "[" + string.Join(",", addons) + "]") + "}";
    }

    private static string ShowFiles((string Name, byte[] Content)[] files) => string.Join("\n", files.Select(f =>
    {
        var text = Encoding.UTF8.GetString(f.Content);
        // Hex as well when the bytes are not the text's own UTF-8, since the text alone would not reproduce them.
        var exact = Encoding.UTF8.GetBytes(text).AsSpan().SequenceEqual(f.Content);
        return $"  {f.Name}: {Fuzzer.Literal(text)}{(exact ? "" : " (hex " + Convert.ToHexString(f.Content) + ")")}";
    }));
}

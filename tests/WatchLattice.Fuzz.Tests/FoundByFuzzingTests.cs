using System.Text;
using System.Text.Json;
using WatchLattice.BrowserExtensionWatchdog;
using WatchLattice.Common.Activity;
using WatchLattice.Common.Alerts;
using WatchLattice.Common.Export;
using WatchLattice.Common.Settings;
using WatchLattice.DefenderWatchdog;
using WatchLattice.FirewallWatchdog;
using WatchLattice.Fuzz.Tests.Harness;
using WatchLattice.HostsProxyWatchdog;
using WatchLattice.Persistence;
using WatchLattice.Persistence.Verification;
using WatchLattice.ScriptHostAudit;
using WatchLattice.Updater;
using Xunit;

namespace WatchLattice.Fuzz.Tests;

/// <summary>
/// One plain test for each defect the fuzz tests found, with the smallest
/// input that showed it, so each stays fixed whatever inputs later runs
/// happen to generate. docs/fuzzing.md lists them in words.
/// </summary>
public class FoundByFuzzingTests
{
    private const string ExtensionId = "abcdefghijklmnopabcdefghijklmnop";
    private const string OtherId = "ponmlkjihgfedcbaponmlkjihgfedcba";

    private static readonly SystemPaths Paths = new(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["SystemRoot"] = @"C:\Windows", ["windir"] = @"C:\Windows", ["SystemDrive"] = "C:", ["ProgramFiles"] = @"C:\Program Files",
        ["ProgramFiles(x86)"] = @"C:\Program Files (x86)", ["ProgramData"] = @"C:\ProgramData", ["PUBLIC"] = @"C:\Users\Public",
    }, Is64BitOperatingSystem: true);

    private static readonly DateTimeOffset Now = new(2026, 11, 20, 12, 0, 0, TimeSpan.Zero);

    // Browser extension watchdog. Each of these once stopped the scan of every browser and every user until the file changed.

    [Theory]
    [InlineData("\"name\":\"__MSG__\",\"default_locale\":\"en\"")]
    [InlineData("\"name\":\"\\ud800\"")]
    [InlineData("\"name\":\"ok\",\"\\ud800\":1")]
    public void Chromium_AManifestThatCannotBeRead_DoesNotHideTheOtherExtensions(string manifestFields)
    {
        using var temp = new TempFolder();
        // The extension's own files, where a name such as "__MSG_appName__" is looked up; "__MSG__" has nothing to look up.
        temp.Write($"Default/Extensions/{ExtensionId}/1.0_0/manifest.json", "{\"name\":\"__MSG__\",\"default_locale\":\"en\",\"version\":\"1.0\"}"u8.ToArray());
        temp.Write("Default/Preferences", Encoding.UTF8.GetBytes(
            "{\"extensions\":{\"settings\":{\"" + ExtensionId + "\":{\"location\":1,\"state\":1,\"manifest\":{" + manifestFields + ",\"version\":\"1.0\"}},"
            + "\"" + OtherId + "\":{\"location\":1,\"state\":1,\"manifest\":{\"name\":\"Other\",\"version\":\"2.0\"}}}}}"));

        var profile = Assert.Single(ChromiumProfileReader.Read(Browsers.Chrome, "user", "User", temp.Path, 1024 * 1024, CancellationToken.None));

        Assert.Null(profile.Error);
        Assert.Equal(new[] { ExtensionId, OtherId }, profile.Extensions!.Select(e => e.Id).Order(StringComparer.Ordinal));
        Assert.Contains(profile.Extensions!, e => e.Name == "Other");
        Assert.All(profile.Extensions!, e => Assert.False(string.IsNullOrWhiteSpace(e.Name)));
    }

    [Fact]
    public void Chromium_AnExtensionFolderOnAnotherComputer_IsNeverOpened()
    {
        using var temp = new TempFolder();
        // Where "\\server\share\ext" would lead if it were joined to the profile instead of refused; on Windows it would be the network.
        temp.Write("Default/Extensions/server/share/ext/manifest.json", "{\"name\":\"Planted\",\"version\":\"9.9\"}"u8.ToArray());
        temp.Write("Default/Preferences", Encoding.UTF8.GetBytes(
            "{\"extensions\":{\"settings\":{\"" + ExtensionId + "\":{\"location\":4,\"state\":1,\"path\":\"\\\\\\\\server\\\\share\\\\ext\"}}}}"));

        var profile = Assert.Single(ChromiumProfileReader.Read(Browsers.Chrome, "user", "User", temp.Path, 1024 * 1024, CancellationToken.None));

        var extension = Assert.Single(profile.Extensions!);
        Assert.Equal(ExtensionId, extension.Name);
        Assert.Null(extension.Version);
    }

    [Theory]
    [InlineData(@"\\server\share\profile")]
    [InlineData("//server/share/profile")]
    [InlineData(@"\\?\C:\profile")]
    public void Firefox_AProfileOnAnotherComputer_IsReportedAndNotOpened(string path)
    {
        using var temp = new TempFolder();
        temp.Write("profiles.ini", Encoding.UTF8.GetBytes($"[Profile0]\nName=remote\nIsRelative=0\nPath={path}\n"));

        var profile = Assert.Single(FirefoxProfileReader.Read("user", "User", temp.Path, 1024 * 1024, CancellationToken.None));

        Assert.Null(profile.Extensions);
        Assert.Contains("not opened", profile.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void ExtensionPolicy_TextThatIsNotValidUnicode_IsReadWithoutThrowing()
    {
        var entries = WindowsExtensionPolicyReader.ParseExtensionSettings(
            "{\"" + ExtensionId + "\":{\"installation_mode\":\"force_installed\"},\"x\ud800\":{\"installation\\udaaa\":\"\"}}", Browsers.Edge, "Machine", "this computer");

        Assert.Equal(ExtensionId, Assert.Single(entries).ExtensionId);
    }

    // Script host audit.

    [Theory]
    [InlineData("tool.exe password=\"\"Zq9Secret", "tool.exe password=[hidden]")]
    [InlineData("tool.exe -Password \"abc\"Zq9Secret -Force", "tool.exe -Password [hidden] -Force")]
    [InlineData("tool.exe -Password \"Zq9Secret -Force", "tool.exe -Password [hidden]")]
    [InlineData("azcopy \"https://a.example/c?sv=1&sig=Zq9Secret\" --recursive", "azcopy \"https://a.example/c?sv=1&sig=[hidden]\" --recursive")]
    public void Redactor_AValueQuotedOnlyInPart_IsHiddenWhole(string commandLine, string expected)
    {
        Assert.Equal((expected, true), CommandLineRedactor.Redact(commandLine));
    }

    // Persistence auditor and verification.

    [Theory]
    [InlineData("a")]
    [InlineData(".")]
    [InlineData("%")]
    public void Resolve_AOneCharacterName_DoesNotThrow(string name)
    {
        // Reached from the auditor's own grading of a service change, so this once stopped the whole module.
        Assert.NotNull(WindowsPath.Resolve(name, Paths, null, _ => false).Note);
        Assert.Equal(ServiceLocation.Unresolved, ServiceAnalysis.LocationOf(new ServiceDefinition(0x10, 2, name, null, null, null).ToProjection(), Paths));
    }

    [Theory]
    [InlineData(":")]
    [InlineData(":x")]
    [InlineData("x:y:z")]
    public void Resolve_AColonAnywhereButAfterADriveLetter_IsRefusedBeforeAnythingIsLookedFor(string name)
    {
        var probed = new List<string>();
        var resolved = WindowsPath.Resolve(name, Paths, null, path => { probed.Add(path); return true; });

        Assert.Equal(PathResolution.Invalid, resolved.Kind);
        Assert.Empty(probed);
    }

    [Theory]
    [InlineData(@"C:\Users\Public\x.exe. -k netsvcs")]
    [InlineData("\"\\SystemRoot\\Temp\\x.exe\" -k netsvcs")]
    [InlineData("\"System32\\Tasks\\x.exe\"")]
    public void Service_InAFolderUsersCanWrite_IsGradedThatWayHoweverItIsSpelled(string imagePath)
    {
        var after = new ServiceDefinition(0x10, 2, imagePath, null, "LocalSystem", null);

        Assert.Equal(ServiceLocation.UserWritable, ServiceAnalysis.LocationOf(after.ToProjection(), Paths));
    }

    [Theory]
    [InlineData("{\"Enabled\":true,\"UserId\":\"x\ud800\"}")]
    [InlineData("{\"Enabled\":true,\"UserId\":\"\\ud800\"}")]
    [InlineData("{\"Enabled\":true,\"\\ud800\":1}")]
    [InlineData("{\"Enabled\":true,\"Enabled\":false}")]
    [InlineData("{\"Actions\":[{\"Execute\":\"a\",\"Execute\":\"b\"}]}")]
    public void LoggedTask_TextThatCannotBeRead_IsRefusedTheDocumentedWay(string json)
    {
        // The auditor asks this of every changed task; an exception it does not expect would stop the module.
        Assert.False(TaskComparison.IsTimingOnlyChange(json, json));
        var refused = Record.Exception(() => TaskComparison.CompareLogged(json, json));
        Assert.True(refused is null or JsonException or InvalidDataException, refused?.ToString());
        refused = Record.Exception(() => TaskFacts.FromProjection(json));
        Assert.True(refused is null or JsonException or InvalidDataException, refused?.ToString());
        Assert.Null(ServiceDefinition.TryParse("{\"ImagePath\":\"x\ud800\",\"ImagePath\":1}"));
    }

    [Fact]
    public void Diff_NamesThatDifferOnlyByCase_AreOneEntry()
    {
        // A Startup folder can be made case-sensitive; this once threw, and the baseline was then refused as damaged.
        var before = new[] { new PersistenceEntry("a.lnk", "one"), new PersistenceEntry("A.lnk", "two") };
        var after = new[] { new PersistenceEntry("A.lnk", "two"), new PersistenceEntry("a.lnk", "three") };

        Assert.Empty(PersistenceDiff.Compare(before, before));
        var change = Assert.Single(PersistenceDiff.Compare(before, after));
        Assert.Equal(PersistenceChangeKind.Changed, change.Kind);
        Assert.Equal("one\ntwo", change.Before);
        Assert.Equal("three\ntwo", change.After);
    }

    // Hosts file.

    [Theory]
    [InlineData("download.windowsupdate.com\uff0e", "download.windowsupdate.com")]
    [InlineData("download.windowsupdate.com.\u200b", "download.windowsupdate.com")]
    [InlineData("DOWNLOAD.WindowsUpdate.com..", "download.windowsupdate.com")]
    public void Hosts_ANameWrittenWithAnotherKindOfDot_IsStillTheWatchedName(string written, string expected)
    {
        var host = HostsFileParser.NormalizeHost(written);

        Assert.Equal(expected, host);
        Assert.True(HostsFileParser.IsWithin(host!, "windowsupdate.com"));
    }

    [Theory]
    [InlineData("a .")]
    [InlineData("a . .")]
    [InlineData(" a. ")]
    public void Hosts_ANameReadASecondTime_IsUnchanged(string written)
    {
        var host = HostsFileParser.NormalizeHost(written);

        Assert.Equal("a", host);
        Assert.Equal(host, HostsFileParser.NormalizeHost(host));
    }

    // Updater.

    [Theory]
    [InlineData("1.\u0662.3")]
    [InlineData("\uff11.2.3")]
    [InlineData("1.2.\u0969")]
    public void ReleaseVersion_DigitsFromOtherScripts_AreNotAVersion(string text)
    {
        // The pattern's \d accepted these and int.Parse then threw FormatException out of TryParse.
        Assert.False(ReleaseVersion.TryParse(text, out _));
    }

    [Fact]
    public void Checksums_TextThatIsNotAHash_MatchesNothing()
    {
        var hash = new string('a', 64);

        Assert.False(Sha256Sums.Matches(hash, new string('g', 64)));
        Assert.False(Sha256Sums.Matches(new string('\u0661', 64), hash));
        Assert.True(Sha256Sums.Matches(hash, hash.ToUpperInvariant()));
        Assert.Throws<InvalidDataException>(() => Sha256Sums.Parse(hash + "  ./\n"));
        Assert.Throws<InvalidDataException>(() => InstallManifest.Parse($"# WatchLattice 0.11.0\n{hash}  Hub/a\0b.dll\n"));
    }

    [Theory]
    [InlineData("{\"tag_name\":\"v1.0.0\",\"html_url\":\"https://github.com/o/r\",\"assets\":[5]}")]
    [InlineData("{\"tag_name\":\"v1.0.0\",\"html_url\":\"https://github.com/o/r\",\"assets\":[{\"name\":\"\\ud800\"}]}")]
    [InlineData("{\"tag_name\":\"\\ud800\",\"html_url\":\"https://github.com/o/r\"}")]
    [InlineData("{\"tag_name\":\"v1.0.0\",\"html_url\":\"/\\\\\u202e\"}")]
    public void ReleaseMetadata_OfTheWrongShape_IsRefusedTheDocumentedWay(string json)
    {
        Assert.Throws<InvalidDataException>(() => GitHubReleaseSource.Parse(Encoding.UTF8.GetBytes(json)));
    }

    [Fact]
    public void ReleaseMetadata_ASizeThatIsNotANumber_IsUnknownRatherThanAnError()
    {
        var release = GitHubReleaseSource.Parse(Encoding.UTF8.GetBytes(
            "{\"tag_name\":\"v1.0.0\",\"html_url\":\"https://github.com/o/r\",\"assets\":[{\"name\":\"a.zip\",\"size\":\"12\",\"browser_download_url\":\"https://github.com/o/r/releases/download/v1.0.0/a.zip\"}]}"));

        Assert.Equal(-1, Assert.Single(release.Assets).Size);
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("{\"runtimeOptions\":{\"frameworks\":[\"Microsoft.NETCore.App\"]}}")]
    [InlineData("{\"runtimeOptions\":{\"framework\":{\"name\":\"\\ud800\",\"version\":\"10.0.0\"}}}")]
    [InlineData("{\"runtimeOptions\":{\"framework\":{\"name\":\"Microsoft.NETCore.App.\",\"version\":\"10.0.0\"}}}")]
    public void RuntimeConfig_OfTheWrongShape_IsRefusedTheDocumentedWay(string json)
    {
        using var temp = new TempFolder();
        var path = temp.Write("app.runtimeconfig.json", Encoding.UTF8.GetBytes(json));

        Assert.Throws<InvalidDataException>(() => RuntimeRequirements.Read(path));
    }

    // Exports, approvals and settings.

    [Fact]
    public void FullExport_ANameCutShortOrBehindAnEscape_IsStillHidden()
    {
        var redactor = new NameRedactor(new[] { "zqbrian" }, new[] { "ZQ-PC-01" });
        var options = new FullExportOptions { MaxTextLength = 40 };
        // The cut falls inside the name. Hiding names after cutting left "zqbri" in the file.
        var activity = new ActivitySnapshot(ActivitySnapshot.CurrentVersion, Guid.NewGuid(),
            new[] { new ActivityEntry(Now, Microsoft.Extensions.Logging.LogLevel.Warning, "Persistence", new string('x', 20) + @" C:\Users\zqbrian\AppData\Local\file.txt") });
        // In the written JSON the name follows "\t", and the t made it look like part of a longer word.
        var settings = SettingValues.Parse("{\"Alerts\":{\"FeedPath\":\"\\tzqbrian\\nZQ-PC-01\"}}");
        var data = new FullExportData(Now, "0.11.0", "Windows 11", Array.Empty<ExportModule>(), null, AlertReviewSet.Empty, activity, settings, null, null, null, Array.Empty<string>());

        var export = FullExport.Build(data, options, redactor);

        Assert.DoesNotContain("zqbri", export, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ZQ-PC", export, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(@"C:\Users\<user>", export, StringComparison.Ordinal);
        Assert.Contains(@"\t<user>\n<computer>", export, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("RunKeys/HKCU/Updater ")]
    [InlineData(" RunKeys/HKCU/Updater")]
    [InlineData("RunKeys/HKCU/Updater\ud800")]
    public void Approval_ForAnEntryWhoseNameASettingsFileCannotHoldExactly_StillMatchesIt(string resource)
    {
        const string value = "\"C:\\Program Files\\App\\updater.exe\" /background";
        var alert = new ProtectionAlert(Guid.NewGuid(), Now, BaselineApprovals.PersistenceModule, "ENTRY_ADDED", AlertSeverity.Warning, "New autostart entry",
            "Details\n" + BaselineApprovals.FingerprintLine(value), resource);

        var approval = BaselineApprovals.For(alert)!;
        // The trip to the elevated editor, then into the settings file and back out as the module reads it.
        Assert.True(BaselineApprovals.TryDecode(BaselineApprovals.Encode(approval), out var decoded));
        var saved = SettingValues.Parse(SettingValues.Serialize(new System.Text.Json.Nodes.JsonObject { ["Line"] = decoded.Value }));
        Assert.True(ApprovedEntry.TryParse(saved["Line"]!.GetValue<string>().Trim(), out var entry));

        Assert.True(entry.Matches(resource, value));
        Assert.False(entry.Matches(resource, value + " "));
        Assert.False(entry.Matches(resource + "x", value));
        var settings = new System.Text.Json.Nodes.JsonObject();
        Assert.True(BaselineApprovals.Stage(settings, approval));
        Assert.False(BaselineApprovals.Stage(settings, decoded));
    }

    [Fact]
    public void ApprovalToken_WithALineBreakAfterAnExtensionId_IsRefused()
    {
        // "$" in a .NET pattern also matches just before a final line break, which let this through.
        var token = Convert.ToBase64String(Encoding.UTF8.GetBytes(BaselineApprovals.ExtensionSetting + "\n" + ExtensionId + "\n")).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        Assert.False(BaselineApprovals.TryDecode(token, out _));
        Assert.False(BaselineApprovals.IsExtensionId(ExtensionId + "\n"));
        Assert.True(BaselineApprovals.IsExtensionId(ExtensionId));
    }

    [Theory]
    [InlineData("C:\\Users\\me\\file.txt\n")]
    [InlineData("C:\\Users\\me\\file\u007f.txt")]
    [InlineData("C:\\Users\\me\\file\u0085.txt")]
    public void OpenFileLocation_APathWithAControlCharacter_IsRefused(string path)
    {
        Assert.False(SafeActionLauncher.IsLocalPath(path));
        Assert.True(SafeActionLauncher.IsLocalPath(@"C:\Users\me\file.txt"));
    }

    [Theory]
    [InlineData("{\"Alerts\":{\"Enabled\":true,\"enabled\":false}}")]
    [InlineData("{\"Alerts\":{\"Enabled\":true},\"alerts\":{\"HistoryLimit\":5}}")]
    [InlineData("{\"Alerts:Enabled\":true,\"Alerts\":{\"Enabled\":false}}")]
    [InlineData("{\"Alerts\":{\"FeedPath\":\"\\ud800\"}}")]
    [InlineData("{\"\\ud800\":1}")]
    public void Settings_OneSettingWrittenTwice_OrTextThatCannotBeRead_IsRefusedTheDocumentedWay(string json)
    {
        // The hub itself will not start with such a file; the editor now says why instead of failing part way through a check.
        var refused = Record.Exception(() => SettingValues.Parse(json));

        Assert.True(refused is JsonException or InvalidDataException, refused?.ToString() ?? "It was accepted.");
    }

    [Fact]
    public void Settings_AnEmptyName_IsKeptApartFromTheSettingBesideIt()
    {
        var settings = SettingValues.Parse("{\"\":{\"FeedPath\":\"a\"},\"FeedPath\":\"b\"}");

        Assert.Empty(SettingsValidator.CheckBinding(new[] { ("Alerts", typeof(AlertDeliveryOptions)) }, settings));
        Assert.Equal(new[] { ":FeedPath", "FeedPath" }, SettingsValidator.ToConfiguration(settings).Select(p => p.Key));
    }

    // Status queries.

    [Theory]
    [InlineData("{\"AntivirusSignatureLastUpdated\":\"/Date(9223372036854775807)/\"}")]
    [InlineData("{\"AntivirusSignatureLastUpdated\":\"/Date(-99999999999999999)/\"}")]
    [InlineData("{\"AMRunningMode\":\"\\ud800\"}")]
    [InlineData("{\"AMRunningMode\":\"x\ud800\"}")]
    public void StatusQueries_ADateOrTextThatCannotBeRead_IsHandledWithoutThrowing(string json)
    {
        var defender = DefenderStatusParser.Parse(json);
        Assert.Equal(defender.Available, defender.Error is null);
        Assert.Null(defender.SignatureLastUpdated);

        var firewall = FirewallStatusParser.Parse(json.Replace("AMRunningMode", "RulesError", StringComparison.Ordinal));
        Assert.False(firewall.Available);
    }
}

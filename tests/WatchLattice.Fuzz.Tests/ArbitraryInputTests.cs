using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml;
using FsCheck;
using WatchLattice.BrowserExtensionWatchdog;
using WatchLattice.Canary;
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
/// Every reader of text or bytes that someone else can write, given inputs
/// from FsCheck (see <see cref="Arbitrary"/>): a second source of inputs,
/// written apart from the per-format tests beside this file, which start
/// from real samples. Each reader must return, or refuse the input in the
/// way its callers handle. Anything else thrown here would, in the hub,
/// stop a module or the editor.
/// </summary>
public class ArbitraryInputTests
{
    private const string ExtensionId = "abcdefghijklmnopabcdefghijklmnop";
    private const string Hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    private static readonly SystemPaths Paths = new(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["SystemRoot"] = @"C:\Windows", ["windir"] = @"C:\Windows", ["SystemDrive"] = "C:", ["ProgramFiles"] = @"C:\Program Files",
        ["ProgramFiles(x86)"] = @"C:\Program Files (x86)", ["ProgramData"] = @"C:\ProgramData", ["PUBLIC"] = @"C:\Users\Public",
    }, Is64BitOperatingSystem: true);

    [Fact]
    public void HostsFile_AnyText_IsReadWithoutThrowing_AndEveryNameIsInItsOneForm()
    {
        var inputs = Arbitrary.TextOf("127.0.0.1", "0.0.0.0", "::1", "::", "10.1.2.3", "localhost", "download.windowsupdate.com", "WWW.Example.COM.", "xn--", "\uff0e", "\u3002", "#", "\n", "\r\n", " ", "\t");
        Arbitrary.Check(nameof(HostsFile_AnyText_IsReadWithoutThrowing_AndEveryNameIsInItsOneForm), 1500, inputs, text =>
        {
            foreach (var (host, addresses) in HostsFileParser.Parse(text))
            {
                Assert.Equal(host, HostsFileParser.NormalizeHost(host));
                Assert.NotEmpty(addresses);
                foreach (var address in addresses) HostsFileParser.IsBlockingAddress(address);
            }
            if (HostsFileParser.NormalizeHost(text) is { } name)
            {
                Assert.Equal(name, HostsFileParser.NormalizeHost(name));
                Assert.True(HostsFileParser.IsWithin(name, name));
            }
            HostsFileParser.IsBlockingAddress(text);
        });
    }

    [Fact]
    public void ProxySettings_AnyBytes_AreReadWithoutThrowing()
    {
        Arbitrary.Check(nameof(ProxySettings_AnyBytes_AreReadWithoutThrowing), 1500, Arbitrary.Bytes, bytes =>
        {
            foreach (var winInet in new[] { true, false })
            {
                var values = new Dictionary<string, string>();
                ConnectionSettingsBlob.AddTo(values, "P.", bytes, winInet);
                Assert.NotEmpty(values);
                Assert.All(values, value => Assert.StartsWith("P.", value.Key, StringComparison.Ordinal));
            }
        });
    }

    [Fact]
    public void BrowserSettings_AnyText_AreReadWithoutThrowing()
    {
        var inputs = Arbitrary.Json("*", ExtensionId, "installation_mode", "force_installed", "blocked", "update_url", "install_url", "addon@example.test", "https://example.test/u.xml",
            "[Profile0]", "[Install", "Name=", "Path=", "IsRelative=", "Default=1", "\n", ";");
        Arbitrary.Check(nameof(BrowserSettings_AnyText_AreReadWithoutThrowing), 1500, inputs, text =>
        {
            foreach (var entry in WindowsExtensionPolicyReader.ParseExtensionSettings(text, Browsers.Edge, "Machine", "this computer"))
            {
                Assert.False(string.IsNullOrEmpty(entry.ExtensionId));
                entry.Describe();
            }
            if (WindowsExtensionPolicyReader.ParseForcelistValue(text) is var (id, _)) Assert.NotEqual("", id);
            foreach (var (_, _, path) in FirefoxProfileReader.ParseProfilesIni(text)) Assert.False(string.IsNullOrWhiteSpace(path));
        });
    }

    [Fact]
    public void BrowserProfiles_AnyFiles_GiveTheirExtensionsOrAReason()
    {
        using var temp = new TempFolder();
        var inputs = Arbitrary.Json("extensions", "settings", "profile", "info_cache", "name", "location", "state", "path", "manifest", "version", "update_url", "default_locale",
            "disable_reasons", "addons", "id", "type", "active", "userDisabled", "defaultLocale", "Default", ExtensionId, "__MSG_appName__", "__MSG__", "..", "\\\\server\\share\\ext", "extension");
        Arbitrary.Check(nameof(BrowserProfiles_AnyFiles_GiveTheirExtensionsOrAReason), 300, inputs, text =>
        {
            var bytes = Encoding.UTF8.GetBytes(text);
            temp.Clear();
            temp.Write("Local State", bytes);
            temp.Write("Default/Preferences", bytes);
            temp.Write("Default/Secure Preferences", Encoding.UTF8.GetBytes(
                "{\"extensions\":{\"settings\":{\"" + ExtensionId + "\":{\"location\":1,\"manifest\":{\"name\":\"__MSG_appName__\",\"version\":\"1.0\"}}}}}"));
            temp.Write($"Default/Extensions/{ExtensionId}/1.0_0/manifest.json", bytes);
            temp.Write("profiles.ini", "[Profile0]\nName=default\nIsRelative=1\nPath=Profiles/abc.default\n"u8.ToArray());
            temp.Write("Profiles/abc.default/extensions.json", bytes);

            var profiles = ChromiumProfileReader.Read(Browsers.Chrome, "user", "User", temp.Path, 1024 * 1024, CancellationToken.None)
                .Concat(FirefoxProfileReader.Read("user", "User", temp.Path, 1024 * 1024, CancellationToken.None)).ToList();

            Assert.Contains(profiles, profile => profile.ProfileFolder == "Default");
            foreach (var profile in profiles)
            {
                Assert.True(profile.Extensions is null != profile.Error is null, "A profile has either extensions or an error.");
                Assert.All(profile.Extensions ?? Array.Empty<InstalledExtension>(), extension => Assert.False(string.IsNullOrWhiteSpace(extension.Name)));
            }
        });
    }

    [Fact]
    public void CommandLines_AnyText_AreReadAndRedactedWithoutThrowing()
    {
        var inputs = Arbitrary.TextOf("powershell.exe", "-EncodedCommand", "-Password", "password=", "--token", "/p:", "https://user:", "@example.test/", "?sig=", "&", "\"", "'", " ", ";",
            "<Event>", "<EventData>", "<Data Name='NewProcessName'>", "<Data Name='CommandLine'>", "</Data>", "</EventData>", "</Event>", "<!DOCTYPE x [<!ENTITY a 'b'>]>", "&a;");
        Arbitrary.Check(nameof(CommandLines_AnyText_AreReadAndRedactedWithoutThrowing), 1500, inputs, text =>
        {
            var (redacted, hidden) = CommandLineRedactor.Redact(text);
            if (!hidden) Assert.Equal(text, redacted);
            else Assert.Contains(CommandLineRedactor.Mask, redacted, StringComparison.Ordinal);
            if (ProcessCreationEvent.FromXml(text) is { } launch) Assert.False(string.IsNullOrWhiteSpace(launch.NewProcessName));
        });
    }

    [Fact]
    public void Paths_AnyText_ResolveOrAreRefused_WithoutThrowing()
    {
        var inputs = Arbitrary.TextOf(@"C:\", @"C:\Windows\System32\", @"\SystemRoot\", @"System32\", "%SystemRoot%", "%ProgramData%", "%", @"\\server\share\", @"\\?\", @"\??\", "svchost.exe", "x.dll", ".exe", ".", "..", "\"", " ", ":", ",", "-k", "{", "}", "00000000-0000-0000-0000-000000000000");
        Arbitrary.Check(nameof(Paths_AnyText_ResolveOrAreRefused_WithoutThrowing), 2000, inputs, text =>
        {
            var probed = new List<string>();
            var resolved = WindowsPath.Resolve(text, Paths, null, path => { probed.Add(path); return false; });
            if (resolved.Kind is PathResolution.Resolved or PathResolution.SearchOrder) Assert.Matches(@"\A[A-Za-z]:\\", resolved.Path);
            Assert.NotNull(resolved.Note);
            // Whatever is looked for is a plain path on this computer: never a share, a device or a stream.
            Assert.All(probed, path => Assert.Matches(@"\A[A-Za-z]:\\[^:]*\z", path));
            ServiceAnalysis.Classify(resolved, Paths);

            var service = new ServiceDefinition(0x10, 2, text, text, text, text);
            Assert.Equal(service, ServiceDefinition.TryParse(service.ToProjection()) is { } read ? Restore(read, service) : null);
            ServiceAnalysis.LocationOf(service.ToProjection(), Paths);
            ServiceAnalysis.LocationOf(text, Paths);
            Assert.False(ServiceAnalysis.IsRoutineUpdate(service, service, Paths));
            Assert.Contains(WindowsPath.ExtractCommandPath(text), text, StringComparison.Ordinal);
            if (WindowsPath.IsValidTaskPath(text)) WindowsPath.SplitTaskPath(text);
            if (WindowsPath.TryNormalizeClsid(text, out var clsid)) Assert.True(WindowsPath.TryNormalizeClsid(clsid, out _));
        });
    }

    [Fact]
    public void LoggedDefinitions_AnyJson_AreReadOrRefusedTheDocumentedWay()
    {
        var inputs = Arbitrary.Json("Enabled", "Hidden", "UserId", "RunLevel", "Actions", "Triggers", "Execute", "Arguments", "ClassId", "Type", "Start", "ImagePath", "ServiceDll", "ObjectName",
            "FailureCommand", "Id", "Command", @"C:\Windows\System32\svchost.exe -k netsvcs", @"\Microsoft\Windows\Defrag\ScheduledDefrag", "LocalSystem", "S-1-5-18", "Highest");
        Arbitrary.Check(nameof(LoggedDefinitions_AnyJson_AreReadOrRefusedTheDocumentedWay), 1500, inputs, json =>
        {
            Assert.False(TaskComparison.IsTimingOnlyChange(json, json));
            Refusable<JsonException, InvalidDataException>(() => TaskFacts.FromProjection(json));
            Refusable<JsonException, InvalidDataException>(() => Assert.Empty(TaskComparison.CompareLogged(json, json)));
            Refusable<JsonException, InvalidDataException>(() =>
            {
                var entries = WindowsPersistenceProvider.ParseScheduledTasks(json);
                Assert.Empty(PersistenceDiff.Compare(entries, entries));
            });
            if (ServiceDefinition.TryParse(json) is { } service) ServiceAnalysis.Target(service, Paths, _ => false);
            ServiceAnalysis.LocationOf(json, Paths);
        });
    }

    [Fact]
    public void TaskXml_AnyText_IsReadOrRefusedTheDocumentedWay()
    {
        var inputs = Arbitrary.TextOf("<Task>", "</Task>", "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">", "<Actions Context=\"Author\">", "</Actions>", "<Exec>", "</Exec>",
            "<Command>", "</Command>", "<Arguments>", "</Arguments>", "<ComHandler>", "<ClassId>", "<Principals>", "<Principal id=\"Author\">", "<UserId>", "<Settings>", "<Enabled>false</Enabled>",
            "<!DOCTYPE t [<!ENTITY a SYSTEM \"file:///c:/windows/win.ini\">]>", "&a;", "<![CDATA[", "]]>", "<?xml version=\"1.0\" encoding=\"UTF-16\"?>", "cmd.exe");
        Arbitrary.Check(nameof(TaskXml_AnyText_IsReadOrRefusedTheDocumentedWay), 1500, inputs, xml =>
            Refusable<XmlException, InvalidDataException>(() => Assert.All(TaskFacts.FromXml(xml).Actions, action => Assert.NotNull(action.Describe()))));
    }

    [Fact]
    public void ReleaseFiles_AnyText_AreReadOrRefusedTheDocumentedWay()
    {
        var inputs = Arbitrary.TextOf(Hash, Hash.ToUpperInvariant(), "0123", "  ", " *", "\n", "\r\n", "#", "# WatchLattice 0.11.0", "Hub/", "Tray/", "../", "./", "a.dll", "WatchLattice-0.11.0-win-x64.zip",
            "v", "0", "1", "10", ".", "-", "+", "rc.1", "2147483648", "\u0662");
        Arbitrary.Check(nameof(ReleaseFiles_AnyText_AreReadOrRefusedTheDocumentedWay), 2000, inputs, text =>
        {
            if (ReleaseVersion.TryParse(text, out var version)) Assert.Equal(version, ReleaseVersion.Parse(version.ToString()));
            else Assert.Throws<FormatException>(() => ReleaseVersion.Parse(text));
            Sha256Sums.Matches(text, Hash);
            Refusable<InvalidDataException, InvalidDataException>(() => Assert.All(Sha256Sums.Parse(text), sum => Assert.Matches(@"\A[0-9a-f]{64}\z", sum.Value)));
            Refusable<InvalidDataException, InvalidDataException>(() => Assert.All(InstallManifest.Parse(text).Files, file =>
                Assert.DoesNotContain("..", file.Key.Split('/', '\\'))));
        });
    }

    [Fact]
    public void ReleaseMetadata_AnyJson_IsReadOrRefusedTheDocumentedWay()
    {
        using var temp = new TempFolder();
        var inputs = Arbitrary.Json("tag_name", "name", "html_url", "published_at", "prerelease", "draft", "assets", "size", "browser_download_url", "v0.11.0", "2026-11-20T10:00:00Z",
            "https://github.com/notbrianbob/WatchLattice/releases/tag/v0.11.0", "https://github.com/notbrianbob/WatchLattice/releases/download/v0.11.0/WatchLattice-0.11.0-win-x64.zip",
            "WatchLattice-0.11.0-win-x64.zip", "SHA256SUMS.txt", "http://", "https://", "runtimeOptions", "framework", "frameworks", "includedFrameworks", "version", "Microsoft.NETCore.App", "10.0.0");
        Arbitrary.Check(nameof(ReleaseMetadata_AnyJson_IsReadOrRefusedTheDocumentedWay), 1000, inputs, json =>
        {
            var bytes = Encoding.UTF8.GetBytes(json);
            Refusable<JsonException, InvalidDataException>(() =>
            {
                var release = GitHubReleaseSource.Parse(bytes);
                Assert.Equal(Uri.UriSchemeHttps, release.HtmlUrl.Scheme);
                Assert.All(release.Assets, asset => Assert.Equal(Uri.UriSchemeHttps, asset.DownloadUrl.Scheme));
                UpdateEvaluator.FindNewer(new ReleaseVersion(0, 10, 0), release, "notbrianbob/WatchLattice");
            });
            var path = temp.Write("app.runtimeconfig.json", bytes);
            Refusable<InvalidDataException, InvalidDataException>(() => Assert.All(RuntimeRequirements.Read(path), requirement =>
                Assert.Matches(@"\A[A-Za-z0-9]+(\.[A-Za-z0-9]+)*\z", requirement.Name)));
        });
    }

    [Fact]
    public void Settings_AnyJson_AreReadOrRefused_AndWhatIsReadSavesAndReadsBackTheSame()
    {
        var inputs = Arbitrary.Json("Alerts", "alerts", "Enabled", "FeedPath", "HistoryLimit", "Modules", "Canary", "Persistence", "ApprovedEntries", "Updater", "Repository", "Password", "ApiKey", "A:B", "",
            "//", "/*", "*/", "\ufeff");
        Arbitrary.Check(nameof(Settings_AnyJson_AreReadOrRefused_AndWhatIsReadSavesAndReadsBackTheSame), 1500, inputs, text =>
            Refusable<JsonException, InvalidDataException>(() =>
            {
                var settings = SettingValues.Parse(text);
                Assert.True(SettingValues.Same(settings, SettingValues.Parse(SettingValues.Serialize(settings))));
                SettingsValidator.ToConfiguration(settings);
                SettingsValidator.CheckBinding(new[] { ("Alerts", typeof(AlertDeliveryOptions)) }, settings);
                FullExport.RedactSecrets(settings);
                Assert.DoesNotContain("```", FullExport.Fence(settings.ToJsonString()), StringComparison.Ordinal);
            }));
    }

    [Fact]
    public void Approvals_AnyText_AreOnlyAcceptedWhenWellFormed()
    {
        var inputs = Arbitrary.TextOf("sha256:", Hash, "sha256:" + Hash + " ", "ScheduledTasks/\\MyTask", "RunKeys/HKCU/Updater", ExtensionId, "*", "\n", " ",
            "UGVyc2lzdGVuY2U6QXBwcm92ZWRFbnRyaWVz", "Cg", "-", "_", "=", @"C:\Users\me\file.txt", @"C:\", @"\\server\share\", "..", "/");
        Arbitrary.Check(nameof(Approvals_AnyText_AreOnlyAcceptedWhenWellFormed), 2000, inputs, text =>
        {
            if (ApprovedEntry.TryParse(text, out var entry))
            {
                Assert.True(ApprovedEntry.TryParse(entry.ToString(), out var again));
                Assert.Equal(entry.ToString(), again.ToString());
            }
            if (BaselineApprovals.TryDecode(text, out var approval))
            {
                Assert.Contains(approval.SettingPath, BaselineApprovals.SettingPaths);
                Assert.True(BaselineApprovals.IsValid(approval.SettingPath, approval.Value));
            }
            if (BaselineApprovals.IsExtensionId(text)) Assert.DoesNotContain(text, char.IsControl);
            if (SafeActionLauncher.IsLocalPath(text)) Assert.DoesNotContain(text, c => char.IsControl(c) || c is '"' or '/');
            else Assert.Null(SafeActionLauncher.StartInfo(new SafeAction(SafeActionKind.OpenFileLocation, "Open", text), _ => true));
        });
    }

    [Fact]
    public void ExportedText_AnyText_StaysOnOneLine_InsideItsBlock_WithNamesHidden()
    {
        var redactor = new NameRedactor(new[] { "zqbrian" }, new[] { "ZQ-PC-01" });
        var inputs = Arbitrary.TextOf("zqbrian", "ZQBRIAN", "ZQ-PC-01", "zq-pc-01", @"C:\Users\", @"\\", "someone@example.test", "```", "~~~", "|", "\n", "\r\n", "\u2028", " ", "#", ">", "<", "=", "\"", "'");
        Arbitrary.Check(nameof(ExportedText_AnyText_StaysOnOneLine_InsideItsBlock_WithNamesHidden), 2000, inputs, text =>
        {
            Assert.DoesNotContain(FullExport.Cell(text, 40), c => c is '\n' or '\r' or '|' or '\u2028' or '\u2029');
            Assert.DoesNotContain("```", FullExport.Fence(text), StringComparison.Ordinal);
            var hidden = redactor.Apply(text);
            foreach (var name in new[] { "zqbrian", "ZQ-PC-01" })
            {
                for (var at = hidden.IndexOf(name, StringComparison.OrdinalIgnoreCase); at >= 0; at = hidden.IndexOf(name, at + 1, StringComparison.OrdinalIgnoreCase))
                {
                    // A name inside a longer word is another word; one standing alone must be gone.
                    var end = at + name.Length;
                    Assert.True((at > 0 && IsWordCharacter(hidden[at - 1])) || (end < hidden.Length && IsWordCharacter(hidden[end])), $"{name} was left in {Fuzzer.Literal(hidden)}");
                }
            }
            Assert.DoesNotContain("someone@example.test", hidden, StringComparison.OrdinalIgnoreCase);
        });
    }

    [Fact]
    public void StatusAndStateFiles_AnyJson_AreReadOrRefusedTheDocumentedWay()
    {
        using var temp = new TempFolder();
        var inputs = Arbitrary.Json("version", "alerts", "modules", "entries", "records", "runs", "checks", "files", "id", "at", "severity", "Warning", "message", "AMRunningMode", "Normal",
            "AntivirusSignatureLastUpdated", "/Date(1763640000000)/", "/Date(9223372036854775807)/", "Profiles", "Name", "Enabled", "Domain", "Public", "Rules", "RulesError",
            "2026-11-20T12:00:00+00:00", "00000000-0000-0000-0000-000000000000");
        Arbitrary.Check(nameof(StatusAndStateFiles_AnyJson_AreReadOrRefusedTheDocumentedWay), 800, inputs, json =>
        {
            var defender = DefenderStatusParser.Parse(json);
            Assert.Equal(defender.Available, defender.Error is null);
            var firewall = FirewallStatusParser.Parse(json);
            Assert.Equal(firewall.Available, firewall.Error is null);

            var path = temp.Write("state.json", Encoding.UTF8.GetBytes(json));
            Refusable<JsonException, InvalidDataException>(() => AlertSnapshot.Read(path, includeHeartbeat: false));
            Refusable<JsonException, InvalidDataException>(() => ActivitySnapshot.Read(path));
            Refusable<JsonException, InvalidDataException>(() => VerificationStore.Read(path).ToList());
            Assert.NotNull(TrayPreferences.Load(path).Preferences);
            Assert.NotNull(CanaryManifest.Load(path).Files);
        });
    }

    /// <summary>Runs a reader that may refuse its input with one of two exceptions and nothing else.</summary>
    private static void Refusable<TFirst, TSecond>(Action read) where TFirst : Exception where TSecond : Exception
    {
        try
        {
            read();
        }
        catch (Exception ex) when (ex is TFirst or TSecond)
        {
            // The documented way for this reader to refuse; its callers report it and carry on.
        }
    }

    /// <summary>
    /// A stored definition holds its text as UTF-8, which has no way to write
    /// half of a surrogate pair; every other character must come back as it went in.
    /// </summary>
    private static ServiceDefinition Restore(ServiceDefinition read, ServiceDefinition written)
    {
        static string? Stored(string? text) => text is null ? null : Encoding.UTF8.GetString(Encoding.UTF8.GetBytes(text));
        return read == written with { ImagePath = Stored(written.ImagePath), ServiceDll = Stored(written.ServiceDll), ObjectName = Stored(written.ObjectName), FailureCommand = Stored(written.FailureCommand) }
            ? written
            : read;
    }

    private static bool IsWordCharacter(char c) => char.IsLetterOrDigit(c) || c is '_' or '-';
}

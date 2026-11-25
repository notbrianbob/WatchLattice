using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using WatchLattice.Canary;
using WatchLattice.Common;
using WatchLattice.Common.Activity;
using WatchLattice.Common.Alerts;
using WatchLattice.Common.Checkup;
using WatchLattice.Common.Export;
using WatchLattice.Common.Settings;
using WatchLattice.DefenderWatchdog;
using WatchLattice.FirewallWatchdog;
using WatchLattice.Fuzz.Tests.Harness;
using Xunit;

namespace WatchLattice.Fuzz.Tests;

/// <summary>
/// Alert text is partly chosen by whatever caused the alert: a file name, a
/// command line, a task's arguments. It ends up in exports people open in a
/// spreadsheet or paste into an AI assistant, in approvals passed to the
/// elevated settings editor, and in state files read back at the next start.
/// None of those may be steered by that text.
/// </summary>
public class CommonFuzzTests
{
    /// <summary>Text that tries to add structure to an export.</summary>
    private static readonly string[] Markup =
    {
        "\n", "\r\n", "\r", "\u2028", "\u2029", "\t", "|", " | ", "\\|", "```", "````", "~~~", "`", "``", "\n```\n", "\n## Heading\n", "# ", "\n# Ignore the above",
        "> ", "- ", "| a | b |", "|---|---|", "<user>", "<!--", "-->", "\u2026", " ", "\u00a0", "\u200b", "=1+1", "+cmd", "-2", "@SUM(A1)", "\"", "\"\"", ",", ";", "'",
        "C:\\Users\\", "\\AppData\\Local\\", "\\\\", "/", ":", ".", "(", ")", "File ", " was changed by ", "HKCU\\Software\\", "Task ",
    };

    private static readonly string[] Boundaries = { " ", "\\", "/", "\"", ":", ".", "'", "(", ")", "\t", "\n", ",", ";", "=", "|", "`", "$", "\\\\", "@ " };

    private static readonly string[] UserNames = { "zqbrian", "Zq.Brian-Smith", "zqjos\u00e9", "zq\u540d\u524dx", "Zq Brian", "zq_o'neil", "zqd\ud83d\ude00x", "ZQB" };
    private static readonly string[] ComputerNames = { "ZQ-PC-01", "zqdesktop", "ZQDOMAIN", "zq-laptop.example" };
    private static readonly string[] Emails = { "zq.person+tag@mail.example.org", "ZQ_owner@example.co", "zq-x%y@sub-domain.example.museum" };

    private static readonly string[] Modules = { "Persistence", "ScriptHostAudit", "BrowserExtensionWatchdog", "DefenderWatchdog", "Canary", "DailySummary", "Unknown", "" };
    private static readonly string[] Codes = { "ENTRY_ADDED", "ENTRY_CHANGED", "SCRIPT_HOST_LAUNCHED", "EXTENSION_ADDED", "BROAD_EXCLUSION:C:\\", "CANARY_MODIFIED", "STATUS_UNAVAILABLE_CLEARED", "DAILY_SUMMARY", "" };

    private static readonly DateTimeOffset Now = new(2026, 11, 20, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Csv_AnyAlertText_ReadsBackAsTheSameCells_AndNeverAsAFormula()
    {
        Fuzzer.Run(2500, r => Enumerable.Range(0, r.Next(1, 5)).Select(_ => Alert(r, () => r.Text(Markup, 5, 30))).ToArray(), alerts =>
        {
            var rows = AlertGrouping.Build(alerts, AlertReviewSet.Empty, group: false);
            using var csv = new StringWriter();
            AlertExport.Write(csv, rows, AlertExportFormat.Csv, grouped: false, Now);

            var table = ParseCsv(csv.ToString());
            // One line per alert whatever its text holds: a line break or comma in a file name adds no row and no column.
            Assert.Equal(rows.Count + 1, table.Count);
            Assert.Equal(AlertExport.CsvColumns, table[0]);
            for (var i = 0; i < rows.Count; i++)
            {
                var alert = rows[i].Latest;
                var cells = table[i + 1];
                Assert.Equal(AlertExport.CsvColumns.Length, cells.Count);
                Assert.All(cells, cell => Assert.False(RunsAsFormula(cell), "A spreadsheet would run this cell: " + Fuzzer.Literal(cell)));
                Assert.Equal(alert.Title, WithoutGuard(cells[6], alert.Title));
                Assert.Equal(alert.Message, WithoutGuard(cells[7], alert.Message));
                Assert.Equal(alert.Resource ?? "", WithoutGuard(cells[8], alert.Resource ?? ""));
                Assert.Equal(alert.Id.ToString(), cells[11]);
            }

            using var json = new StringWriter();
            AlertExport.Write(json, rows, AlertExportFormat.Json, grouped: false, Now);
            using var document = JsonDocument.Parse(json.ToString());
            Assert.Equal(rows.Count, document.RootElement.GetProperty("rows").GetArrayLength());
        }, ShowAlerts);
    }

    [Fact]
    public void NameRedactor_ANameStandingAsAWord_NeverSurvives_AndOtherTextIsLeftAlone()
    {
        Fuzzer.Run(4000, r =>
        {
            var users = new[] { r.Pick(UserNames), r.Pick(UserNames) };
            var computers = new[] { r.Pick(ComputerNames), r.Pick(ComputerNames) };
            return (Users: users, Computers: computers, Text: MachineText(r, users.Concat(computers).ToArray()));
        }, input =>
        {
            var redactor = new NameRedactor(input.Users, input.Computers);
            var hidden = redactor.Apply(input.Text);

            AssertHidden(hidden, input.Users.Concat(input.Computers));
            // Hiding again changes nothing, and a redactor with nothing to hide changes nothing at all.
            Assert.Equal(hidden, redactor.Apply(hidden));
            Assert.Equal(input.Text, NameRedactor.None.Apply(input.Text));
            // Names too short to hide safely are skipped, so with only those (and no address in the text) nothing changes.
            var nothing = new NameRedactor(new string?[] { null, "", "ab" }, Array.Empty<string?>());
            if (!input.Text.Contains('@')) Assert.Equal(input.Text, nothing.Apply(input.Text));
        }, input => $"users [{string.Join(", ", input.Users)}], computers [{string.Join(", ", input.Computers)}], text {Fuzzer.Literal(input.Text)}");
    }

    [Fact]
    public void NameRedactor_AnyNamesAndText_NeverThrows()
    {
        Fuzzer.Run(3000, r => (Names: Enumerable.Range(0, r.Next(4)).Select(_ => r.Chance(0.2) ? null : r.Token(Markup)).ToArray(), Text: r.Text(Markup, 6, 60)), input =>
        {
            var redactor = new NameRedactor(input.Names, input.Names.Reverse());
            Assert.NotNull(redactor.Apply(input.Text));
        }, input => $"names [{string.Join(", ", input.Names.Select(n => n is null ? "null" : Fuzzer.Literal(n)))}], text {Fuzzer.Literal(input.Text)}");
    }

    [Fact]
    public void FullExport_AnyTextFromTheMachine_CannotAddStructure_OrLeakANameItWasToldToHide()
    {
        Fuzzer.Run(700, r =>
        {
            var users = new[] { r.Pick(UserNames), r.Pick(UserNames) };
            var computers = new[] { r.Pick(ComputerNames) };
            var names = users.Concat(computers).ToArray();
            string Text() => MachineText(r, names);
            string Long() => r.Chance(0.3) ? string.Concat(Enumerable.Range(0, r.Next(20, 60)).Select(_ => Text())) : Text();

            var alerts = Enumerable.Range(0, r.Next(6)).Select(_ => Alert(r, Long)).ToArray();
            var feed = r.Chance(0.1) ? null : new AlertSnapshot(AlertSnapshot.CurrentVersion, Guid.NewGuid(), Now.AddSeconds(-r.Next(60)), r.Chance(0.8),
                Enumerable.Range(0, r.Next(4)).Select(i => new ModuleStatus(r.Chance(0.5) ? "Persistence" : Text() + i, r.Pick(Enum.GetValues<ModuleRunState>()), Now)).DistinctBy(m => m.Id, StringComparer.OrdinalIgnoreCase).ToArray(),
                alerts, Update: r.Chance(0.2) ? new UpdateNotice("0.10.0", "0.11.0", "WatchLattice 0.11.0", "https://github.com/notbrianbob/WatchLattice/releases/tag/v0.11.0", Now, Now, true) : null);
            var activity = r.Chance(0.1) ? null : new ActivitySnapshot(ActivitySnapshot.CurrentVersion, Guid.NewGuid(),
                Enumerable.Range(0, r.Next(6)).Select(_ => new ActivityEntry(Now.AddMinutes(-r.Next(600)), r.Pick(LogLevel.Information, LogLevel.Warning, LogLevel.Error), r.Chance(0.8) ? "Persistence" : Text(), Long())).ToArray());
            var settings = r.Chance(0.1) ? null : new JsonObject
            {
                ["Alerts"] = new JsonObject { ["FeedPath"] = Text(), ["HistoryLimit"] = 200 },
                ["Persistence"] = new JsonObject { ["ApprovedEntries"] = new JsonArray(Enumerable.Range(0, r.Next(3)).Select(_ => (JsonNode?)JsonValue.Create(Text())).ToArray()), ["api-Key"] = "ZqSecretValue1", ["Password"] = "ZqSecretValue2" },
                ["Custom"] = new JsonObject { ["Nested"] = new JsonObject { ["Client.Secret"] = "ZqSecretValue3", ["Note"] = Text() } },
            };
            var data = new FullExportData(Now, "0.11.0", "Windows 11 " + Text(), new[] { new ExportModule("Persistence", "Persistence auditor", true), new ExportModule("Canary", "Canary files", false) },
                feed, AlertReviewSet.Empty, activity, settings,
                r.Next(3) switch { 0 => null, 1 => new DefenderFacts(false, null, null, null, Text()), _ => new DefenderFacts(true, r.Chance(0.5), null, Now) },
                r.Chance(0.3) ? null : new[] { new CheckupItem("uac", "User Account Control", CheckupStatus.Advice, Text(), "why", "how") },
                r.Chance(0.3) ? null : new ExportIntegrity("2 files changed", Enumerable.Range(0, r.Next(4)).Select(_ => Long()).ToArray(), r.Chance(0.5) ? Text() : null),
                Enumerable.Range(0, r.Next(3)).Select(_ => Text()).ToArray());
            return (Data: data, Users: users, Computers: computers, MaxText: r.Pick(400, 400, 40, 5, 1));
        }, input =>
        {
            var options = new FullExportOptions { MaxTextLength = input.MaxText };
            var export = FullExport.Build(input.Data, options, new NameRedactor(input.Users, input.Computers));

            AssertHidden(export, input.Users.Concat(input.Computers), Emails.Append("ZqSecretValue"));
            AssertOnlyTheExportsOwnStructure(export, input.Data);

            // With names kept, the same structure holds: only the names differ.
            AssertOnlyTheExportsOwnStructure(FullExport.Build(input.Data, options with { HideNames = false }, NameRedactor.None), input.Data);
        }, input => $"users [{string.Join(", ", input.Users)}], computers [{string.Join(", ", input.Computers)}], max text {input.MaxText}, data {JsonSerializer.Serialize(input.Data)}");
    }

    [Fact]
    public void ExportHelpers_AnyText_GiveOneLineThatCannotCloseABlockOrEndACell()
    {
        Fuzzer.RunText(5000, r => r.Text(Markup, 6, 60), text =>
        {
            var cell = FullExport.Cell(text, 40);
            Assert.DoesNotContain(cell, c => c is '\n' or '\r' or '|' or '\u2028' or '\u2029');
            Assert.True(cell.Length <= 40 + cell.Split("&#124;").Length * 5, "A cell is no longer than its limit, entities aside.");
            var fenced = FullExport.Fence(text);
            Assert.DoesNotContain("```", fenced, StringComparison.Ordinal);
            Assert.DoesNotContain("~~~", fenced, StringComparison.Ordinal);
            Assert.Equal(text, fenced.Replace("\u200b", "", StringComparison.Ordinal) is var plain && plain == text.Replace("\u200b", "", StringComparison.Ordinal) ? text : plain);
        });
    }

    [Fact]
    public void RedactSecrets_AnySettings_HideEveryValueUnderASecretLookingName()
    {
        var keys = new[] { "Password", "password", "Api-Key", "api_key", "Client.Secret", "ConnectionString", "AccessToken", "Credential", "Name", "Enabled", "Paths", "private-key", "PrivateKey" };
        Fuzzer.RunText(3000, r => r.Json(keys, new[] { "ZqSecretValue", "plain" }), json =>
        {
            JsonObject settings;
            try
            {
                settings = SettingValues.Parse(json);
            }
            catch (Exception ex) when (ex is JsonException or InvalidDataException)
            {
                return;
            }
            FullExport.RedactSecrets(settings);
            void Walk(JsonNode? node, bool underSecret)
            {
                switch (node)
                {
                    case JsonObject o:
                        foreach (var (key, child) in o) Walk(child, LooksSecret(key));
                        break;
                    case JsonArray a:
                        // A list under a secret-looking name is searched, not blanked; its plain values stay.
                        foreach (var item in a) Walk(item, false);
                        break;
                    case JsonValue v when underSecret:
                        Assert.Equal("<hidden>", v.GetValue<string>());
                        break;
                }
            }
            Walk(settings, false);
        });
    }

    [Fact]
    public void Approvals_AnyText_ParseOrAreRefused_AndWhatParsesReadsBackTheSame()
    {
        var hash = new string('a', 64);
        var words = new[] { "sha256:", "SHA256:", hash, new string('A', 64), new string('g', 64), new string('a', 63), " ", "  ", "\n", "\t", "ScheduledTasks/\\MyTask", "RunKeys/HKCU/Updater", "winword.exe|powershell.exe", "|", "/", "\u0661" };
        Fuzzer.RunText(6000, r => r.Chance(0.5) ? r.Text(words, 4, 10) : r.Mutate($"sha256:{hash} ScheduledTasks/\\MyTask", words), text =>
        {
            if (!ApprovedEntry.TryParse(text, out var entry))
            {
                Assert.False(BaselineApprovals.IsValid(BaselineApprovals.PersistenceSetting, text));
                return;
            }
            Assert.Matches(@"\A[0-9a-f]{64}\z", entry.Sha256);
            Assert.DoesNotContain(entry.Resource, c => char.IsControl(c));
            // An approval is stored in one spelling only, so the same approval is never listed twice.
            Assert.True(ApprovedEntry.TryParse(entry.ToString(), out var again));
            Assert.Equal(entry, again);
            Assert.True(BaselineApprovals.IsValid(BaselineApprovals.PersistenceSetting, entry.ToString()));
        });
    }

    [Fact]
    public void Approvals_AnyAlert_ApproveOnlyTheExactThingItNames_AndSurviveTheTripToTheElevatedEditor()
    {
        Fuzzer.Run(4000, r =>
        {
            var value = r.Text(Markup, 4, 20);
            var message = r.Next(4) switch
            {
                0 => r.Text(Markup, 5, 20),
                1 => r.Text(Markup, 5, 20) + "\n" + BaselineApprovals.FingerprintLine(value),
                // A fingerprint line that the entry's own text tries to supply, followed by more text.
                2 => BaselineApprovals.FingerprintLine("something else") + "\n" + r.Text(Markup, 3, 8) + "\n" + BaselineApprovals.FingerprintLine(value),
                _ => BaselineApprovals.FingerprintLine(value) + r.Text(Markup, 1, 4),
            };
            var resource = r.Next(4) switch { 0 => null, 1 => "Chrome/S-1-5-21/Default/" + r.Pick("abcdefghijklmnopabcdefghijklmnop", "{12345678-1234-1234-1234-123456789012}", "a*", "", r.Token(Markup)), _ => r.Text(Markup, 3, 10) };
            return (Alert: new ProtectionAlert(Guid.NewGuid(), Now, r.Pick(Modules), r.Pick(Codes), AlertSeverity.Warning, "title", message, resource), Value: value);
        }, input =>
        {
            var approval = BaselineApprovals.For(input.Alert);
            if (approval is null) return;

            Assert.Contains(approval.SettingPath, BaselineApprovals.SettingPaths);
            Assert.True(BaselineApprovals.IsValid(approval.SettingPath, approval.Value));
            Assert.DoesNotContain(approval.Value, c => char.IsControl(c));
            if (approval.SettingPath != BaselineApprovals.ExtensionSetting)
            {
                // The hash approved is the one on the alert's last line, which the module wrote after everything else.
                Assert.True(ApprovedEntry.TryParse(approval.Value, out var entry));
                var last = input.Alert.Message[(input.Alert.Message.LastIndexOf('\n') + 1)..];
                Assert.Equal(BaselineApprovals.FingerprintLabel + ApprovedEntry.Prefix + entry.Sha256, last, ignoreCase: true);
                Assert.Equal(ApprovedEntry.Stored(input.Alert.Resource!), entry.Resource);
                Assert.True(entry.Matches(input.Alert.Resource, input.Value) == last.EndsWith(ApprovedEntry.Fingerprint(input.Value), StringComparison.Ordinal));
            }

            var token = BaselineApprovals.Encode(approval);
            Assert.Matches(@"\A[A-Za-z0-9_-]+\z", token);
            Assert.True(BaselineApprovals.TryDecode(token, out var decoded));
            Assert.Equal((approval.SettingPath, approval.Value), (decoded.SettingPath, decoded.Value));

            var settings = new JsonObject();
            Assert.True(BaselineApprovals.Stage(settings, approval));
            Assert.False(BaselineApprovals.Stage(settings, decoded));
            Assert.True(BaselineApprovals.IsApproved(settings, approval));
        }, input => JsonSerializer.Serialize(input.Alert));
    }

    [Fact]
    public void ApprovalTokens_AnyText_DecodeOnlyToWellFormedApprovals()
    {
        var sample = BaselineApprovals.Encode(new BaselineApproval(BaselineApprovals.PersistenceSetting, $"sha256:{new string('a', 64)} ScheduledTasks/\\MyTask", ""));
        var paths = BaselineApprovals.SettingPaths.Concat(new[] { "Updater:Repository", "Modules:Canary:Enabled", "" }).ToArray();
        Fuzzer.RunText(6000, r => r.Next(3) switch
        {
            0 => r.Mutate(sample, new[] { "-", "_", "=", "+", "/", "A" }),
            1 => Convert.ToBase64String(Encoding.UTF8.GetBytes(r.Pick(paths) + r.Pick("\n", "", "\r\n") + r.Pick($"sha256:{new string('b', 64)} x", "abcdefghijklmnopabcdefghijklmnop", "*", "a\nb", r.Text(Markup, 2, 6)))).TrimEnd('=').Replace('+', '-').Replace('/', '_'),
            _ => Convert.ToBase64String(r.Bytes(40, 400)).TrimEnd('=').Replace('+', '-').Replace('/', '_'),
        }, token =>
        {
            if (!BaselineApprovals.TryDecode(token, out var approval)) return;
            // The elevated editor adds whatever decodes, so it can only ever be an approval, for an approval setting.
            Assert.Contains(approval.SettingPath, BaselineApprovals.SettingPaths);
            Assert.True(BaselineApprovals.IsValid(approval.SettingPath, approval.Value));
            Assert.DoesNotContain(approval.Value, c => char.IsControl(c));
            Assert.NotEqual("", approval.Description);
        });
    }

    [Fact]
    public void Settings_AnyFile_IsReadOrRefused_AndWhatIsReadCanBeCheckedAndSaved()
    {
        var sections = new[]
        {
            new SettingsSection("Alerts", "Alerts", SettingsSchema.Fields("Alerts", typeof(AlertDeliveryOptions))),
            new SettingsSection("Updater", "Updater", new[] { new SettingField("Updater:Repository", "Repository", SettingKind.Text, false, LockedReason: "locked") }),
        };
        var types = new[] { ("Alerts", typeof(AlertDeliveryOptions)) };
        const string sample = "{\n  // comment\n  \"Modules\": { \"Canary\": { \"Enabled\": true } },\n  \"Alerts\": { \"Enabled\": true, \"FeedPath\": null, \"HistoryLimit\": 200, },\n  \"Updater\": { \"Repository\": \"notbrianbob/WatchLattice\" }\n}\n";
        var keys = new[] { "Alerts", "alerts", "Enabled", "enabled", "ENABLED", "FeedPath", "HistoryLimit", "Updater", "Repository", "Modules", "Canary", "A:B", "" };
        var strings = new[] { "true", "false", "200", "-1", "1e400", "99999999999999999999", "C:\\feed\\alerts.json", "notbrianbob/WatchLattice", "", " " };
        Fuzzer.RunText(4000, r => r.Next(3) switch { 0 => r.Json(keys, strings), 1 => r.Mutate(sample, keys.Concat(strings).ToArray()), _ => "\uFEFF" + r.Json(keys, strings, 2) }, text =>
        {
            JsonObject settings;
            try
            {
                settings = SettingValues.Parse(text);
            }
            catch (Exception ex) when (ex is JsonException or InvalidDataException)
            {
                // The documented ways to refuse a settings file; the editor shows the reason and changes nothing.
                return;
            }
            var check = SettingsValidator.Check(sections, settings, settings);
            Assert.Empty(check.Changes);
            Assert.Empty(SettingsValidator.Diff(settings, settings));
            Assert.All(check.Errors.Concat(check.Warnings), Assert.NotNull);
            SettingsValidator.CheckBinding(types, settings);
            foreach (var field in sections.SelectMany(s => s.Fields))
            {
                var value = SettingValues.Effective(settings, field);
                var shown = SettingValues.Format(field, value);
                if (SettingsValidator.CheckValue(field, value) is null && SettingValues.TryParse(field, shown, out var typed, out _) && field.Kind != SettingKind.Unsupported)
                    Assert.Null(SettingsValidator.CheckValue(field, typed));
            }
            // Saving and reading again gives the same settings, and a copy is independent of the original.
            var saved = SettingValues.Parse(SettingValues.Serialize(settings));
            Assert.True(SettingValues.Same(settings, saved));
            var copy = SettingValues.Clone(settings);
            SettingValues.Set(copy, "Alerts:HistoryLimit", 5);
            SettingValues.Remove(copy, "Updater:Repository");
            Assert.True(SettingValues.Same(settings, saved));
            FullExport.RedactSecrets(copy);
        });
    }

    [Fact]
    public void StateFiles_AnyBytes_AreReadOrRefused_AndWhatIsReadCanBeShownAndExported()
    {
        using var temp = new TempFolder();
        var feedPath = Path.Join(temp.Path, "alerts.json");
        var sampleRandom = new FuzzRandom(1);
        AtomicJsonFile.Write(feedPath, new AlertSnapshot(AlertSnapshot.CurrentVersion, Guid.NewGuid(), Now, true,
            new[] { new ModuleStatus("Persistence", ModuleRunState.Running, Now) }, new[] { Alert(sampleRandom, () => "text"), Alert(sampleRandom, () => "more") },
            7, new UpdateNotice("0.10.0", "0.11.0", "WatchLattice 0.11.0", "https://github.com/notbrianbob/WatchLattice/releases/tag/v0.11.0", Now, Now, true)));
        var feedSample = File.ReadAllBytes(feedPath);
        AtomicJsonFile.Write(feedPath, new ActivitySnapshot(ActivitySnapshot.CurrentVersion, Guid.NewGuid(), new[] { new ActivityEntry(Now, LogLevel.Warning, "Persistence", "message") }));
        var activitySample = File.ReadAllBytes(feedPath);
        var words = new[] { "null", "[]", "{}", "\"alerts\":", "\"modules\":", "\"entries\":", "\"version\":", "\"severity\":", "99", "-1", "\"0001-01-01T00:00:00+00:00\"", "\"9999-12-31T23:59:59.9999999+00:00\"", "\"\\ud800\"", "\"at\":" };

        Fuzzer.Run(2500, r =>
        {
            var sample = r.Chance(0.5) ? feedSample : activitySample;
            return r.Chance(0.5) ? r.Mutate(sample) : Encoding.UTF8.GetBytes(r.Mutate(Encoding.UTF8.GetString(sample), words, 3));
        }, bytes =>
        {
            File.WriteAllBytes(feedPath, bytes);
            AlertSnapshot? feed = null;
            ActivitySnapshot? activity = null;
            try
            {
                feed = AlertSnapshot.Read(feedPath, includeHeartbeat: false);
            }
            catch (Exception ex) when (ex is JsonException or InvalidDataException)
            {
                // The documented way to refuse a feed; the tray then shows that it can't be read.
            }
            try
            {
                activity = ActivitySnapshot.Read(feedPath);
            }
            catch (Exception ex) when (ex is JsonException or InvalidDataException)
            {
                // The same for the activity file.
            }
            Assert.NotNull(TrayPreferences.Load(feedPath).Preferences);
            Assert.NotNull(CanaryManifest.Load(feedPath).Files);
            if (feed is null && activity is null) return;

            // Everything the tray and the exports do with a feed they accepted.
            var data = new FullExportData(Now, "0.11.0", "Windows 11", Array.Empty<ExportModule>(), feed, AlertReviewSet.Empty, activity, null, null, null, null, Array.Empty<string>());
            AssertOnlyTheExportsOwnStructure(FullExport.Build(data, new FullExportOptions(), new NameRedactor(UserNames, ComputerNames)), data);
            if (feed is null) return;
            _ = feed.IsFresh(Now);
            if (feed.Update is { } update) update.TryGetReleasePage(out _);
            foreach (var grouped in new[] { true, false })
            {
                var rows = AlertGrouping.Build(feed.Alerts, AlertReviewSet.Empty, grouped);
                using var csv = new StringWriter();
                AlertExport.Write(csv, rows, AlertExportFormat.Csv, grouped, Now);
                using var json = new StringWriter();
                AlertExport.Write(json, rows, AlertExportFormat.Json, grouped, Now);
            }
            foreach (var alert in feed.Alerts)
            {
                Assert.NotNull(AlertGuidanceCatalog.For(alert));
                BaselineApprovals.For(alert);
                AttackMapping.For(alert.Module, alert.Code, alert.Resource);
            }
            _ = DailySummary.Latest(feed.Alerts);
        }, Fuzzer.Hex, Fuzzer.ShrinkBytes);
    }

    [Fact]
    public void StatusQueries_AnyOutput_AreReadOrReportedUnavailable_WithoutThrowing()
    {
        const string defender = "{\"AMServiceEnabled\":true,\"AntivirusEnabled\":true,\"RealTimeProtectionEnabled\":true,\"IsTamperProtected\":false,\"AMRunningMode\":\"Normal\","
            + "\"AntivirusSignatureVersion\":\"1.2.3.4\",\"AntivirusSignatureLastUpdated\":\"/Date(1763632800000)/\",\"Preferences\":{\"ExclusionPath\":[\"C:\\\\Temp\"],\"ExclusionExtension\":null,"
            + "\"ExclusionProcess\":\"N/A: Must be an administrator\",\"ExclusionIpAddress\":[],\"AsrRuleIds\":[\"d4f940ab-401b-4efc-aadc-ad5f3c50688a\"],\"AsrRuleActions\":[1],\"MAPSReporting\":2,"
            + "\"DisableBlockAtFirstSeen\":false,\"CloudBlockLevel\":0},\"PreferencesError\":null}";
        const string firewall = "{\"Profiles\":[{\"Name\":\"Domain\",\"Enabled\":\"True\",\"DefaultInboundAction\":\"Block\"},{\"Name\":\"Private\",\"Enabled\":\"False\",\"DefaultInboundAction\":\"NotConfigured\"}],"
            + "\"ActiveCategories\":{\"value\":[\"Private\",\"DomainAuthenticated\"],\"Count\":2},\"Rules\":[{\"Id\":\"{A}\",\"DisplayName\":\"Remote Desktop\",\"Profile\":\"Any\"}],\"RulesError\":null}";
        var words = new[]
        {
            "Preferences", "ExclusionPath", "AsrRuleIds", "AsrRuleActions", "Profiles", "Rules", "ActiveCategories", "value", "Name", "Enabled", "Id", "null", "[]", "{}", "true",
            "/Date(", ")/", "/Date(9223372036854775807)/", "/Date(-99999999999999999)/", "\\ud800", "N/A", "Domain", "Public", "99999999999",
        };
        Fuzzer.RunText(5000, r => r.Next(4) switch { 0 => r.Json(words, words), 1 => r.Text(words), 2 => r.Mutate(defender, words), _ => r.Mutate(firewall, words) }, json =>
        {
            var status = DefenderStatusParser.Parse(json);
            Assert.Equal(status.Available, status.Error is null);
            DefenderHealthEvaluator.Evaluate(status, new DefenderWatchdogOptions(), Now);

            var firewallStatus = FirewallStatusParser.Parse(json);
            Assert.Equal(firewallStatus.Available, firewallStatus.Error is null);
            if (firewallStatus.Available)
            {
                Assert.All(firewallStatus.Profiles, profile => Assert.Contains(profile.Name, new[] { "Domain", "Private", "Public" }));
                foreach (var profile in new[] { "Domain", "Private", "Public" }) firewallStatus.MayBeActive(profile);
            }
        });
    }

    [Fact]
    public void OpenFileLocation_AnyPathFromAnAlert_IsOnlyAcceptedWhenItIsAPlainLocalPath()
    {
        var words = new[] { "C:\\", "c:\\Users\\me\\file.docx", "\\\\server\\share\\", "\\\\?\\C:\\", "..", ".", "\\", "/", "\"", "\n", "\r\n", "\t", "*", "?", "|", "<", ">", " ", "D:", "file.txt", "\0", "%TEMP%", "&", "," };
        Fuzzer.RunText(6000, r => r.Chance(0.5) ? r.Text(words, 4, 12) : "C:\\" + r.Text(words, 3, 8), path =>
        {
            if (!SafeActionLauncher.IsLocalPath(path))
            {
                Assert.Null(SafeActionLauncher.StartInfo(new SafeAction(SafeActionKind.OpenFileLocation, "Open", path), _ => true));
                return;
            }
            // This text goes on Explorer's command line, between quotes.
            Assert.Matches(@"\A[A-Za-z]:\\", path);
            Assert.DoesNotContain(path, c => char.IsControl(c) || c is '"' or '*' or '?' or '<' or '>' or '|' or '/');
            Assert.DoesNotContain("..", path.Split('\\'));
            Assert.DoesNotContain(".", path.Split('\\'));
        });
    }

    /// <summary>Text as it comes from the machine: markup that tries to break out, with the names and addresses standing as whole words.</summary>
    private static string MachineText(FuzzRandom r, string[] names)
    {
        var text = new StringBuilder();
        for (var i = r.Count(5, 20); i >= 0; i--)
        {
            if (r.Chance(0.3))
            {
                var name = r.Chance(0.2) ? r.Pick(Emails) : r.Pick(names);
                if (r.Chance(0.3)) name = r.Chance(0.5) ? name.ToUpperInvariant() : name.ToLowerInvariant();
                text.Append(r.Pick(Boundaries)).Append(name).Append(r.Pick(Boundaries));
            }
            else
            {
                text.Append(r.Chance(0.8) ? r.Pick(Markup) : r.Token(Markup));
            }
        }
        return text.ToString();
    }

    private static ProtectionAlert Alert(FuzzRandom r, Func<string> text) =>
        new(Guid.NewGuid(), Now.AddMinutes(-r.Next(5000)), r.Pick(Modules), r.Pick(Codes), r.Pick(Enum.GetValues<AlertSeverity>()), text(), text(), r.Chance(0.3) ? null : text());

    private static string ShowAlerts(ProtectionAlert[] alerts) => JsonSerializer.Serialize(alerts);

    private static bool LooksSecret(string key)
    {
        var compact = key.Replace("-", "").Replace(".", "");
        return new[] { "password", "secret", "token", "apikey", "api_key", "credential", "privatekey", "connectionstring" }.Any(w => compact.Contains(w, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Fails when a name is left standing as a word, which is the documented
    /// rule: not touching a letter, digit, '_' or '-' on either side. (Inside a
    /// longer word it is left alone, so "Bri" does not mangle "Bridge".)
    /// E-mail addresses and secrets must not be left anywhere at all.
    /// </summary>
    private static void AssertHidden(string text, IEnumerable<string> names, IEnumerable<string>? anywhere = null)
    {
        static bool WordChar(char c) => char.IsLetterOrDigit(c) || c is '_' or '-';
        foreach (var (name, wholeWord) in names.Select(n => (n, true)).Concat((anywhere ?? Emails).Select(n => (n, false))))
        {
            for (var at = text.IndexOf(name, StringComparison.OrdinalIgnoreCase); at >= 0; at = text.IndexOf(name, at + 1, StringComparison.OrdinalIgnoreCase))
            {
                var end = at + name.Length;
                var joinedBefore = at > 0 && WordChar(text[at - 1]);
                var joinedAfter = end < text.Length && WordChar(text[end]);
                if (wholeWord && (joinedBefore || joinedAfter)) continue;
                Assert.Fail($"{Fuzzer.Literal(name)} was left in: {Fuzzer.Literal(text[Math.Max(0, at - 40)..Math.Min(text.Length, end + 40)])}");
            }
        }
    }

    /// <summary>What Excel, LibreOffice and Google Sheets treat as the start of a formula.</summary>
    private static bool RunsAsFormula(string cell) => cell.TrimStart(' ') is { Length: > 0 } text && text[0] is '=' or '+' or '-' or '@' or '\t' or '\r' or '\n';

    /// <summary>The cell as written, without the apostrophe that was put in front to stop it running as a formula.</summary>
    private static string WithoutGuard(string cell, string original) => cell == "'" + original ? original : cell;

    /// <summary>An RFC 4180 reader, written apart from the code under test.</summary>
    private static List<List<string>> ParseCsv(string text)
    {
        var rows = new List<List<string>>();
        var row = new List<string>();
        var cell = new StringBuilder();
        var quoted = false;
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (quoted)
            {
                if (c == '"' && i + 1 < text.Length && text[i + 1] == '"') { cell.Append('"'); i++; }
                else if (c == '"') quoted = false;
                else cell.Append(c);
            }
            else if (c == '"' && cell.Length == 0) quoted = true;
            else if (c == ',') { row.Add(cell.ToString()); cell.Clear(); }
            else if (c == '\r' && i + 1 < text.Length && text[i + 1] == '\n')
            {
                row.Add(cell.ToString());
                cell.Clear();
                rows.Add(row);
                row = new List<string>();
                i++;
            }
            else cell.Append(c);
        }
        Assert.False(quoted, "The file ends inside a quoted cell.");
        Assert.True(row.Count == 0 && cell.Length == 0, "The file does not end with a line break.");
        return rows;
    }

    /// <summary>
    /// The export is Markdown that a person pastes into an AI assistant. Its
    /// headings, tables and code blocks must be exactly the ones the export
    /// writes itself, whatever the alert and log text in it says.
    /// </summary>
    private static void AssertOnlyTheExportsOwnStructure(string export, FullExportData data)
    {
        Assert.DoesNotContain('\r', export);
        Assert.DoesNotContain("~~~", export, StringComparison.Ordinal);
        var blocks = (data.Settings is null ? 0 : 1) + (data.Activity is null ? 0 : 1);
        Assert.Equal(blocks * 2, export.Split("```").Length - 1);

        var headings = new HashSet<string>(StringComparer.Ordinal)
        {
            "# WatchLattice data export", "## About WatchLattice", "## What to check", "## 1. Summary", "## 2. Modules", "## 3. Microsoft Defender", "## 4. Security checkup",
            "## 5. Install integrity", "## 6. Settings", "## 7. Alerts", "## 8. What these alerts mean", "## 9. Recent hub activity", "## 10. About this export",
        };
        var seen = new List<string>();
        var inBlock = false;
        var columns = 0;
        foreach (var line in export.Split('\n'))
        {
            if (line.StartsWith("```", StringComparison.Ordinal))
            {
                Assert.Contains(line, inBlock ? new[] { "```" } : new[] { "```json", "```text" });
                inBlock = !inBlock;
                continue;
            }
            if (inBlock) continue;
            if (line.TrimStart().StartsWith('#'))
            {
                Assert.Contains(line, headings);
                seen.Add(line);
            }
            if (line.StartsWith('|'))
            {
                // A table's first line sets its number of columns; every row after it has the same.
                var pipes = line.Count(c => c == '|');
                if (columns == 0) columns = pipes;
                Assert.Equal(columns, pipes);
            }
            else
            {
                columns = 0;
            }
            if (line.TrimStart().StartsWith('>')) Assert.StartsWith("> **To the AI assistant reading this:**", line, StringComparison.Ordinal);
        }
        Assert.False(inBlock, "A code block was left open.");
        Assert.Equal(seen.Distinct(), seen);
        Assert.True(seen.Count >= headings.Count - 1, "A section is missing.");
    }
}

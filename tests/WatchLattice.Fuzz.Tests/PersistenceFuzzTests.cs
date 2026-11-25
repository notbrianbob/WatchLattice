using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;
using WatchLattice.Fuzz.Tests.Harness;
using WatchLattice.Persistence;
using WatchLattice.Persistence.Verification;
using Xunit;

namespace WatchLattice.Fuzz.Tests;

/// <summary>
/// Autostart entries are written by whatever wants to start with Windows:
/// a task's program, arguments and folder, a service's ImagePath, a COM
/// registration, a file name in a Startup folder. The auditor and the
/// verifier read them all; none may stop either one, and a path must never
/// be judged by anything but where it really leads.
/// </summary>
public class PersistenceFuzzTests
{
    private static readonly SystemPaths Paths = new(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["SystemRoot"] = @"C:\Windows", ["windir"] = @"C:\Windows", ["SystemDrive"] = "C:", ["ProgramFiles"] = @"C:\Program Files",
        ["ProgramFiles(x86)"] = @"C:\Program Files (x86)", ["ProgramData"] = @"C:\ProgramData", ["PUBLIC"] = @"C:\Users\Public",
    }, Is64BitOperatingSystem: true);

    private static readonly string[] PathWords =
    {
        "C:\\", "c:/", "C:", "D:\\dir\\", "\\\\server\\share\\", "\\\\?\\", "\\??\\", "\\\\.\\", "\\\\?\\UNC\\server\\share\\", "\\SystemRoot\\", "System32\\",
        "%SystemRoot%", "%windir%", "%ProgramFiles%", "%ProgramFiles(x86)%", "%ProgramData%", "%PUBLIC%", "%LOCALAPPDATA%", "%USERPROFILE%", "%", "%%",
        "Windows", "System32", "Program Files", "Users\\Public", "Temp", "..", ".", "...", "\\", "/", "\\\\", ":", "::$DATA", "\"", " ", ". ", "*", "?", "|",
        "svchost.exe", "cmd.exe", "x.dll", ".exe", ".EXE ", " -k netsvcs", " /c ", "a", "ab",
    };

    private static readonly Regex Canonical = new(@"\A[A-Z]:\\(?:[^\\]+(?:\\[^\\]+)*)?\z", RegexOptions.CultureInvariant);

    private const string SampleProjection =
        "{\"Enabled\":true,\"UserId\":\"S-1-5-18\",\"GroupId\":null,\"RunLevel\":\"Highest\",\"LogonType\":\"ServiceAccount\","
        + "\"Actions\":[{\"Execute\":\"%windir%\\\\system32\\\\defrag.exe\",\"Arguments\":\"-c -h\",\"WorkingDirectory\":null,\"ClassId\":null,\"Data\":null},"
        + "{\"Execute\":null,\"Arguments\":null,\"WorkingDirectory\":null,\"ClassId\":\"{0358B920-0AC7-461F-98F4-58E32CD89148}\",\"Data\":\"$(Arg0)\"}],"
        + "\"Triggers\":[{\"Type\":\"MSFT_TaskDailyTrigger\",\"Enabled\":true,\"StartBoundary\":\"2026-01-01T03:00:00\",\"EndBoundary\":null,\"DaysInterval\":1,\"Delay\":null}]}";

    private static readonly string[] ProjectionKeys =
    {
        "Enabled", "enabled", "UserId", "GroupId", "RunLevel", "LogonType", "Actions", "Triggers", "Execute", "Arguments", "WorkingDirectory",
        "ClassId", "Data", "Type", "StartBoundary", "EndBoundary", "DaysInterval", "Delay", "Interval", "Duration", "Subscription",
    };

    private static readonly string[] ProjectionStrings =
    {
        "S-1-5-18", "SYSTEM", "NT AUTHORITY\\SYSTEM", "BUILTIN\\Administrators", "Highest", "HighestAvailable", "LeastPrivilege", "Limited",
        "InteractiveToken", "ServiceAccount", "cmd.exe", "C:\\Windows\\System32\\cmd.exe", "{0358B920-0AC7-461F-98F4-58E32CD89148}",
        "0358b920-0ac7-461f-98f4-58e32cd89148", "2026-01-01T03:00:00", "PT5M", "",
    };

    private const string SampleTaskXml =
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?><Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">"
        + "<RegistrationInfo><Author>Microsoft</Author></RegistrationInfo><Triggers><CalendarTrigger><StartBoundary>2026-01-01T03:00:00</StartBoundary>"
        + "<ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger><LogonTrigger/></Triggers>"
        + "<Principals><Principal id=\"Other\"><UserId>S-1-5-19</UserId></Principal><Principal id=\"Author\"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>"
        + "<Settings><Enabled>true</Enabled></Settings><Actions Context=\"Author\"><Exec><Command>%windir%\\system32\\defrag.exe</Command><Arguments>-c -h</Arguments></Exec>"
        + "<ComHandler><ClassId>{0358B920-0AC7-461F-98F4-58E32CD89148}</ClassId><Data><![CDATA[$(Arg0)]]></Data></ComHandler></Actions></Task>";

    [Fact]
    public void Resolve_AnyText_NeverThrows_AndOnlyEverNamesCanonicalLocalPaths()
    {
        Fuzzer.Run(6000, r => (Raw: r.Next(3) switch { 0 => r.Text(PathWords, 5, 30), 1 => r.Token(PathWords), _ => Decorate(r, CanonicalPath(r)) },
            WorkingDirectory: r.Chance(0.6) ? null : r.Chance(0.5) ? CanonicalPath(r, file: false) : r.Text(PathWords, 4, 12),
            Extension: r.Pick(".exe", ".dll", ""), Exists: r.Chance(0.5)), input =>
        {
            var probed = new List<string>();
            var resolved = WindowsPath.Resolve(input.Raw, Paths, name => name.Equals("LOCALAPPDATA", StringComparison.OrdinalIgnoreCase) ? @"C:\Users\someone\AppData\Local" : null,
                path => { probed.Add(path); return input.Exists; }, input.WorkingDirectory, input.Extension);

            Assert.NotNull(resolved.Note);
            // The only paths ever looked for on disk are plain local ones: no network host, device, stream or wildcard.
            Assert.All(probed, AssertCanonical);
            switch (resolved.Kind)
            {
                case PathResolution.Resolved or PathResolution.SearchOrder:
                    Assert.NotNull(resolved.Path);
                    AssertCanonical(resolved.Path);
                    break;
                case PathResolution.Unresolved:
                    Assert.Null(resolved.Path);
                    break;
                default:
                    Assert.Empty(probed);
                    break;
            }
        }, input => $"{Fuzzer.Literal(input.Raw)}, working directory {(input.WorkingDirectory is null ? "null" : Fuzzer.Literal(input.WorkingDirectory))}, extension {Fuzzer.Literal(input.Extension)}",
        input => Fuzzer.ShrinkText(input.Raw).Select(raw => input with { Raw = raw }));
    }

    [Fact]
    public void Resolve_APathWrittenAnyEquivalentWay_LeadsToTheSameFile()
    {
        Fuzzer.Run(4000, r =>
        {
            var expected = CanonicalPath(r);
            return (Expected: expected, Raw: Decorate(r, expected));
        }, input =>
        {
            var resolved = WindowsPath.Resolve(input.Raw, Paths, null, _ => false);
            Assert.Equal(PathResolution.Resolved, resolved.Kind);
            Assert.Equal(input.Expected, resolved.Path);
        }, input => $"{Fuzzer.Literal(input.Raw)}, which is {Fuzzer.Literal(input.Expected)}");
    }

    [Fact]
    public void TaskPathsAndClassIds_AnyText_AreValidatedWithoutThrowing()
    {
        var words = new[] { "\\", "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag", "..", ".", " ", "{0358B920-0AC7-461F-98F4-58E32CD89148}", "0358b920-0ac7-461f-98f4-58e32cd89148", "{", "}", "-", "(0358B920-0AC7-461F-98F4-58E32CD89148)" };
        Fuzzer.RunText(6000, r => r.Chance(0.5) ? r.Text(words, 4, 20) : r.Mutate(r.Pick(words), words), text =>
        {
            if (WindowsPath.IsValidTaskPath(text))
            {
                var (folder, name) = WindowsPath.SplitTaskPath(text);
                Assert.StartsWith("\\", folder, StringComparison.Ordinal);
                Assert.NotEqual("", name);
                Assert.DoesNotContain('\\', name);
                Assert.Equal(text, folder == "\\" ? "\\" + name : folder + "\\" + name);
            }
            if (WindowsPath.TryNormalizeClsid(text, out var clsid))
            {
                Assert.Matches(@"\A\{[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}\}\z", clsid);
                Assert.True(WindowsPath.TryNormalizeClsid(clsid, out var again));
                Assert.Equal(clsid, again);
            }
            Assert.Contains(WindowsPath.ExtractCommandPath(text), text, StringComparison.Ordinal);
            Assert.Contains(WindowsPath.Unquote(text), text, StringComparison.Ordinal);
            Accounts.IsSid(text);
            ServiceAnalysis.IsValidServiceName(text);
            // With every variable empty, at most one stray percent sign can be left.
            var expanded = WindowsPath.ExpandVariables(text, _ => "", out _);
            if (expanded is not null) Assert.True(expanded.Count(c => c == '%') <= 1);
        });
    }

    [Fact]
    public void Service_AnyDefinition_IsAnalyzedWithoutThrowing()
    {
        Fuzzer.Run(4000, r => (Before: Service(r), After: Service(r)), input =>
        {
            foreach (var service in new[] { input.Before, input.After })
            {
                var (program, arguments) = ServiceAnalysis.SplitCommand(service.ImagePath);
                Assert.NotNull(program);
                Assert.NotNull(arguments);
                if (ServiceAnalysis.Target(service, Paths, _ => false) is { } target) ServiceAnalysis.Classify(target.Resolved, Paths);
                ServiceAnalysis.DescribeAccount(service.ObjectName);

                // What the baseline stores reads back as the same definition.
                var projection = service.ToProjection();
                Assert.Equal(service, ServiceDefinition.TryParse(projection));
                ServiceAnalysis.LocationOf(projection, Paths);
            }
            ServiceAnalysis.Differences(input.Before, input.After);
            ServiceAnalysis.ChangesTarget(input.Before, input.After, Paths);
            ServiceAnalysis.IsPrivilegeGain(input.Before, input.After);
            Assert.False(ServiceAnalysis.IsRoutineUpdate(input.Before, input.Before, Paths));
            Assert.Empty(ServiceAnalysis.Differences(input.After, input.After));
        }, input => $"before {input.Before}, after {input.After}");
    }

    [Fact]
    public void Service_AnyStoredText_ParsesOrIsRefused_WithoutThrowing()
    {
        var sample = new ServiceDefinition(0x20, 2, @"%SystemRoot%\system32\svchost.exe -k netsvcs", @"%SystemRoot%\System32\x.dll", "LocalSystem", null).ToProjection();
        var keys = new[] { "Type", "Start", "ImagePath", "ServiceDll", "ObjectName", "FailureCommand", "type" };
        Fuzzer.RunText(4000, r => r.Next(3) switch { 0 => r.Json(keys, PathWords), 1 => r.Text(PathWords), _ => r.Mutate(sample, PathWords) }, text =>
        {
            ServiceDefinition.TryParse(text);
            ServiceAnalysis.LocationOf(text, Paths);
        });
    }

    [Fact]
    public void Service_MovedToAFolderUsersCanWrite_IsNeverARoutineUpdate()
    {
        // However the new path is spelled, it is judged by the folder it really leads to.
        var writable = new[]
        {
            @"C:\Users\Public\{0}", @"C:\Program Files\..\Users\Public\{0}", @"C:\Program Files\App\..\..\ProgramData\{0}", @"C:\Program Files\App\.\..\..\Users\Public\.\{0}. ",
            @"\??\C:\Windows\Temp\{0}", @"\\?\C:\ProgramData\App\{0}", @"%SystemRoot%\Temp\{0}", @"\SystemRoot\Temp\{0}", @"System32\..\Temp\{0}", @"System32\Tasks\{0}",
            @"C:/Users/Public/{0}", @"%ProgramFiles%\..\ProgramData\{0}", @"%ProgramData%\{0}", @"%PUBLIC%\{0}", @"C:\Windows\System32\spool\drivers\color\{0}",
            @"c:\windows\SYSTEM32\..\tracing\{0}", @"C:\Program Files (x86)\\..\\Users\Someone\AppData\Local\{0}",
        };
        Fuzzer.Run(3000, r =>
        {
            var file = r.Identifier() + ".exe";
            var location = string.Format(r.Pick(writable), file);
            if (r.Chance(0.3)) location = RandomCase(r, location);
            var quoted = r.Chance(0.5);
            var arguments = r.Pick("", " -k netsvcs", " /service");
            return (Before: new ServiceDefinition(0x10, 2, $"\"C:\\Program Files\\App\\1.0\\{file}\"{arguments}", null, "LocalSystem", null),
                After: new ServiceDefinition(0x10, 2, (quoted ? $"\"{location}\"" : location) + arguments, null, "LocalSystem", null));
        }, input =>
        {
            Assert.Equal(ServiceLocation.UserWritable, ServiceAnalysis.LocationOf(input.After.ToProjection(), Paths));
            Assert.False(ServiceAnalysis.IsRoutineUpdate(input.Before, input.After, Paths));
            Assert.True(ServiceAnalysis.ChangesTarget(input.Before, input.After, Paths));
        }, input => Fuzzer.Literal(input.After.ImagePath!));
    }

    [Fact]
    public void LoggedTask_AnyText_ParsesOrIsRefused_AndEqualsItself()
    {
        Fuzzer.RunText(4000, r => r.Next(4) switch
        {
            0 => r.Json(ProjectionKeys, ProjectionStrings),
            1 => r.Text(ProjectionStrings),
            _ => r.Mutate(SampleProjection, ProjectionKeys.Concat(ProjectionStrings).ToArray()),
        }, json =>
        {
            Assert.False(TaskComparison.IsTimingOnlyChange(json, json));
            TaskComparison.IsTimingOnlyChange(SampleProjection, json);
            try
            {
                var facts = TaskFacts.FromProjection(json);
                Assert.All(facts.Actions, action => Assert.NotNull(action.Describe()));
                Assert.Empty(TaskComparison.CompareCurrent(facts, facts, new NoAccounts(), out _));
                Assert.Empty(TaskComparison.CompareLogged(json, json));
                foreach (var change in TaskComparison.CompareLogged(SampleProjection, json))
                {
                    TaskComparison.IsTargetChange(change);
                    TaskComparison.IsTimingChange(change);
                    TaskComparison.IsPrivilegeGain(change, new NoAccounts());
                }
            }
            catch (Exception ex) when (ex is JsonException or InvalidDataException)
            {
                // The documented way to refuse text that is not a logged definition.
            }
        });
    }

    [Fact]
    public void TaskXml_AnyText_ParsesOrIsRefused_AndEqualsItself()
    {
        var words = new[] { "<Exec>", "</Exec>", "<Command>", "</Command>", "<ComHandler>", "<ClassId>", "<Principal id=\"", "<Actions Context=\"", "<Settings>", "<Enabled>false</Enabled>", "<!DOCTYPE t [<!ENTITY a SYSTEM \"file:///c:/windows/win.ini\">]>", "&a;", "<![CDATA[", "]]>", "<Task>", "</Task>", "xmlns=\"" };
        Fuzzer.RunText(4000, r => r.Chance(0.15) ? r.Text(words, 8, 40) : r.Mutate(SampleTaskXml, words), xml =>
        {
            try
            {
                var facts = TaskFacts.FromXml(xml);
                Assert.All(facts.Actions, action => Assert.NotNull(action.Describe()));
                Assert.Empty(TaskComparison.CompareCurrent(facts, facts, new NoAccounts(), out _));
            }
            catch (Exception ex) when (ex is XmlException or InvalidDataException)
            {
                // The documented way to refuse text that is not a task definition, including any DTD.
            }
        });
    }

    [Fact]
    public void DeeplyNestedDefinitions_AreRefusedOrRead_NotAStackOverflow()
    {
        var nestedXml = string.Concat(Enumerable.Repeat("<a>", 200_000)) + string.Concat(Enumerable.Repeat("</a>", 200_000));
        // Reading this into a document would take minutes, so nesting is refused before that.
        Assert.Throws<InvalidDataException>(() => TaskFacts.FromXml("<Task>" + nestedXml + "</Task>"));
        Assert.Null(WatchLattice.ScriptHostAudit.ProcessCreationEvent.FromXml(nestedXml));

        var nestedJson = new string('[', 100_000) + new string(']', 100_000);
        Assert.ThrowsAny<JsonException>(() => TaskFacts.FromProjection(nestedJson));
        Assert.ThrowsAny<JsonException>(() => TaskComparison.CompareLogged(nestedJson, nestedJson));
        Assert.Null(ServiceDefinition.TryParse("{\"ImagePath\":" + nestedJson + "}"));
    }

    [Fact]
    public void ComHandler_AnyRegistrations_ResolveWithoutThrowing_AndRedirectLoopsEnd()
    {
        var classes = new[] { "{11111111-1111-1111-1111-111111111111}", "{22222222-2222-2222-2222-222222222222}", "{33333333-3333-3333-3333-333333333333}", "{44444444-4444-4444-4444-444444444444}", "{55555555-5555-5555-5555-555555555555}", "{66666666-6666-6666-6666-666666666666}" };
        Fuzzer.Run(3000, r =>
        {
            var registry = new FakeRegistry();
            foreach (var clsid in classes)
            {
                foreach (var (scope, sid) in new[] { (ComScope.Machine64, (string?)null), (ComScope.Machine32, null), (ComScope.User, "S-1-5-21-1-2-3-1001") })
                {
                    if (r.Chance(0.4)) continue;
                    registry.Entries[(scope, clsid, sid)] = new ComRegistration("HKLM\\" + clsid, r.Chance(0.8),
                        r.Chance(0.5) ? r.Token(PathWords) : null, r.Chance(0.3) ? r.Token(PathWords) : null,
                        r.Chance(0.6) ? r.Chance(0.9) ? r.Pick(classes) : r.Token() : null, r.Chance(0.05), r.Chance(0.05), r.Chance(0.05) ? r.Token() : null);
                }
            }
            return (Registry: registry, Clsid: r.Chance(0.85) ? r.Pick(classes) : r.Token(), Is64: r.Chance(0.8));
        }, input =>
        {
            var resolution = ComResolver.Resolve(input.Registry, input.Clsid, new[] { "S-1-5-21-1-2-3-1001" }, input.Is64);

            Assert.NotNull(resolution.Detail);
            Assert.Equal(resolution.Clsid is null, !WindowsPath.TryNormalizeClsid(input.Clsid, out _));
            if (resolution.Clsid is null) Assert.Equal(CheckStatus.Fail, resolution.Status);
            // A chain of redirects is followed a few steps at most, however the registry is arranged.
            Assert.True(input.Registry.Reads <= 40, $"{input.Registry.Reads} registry reads");
        }, input => $"{Fuzzer.Literal(input.Clsid)} with {string.Join("; ", input.Registry.Entries.Select(e => $"{e.Key.Scope} {e.Key.Clsid} -> {e.Value}"))}");
    }

    [Fact]
    public void Inventory_AnyOutput_ParsesOrIsRefused_AndComparesWithoutThrowing()
    {
        const string sample = "[{\"Id\":\"\\\\Microsoft\\\\Windows\\\\Defrag\\\\ScheduledDefrag\",\"Command\":\"{\\\"Enabled\\\":true}\"},{\"Id\":\"\\\\MyTask\",\"Command\":\"{}\"}]";
        var keys = new[] { "Id", "id", "ID", "Command", "command" };
        Fuzzer.RunText(4000, r => r.Next(3) switch { 0 => r.Json(keys, ProjectionStrings), 1 => "[" + r.Json(keys, ProjectionStrings, 2) + "]", _ => r.Mutate(sample, keys) }, json =>
        {
            try
            {
                var entries = WindowsPersistenceProvider.ParseScheduledTasks(json);
                Assert.All(entries, entry =>
                {
                    Assert.False(string.IsNullOrWhiteSpace(entry.Id));
                    Assert.NotNull(entry.Command);
                });
                Assert.Empty(PersistenceDiff.Compare(entries, entries));
            }
            catch (Exception ex) when (ex is JsonException or InvalidDataException)
            {
                // The documented way to refuse output that is not an inventory.
            }
        });
    }

    [Fact]
    public void Diff_AnyEntries_NeverThrows_AndReportsEveryDifference()
    {
        Fuzzer.Run(3000, r =>
        {
            // Names that differ only by case happen: a Startup folder can be made case-sensitive.
            PersistenceEntry Entry() => new(r.Pick("a.lnk", "A.lnk", "b.cmd", "B.CMD", r.Identifier(1, 3)), r.Pick("one", "two", r.Identifier()));
            return (Before: Enumerable.Range(0, r.Next(6)).Select(_ => Entry()).ToArray(), After: Enumerable.Range(0, r.Next(6)).Select(_ => Entry()).ToArray());
        }, input =>
        {
            Assert.Empty(PersistenceDiff.Compare(input.Before, input.Before));
            var changes = PersistenceDiff.Compare(input.Before, input.After);

            Assert.Equal(changes.Count, changes.Select(c => c.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count());
            // Something that starts with Windows was added, removed or changed exactly when the two sets of entries differ.
            string Set(PersistenceEntry[] entries) => string.Join("\n", entries.Select(e => e.Id.ToUpperInvariant() + "=" + e.Command).Distinct().Order(StringComparer.Ordinal));
            Assert.Equal(Set(input.Before) == Set(input.After), changes.Count == 0);
        }, input => $"before [{string.Join(", ", input.Before.AsEnumerable())}], after [{string.Join(", ", input.After.AsEnumerable())}]");
    }

    [Fact]
    public void VerificationFindings_AnyFile_AreReadOrRefused_WithoutThrowing()
    {
        using var temp = new TempFolder();
        var path = Path.Join(temp.Path, "alerts.json.verifications.json");
        var store = new VerificationStore(path);
        var alert = Guid.NewGuid();
        store.Add(new VerificationRecord(alert, "ENTRY_CHANGED", DateTimeOffset.UnixEpoch, "ScheduledTasks/\\MyTask",
            new PersistenceObservation("ScheduledTasks", "\\MyTask", PersistenceChangeKind.Changed, "{}", SampleProjection, DateTimeOffset.UnixEpoch), Array.Empty<VerificationRun>()));
        store.AddRun(alert, new VerificationRun(Guid.NewGuid(), VerificationTrigger.Automatic, "SYSTEM", DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch, "Scheduled task",
            VerificationOutcome.NeedsReview, "summary", new[] { new VerificationCheck("task", "Current task", CheckStatus.Warning, "detail") },
            new[] { new FieldChange("Actions[0].Execute", ChangeArea.Action, "a", "b") }, Array.Empty<FieldChange>(),
            new[] { new ActionEvidence(0, "Exec", "Runs a", File: new FileEvidence("C:\\a.exe", true, 1, Signature: SignatureEvidence.NotSigned)) }, "<Task/>", Array.Empty<string>()));
        store.Save();
        var sample = File.ReadAllText(path);
        var words = new[] { "null", "[]", "{}", "\"records\":", "\"runs\":", "\"checks\":", "\"version\":", "\"Suspicious\"", "\"Nope\"", "99", "\"alertId\":\"00000000-0000-0000-0000-000000000000\"" };

        Fuzzer.RunText(1500, r => r.Mutate(sample, words, 3), text =>
        {
            File.WriteAllBytes(path, Encoding.UTF8.GetBytes(text));
            try
            {
                foreach (var record in VerificationStore.Read(path))
                {
                    Assert.NotNull(record.Resource);
                    Assert.NotNull(record.Original.SourceId);
                    Assert.All(record.Runs, run => Assert.NotNull(run.Checks));
                    _ = record.Latest;
                }
            }
            catch (Exception ex) when (ex is JsonException or InvalidDataException)
            {
                // The documented way to refuse a damaged file; the store then moves it aside.
            }
        });
    }

    private static void AssertCanonical(string path)
    {
        Assert.Matches(Canonical, path);
        Assert.DoesNotContain(path, c => char.IsControl(c) || c is '*' or '?' or '"' or '<' or '>' or '|' or '/');
        Assert.Equal(-1, path.IndexOf(':', 2));
        Assert.All(path[3..].Split('\\', StringSplitOptions.RemoveEmptyEntries), part =>
        {
            Assert.NotEqual(".", part);
            Assert.NotEqual("..", part);
            Assert.False(part.EndsWith('.') || part.EndsWith(' '), "Windows drops trailing dots and spaces, so a canonical name has none.");
        });
    }

    /// <summary>A plain absolute path as <see cref="WindowsPath.Resolve"/> returns it.</summary>
    private static string CanonicalPath(FuzzRandom r, bool file = true)
    {
        var root = r.Pick(@"C:\Windows\System32", @"C:\Windows", @"C:\Program Files", @"C:\Program Files (x86)\Vendor", @"D:\Tools", @"C:\ProgramData", "C:");
        var folders = Enumerable.Range(0, r.Next(3)).Select(_ => r.Pick(r.Identifier(), "v1.0", "My App", "x64"));
        return string.Join('\\', new[] { root }.Concat(folders).Concat(file ? new[] { r.Identifier() + r.Pick(".exe", ".dll", ".cmd") } : Array.Empty<string>()))
            + (root == "C:" && !file && !folders.Any() ? "\\" : "");
    }

    /// <summary>The same path as a registry value or task might spell it.</summary>
    private static string Decorate(FuzzRandom r, string canonical)
    {
        var parts = canonical.Split('\\', StringSplitOptions.RemoveEmptyEntries).ToList();
        var text = new StringBuilder(r.Chance(0.3) ? parts[0].ToLowerInvariant() : parts[0]);
        foreach (var part in parts.Skip(1))
        {
            text.Append(r.Pick("\\", "\\", "/", "\\\\", "\\.\\"));
            if (r.Chance(0.15)) text.Append(r.Identifier()).Append(r.Pick("\\..\\", "/../"));
            text.Append(part);
        }
        if (parts.Count == 1) text.Append('\\');
        else if (r.Chance(0.1)) text.Append(r.Pick(".", " ", ". ."));
        var path = text.ToString();
        foreach (var (folder, variable) in new[] { (@"C:\Windows", "%SystemRoot%"), (@"C:\Windows", "%WINDIR%"), (@"C:\Program Files (x86)", "%ProgramFiles(x86)%"), (@"C:\ProgramData", "%programdata%") })
        {
            if (r.Chance(0.3) && path.StartsWith(folder + "\\", StringComparison.Ordinal)) path = variable + path[folder.Length..];
        }
        if (r.Chance(0.15) && !path.StartsWith('%')) path = r.Pick(@"\\?\", @"\??\") + path;
        if (r.Chance(0.3)) path = "\"" + path + "\"";
        return r.Pick("", " ", "\t") + path + r.Pick("", " ");
    }

    private static string RandomCase(FuzzRandom r, string text) =>
        string.Concat(text.Select(c => r.Chance(0.5) ? char.ToUpperInvariant(c) : char.ToLowerInvariant(c)));

    private static ServiceDefinition Service(FuzzRandom r)
    {
        string? Field(double present) => r.Chance(present) ? r.Next(3) switch { 0 => r.Token(PathWords), 1 => Decorate(r, CanonicalPath(r)) + r.Pick("", " -k netsvcs"), _ => r.Text(PathWords, 4, 16) } : null;
        // Lone surrogates are left out here: the stored projection replaces them, so it would not compare equal.
        string? Clean(string? value) => value is null ? null : string.Concat(value.Where(c => !char.IsSurrogate(c)));
        return new ServiceDefinition(r.Pick(0x10, 0x20, 0x110, 0x50, 0xd0, 1, -1), r.Pick(0, 1, 2, 3, 4, -1),
            Clean(Field(0.9)), Clean(Field(0.3)), Clean(r.Pick(null, "", "LocalSystem", "NT AUTHORITY\\LocalService", ".\\user", r.Token())), Clean(Field(0.1)));
    }

    private sealed class NoAccounts : IAccountResolver
    {
        public string CurrentAccount => "test";
        public string? ToSid(string account) => null;
        public string? ProfilePath(string sid) => null;
    }

    private sealed class FakeRegistry : IComRegistry
    {
        public Dictionary<(ComScope Scope, string Clsid, string? Sid), ComRegistration> Entries { get; } = new();

        public int Reads { get; private set; }

        public ComRegistration Read(ComScope scope, string clsid, string? userSid = null)
        {
            Reads++;
            return Entries.TryGetValue((scope, clsid, userSid), out var registration) ? registration : new ComRegistration("HKLM\\" + clsid, false);
        }

        public IReadOnlyList<string> LoadedUserSids() => new[] { "S-1-5-21-1-2-3-1001" };
    }
}

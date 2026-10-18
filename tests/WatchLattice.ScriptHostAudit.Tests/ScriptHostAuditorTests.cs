using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using WatchLattice.Common.Alerts;
using Xunit;

namespace WatchLattice.ScriptHostAudit.Tests;

public sealed class ScriptHostAuditorTests : IDisposable
{
    private const string Encoded = "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgA";

    private readonly string _folder = Path.Join(Path.GetTempPath(), $"watchlattice-scripthost-{Guid.NewGuid():N}");
    private readonly FakeLog _log = new();
    private readonly List<ScriptHostAlert> _published = new();
    private readonly List<ScriptHostAuditor> _auditors = new();

    public ScriptHostAuditorTests()
    {
        Directory.CreateDirectory(_folder);
    }

    private ScriptHostAuditOptions Options(Action<ScriptHostAuditOptions>? configure = null)
    {
        var options = new ScriptHostAuditOptions
        {
            StatePath = Path.Join(_folder, "state.json"),
            AlertLogPath = Path.Join(_folder, "audit.log"),
        };
        configure?.Invoke(options);
        return options;
    }

    private ScriptHostAuditor Create(ScriptHostAuditOptions? options = null, IAlertPublisher? alerts = null)
    {
        var auditor = new ScriptHostAuditor(_log, Microsoft.Extensions.Options.Options.Create(options ?? Options()),
            NullLogger<ScriptHostAuditor>.Instance, alerts);
        auditor.Published += _published.Add;
        _auditors.Add(auditor);
        return auditor;
    }

    /// <summary>A started auditor that has taken its first bookmark.</summary>
    private ScriptHostAuditor Started(ScriptHostAuditOptions? options = null, IAlertPublisher? alerts = null)
    {
        var auditor = Create(options, alerts);
        auditor.CheckOnce(default);
        _published.Clear();
        return auditor;
    }

    private IEnumerable<ScriptHostAlert> Launches => _published.Where(a => a.Code == ScriptHostAuditor.ScriptHostLaunched);

    [Fact]
    public void TheFirstCheck_StartsFromTheNewestRecord_WithoutReportingHistory()
    {
        _log.Other(3).Add(Events.PowerShell, Encoded, Events.Word).Other();
        var auditor = Create();

        Assert.Empty(auditor.CheckOnce(default));

        Assert.Empty(_published);
        Assert.Equal(0, _log.ReadCalls);
        Assert.Equal(5, WatchLattice.Common.AtomicJsonFile.Read<ScriptHostAuditState>(Path.Join(_folder, "state.json")).LastRecordId);
    }

    [Fact]
    public void ALaunchAfterTheBookmark_IsReported_WithItsDetailsAndFingerprint()
    {
        _log.Other(2);
        var alerts = new Recorder();
        var auditor = Started(alerts: alerts);
        _log.Other().Add(Events.PowerShell, Encoded, Events.Word);

        auditor.CheckOnce(default);

        var alert = Assert.Single(_published);
        Assert.Equal(ScriptHostAuditor.ScriptHostLaunched, alert.Code);
        Assert.Equal(AlertSeverity.Critical, alert.Severity);
        Assert.Equal("Highly suspicious script host launch", alert.Title);
        Assert.Equal($"{Events.Word}|{Events.PowerShell}", alert.Resource);
        Assert.StartsWith($"powershell.exe started by WINWORD.EXE ({Events.Word}) for DESKTOP-TEST\\alex, not elevated, medium integrity, at 2026-10-18 06:00:00 UTC.", alert.Message);
        Assert.Contains($"\nProgram: {Events.PowerShell}\n", alert.Message);
        Assert.Contains($"\nCommand line: {Encoded}\n", alert.Message);
        Assert.Contains("Why this is reported: started by WINWORD.EXE, an Office app", alert.Message);
        Assert.Contains("Security log record 4, process ID 0x1a2c, parent process ID 0x2b4.", alert.Message);
        Assert.Contains("did not stop the process", alert.Message);
        Assert.EndsWith("\n" + BaselineApprovals.FingerprintLine(Encoded), alert.Message);
        Assert.Equal((ScriptHostAuditor.ModuleId, ScriptHostAuditor.ScriptHostLaunched), Assert.Single(alerts.Published));

        // Nothing new: nothing reported again.
        auditor.CheckOnce(default);
        Assert.Single(_published);
    }

    [Fact]
    public void LaunchesBelowMinimumSeverity_AndOtherPrograms_AreNotReported()
    {
        var auditor = Started();
        _log.Add(Events.PowerShell, "powershell.exe -File C:\\Scripts\\backup.ps1")
            .Add(@"C:\Windows\System32\notepad.exe", "notepad.exe", Events.Word);

        auditor.CheckOnce(default);
        Assert.Empty(_published);

        var everything = Started(Options(o => { o.MinimumSeverity = AlertSeverity.Info; o.StatePath = Path.Join(_folder, "other.json"); }));
        _log.Add(Events.PowerShell, "powershell.exe -File C:\\Scripts\\backup.ps1");
        everything.CheckOnce(default);
        var info = Assert.Single(_published);
        Assert.Equal(AlertSeverity.Info, info.Severity);
        Assert.Equal("Script host launch", info.Title);
    }

    [Fact]
    public void AllowedAndApprovedLaunches_RaiseNoAlert()
    {
        var approved = ApprovedEntry.For($"{Events.Word}|{Events.PowerShell}", Encoded).ToString();
        var auditor = Started(Options(o =>
        {
            o.AllowedLaunches = new[] { "Code.exe|powershell.exe|*" };
            o.ApprovedLaunches = new[] { approved, "not an approval" };
        }));
        _log.Add(Events.PowerShell, Encoded, Events.VsCode)
            .Add(Events.PowerShell, Encoded, Events.Word)
            .Add(Events.PowerShell, Encoded + " -x", Events.Word);

        auditor.CheckOnce(default);

        // Only the launch whose command line differs from the approved one is reported.
        var alert = Assert.Single(Launches);
        Assert.Contains($"Command line: {Encoded} -x\n", alert.Message);
    }

    [Fact]
    public void ApprovingALaunchAlert_FromTheDashboard_StopsTheSameLaunchAlerting()
    {
        var auditor = Started();
        _log.Add(Events.PowerShell, Encoded, Events.Word);
        auditor.CheckOnce(default);
        var alert = Assert.Single(_published);

        var approval = BaselineApprovals.For(new ProtectionAlert(Guid.NewGuid(), DateTimeOffset.UtcNow, ScriptHostAuditor.ModuleId,
            alert.Code, alert.Severity, alert.Title, alert.Message, alert.Resource));
        Assert.NotNull(approval);
        Assert.Equal(BaselineApprovals.ScriptHostSetting, approval.SettingPath);
        Assert.Contains("WINWORD.EXE starting C:\\Windows", approval.Description);
        Assert.True(BaselineApprovals.IsValid(approval.SettingPath, approval.Value));
        Assert.True(BaselineApprovals.TryDecode(BaselineApprovals.Encode(approval), out var decoded));
        Assert.Equal(approval, decoded);

        _published.Clear();
        File.Delete(Path.Join(_folder, "state.json"));
        var approvedAuditor = Started(Options(o => o.ApprovedLaunches = new[] { approval.Value }));
        _log.Add(Events.PowerShell, Encoded, Events.Word).Add(Events.PowerShell, Encoded, Events.Explorer);
        approvedAuditor.CheckOnce(default);
        Assert.Equal(Events.Explorer + "|" + Events.PowerShell, Assert.Single(Launches).Resource);
    }

    [Fact]
    public void ALaunchWithoutACommandLine_HasNoFingerprint_AndSaysCommandLinesAreOff()
    {
        _log.Status = new AuditStatus(true, null);
        var auditor = Started();
        _log.Add(Events.PowerShell, commandLine: null, Events.Word);

        var findings = auditor.CheckOnce(default);

        var alert = Assert.Single(Launches);
        Assert.Contains("Command line: not recorded", alert.Message);
        Assert.DoesNotContain(BaselineApprovals.FingerprintLabel, alert.Message);
        Assert.Null(BaselineApprovals.For(new ProtectionAlert(Guid.NewGuid(), DateTimeOffset.UtcNow, ScriptHostAuditor.ModuleId,
            alert.Code, alert.Severity, alert.Title, alert.Message, alert.Resource)));
        Assert.Equal(ScriptHostAuditor.CommandLineNotRecorded, Assert.Single(findings).Code);
    }

    [Fact]
    public void CommandLines_CanBeKeptOutOfAlerts_AndStillApproved()
    {
        var auditor = Started(Options(o => o.CommandLineInAlerts = false));
        _log.Add(Events.PowerShell, Encoded, Events.Word);

        auditor.CheckOnce(default);

        var alert = Assert.Single(Launches);
        Assert.DoesNotContain("SQBFAFgA", alert.Message);
        Assert.Contains($"Command line: {Encoded.Length} characters, left out because CommandLineInAlerts is off", alert.Message);
        Assert.Contains("encoded command", alert.Message);
        Assert.EndsWith(BaselineApprovals.FingerprintLine(Encoded), alert.Message);
    }

    [Fact]
    public void ManyLaunchesInOneCheck_AreSummarized_AtTheHighestSeverity()
    {
        var auditor = Started(Options(o => { o.MaxIndividualAlerts = 2; o.MaxChangesPerAlert = 2; }));
        _log.Add(Events.PowerShell, "powershell.exe -w hidden x")
            .Add(Events.PowerShell, Encoded, Events.Word)
            .Add(Events.PowerShell, "powershell.exe -enc y");

        auditor.CheckOnce(default);

        var summary = Assert.Single(_published);
        Assert.Equal(ScriptHostAuditor.ScriptHostLaunches, summary.Code);
        Assert.Equal(AlertSeverity.Critical, summary.Severity);
        Assert.Equal("3 script host launches", summary.Title);
        Assert.Contains("and 1 more", summary.Message);
        // The auditor keeps its log open for writing, so read it the way a viewer would.
        using var log = new StreamReader(new FileStream(Path.Join(_folder, "audit.log"), FileMode.Open, FileAccess.Read, FileShare.ReadWrite));
        Assert.Equal(3, log.ReadToEnd().Split('\n').Count(l => l.Contains(ScriptHostAuditor.ScriptHostLaunched)));
    }

    [Fact]
    public void AuditingOff_IsReportedOnceAsInfo_AndClearsWhenTurnedOn()
    {
        _log.Status = new AuditStatus(false, false);
        var auditor = Create();

        var findings = auditor.CheckOnce(default);
        auditor.CheckOnce(default);

        // Off means no command line finding as well: there are no events to have one.
        var finding = Assert.Single(findings);
        Assert.Equal(ScriptHostAuditor.ProcessAuditingOff, finding.Code);
        Assert.Equal(AlertSeverity.Info, finding.Severity);
        Assert.Contains("does not change audit policy", finding.Message);
        Assert.Single(_published);

        _log.Status = new AuditStatus(true, true);
        Assert.Empty(auditor.CheckOnce(default));
        Assert.Equal(ScriptHostAuditor.ProcessAuditingOff + AlertEventIds.ClearedSuffix, _published[^1].Code);
        Assert.Equal(AlertSeverity.Info, _published[^1].Severity);
    }

    [Fact]
    public void AnUnreadablePolicy_IsInfo_AndLaunchesAreStillRead()
    {
        _log.Status = new AuditStatus(null, true, "access denied");
        var auditor = Started();
        _log.Add(Events.PowerShell, Encoded);

        var findings = auditor.CheckOnce(default);

        Assert.Contains("access denied", Assert.Single(findings, f => f.Code == ScriptHostAuditor.AuditPolicyUnavailable).Message);
        Assert.Single(Launches);
    }

    [Fact]
    public void AnUnreadableSecurityLog_IsAStandingWarning_AndRecovers()
    {
        _log.ReadError = new UnauthorizedAccessException("Attempted to perform an unauthorized operation.");
        var auditor = Create();

        var finding = Assert.Single(auditor.CheckOnce(default));
        Assert.Equal(ScriptHostAuditor.SecurityLogUnavailable, finding.Code);
        Assert.Equal(AlertSeverity.Warning, finding.Severity);
        Assert.Contains("unauthorized", finding.Message);

        _log.ReadError = null;
        Assert.Empty(auditor.CheckOnce(default));
        Assert.Equal(ScriptHostAuditor.SecurityLogUnavailable + AlertEventIds.ClearedSuffix, _published[^1].Code);
    }

    [Fact]
    public void AClearedLog_IsReported_AndReadingStartsOver()
    {
        _log.Other(10);
        var auditor = Started();
        _log.Clear();
        _log.Other().Add(Events.PowerShell, Encoded);

        auditor.CheckOnce(default);

        var missed = Assert.Single(_published, a => a.Code == ScriptHostAuditor.EventsMissed);
        Assert.Equal("Security log cleared", missed.Title);
        Assert.Contains("event 1102", missed.Message);
        Assert.Single(Launches);

        _published.Clear();
        _log.Add(Events.PowerShell, Encoded);
        auditor.CheckOnce(default);
        Assert.Single(Launches);
        Assert.DoesNotContain(_published, a => a.Code == ScriptHostAuditor.EventsMissed);
    }

    [Fact]
    public void OverwrittenRecords_AreReported()
    {
        _log.Other(5);
        var auditor = Started();
        _log.Other(10).Add(Events.PowerShell, Encoded);
        _log.Overwrite(8);

        auditor.CheckOnce(default);

        var missed = Assert.Single(_published, a => a.Code == ScriptHostAuditor.EventsMissed);
        Assert.Contains("3 Security log records after record 5 were overwritten", missed.Message);
        Assert.Single(Launches);
    }

    [Fact]
    public void AnEmptyLog_ReportsNothing()
    {
        var auditor = Create();
        Assert.Empty(auditor.CheckOnce(default));
        Assert.Empty(auditor.CheckOnce(default));
        Assert.Empty(_published);
    }

    [Fact]
    public void AFlood_KeepsTheNewestEvents_AndSaysSomeWereSkipped()
    {
        var auditor = Started(Options(o => o.MaxEventsPerCheck = 100));
        _log.Add(Events.PowerShell, "powershell.exe -enc old");
        for (var i = 0; i < 100; i++) _log.Add(@"C:\Windows\System32\notepad.exe", "notepad.exe");
        _log.Add(Events.PowerShell, "powershell.exe -enc new");

        auditor.CheckOnce(default);

        Assert.Contains("only the newest 100 were checked", Assert.Single(_published, a => a.Code == ScriptHostAuditor.EventsMissed).Message);
        Assert.Contains("-enc new", Assert.Single(Launches).Message);

        _published.Clear();
        auditor.CheckOnce(default);
        Assert.Empty(_published);
    }

    [Fact]
    public void TheBookmark_SurvivesARestart_SoLaunchesWhileStoppedAreReportedOnce()
    {
        var first = Started();
        _log.Add(Events.PowerShell, "powershell.exe -enc one");
        first.CheckOnce(default);
        Assert.Single(Launches);
        _published.Clear();

        _log.Add(Events.PowerShell, "powershell.exe -enc two");
        var second = Create();
        second.CheckOnce(default);

        Assert.Contains("-enc two", Assert.Single(Launches).Message);
    }

    [Fact]
    public void AnUnreadableBookmark_IsReported_AndReadingStartsFromNow()
    {
        File.WriteAllText(Path.Join(_folder, "state.json"), "{ not json");
        _log.Add(Events.PowerShell, Encoded);
        var auditor = Create();

        auditor.CheckOnce(default);

        Assert.Equal(ScriptHostAuditor.StateUnreadable, Assert.Single(_published).Code);
    }

    [Fact]
    public void AnUnsavableBookmark_IsAStandingWarning()
    {
        var blocked = Path.Join(_folder, "file");
        File.WriteAllText(blocked, "");
        var auditor = Create(Options(o => o.StatePath = Path.Join(blocked, "state.json")));

        var findings = auditor.CheckOnce(default);

        Assert.Equal(ScriptHostAuditor.StateSaveFailed, Assert.Single(findings).Code);
    }

    [Fact]
    public async Task RunAsync_StopsWhenCancelled()
    {
        var auditor = Create();
        using var cancel = new CancellationTokenSource();
        var checks = 0;
        auditor.CheckCompleted += _ =>
        {
            if (++checks == 1) cancel.Cancel();
        };

        await auditor.RunAsync(cancel.Token);

        Assert.Equal(1, checks);
    }

    public void Dispose()
    {
        foreach (var auditor in _auditors) auditor.Dispose();
        try { Directory.Delete(_folder, recursive: true); } catch (IOException) { }
    }

    private sealed class Recorder : IAlertPublisher
    {
        public List<(string Module, string Code)> Published { get; } = new();

        public void Publish(string module, string code, AlertSeverity severity, string title, string message, string? resource = null) =>
            Published.Add((module, code));
    }
}

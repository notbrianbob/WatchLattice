using WatchLattice.Common.Alerts;
using Xunit;

namespace WatchLattice.Common.Tests;

public sealed class TrayStatusTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 17, 12, 0, 0, TimeSpan.Zero);

    private static ProtectionAlert Alert(AlertSeverity severity, string code = "X", int minutesAgo = 5) =>
        new(Guid.NewGuid(), Now.AddMinutes(-minutesAgo), "Canary", code, severity, "Title " + code, "Message", "C:\\file-" + code);

    private static AlertSnapshot Snapshot(bool online = true, ModuleRunState state = ModuleRunState.Running, params ProtectionAlert[] alerts) =>
        new(AlertSnapshot.CurrentVersion, Guid.NewGuid(), online ? Now.AddSeconds(-2) : Now.AddMinutes(-10), online,
            new[] { new ModuleStatus("Canary", state, Now), new ModuleStatus("DefenderWatchdog", ModuleRunState.Running, Now) }, alerts);

    [Fact]
    public void NothingNew_IsOk()
    {
        var status = TrayStatus.Evaluate(Snapshot(alerts: Alert(AlertSeverity.Info)), AlertReviewSet.Empty, Now);
        Assert.Equal(TrayLevel.Ok, status.Level);
        Assert.Equal("WatchLattice: nothing new • 2 modules running", status.Tooltip);
    }

    [Fact]
    public void AnUnreviewedWarning_NeedsAttention_UntilAcknowledged()
    {
        var warning = Alert(AlertSeverity.Warning);
        var snapshot = Snapshot(alerts: warning);
        Assert.Equal(TrayLevel.Attention, TrayStatus.Evaluate(snapshot, AlertReviewSet.Empty, Now).Level);
        Assert.Equal("WatchLattice: 1 alert to review", TrayStatus.Evaluate(snapshot, AlertReviewSet.Empty, Now).Tooltip);

        var reviewed = AlertReviewSet.Empty.Mark(new[] { (AlertGrouping.KeyFor(warning), warning.At) }, dismiss: false, Now);
        Assert.Equal(TrayLevel.Ok, TrayStatus.Evaluate(snapshot, reviewed, Now).Level);
    }

    [Fact]
    public void AnUnreviewedCritical_IsRed_EvenWhenTheHubIsOffline()
    {
        var critical = Alert(AlertSeverity.Critical);
        var status = TrayStatus.Evaluate(Snapshot(online: false, alerts: new[] { critical, Alert(AlertSeverity.Warning, "Y") }), AlertReviewSet.Empty, Now);
        Assert.Equal(TrayLevel.Critical, status.Level);
        Assert.Equal(1, status.NewCritical);
        Assert.Equal(1, status.NewWarnings);
        Assert.Equal("WatchLattice: 1 critical alert to review • hub offline", status.Tooltip);
    }

    [Fact]
    public void ARepeatAfterAcknowledging_CountsAgain_AtItsOwnSeverity()
    {
        var first = Alert(AlertSeverity.Critical, minutesAgo: 30);
        var reviewed = AlertReviewSet.Empty.Mark(new[] { (AlertGrouping.KeyFor(first), first.At) }, dismiss: false, Now);
        var repeat = first with { Id = Guid.NewGuid(), At = Now.AddMinutes(-1), Severity = AlertSeverity.Warning };

        var status = TrayStatus.Evaluate(Snapshot(alerts: new[] { repeat, first }), reviewed, Now);

        Assert.Equal(TrayLevel.Attention, status.Level);
    }

    [Fact]
    public void OfflineOrUnreadable_IsGrey()
    {
        Assert.Equal(TrayLevel.Offline, TrayStatus.Evaluate(Snapshot(online: false), AlertReviewSet.Empty, Now).Level);
        Assert.Equal(TrayLevel.Offline, TrayStatus.Evaluate(Snapshot(), AlertReviewSet.Empty, Now, feedProblem: "denied").Level);
        Assert.Equal("WatchLattice: alert feed unavailable", TrayStatus.Evaluate(null, AlertReviewSet.Empty, Now, "denied").Tooltip);
    }

    [Fact]
    public void AFailedModule_NeedsAttention()
    {
        var status = TrayStatus.Evaluate(Snapshot(state: ModuleRunState.Failed), AlertReviewSet.Empty, Now);
        Assert.Equal(TrayLevel.Attention, status.Level);
        Assert.Equal("WatchLattice: 1 module needs attention", status.Tooltip);
    }

    [Fact]
    public void Tooltip_FitsTheNotificationArea()
    {
        var many = Enumerable.Range(0, 150).Select(i => Alert(AlertSeverity.Critical, "C" + i)).ToArray();
        var snapshot = Snapshot(online: false, alerts: many) with
        {
            Update = new UpdateNotice("1.0.0", "2.0.0", "WatchLattice 2.0.0", "https://github.com/notbrianbob/WatchLattice/releases/tag/v2.0.0", Now, Now, Installable: true),
        };
        Assert.True(TrayStatus.Evaluate(snapshot, AlertReviewSet.Empty, Now).Tooltip.Length <= TrayStatus.MaxTooltip);
    }

    [Fact]
    public void Preferences_DefaultToPopUpsOnAndWelcomeUnseen_AndRoundTrip()
    {
        var path = Path.Join(Path.GetTempPath(), "wl-tray-prefs-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            var (defaults, problem) = TrayPreferences.Load(path);
            Assert.Null(problem);
            Assert.True(defaults.PopUpCriticalAlerts);
            Assert.False(defaults.WelcomeSeen);

            Assert.Null((defaults with { WelcomeSeen = true, PopUpCriticalAlerts = false }).Save(path));
            var (loaded, _) = TrayPreferences.Load(path);
            Assert.True(loaded.WelcomeSeen);
            Assert.False(loaded.PopUpCriticalAlerts);

            File.WriteAllText(path, "{ not json");
            var (fallback, damaged) = TrayPreferences.Load(path);
            Assert.NotNull(damaged);
            Assert.True(fallback.PopUpCriticalAlerts);
        }
        finally
        {
            File.Delete(path);
        }
    }
}

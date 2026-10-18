using WatchLattice.Common.Alerts;
using Xunit;

namespace WatchLattice.Common.Tests;

public sealed class AlertGroupingTests : IDisposable
{
    private static readonly DateTimeOffset Start = new(2026, 10, 17, 16, 0, 0, TimeSpan.Zero);
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "watchlattice-review-" + Guid.NewGuid().ToString("N"));

    private static ProtectionAlert Alert(int minute, string code = "ENTRY_CHANGED", string? resource = @"Run\Updater",
        AlertSeverity severity = AlertSeverity.Warning, string module = "Persistence", string title = "Autostart entry changed") =>
        new(Guid.NewGuid(), Start.AddMinutes(minute), module, code, severity, title, "details", resource);

    [Fact]
    public void Repeats_ForTheSameEntry_BecomeOneRow_NewestFirst()
    {
        var alerts = new[]
        {
            Alert(0), Alert(15), Alert(30, severity: AlertSeverity.Info),
            Alert(20, code: "ENTRY_ADDED", title: "Autostart entry added"),
            Alert(25, resource: @"Run\Other"),
            Alert(5, module: "Firewall", code: "PROFILE_OFF", resource: null, title: "Firewall needs attention"),
            Alert(6, module: "Firewall", code: "PROFILE_OFF", resource: null, title: "Firewall needs attention"),
        };

        var groups = AlertGrouping.Build(alerts, AlertReviewSet.Empty);

        Assert.Equal(4, groups.Count);
        var changed = groups[0];
        Assert.Equal(3, changed.Count);
        Assert.Equal(Start, changed.FirstSeen);
        Assert.Equal(Start.AddMinutes(30), changed.LastSeen);
        Assert.Equal(alerts[2].Id, changed.Latest.Id);
        Assert.Equal(AlertSeverity.Warning, changed.Severity);
        Assert.Equal(AlertReviewState.New, changed.State);
        Assert.Equal(3, changed.NewCount);
        Assert.Equal(new[] { 1, 1, 2 }, groups.Skip(1).Select(g => g.Count));
        Assert.Equal(7, groups.Sum(g => g.Count));
    }

    [Fact]
    public void Ungrouped_ShowsEveryAlert_ButSharesTheGroupsReviewState()
    {
        var alerts = new[] { Alert(0), Alert(10) };
        var key = AlertGrouping.KeyFor(alerts[0]);
        var review = AlertReviewSet.Empty.Mark(new[] { (key, alerts[0].At) }, dismiss: false, Start);

        var rows = AlertGrouping.Build(alerts, review, group: false);

        Assert.Equal(2, rows.Count);
        Assert.All(rows, r => Assert.Equal(key, r.Key));
        Assert.Equal(AlertReviewState.New, rows[0].State);
        Assert.Equal(AlertReviewState.Acknowledged, rows[1].State);
    }

    [Fact]
    public void Acknowledged_And_DismissedGroups_ComeBack_WhenTheAlertRepeats()
    {
        var first = new[] { Alert(0), Alert(5) };
        var key = AlertGrouping.KeyFor(first[0]);
        var acknowledged = AlertReviewSet.Empty.Mark(new[] { (key, first[1].At) }, dismiss: false, Start);
        Assert.Equal(AlertReviewState.Acknowledged, Assert.Single(AlertGrouping.Build(first, acknowledged)).State);

        var dismissed = acknowledged.Mark(new[] { (key, first[1].At) }, dismiss: true, Start);
        var group = Assert.Single(AlertGrouping.Build(first, dismissed));
        Assert.Equal(AlertReviewState.Dismissed, group.State);
        Assert.Equal(0, group.NewCount);

        var repeated = AlertGrouping.Build(first.Append(Alert(9)), dismissed);
        Assert.Equal(AlertReviewState.New, Assert.Single(repeated).State);
        Assert.Equal(1, repeated[0].NewCount);
    }

    [Fact]
    public void Marking_NeverMovesReviewBackwards_AndRestoreShowsDismissedAgain()
    {
        var key = "k";
        var set = AlertReviewSet.Empty.Mark(new[] { (key, Start.AddMinutes(10)) }, dismiss: true, Start);
        // Acknowledging an older occurrence keeps the newer review and the dismissal.
        set = set.Mark(new[] { (key, Start) }, dismiss: false, Start);
        Assert.Equal(Start.AddMinutes(10), set.Find(key)!.ReviewedThrough);
        Assert.True(set.Find(key)!.Dismissed);

        // Acknowledging something newer than the dismissal un-hides it.
        var later = set.Mark(new[] { (key, Start.AddMinutes(20)) }, dismiss: false, Start);
        Assert.False(later.Find(key)!.Dismissed);

        var restored = set.Restore(new[] { key, "missing" }, Start);
        Assert.False(restored.Find(key)!.Dismissed);
        Assert.Equal(Start.AddMinutes(10), restored.Find(key)!.ReviewedThrough);
        Assert.Null(restored.Find("missing"));
    }

    [Fact]
    public void ReviewSet_IsBounded_KeepingTheMostRecentMarks()
    {
        var set = AlertReviewSet.Empty.Mark(
            Enumerable.Range(0, AlertReviewSet.Limit + 5).Select(i => ($"k{i}", Start)), dismiss: false, Start);
        Assert.Equal(AlertReviewSet.Limit, set.Marks.Count);
        set = set.Mark(new[] { ("newest", Start) }, dismiss: false, Start.AddMinutes(1));
        Assert.NotNull(set.Find("newest"));
        Assert.Equal(AlertReviewSet.Limit, set.Marks.Count);
    }

    [Fact]
    public void Store_SavesAndReloads_AndSeesAnotherWritersChanges()
    {
        var path = Path.Combine(_folder, "alert-review.json");
        var store = new AlertReviewStore(path);
        Assert.Empty(store.Refresh().Marks);

        store.Update(s => s.Mark(new[] { ("a", Start) }, dismiss: true, Start));
        var other = new AlertReviewStore(path);
        Assert.True(other.Refresh().Find("a")!.Dismissed);

        other.Update(s => s.Mark(new[] { ("b", Start) }, dismiss: false, Start));
        // The first store merges onto the file as it is now, so neither change is lost.
        var merged = store.Update(s => s.Restore(new[] { "a" }, Start));
        Assert.False(merged.Find("a")!.Dismissed);
        Assert.NotNull(merged.Find("b"));
        Assert.NotNull(new AlertReviewStore(path).Refresh().Find("b"));
    }

    [Fact]
    public void Store_ReportsACorruptFile_AndKeepsWhatItHad()
    {
        var path = Path.Combine(_folder, "alert-review.json");
        var store = new AlertReviewStore(path);
        store.Update(s => s.Mark(new[] { ("a", Start) }, dismiss: false, Start));
        File.WriteAllText(path, "{ not json");
        File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddMinutes(1));

        var current = store.Refresh();

        Assert.NotNull(current.Find("a"));
        Assert.NotNull(store.Problem);
    }

    public void Dispose()
    {
        if (Directory.Exists(_folder)) Directory.Delete(_folder, recursive: true);
    }
}

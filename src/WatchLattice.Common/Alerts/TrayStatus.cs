namespace WatchLattice.Common.Alerts;

/// <summary>What the tray icon shows, from most to least urgent.</summary>
public enum TrayLevel
{
    /// <summary>Hub connected, every module fine, nothing new to review. Green shield.</summary>
    Ok,

    /// <summary>A warning to review, or a module that stopped or keeps restarting. Amber shield.</summary>
    Attention,

    /// <summary>The hub isn't reporting (service stopped, or the feed can't be read). Grey shield.</summary>
    Offline,

    /// <summary>A critical alert nobody has acknowledged yet. Red shield.</summary>
    Critical,
}

/// <summary>
/// The tray icon's state and tooltip, worked out from the alert feed and the
/// user's own acknowledged and dismissed alerts. Unacknowledged critical
/// alerts outrank everything, including the hub being offline, because the
/// alert is still true and still needs a look.
/// </summary>
public sealed record TrayStatus(TrayLevel Level, string Tooltip, int NewCritical, int NewWarnings)
{
    /// <summary>NotifyIcon refuses tooltips over 127 characters.</summary>
    public const int MaxTooltip = 127;

    public static TrayStatus Evaluate(AlertSnapshot? snapshot, AlertReviewSet review, DateTimeOffset now, string? feedProblem = null)
    {
        if (snapshot is null)
            return new(TrayLevel.Offline, Clip(feedProblem is null ? "WatchLattice: waiting for the hub" : "WatchLattice: alert feed unavailable"), 0, 0);

        var unreviewed = AlertGrouping.Build(snapshot.Alerts, review)
            .Where(g => g.State == AlertReviewState.New)
            .ToArray();
        var newCritical = unreviewed.Count(g => FreshSeverity(g, review) == AlertSeverity.Critical);
        var newWarnings = unreviewed.Count(g => FreshSeverity(g, review) == AlertSeverity.Warning);
        var fresh = feedProblem is null && snapshot.IsFresh(now);
        var troubled = snapshot.Modules.Count(m => m.State is ModuleRunState.Failed or ModuleRunState.Restarting or ModuleRunState.Finished);
        var running = snapshot.Modules.Count(m => m.State == ModuleRunState.Running);
        var update = snapshot.Update is null ? "" : " • update available";

        if (newCritical > 0)
        {
            return new(TrayLevel.Critical, Clip($"WatchLattice: {Count(newCritical, "critical alert")} to review"
                + (fresh ? "" : " • hub offline") + update), newCritical, newWarnings);
        }
        if (!fresh)
            return new(TrayLevel.Offline, Clip("WatchLattice: hub offline" + Also(newWarnings) + update), 0, newWarnings);
        if (newWarnings > 0 || troubled > 0)
        {
            var parts = new List<string>();
            if (newWarnings > 0) parts.Add($"{Count(newWarnings, "alert")} to review");
            if (troubled > 0) parts.Add($"{Count(troubled, "module")} need{(troubled == 1 ? "s" : "")} attention");
            return new(TrayLevel.Attention, Clip("WatchLattice: " + string.Join(" • ", parts) + update), 0, newWarnings);
        }
        return new(TrayLevel.Ok, Clip($"WatchLattice: nothing new • {Count(running, "module")} running" + update), 0, 0);
    }

    /// <summary>The highest severity among a group's occurrences the user hasn't reviewed.</summary>
    private static AlertSeverity FreshSeverity(AlertGroup group, AlertReviewSet review)
    {
        var mark = review.Find(group.Key);
        return group.Alerts.Where(a => mark is null || a.At > mark.ReviewedThrough).Select(a => a.Severity).DefaultIfEmpty(AlertSeverity.Info).Max();
    }

    private static string Also(int warnings) => warnings > 0 ? $" • {Count(warnings, "alert")} to review" : "";

    private static string Count(int n, string noun) => n == 1 ? $"1 {noun}" : $"{n} {noun}s";

    private static string Clip(string text) => text.Length <= MaxTooltip ? text : text[..(MaxTooltip - 1)] + "…";
}

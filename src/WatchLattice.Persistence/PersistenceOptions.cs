namespace WatchLattice.Persistence;

public sealed class PersistenceOptions
{
    public int CheckIntervalSeconds { get; set; } = 300;
    public bool WatchRegistry { get; set; } = true;
    public bool WatchStartupFolders { get; set; } = true;
    public bool WatchScheduledTasks { get; set; } = true;

    /// <summary>Inventory auto-start Windows services (program, service DLL, account, failure command).</summary>
    public bool WatchServices { get; set; } = true;

    /// <summary>Inventory permanent WMI event subscriptions (filters, consumers, bindings) in root\subscription.</summary>
    public bool WatchWmiSubscriptions { get; set; } = true;
    public string[] StartupFolders { get; set; } = Array.Empty<string>();
    public string[] IgnoredEntries { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Entries approved as known-good, one per line as <c>sha256:&lt;hash&gt; &lt;source&gt;/&lt;entry&gt;</c>.
    /// Added by Approve as baseline in the dashboard. An entry added or changed
    /// to exactly the approved value raises no alert; any other value still does.
    /// </summary>
    public string[] ApprovedEntries { get; set; } = Array.Empty<string>();
    public string? BaselinePath { get; set; }
    public int MaxStartupFileBytes { get; set; } = 4 * 1024 * 1024;

    /// <summary>Verify a scheduled task or service automatically when an alert reports it added or changed. Never remediates.</summary>
    public bool AutoVerifyAlerts { get; set; } = true;

    /// <summary>Certificate common names or organizations, besides Microsoft, whose signatures pass the publisher check.</summary>
    public string[] FamiliarPublishers { get; set; } = Array.Empty<string>();

    public string ResolveBaselinePath() => Path.GetFullPath(Environment.ExpandEnvironmentVariables(
        string.IsNullOrWhiteSpace(BaselinePath) ? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ScanAlways", "persistence-baseline.json")
            : BaselinePath));

    public IReadOnlyList<string> ResolveStartupFolders() => (StartupFolders.Length > 0 ? StartupFolders : new[]
    {
        Environment.GetFolderPath(Environment.SpecialFolder.Startup),
        Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
    }).Where(p => !string.IsNullOrWhiteSpace(p)).Select(p => Path.GetFullPath(Environment.ExpandEnvironmentVariables(p)))
        .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
}

namespace WatchLattice.BrowserExtensionWatchdog;

/// <summary>Configuration for the browser extension watchdog.</summary>
public sealed class BrowserExtensionWatchdogOptions
{
    public const string SectionName = "BrowserExtensionWatchdog";

    /// <summary>Seconds between checks. Minimum 60. A check reads a few small files per browser profile.</summary>
    public int CheckIntervalSeconds { get; set; } = 300;

    /// <summary>Watch Microsoft Edge profiles and Edge's extension policies.</summary>
    public bool WatchEdge { get; set; } = true;

    /// <summary>Watch Google Chrome profiles and Chrome's extension policies.</summary>
    public bool WatchChrome { get; set; } = true;

    /// <summary>Watch Mozilla Firefox profiles and Firefox's extension policies.</summary>
    public bool WatchFirefox { get; set; } = true;

    /// <summary>Report extension force-install and install policies added to or removed from the registry.</summary>
    public bool WatchPolicies { get; set; } = true;

    /// <summary>Report extensions that were removed (as Info). Additions are always reported.</summary>
    public bool ReportRemovals { get; set; } = true;

    /// <summary>Extension IDs that never raise an alert, for extensions you approved. Wildcards * and ? work.</summary>
    public string[] IgnoredExtensionIds { get; set; } = Array.Empty<string>();

    /// <summary>Up to this many additions (or removals) in one check get an alert each; more are summarized in one alert.</summary>
    public int MaxIndividualAlerts { get; set; } = 5;

    /// <summary>At most this many extensions are listed in one summary alert; the rest are counted.</summary>
    public int MaxChangesPerAlert { get; set; } = 20;

    /// <summary>A Preferences, Local State, extensions.json or manifest file larger than this is not read.</summary>
    public int MaxFileBytes { get; set; } = 32 * 1024 * 1024;

    /// <summary>
    /// Windows user profile folders (such as C:\Users\alex) to read instead of
    /// every profile in the ProfileList. Empty reads every local, domain and
    /// Entra ID user profile on the machine.
    /// </summary>
    public string[] UserProfileFolders { get; set; } = Array.Empty<string>();

    /// <summary>Last observed extensions and policies. Null picks %LOCALAPPDATA%\ScanAlways\browser-extensions-state.json.</summary>
    public string? StatePath { get; set; }

    /// <summary>Rolling alert log. Null picks %LOCALAPPDATA%\ScanAlways\browser-extension-watchdog.log.</summary>
    public string? AlertLogPath { get; set; }

    public IReadOnlyList<string> EnabledBrowsers() =>
        new (bool On, string Browser)[] { (WatchEdge, Browsers.Edge), (WatchChrome, Browsers.Chrome), (WatchFirefox, Browsers.Firefox) }
            .Where(b => b.On).Select(b => b.Browser).ToList();

    public string ResolveStatePath() => Resolve(StatePath, "browser-extensions-state.json");

    public string ResolveAlertLogPath() => Resolve(AlertLogPath, "browser-extension-watchdog.log");

    private static string Resolve(string? configured, string fileName)
    {
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return Path.GetFullPath(Environment.ExpandEnvironmentVariables(configured));
        }

        var root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrEmpty(root))
        {
            root = Path.GetTempPath();
        }
        return Path.Join(root, "ScanAlways", fileName);
    }
}

namespace WatchLattice.HostsProxyWatchdog;

/// <summary>Configuration for the hosts file and proxy watchdog.</summary>
public sealed class HostsProxyWatchdogOptions
{
    public const string SectionName = "HostsProxyWatchdog";

    /// <summary>
    /// Domains whose hosts file entries are always critical: Windows Update,
    /// Defender's cloud, definition and SmartScreen services, and where
    /// WatchLattice downloads its own updates. Each also covers its subdomains.
    /// Blocking or redirecting these is a classic way to keep a machine from
    /// getting fixes and fresh signatures.
    /// </summary>
    public static readonly IReadOnlyList<string> BuiltInProtectedDomains = new[]
    {
        "windowsupdate.com",
        "update.microsoft.com",
        "delivery.mp.microsoft.com",
        "wdcp.microsoft.com",
        "wdcpalt.microsoft.com",
        "wd.microsoft.com",
        "definitionupdates.microsoft.com",
        "smartscreen.microsoft.com",
        "smartscreen-prod.microsoft.com",
        "security.microsoft.com",
        "go.microsoft.com",
        "github.com",
        "githubusercontent.com",
        "virustotal.com",
    };

    /// <summary>Seconds between checks. Minimum 15. Both checks are a file read and a few registry reads.</summary>
    public int CheckIntervalSeconds { get; set; } = 60;

    /// <summary>Report changes to the hosts file (and to where Windows looks for it).</summary>
    public bool WatchHostsFile { get; set; } = true;

    /// <summary>Report changes to WinINET, WinHTTP and environment-variable proxy settings.</summary>
    public bool WatchProxySettings { get; set; } = true;

    /// <summary>Treat <see cref="BuiltInProtectedDomains"/> as protected. Turn off only to replace the list entirely.</summary>
    public bool IncludeBuiltInProtectedDomains { get; set; } = true;

    /// <summary>More domains (each covering its subdomains) whose hosts entries are critical.</summary>
    public string[] ProtectedDomains { get; set; } = Array.Empty<string>();

    /// <summary>Host names (wildcards * and ?) whose hosts entries never raise an alert, for entries you added on purpose.</summary>
    public string[] IgnoredHosts { get; set; } = Array.Empty<string>();

    /// <summary>At most this many individual changes are listed in one alert; the rest are counted.</summary>
    public int MaxChangesPerAlert { get; set; } = 20;

    /// <summary>A hosts file larger than this is not read (it is reported as unreadable).</summary>
    public int MaxHostsFileBytes { get; set; } = 16 * 1024 * 1024;

    /// <summary>Read this file instead of the hosts file Windows uses. Null follows Tcpip's DataBasePath, as Windows does.</summary>
    public string? HostsFilePath { get; set; }

    /// <summary>Last observed hosts entries and proxy settings. Null picks %LOCALAPPDATA%\ScanAlways\hosts-proxy-state.json.</summary>
    public string? StatePath { get; set; }

    /// <summary>Rolling alert log. Null picks %LOCALAPPDATA%\ScanAlways\hosts-proxy-watchdog.log.</summary>
    public string? AlertLogPath { get; set; }

    public IReadOnlyList<string> EffectiveProtectedDomains() =>
        (IncludeBuiltInProtectedDomains ? BuiltInProtectedDomains : Array.Empty<string>())
            .Concat(ProtectedDomains ?? Array.Empty<string>())
            .Select(d => HostsFileParser.NormalizeHost(d.Trim().TrimStart('*', '.')))
            .OfType<string>()
            .Distinct(StringComparer.Ordinal)
            .ToList();

    public string ResolveStatePath() => Resolve(StatePath, "hosts-proxy-state.json");

    public string ResolveAlertLogPath() => Resolve(AlertLogPath, "hosts-proxy-watchdog.log");

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

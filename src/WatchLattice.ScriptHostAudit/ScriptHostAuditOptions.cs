using WatchLattice.Common.Alerts;

namespace WatchLattice.ScriptHostAudit;

/// <summary>Configuration for script host launch auditing.</summary>
public sealed class ScriptHostAuditOptions
{
    public const string SectionName = "ScriptHostAudit";

    /// <summary>Seconds between reads of the Security log. Minimum 10. A read only fetches events newer than the last one seen.</summary>
    public int CheckIntervalSeconds { get; set; } = 30;

    /// <summary>Report launches of the built-in list of script hosts and similar programs (see the README).</summary>
    public bool IncludeBuiltInScriptHosts { get; set; } = true;

    /// <summary>
    /// More program file names whose launches are reported, such as
    /// <c>python.exe</c>. Matched against the new process's file name,
    /// case-insensitively.
    /// </summary>
    public string[] ScriptHosts { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Treat launches by the built-in list of Office apps, browsers, PDF
    /// readers and script hosts as suspicious. Real documents and web pages
    /// rarely need to start PowerShell or mshta; malicious ones often do.
    /// </summary>
    public bool IncludeBuiltInSuspiciousParents { get; set; } = true;

    /// <summary>More parent program file names that make a script host launch suspicious.</summary>
    public string[] SuspiciousParents { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Launches that never alert, one rule per line:
    /// <c>&lt;parent&gt;|&lt;script host&gt;|&lt;command line&gt;</c>. Each part is a
    /// pattern where <c>*</c> and <c>?</c> are wildcards and an empty part
    /// matches anything. A parent or host part containing <c>\</c> is matched
    /// against the full path, otherwise against the file name. For example
    /// <c>C:\Program Files\Microsoft VS Code\Code.exe|powershell.exe|*</c>.
    /// </summary>
    public string[] AllowedLaunches { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Launches approved from the dashboard, one per line:
    /// <c>sha256:&lt;hash of the exact command line&gt; &lt;parent path&gt;|&lt;host path&gt;</c>.
    /// Only the same parent starting the same host with exactly that command line is approved.
    /// </summary>
    public string[] ApprovedLaunches { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Launches assessed below this are only counted in the module's log.
    /// Warning reports launches with a suspicious parent, command line or
    /// folder; Info reports every launch of a script host, which is noisy on
    /// most PCs.
    /// </summary>
    public AlertSeverity MinimumSeverity { get; set; } = AlertSeverity.Warning;

    /// <summary>
    /// Copy each reported launch's command line into its alert. The Security
    /// log is only readable by administrators, but alerts also go to the tray
    /// feed and the Application log, which every user can read, and command
    /// lines sometimes carry passwords or tokens. When off, an alert gives
    /// the command line's length instead (approving it still works).
    /// </summary>
    public bool CommandLineInAlerts { get; set; } = true;

    /// <summary>Up to this many launches in one read get an alert each; more are summarized in one alert.</summary>
    public int MaxIndividualAlerts { get; set; } = 5;

    /// <summary>At most this many launches are listed in one summary alert; the rest are counted.</summary>
    public int MaxChangesPerAlert { get; set; } = 20;

    /// <summary>
    /// At most this many process creation events are read in one check. When
    /// more arrived, the oldest of them are skipped and reported once.
    /// </summary>
    public int MaxEventsPerCheck { get; set; } = 5000;

    /// <summary>Where the last Security log record read is kept. Null picks %LOCALAPPDATA%\ScanAlways\script-host-audit-state.json.</summary>
    public string? StatePath { get; set; }

    /// <summary>Rolling alert log. Null picks %LOCALAPPDATA%\ScanAlways\script-host-audit.log.</summary>
    public string? AlertLogPath { get; set; }

    public static IReadOnlyList<string> DefaultScriptHosts { get; } = new[]
    {
        "powershell.exe", "pwsh.exe", "powershell_ise.exe",
        "mshta.exe", "wscript.exe", "cscript.exe",
        "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
        "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
        "cmstp.exe", "wmic.exe", "msxsl.exe", "hh.exe", "forfiles.exe", "scriptrunner.exe",
    };

    public static IReadOnlyList<string> DefaultSuspiciousParents { get; } = new[]
    {
        // Office
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "onenotem.exe",
        "msaccess.exe", "mspub.exe", "visio.exe", "eqnedt32.exe",
        // Browsers
        "msedge.exe", "chrome.exe", "firefox.exe", "iexplore.exe", "brave.exe", "opera.exe", "vivaldi.exe",
        // Document readers and mail
        "acrord32.exe", "acrobat.exe", "foxitpdfreader.exe", "sumatrapdf.exe", "thunderbird.exe",
        // Script hosts starting other script hosts
        "mshta.exe", "wscript.exe", "cscript.exe",
    };

    public IReadOnlySet<string> WatchedHosts() => Names(IncludeBuiltInScriptHosts ? DefaultScriptHosts : null, ScriptHosts);

    public IReadOnlySet<string> SuspiciousParentNames() => Names(IncludeBuiltInSuspiciousParents ? DefaultSuspiciousParents : null, SuspiciousParents);

    private static HashSet<string> Names(IEnumerable<string>? builtIn, IEnumerable<string>? extra) =>
        (builtIn ?? Array.Empty<string>()).Concat(extra ?? Array.Empty<string>())
            .Where(n => !string.IsNullOrWhiteSpace(n))
            .Select(n => Path.GetFileName(n.Trim()))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

    public string ResolveStatePath() => Resolve(StatePath, "script-host-audit-state.json");

    public string ResolveAlertLogPath() => Resolve(AlertLogPath, "script-host-audit.log");

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

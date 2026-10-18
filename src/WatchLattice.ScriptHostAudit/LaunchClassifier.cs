using System.Text.RegularExpressions;
using WatchLattice.Common.Alerts;

namespace WatchLattice.ScriptHostAudit;

/// <summary>How a script host launch was assessed, and why.</summary>
/// <param name="Severity">Info for an ordinary launch; Warning with one kind of reason; Critical for a suspicious parent plus another reason.</param>
/// <param name="Reasons">One line per reason, in plain words.</param>
/// <param name="AllowedBy">The <c>AllowedLaunches</c> rule it matched, if any.</param>
public sealed record LaunchAssessment(AlertSeverity Severity, IReadOnlyList<string> Reasons, string? AllowedBy);

/// <summary>
/// Grades a script host launch from what event 4688 recorded: who started
/// it, what its command line asks for, and where it ran from. These are
/// heuristics for "worth a look", not verdicts; malware can avoid every one of
/// them and administrators trip them on purpose.
/// </summary>
public sealed class LaunchClassifier
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(100);

    private static readonly HashSet<string> PowerShellHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "pwsh.exe", "powershell_ise.exe",
    };

    // Hosts that ship with Windows and live only in System32, SysWOW64,
    // WinSxS or the .NET Framework folders. A copy anywhere else is unusual.
    // MSBuild is left out because Visual Studio and the .NET SDK carry their own.
    private static readonly HashSet<string> InBoxHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "powershell_ise.exe", "mshta.exe", "wscript.exe", "cscript.exe", "rundll32.exe",
        "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "installutil.exe", "regasm.exe",
        "regsvcs.exe", "cmstp.exe", "wmic.exe", "hh.exe", "forfiles.exe", "scriptrunner.exe",
    };

    private static readonly (string Host, Regex Pattern, string Reason)[] Indicators =
    {
        ("*", Pattern(@"frombase64string"), "decodes Base64 text (FromBase64String)"),
        ("*", Pattern(@"downloadstring|downloadfile|downloaddata|net\.webclient|invoke-webrequest|\biwr\b|start-bitstransfer|invoke-restmethod|\birm\b"), "downloads from the network"),
        ("*", Pattern(@"invoke-expression|\biex\b"), "runs text as code (Invoke-Expression)"),
        ("*", Pattern(@"(?:^|[\s""'(])(?:javascript|vbscript):"), "runs inline script (javascript: or vbscript:)"),
        ("mshta.exe", Pattern(@"https?://"), "runs an HTML application from the network"),
        ("rundll32.exe", Pattern(@"url\.dll|ieframe\.dll.*openurl|zipfldr\.dll.*routethecall|shell32\.dll.*shellexec_rundll"), "uses a DLL export that opens URLs or runs other programs"),
        ("regsvr32.exe", Pattern(@"[/-]i:\s*\S*(?:https?://|\\\\)|scrobj\.dll"), "registers a script component, possibly from the network (scrobj.dll or /i:URL)"),
        ("certutil.exe", Pattern(@"[/-](?:urlcache|verifyctl|decode|decodehex)\b"), "downloads or decodes a file (certutil -urlcache or -decode)"),
        ("bitsadmin.exe", Pattern(@"[/-](?:transfer|addfile|setnotifycmdline)\b"), "downloads a file or sets a command to run (bitsadmin)"),
        ("cmstp.exe", Pattern(@"[/-]s\b|\.inf\b"), "installs a connection profile, which can run commands (cmstp)"),
        ("wmic.exe", Pattern(@"process\s+call\s+create|/node:|\.xsl\b|format:"), "starts a process or runs a stylesheet script (wmic)"),
    };

    private readonly IReadOnlySet<string> _suspiciousParents;
    private readonly (string Text, Regex? Parent, Regex? Host, Regex? CommandLine)[] _allowed;

    public LaunchClassifier(ScriptHostAuditOptions options)
    {
        _suspiciousParents = options.SuspiciousParentNames();
        _allowed = (options.AllowedLaunches ?? Array.Empty<string>())
            .Where(r => !string.IsNullOrWhiteSpace(r))
            .Select(ParseRule)
            .Where(r => r is not null)
            .Select(r => r!.Value)
            .ToArray();
    }

    /// <summary>AllowedLaunches lines that are not <c>parent|host|command line</c>.</summary>
    public static IEnumerable<string> InvalidRules(ScriptHostAuditOptions options) =>
        (options.AllowedLaunches ?? Array.Empty<string>()).Where(r => !string.IsNullOrWhiteSpace(r) && ParseRule(r) is null);

    public LaunchAssessment Assess(ProcessCreationEvent launch)
    {
        var host = launch.HostName;
        var commandLine = launch.CommandLine ?? "";
        var parentReasons = new List<string>();
        var otherReasons = new List<string>();

        if (launch.ParentName is { } parent && _suspiciousParents.Contains(parent))
        {
            parentReasons.Add($"started by {parent}, {ParentKind(parent)}");
        }

        if (PowerShellHosts.Contains(host))
        {
            otherReasons.AddRange(PowerShellFlags(commandLine));
        }
        foreach (var (indicatorHost, pattern, reason) in Indicators)
        {
            if ((indicatorHost == "*" || string.Equals(indicatorHost, host, StringComparison.OrdinalIgnoreCase))
                && IsMatch(pattern, commandLine) && !otherReasons.Contains(reason))
            {
                otherReasons.Add(reason);
            }
        }

        if (InBoxHosts.Contains(host) && !InWindowsFolder(launch.NewProcessName))
        {
            otherReasons.Add($"runs from {Folder(launch.NewProcessName)}, not the Windows folder where {host} ships");
        }

        var severity = parentReasons.Count > 0 && otherReasons.Count > 0 ? AlertSeverity.Critical
            : parentReasons.Count + otherReasons.Count > 0 ? AlertSeverity.Warning
            : AlertSeverity.Info;
        var allowedBy = _allowed.FirstOrDefault(r => Matches(r.Parent, launch.ParentProcessName) && Matches(r.Host, launch.NewProcessName)
            && (r.CommandLine is null || IsMatch(r.CommandLine, commandLine, onTimeout: false))).Text;
        return new LaunchAssessment(severity, parentReasons.Concat(otherReasons).ToList(), allowedBy);
    }

    /// <summary>
    /// PowerShell accepts any unambiguous prefix of a parameter name, so
    /// <c>-enc</c>, <c>-EncodedCommand</c> and <c>-e</c> are the same flag.
    /// </summary>
    private static IEnumerable<string> PowerShellFlags(string commandLine)
    {
        var tokens = commandLine.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)
            .Select(t => t.Trim('"', '\'')).ToArray();
        var encoded = false;
        var hidden = false;
        for (var i = 0; i < tokens.Length; i++)
        {
            var token = tokens[i];
            if (token.Length < 2 || token[0] is not ('-' or '/' or '\u2013' or '\u2014')) continue;
            var name = token[1..].ToLowerInvariant();
            if (name is "e" or "ec" || (name.Length >= 3 && "encodedcommand".StartsWith(name, StringComparison.Ordinal)))
            {
                encoded = true;
            }
            else if ((name is "w" || (name.Length >= 2 && "windowstyle".StartsWith(name, StringComparison.Ordinal)))
                && i + 1 < tokens.Length && tokens[i + 1].ToLowerInvariant() is "hidden" or "hid" or "hidd" or "hidde" or "1")
            {
                hidden = true;
            }
        }
        if (encoded) yield return "passes an encoded command (-EncodedCommand), which hides what it runs";
        if (hidden) yield return "hides its window (-WindowStyle Hidden)";
    }

    private static string ParentKind(string parent) => parent.ToLowerInvariant() switch
    {
        "winword.exe" or "excel.exe" or "powerpnt.exe" or "outlook.exe" or "onenote.exe" or "onenotem.exe"
            or "msaccess.exe" or "mspub.exe" or "visio.exe" or "eqnedt32.exe" => "an Office app; documents rarely need to start a script host",
        "msedge.exe" or "chrome.exe" or "firefox.exe" or "iexplore.exe" or "brave.exe" or "opera.exe" or "vivaldi.exe"
            => "a web browser; web pages rarely need to start a script host",
        "mshta.exe" or "wscript.exe" or "cscript.exe" => "another script host, a common chain in malicious scripts",
        "acrord32.exe" or "acrobat.exe" or "foxitpdfreader.exe" or "sumatrapdf.exe" => "a document reader",
        "thunderbird.exe" => "a mail app",
        _ => "listed in SuspiciousParents",
    };

    private static bool InWindowsFolder(string path)
    {
        var normalized = path.Replace('/', '\\');
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var roots = new[] { string.IsNullOrEmpty(windows) ? @"C:\Windows" : windows.TrimEnd('\\'), @"C:\Windows" }
            .Distinct(StringComparer.OrdinalIgnoreCase);
        return roots.Any(root => normalized.StartsWith(root + @"\System32\", StringComparison.OrdinalIgnoreCase)
            || normalized.StartsWith(root + @"\SysWOW64\", StringComparison.OrdinalIgnoreCase)
            || normalized.StartsWith(root + @"\WinSxS\", StringComparison.OrdinalIgnoreCase)
            || normalized.StartsWith(root + @"\Microsoft.NET\", StringComparison.OrdinalIgnoreCase)
            || string.Equals(normalized, root + @"\hh.exe", StringComparison.OrdinalIgnoreCase));
    }

    private static string Folder(string path)
    {
        var name = ProcessCreationEvent.FileName(path);
        return path.Length > name.Length ? path[..(path.Length - name.Length)].TrimEnd('\\', '/') : "an unknown folder";
    }

    private static bool Matches(Regex? pattern, string? path)
    {
        if (pattern is null) return true;
        if (path is null) return false;
        return IsMatch(pattern, path, onTimeout: false) || IsMatch(pattern, ProcessCreationEvent.FileName(path), onTimeout: false);
    }

    private static (string, Regex?, Regex?, Regex?)? ParseRule(string rule)
    {
        var parts = rule.Trim().Split('|');
        if (parts.Length != 3) return null;
        // Matches() tries each path part against the full path and the file
        // name, so "Code.exe" and "C:\Program Files\*\Code.exe" both work.
        return (rule.Trim(), Wildcard(parts[0]), Wildcard(parts[1]), Wildcard(parts[2]));
    }

    private static Regex? Wildcard(string part)
    {
        var trimmed = part.Trim();
        if (trimmed.Length == 0 || trimmed == "*") return null;
        return new Regex("^" + Regex.Escape(trimmed).Replace(@"\*", ".*").Replace(@"\?", ".") + "$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Singleline, RegexTimeout);
    }

    private static Regex Pattern(string pattern) =>
        new(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);

    // A command line that makes an indicator time out counts as a match,
    // since being unreadable is itself worth a look; for an allow rule it
    // counts as no match, so a timeout never hides a launch.
    private static bool IsMatch(Regex pattern, string text, bool onTimeout = true)
    {
        try { return pattern.IsMatch(text); }
        catch (RegexMatchTimeoutException) { return onTimeout; }
    }
}

using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WatchLattice.Common;
using WatchLattice.Common.Alerts;

namespace WatchLattice.ScriptHostAudit;

/// <summary>A standing finding or a one-off report from the auditor.</summary>
public sealed record ScriptHostAlert(string Code, AlertSeverity Severity, string Title, string Message, string? Resource = null)
{
    public override string ToString() => $"[{Severity}] {Code}: {Message.Replace('\n', ' ')}";
}

/// <summary>
/// Reads Security log event 4688 ("A new process has been created") and
/// reports launches of PowerShell, mshta, wscript, rundll32 and similar
/// programs that attackers use to run code without dropping an obvious
/// executable, graded by who started them and what their command line asks
/// for.
///
/// It is a passive reader. It never turns on auditing, never changes audit
/// policy or the log, and never blocks or stops a process; when Windows is
/// not recording process creation it says so once, as information.
/// </summary>
public sealed class ScriptHostAuditor : IDisposable
{
    public const string ModuleId = "ScriptHostAudit";

    public const string ProcessAuditingOff = "PROCESS_AUDITING_OFF";
    public const string CommandLineNotRecorded = "COMMAND_LINE_NOT_RECORDED";
    public const string AuditPolicyUnavailable = "AUDIT_POLICY_UNAVAILABLE";
    public const string SecurityLogUnavailable = "SECURITY_LOG_UNAVAILABLE";
    public const string ScriptHostLaunched = "SCRIPT_HOST_LAUNCHED";
    public const string ScriptHostLaunches = "SCRIPT_HOST_LAUNCHES";
    public const string EventsMissed = "EVENTS_MISSED";
    public const string StateSaveFailed = "STATE_SAVE_FAILED";
    public const string StateUnreadable = "STATE_UNREADABLE";

    private const int MessageLimit = 2048;
    private const int CommandLineExcerpt = 1000;

    private readonly IProcessCreationSource _source;
    private readonly ScriptHostAuditOptions _options;
    private readonly ILogger<ScriptHostAuditor> _logger;
    private readonly IAlertPublisher? _alerts;
    private readonly TimeProvider _time;
    private readonly LaunchClassifier _classifier;
    private readonly IReadOnlySet<string> _hosts;
    private readonly IReadOnlyList<ApprovedEntry> _approved;
    private Dictionary<string, ScriptHostAlert> _active = new();
    private ScriptHostAuditState? _state;
    private string? _saveError;
    private ScanLogWriter? _alertLog;
    private bool _alertLogOpened;
    private bool _summaryLogged;

    public ScriptHostAuditor(
        IProcessCreationSource source,
        IOptions<ScriptHostAuditOptions> options,
        ILogger<ScriptHostAuditor> logger,
        IAlertPublisher? alerts = null,
        TimeProvider? time = null)
    {
        _source = source;
        _options = options.Value;
        _logger = logger;
        _alerts = alerts;
        _time = time ?? TimeProvider.System;
        _classifier = new LaunchClassifier(_options);
        _hosts = _options.WatchedHosts();
        _approved = ParseApprovals();
        foreach (var rule in LaunchClassifier.InvalidRules(_options))
        {
            _logger.LogWarning("ScriptHostAudit:AllowedLaunches has a line that is not \"<parent>|<script host>|<command line>\"; it is ignored: {Line}", rule);
        }
    }

    /// <summary>Raised for every alert this auditor publishes, standing or one-off, including recoveries.</summary>
    public event Action<ScriptHostAlert>? Published;

    /// <summary>Raised after every check, with the standing findings.</summary>
    public event Action<IReadOnlyList<ScriptHostAlert>>? CheckCompleted;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        var interval = TimeSpan.FromSeconds(Math.Max(10, _options.CheckIntervalSeconds));
        _logger.LogInformation("Script host audit starting: reading process creation events (4688) from the Security log every {Interval} for {Count} programs; reporting {Severity} and above.",
            interval, _hosts.Count, _options.MinimumSeverity);
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                CheckOnce(cancellationToken);
                await Task.Delay(interval, _time, cancellationToken);
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown.
        }
    }

    /// <summary>Reads new events once, reports launches and changed standing findings, and returns the standing findings.</summary>
    public IReadOnlyList<ScriptHostAlert> CheckOnce(CancellationToken cancellationToken)
    {
        var state = LoadState();
        var current = new Dictionary<string, ScriptHostAlert>();

        var status = SafeAuditStatus();
        if (status.ProcessCreationAudited == false)
        {
            current[ProcessAuditingOff] = new ScriptHostAlert(ProcessAuditingOff, AlertSeverity.Info, "Process creation auditing is off",
                "Windows is not recording process creation (Security event 4688), so script host launches can't be reported. "
                + "WatchLattice does not change audit policy. To turn it on, see the Script Host Audit README "
                + "(auditpol /set /subcategory:\"Process Creation\" /success:enable, or the Group Policy setting).");
        }
        else if (status.ProcessCreationAudited is null)
        {
            current[AuditPolicyUnavailable] = new ScriptHostAlert(AuditPolicyUnavailable, AlertSeverity.Info, "Audit policy could not be read",
                $"Could not confirm that Windows records process creation: {status.Error ?? "unknown error"}. "
                + "Launches are still reported whenever the Security log has them.");
        }

        var missingCommandLines = 0;
        try
        {
            missingCommandLines = ReadNewLaunches(state, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            current[SecurityLogUnavailable] = new ScriptHostAlert(SecurityLogUnavailable, AlertSeverity.Warning, "Security log unavailable",
                $"The Security event log could not be read, so script host launches are not reported until it can: {ex.Message}");
        }

        if (status.ProcessCreationAudited != false
            && (status.CommandLineIncluded == false || (status.CommandLineIncluded is null && missingCommandLines > 0)))
        {
            current[CommandLineNotRecorded] = new ScriptHostAlert(CommandLineNotRecorded, AlertSeverity.Info, "Command lines are not recorded",
                "Process creation events don't include command lines, so launches are graded by their parent and folder only, "
                + "and can't be approved from the dashboard. Turn on \"Include command line in process creation events\" "
                + "(see the Script Host Audit README).");
        }
        if (_saveError is not null)
        {
            current[StateSaveFailed] = new ScriptHostAlert(StateSaveFailed, AlertSeverity.Warning, "Script host audit bookmark not saved",
                $"The auditor could not save how far it has read, so after a restart it starts again from the newest event: {_saveError}");
        }

        foreach (var finding in current.Values.Where(f => !_active.ContainsKey(f.Code)))
        {
            Report(finding, "SCRIPT HOST AUDIT ALERT");
        }
        foreach (var finding in _active.Values.Where(f => !current.ContainsKey(f.Code)))
        {
            Report(finding with
            {
                Code = finding.Code + AlertEventIds.ClearedSuffix,
                Severity = AlertSeverity.Info,
                Title = finding.Title + ": resolved",
                Message = finding.Message + " This is no longer reported.",
            }, "Script host audit recovered:");
        }
        _active = current;

        if (!_summaryLogged)
        {
            _summaryLogged = true;
            _logger.LogInformation("{ScriptHostAuditSummary}", current.Count == 0
                ? "Script host audit: process creation auditing is on and the Security log is readable."
                : "Script host audit: " + string.Join(" ", current.Values.Select(f => f.Message)));
        }
        var findings = current.Values.ToList();
        CheckCompleted?.Invoke(findings);
        return findings;
    }

    /// <summary>Reads past the bookmark and reports launches. Returns how many watched launches had no command line.</summary>
    private int ReadNewLaunches(ScriptHostAuditState state, CancellationToken cancellationToken)
    {
        var range = _source.ReadRange();
        if (state.LastRecordId is not { } last)
        {
            // First run: start from now rather than reporting the log's history.
            state.LastRecordId = range.Newest ?? 0;
            SaveState(state);
            _logger.LogInformation("Script host audit: starting after Security log record {Record}; earlier launches are not reported.", state.LastRecordId);
            return 0;
        }

        if ((range.Newest ?? 0) < last)
        {
            Report(new ScriptHostAlert(EventsMissed, AlertSeverity.Warning, "Security log cleared",
                $"The Security log now ends {(range.Newest is { } n ? $"at record {n}" : "empty")}, before record {last} that the auditor last read, so it was cleared or replaced. "
                + "Launches recorded before that can't be reported. Clearing the Security log is something attackers do to hide their tracks; "
                + "if you didn't, look for event 1102 (\"The audit log was cleared\") to see which account did."), "SCRIPT HOST AUDIT CHANGE");
            last = 0;
        }
        else if (range.Oldest is { } oldest && oldest > last + 1)
        {
            Report(new ScriptHostAlert(EventsMissed, AlertSeverity.Warning, "Security log events missed",
                $"{Count(oldest - last - 1, "Security log record")} after record {last} were overwritten before the auditor read them, "
                + "so launches among them can't be reported. This happens when the hub was stopped for a while or the Security log is small; "
                + "a larger maximum log size (Event Viewer > Security > Properties) helps."), "SCRIPT HOST AUDIT CHANGE");
        }

        var max = Math.Max(100, _options.MaxEventsPerCheck);
        var batch = _source.ReadAfter(last, _hosts.Contains, max, cancellationToken);
        if (batch.Truncated)
        {
            Report(new ScriptHostAlert(EventsMissed, AlertSeverity.Warning, "Script host audit fell behind",
                $"More than {max} processes started since the last check, so only the newest {max} were checked and launches among the older ones may be missed. "
                + "Raise MaxEventsPerCheck or lower CheckIntervalSeconds if this repeats."), "SCRIPT HOST AUDIT CHANGE");
        }

        var report = new List<(ProcessCreationEvent Launch, LaunchAssessment Assessment)>();
        var missing = 0;
        foreach (var launch in batch.Events)
        {
            if (launch.CommandLine is null) missing++;
            var assessment = _classifier.Assess(launch);
            if (assessment.Severity < _options.MinimumSeverity)
            {
                _logger.LogDebug("Script host audit: {Host} started by {Parent} ({Severity}), below MinimumSeverity.",
                    launch.HostName, launch.ParentName ?? "an unknown parent", assessment.Severity);
            }
            else if (assessment.AllowedBy is { } rule)
            {
                _logger.LogInformation("Script host audit: {Host} started by {Parent} matches allowed launch rule \"{Rule}\", so it raised no alert.",
                    launch.HostName, launch.ParentName ?? "an unknown parent", rule);
            }
            else if (launch.CommandLine is { } commandLine && _approved.Any(a => a.Matches(Resource(launch), commandLine)))
            {
                _logger.LogInformation("Script host audit: {Host} started by {Parent} matches an approved launch, so it raised no alert.",
                    launch.HostName, launch.ParentName ?? "an unknown parent");
            }
            else
            {
                report.Add((launch, assessment));
            }
        }

        if (report.Count <= Math.Max(1, _options.MaxIndividualAlerts))
        {
            foreach (var (launch, assessment) in report)
            {
                Report(LaunchAlert(launch, assessment), "SCRIPT HOST AUDIT CHANGE");
            }
        }
        else
        {
            var limit = Math.Max(1, _options.MaxChangesPerAlert);
            var lines = report.Take(limit).Select(r => $"{Describe(r.Launch)} [{r.Assessment.Severity}]: {string.Join("; ", r.Assessment.Reasons.DefaultIfEmpty("no specific reason"))}");
            var text = $"{report.Count} script host launches since the last check: " + string.Join(" | ", lines)
                + (report.Count > limit ? $" | and {report.Count - limit} more" : "")
                + ". See the module's log for each one. WatchLattice only reports these; it did not stop them.";
            Report(new ScriptHostAlert(ScriptHostLaunches, report.Max(r => r.Assessment.Severity), $"{report.Count} script host launches", Fit(text, "")),
                "SCRIPT HOST AUDIT CHANGE");
            foreach (var (launch, assessment) in report)
            {
                AlertLog()?.WriteLine("SCRIPT HOST AUDIT CHANGE " + LaunchAlert(launch, assessment));
            }
        }

        var newest = Math.Max(batch.NewestRecordId ?? 0, range.Newest ?? 0);
        if (newest != state.LastRecordId)
        {
            state.LastRecordId = newest;
            SaveState(state);
        }
        return missing;
    }

    private ScriptHostAlert LaunchAlert(ProcessCreationEvent launch, LaunchAssessment assessment)
    {
        var details = new List<string>
        {
            $"{launch.HostName} started by {(launch.ParentProcessName is { } parent ? $"{ProcessCreationEvent.FileName(parent)} ({parent})" : "an unknown parent (this Windows version doesn't record it)")}"
            + $" for {launch.User}"
            + (launch.Elevation is { } elevation ? $", {elevation}" : "")
            + (launch.Integrity is { } integrity ? $", {integrity} integrity" : "")
            + (launch.TimeCreated is { } at ? $", at {at.ToUniversalTime():yyyy-MM-dd HH:mm:ss} UTC" : "") + ".",
            $"Program: {launch.NewProcessName}",
            launch.CommandLine is not { } commandLine
                ? "Command line: not recorded (turn on \"Include command line in process creation events\")."
                : _options.CommandLineInAlerts
                    ? $"Command line: {Excerpt(Clean(commandLine), CommandLineExcerpt)}"
                    : $"Command line: {commandLine.Length} characters, left out because CommandLineInAlerts is off (see Security log record {launch.RecordId}).",
        };
        if (assessment.Reasons.Count > 0)
        {
            details.Add("Why this is reported: " + string.Join("; ", assessment.Reasons) + ".");
        }
        details.Add($"Security log record {launch.RecordId}"
            + (launch.NewProcessId is { } pid ? $", process ID {pid}" : "")
            + (launch.ParentProcessId is { } ppid ? $", parent process ID {ppid}" : "") + ".");
        details.Add(assessment.Severity == AlertSeverity.Info
            ? "WatchLattice only reports this; it did not stop the process."
            : "WatchLattice only reports this; it did not stop the process. If you didn't expect it, find what started the parent program, "
              + "and run a Microsoft Defender full scan.");

        var message = Fit(string.Join("\n", details),
            launch.CommandLine is { } exact ? "\n" + BaselineApprovals.FingerprintLine(exact) : "");
        var title = assessment.Severity switch
        {
            AlertSeverity.Critical => "Highly suspicious script host launch",
            AlertSeverity.Warning => "Suspicious script host launch",
            _ => "Script host launch",
        };
        return new ScriptHostAlert(ScriptHostLaunched, assessment.Severity, title, message, Resource(launch));
    }

    /// <summary>The alert resource, and what an approval names: the parent's and the host's full paths.</summary>
    public static string Resource(ProcessCreationEvent launch) =>
        $"{launch.ParentProcessName ?? "(unknown parent)"}|{launch.NewProcessName}";

    private static string Describe(ProcessCreationEvent launch) =>
        $"{launch.HostName} by {launch.ParentName ?? "an unknown parent"} for {launch.User}";

    private AuditStatus SafeAuditStatus()
    {
        try
        {
            return _source.ReadAuditStatus();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new AuditStatus(null, null, ex.Message);
        }
    }

    private IReadOnlyList<ApprovedEntry> ParseApprovals()
    {
        var approved = new List<ApprovedEntry>();
        foreach (var line in _options.ApprovedLaunches ?? Array.Empty<string>())
        {
            if (ApprovedEntry.TryParse(line?.Trim(), out var entry)) approved.Add(entry);
            else _logger.LogWarning("ScriptHostAudit:ApprovedLaunches has a line that is not \"sha256:<64 hex digits> <parent>|<script host>\"; it is ignored: {Line}", line);
        }
        return approved;
    }

    private static string Clean(string text)
    {
        var builder = new StringBuilder(text.Length);
        foreach (var c in text) builder.Append(char.IsControl(c) ? ' ' : c);
        return builder.ToString();
    }

    private static string Excerpt(string value, int limit) => value.Length <= limit ? value : value[..limit] + "… (truncated)";

    private static string Fit(string message, string tail) =>
        message.Length + tail.Length <= MessageLimit ? message + tail : message[..(MessageLimit - tail.Length - 1)] + "…" + tail;

    private static string Count(long count, string singular) => $"{count} {(count == 1 ? singular : singular + "s")}";

    private ScriptHostAuditState LoadState()
    {
        if (_state is not null)
        {
            return _state;
        }

        try
        {
            var loaded = AtomicJsonFile.Read<ScriptHostAuditState>(_options.ResolveStatePath());
            if (!loaded.IsValid())
            {
                throw new InvalidDataException("Invalid or unsupported script host audit state file.");
            }
            _state = loaded;
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            _state = new ScriptHostAuditState();
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or JsonException)
        {
            // The bookmark only avoids repeats and gaps, so start again from the newest event rather than stop.
            _state = new ScriptHostAuditState();
            Report(new ScriptHostAlert(StateUnreadable, AlertSeverity.Warning, "Script host audit bookmark reset",
                $"The saved position in the Security log could not be read, so launches while the hub was stopped can't be reported: {ex.Message}"),
                "SCRIPT HOST AUDIT CHANGE");
        }
        return _state;
    }

    private void SaveState(ScriptHostAuditState state)
    {
        try
        {
            AtomicJsonFile.Write(_options.ResolveStatePath(), state);
            _saveError = null;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
        {
            _saveError = ex.Message;
        }
    }

    private void Report(ScriptHostAlert alert, string prefix)
    {
        _alerts?.Publish(ModuleId, alert.Code, alert.Severity, alert.Title, alert.Message, alert.Resource);
        var line = $"{prefix} {alert}";
        _logger.Log(alert.Severity switch
        {
            AlertSeverity.Critical => LogLevel.Critical,
            AlertSeverity.Warning => LogLevel.Warning,
            _ => LogLevel.Information,
        }, "{ScriptHostAudit}", line);
        AlertLog()?.WriteLine(line);
        Published?.Invoke(alert);
    }

    private ScanLogWriter? AlertLog()
    {
        if (!_alertLogOpened)
        {
            _alertLogOpened = true;
            try
            {
                _alertLog = new ScanLogWriter(_options.ResolveAlertLogPath());
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _logger.LogWarning("Could not open script host audit log: {Error}", ex.Message);
            }
        }
        return _alertLog;
    }

    public void Dispose()
    {
        _alertLog?.Dispose();
        _alertLog = null;
    }
}

using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WatchLattice.Common;
using WatchLattice.Common.Alerts;

namespace WatchLattice.HostsProxyWatchdog;

/// <summary>
/// Periodically reads the hosts file and the system's proxy settings, which
/// malware changes to block security updates, send lookups for real sites to
/// its own servers, or route web traffic through a proxy it controls. It
/// records a baseline on the first check and reports every later change with
/// what it was before and after; hosts entries for Windows Update, Defender
/// and WatchLattice's own update hosts are a standing critical finding.
///
/// It is read-only by design. It never edits the hosts file, never resets a
/// proxy, and never deletes anything; it observes and reports.
/// </summary>
public sealed class HostsProxyWatchdog : IDisposable
{
    public const string ModuleId = "HostsProxyWatchdog";
    public const string StateSaveFailed = "STATE_SAVE_FAILED";
    public const string StateUnreadable = "STATE_UNREADABLE";

    private readonly IHostsProxyProvider _provider;
    private readonly HostsProxyWatchdogOptions _options;
    private readonly ILogger<HostsProxyWatchdog> _logger;
    private readonly IAlertPublisher? _alerts;
    private Dictionary<string, HostsProxyFinding> _active = new();
    private HostsProxyState? _state;
    private string? _saveError;
    private ScanLogWriter? _alertLog;
    private bool _alertLogOpened;
    private bool _summaryLogged;

    public HostsProxyWatchdog(
        IHostsProxyProvider provider,
        IOptions<HostsProxyWatchdogOptions> options,
        ILogger<HostsProxyWatchdog> logger,
        IAlertPublisher? alerts = null)
    {
        _provider = provider;
        _options = options.Value;
        _logger = logger;
        _alerts = alerts;
    }

    /// <summary>Raised when a new standing problem appears (not on every check while it persists).</summary>
    public event Action<HostsProxyFinding>? AlertRaised;

    /// <summary>Raised when a previously reported standing problem clears.</summary>
    public event Action<HostsProxyFinding>? AlertCleared;

    /// <summary>Raised for each one-off change: the baseline, a hosts file change, or a proxy change.</summary>
    public event Action<HostsProxyChange>? ChangeDetected;

    public HostsProxySnapshot? LastSnapshot { get; private set; }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        var interval = TimeSpan.FromSeconds(Math.Max(15, _options.CheckIntervalSeconds));
        _logger.LogInformation("Hosts file and proxy watchdog starting: checking {What} every {Interval}.",
            (_options.WatchHostsFile, _options.WatchProxySettings) switch
            {
                (true, true) => "the hosts file and proxy settings",
                (true, false) => "the hosts file",
                (false, true) => "proxy settings",
                _ => "nothing (both checks are off)",
            },
            interval);

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                await CheckOnceAsync(cancellationToken);
                await Task.Delay(interval, cancellationToken);
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown.
        }
    }

    /// <summary>Runs one check, raises alerts for new, cleared and changed state, and returns the standing findings.</summary>
    public async Task<IReadOnlyList<HostsProxyFinding>> CheckOnceAsync(CancellationToken cancellationToken)
    {
        var state = LoadState();

        HostsProxySnapshot snapshot;
        try
        {
            snapshot = await _provider.ReadAsync(_options.WatchHostsFile, _options.WatchProxySettings, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            snapshot = new HostsProxySnapshot
            {
                Hosts = _options.WatchHostsFile ? HostsFileSnapshot.Unavailable("hosts", ex.Message) : null,
                ProxyError = _options.WatchProxySettings ? ex.Message : null,
            };
        }
        LastSnapshot = snapshot;

        TrackChanges(state, snapshot);

        var findings = HostsProxyEvaluator.Evaluate(snapshot, _options);
        var current = findings.ToDictionary(f => f.Code);
        if (snapshot.Hosts is { Error: not null } unreadable)
        {
            // Not being able to read the file is not evidence that an entry went
            // away, so keep that finding open instead of reporting a recovery.
            KeepActive(current, HostsProxyEvaluator.ProtectedHostOverridden);
            if (unreadable.DatabasePath is null)
            {
                KeepActive(current, HostsProxyEvaluator.HostsPathMoved);
            }
        }
        if (_saveError is not null)
        {
            current[StateSaveFailed] = new HostsProxyFinding(StateSaveFailed, AlertSeverity.Warning,
                $"Hosts file and proxy changes are tracked in memory but will not survive a restart: {_saveError}");
        }

        foreach (var finding in current.Values.Where(f => !_active.ContainsKey(f.Code)))
        {
            RaiseAlert(finding);
        }
        foreach (var finding in _active.Values.Where(f => !current.ContainsKey(f.Code)))
        {
            ClearAlert(finding);
        }
        _active = current;

        if (!_summaryLogged)
        {
            _summaryLogged = true;
            _logger.LogInformation("{HostsProxySummary}", current.Count == 0
                ? "Hosts file and proxy settings: nothing needs attention."
                : "Hosts file and proxy settings: " + string.Join("; ", current.Values.Select(f => f.Message)));
        }
        return current.Values.ToList();
    }

    private void KeepActive(Dictionary<string, HostsProxyFinding> current, string code)
    {
        if (_active.TryGetValue(code, out var finding))
        {
            current.TryAdd(code, finding);
        }
    }

    private void TrackChanges(HostsProxyState state, HostsProxySnapshot snapshot)
    {
        var dirty = false;
        var baseline = new List<string>();

        if (!_options.WatchHostsFile)
        {
            // Forget the baseline, so turning the check back on starts fresh
            // instead of reporting everything changed in between.
            dirty |= state.Hosts is not null;
            state.Hosts = null;
        }
        else if (snapshot.Hosts is { Entries: { } entries } hosts)
        {
            var record = true;
            if (state.Hosts is null)
            {
                baseline.Add($"{entries.Count} host name{(entries.Count == 1 ? "" : "s")} in {hosts.Path}");
            }
            else if (HostsProxyEvaluator.CompareHosts(state.Hosts, entries, hosts.Path, _options) is { } change)
            {
                ReportChange(change);
            }
            else
            {
                record = false;
            }

            if (record)
            {
                state.Hosts = entries.ToDictionary(e => e.Key, e => e.Value.ToArray(), StringComparer.Ordinal);
                dirty = true;
            }
        }

        if (!_options.WatchProxySettings)
        {
            dirty |= state.Proxy is not null;
            state.Proxy = null;
        }
        else if (snapshot.Proxy is { } scopes)
        {
            var readable = scopes.Where(s => s.Error is null).ToList();
            if (state.Proxy is null && readable.Count > 0)
            {
                state.Proxy = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
                baseline.Add($"proxy settings ({HostsProxyEvaluator.DescribeProxyScopes(readable, _options)})");
                dirty = true;
            }
            else if (state.Proxy is not null)
            {
                foreach (var scope in readable)
                {
                    if (!state.Proxy.TryGetValue(scope.Id, out var before))
                    {
                        _logger.LogInformation("Recorded proxy settings for {Scope} for the first time: {Settings}.",
                            scope.DisplayName, HostsProxyEvaluator.DescribeProxyScopes(new[] { scope }, _options));
                        AlertLog()?.WriteLine($"Recorded proxy settings for {scope.DisplayName} for the first time.");
                    }
                    else if (HostsProxyEvaluator.CompareProxy(before, scope, _options) is { } change)
                    {
                        ReportChange(change);
                    }
                    else
                    {
                        continue;
                    }
                    dirty = true;
                }
            }

            if (state.Proxy is not null)
            {
                foreach (var scope in readable)
                {
                    state.Proxy[scope.Id] = new Dictionary<string, string>(scope.Values, StringComparer.Ordinal);
                }
            }
        }

        if (baseline.Count > 0)
        {
            ReportChange(new HostsProxyChange(HostsProxyEvaluator.BaselineCreated, AlertSeverity.Info,
                "Hosts file and proxy baseline recorded",
                $"Recorded {string.Join(" and ", baseline)}. This is an inventory, not a safety verdict; only changes from now on are reported."));
        }

        if (dirty || _saveError is not null)
        {
            SaveState(state);
        }
    }

    private HostsProxyState LoadState()
    {
        if (_state is not null)
        {
            return _state;
        }

        try
        {
            var loaded = AtomicJsonFile.Read<HostsProxyState>(_options.ResolveStatePath());
            if (!loaded.IsValid())
            {
                throw new InvalidDataException("Invalid or unsupported hosts and proxy state file.");
            }
            if (loaded.Hosts is not null)
            {
                loaded.Hosts = new(loaded.Hosts, StringComparer.Ordinal);
            }
            if (loaded.Proxy is not null)
            {
                loaded.Proxy = loaded.Proxy.ToDictionary(
                    s => s.Key, s => new Dictionary<string, string>(s.Value, StringComparer.Ordinal), StringComparer.OrdinalIgnoreCase);
            }
            _state = loaded;
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            _state = new HostsProxyState();
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or JsonException)
        {
            // The state only enables change reports, so start over rather than
            // stop watching; say so once, because changes made while the hub
            // was stopped can't be reported this time.
            _state = new HostsProxyState();
            ReportChange(new HostsProxyChange(StateUnreadable, AlertSeverity.Warning, "Hosts file and proxy watchdog state reset",
                $"The saved hosts file and proxy state could not be read, so changes made while the hub was stopped can't be reported: {ex.Message}"));
        }
        return _state;
    }

    private void SaveState(HostsProxyState state)
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

    private void RaiseAlert(HostsProxyFinding finding)
    {
        _alerts?.Publish(ModuleId, finding.Code, finding.Severity, "Hosts file or proxy needs attention", finding.Message, finding.Resource);
        var line = $"HOSTS/PROXY ALERT {finding}";
        if (finding.Severity == AlertSeverity.Critical)
        {
            _logger.LogCritical("{HostsProxyAlert}", line);
        }
        else
        {
            _logger.LogWarning("{HostsProxyAlert}", line);
        }
        AlertLog()?.WriteLine(line);
        AlertRaised?.Invoke(finding);
    }

    private void ClearAlert(HostsProxyFinding finding)
    {
        _alerts?.Publish(ModuleId, finding.Code + "_CLEARED", AlertSeverity.Info,
            "Hosts file or proxy recovered", finding.Message + " This is no longer reported.", finding.Resource);
        var line = $"Hosts/proxy recovered: {finding.Message} This is no longer reported.";
        _logger.LogInformation("{HostsProxyRecovered}", line);
        AlertLog()?.WriteLine(line);
        AlertCleared?.Invoke(finding);
    }

    private void ReportChange(HostsProxyChange change)
    {
        _alerts?.Publish(ModuleId, change.Code, change.Severity, change.Title, change.Message, change.Resource);
        var line = $"HOSTS/PROXY CHANGE {change}";
        _logger.Log(change.Severity switch
        {
            AlertSeverity.Critical => LogLevel.Critical,
            AlertSeverity.Warning => LogLevel.Warning,
            _ => LogLevel.Information,
        }, "{HostsProxyChange}", line);
        AlertLog()?.WriteLine(line);
        ChangeDetected?.Invoke(change);
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
                _logger.LogWarning("Could not open hosts file and proxy watchdog log: {Error}", ex.Message);
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

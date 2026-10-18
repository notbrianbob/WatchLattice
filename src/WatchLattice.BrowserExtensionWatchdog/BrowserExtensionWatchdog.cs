using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WatchLattice.Common;
using WatchLattice.Common.Alerts;

namespace WatchLattice.BrowserExtensionWatchdog;

/// <summary>
/// Periodically inventories the extensions installed in every Edge, Chrome
/// and Firefox profile on the machine, and the policies and registrations
/// that install extensions from outside the browser. Malicious extensions are
/// a common way to steal sessions and passwords, inject ads, or redirect
/// searches, and they are often installed by another program rather than by
/// the user. It records a baseline on the first check and then reports each
/// extension added or removed, with its ID, name, browser, profile and how it
/// was installed (including whether by policy).
///
/// It is read-only by design. It never disables, removes or changes an
/// extension, a profile or a policy; it observes and reports.
/// </summary>
public sealed class BrowserExtensionWatchdog : IDisposable
{
    public const string ModuleId = "BrowserExtensionWatchdog";

    public const string BaselineCreated = "BASELINE_CREATED";
    public const string ExtensionAdded = "EXTENSION_ADDED";
    public const string ExtensionsAdded = "EXTENSIONS_ADDED";
    public const string ExtensionRemoved = "EXTENSION_REMOVED";
    public const string ExtensionsRemoved = "EXTENSIONS_REMOVED";
    public const string PolicyAdded = "POLICY_EXTENSION_ADDED";
    public const string PoliciesAdded = "POLICY_EXTENSIONS_ADDED";
    public const string PolicyRemoved = "POLICY_EXTENSION_REMOVED";
    public const string PoliciesRemoved = "POLICY_EXTENSIONS_REMOVED";
    public const string ProfileAdded = "PROFILE_ADDED";
    public const string ProfileRemoved = "PROFILE_REMOVED";
    public const string ProfileUnreadable = "PROFILE_UNREADABLE";
    public const string PolicyUnavailable = "POLICY_UNAVAILABLE";
    public const string StateSaveFailed = "STATE_SAVE_FAILED";
    public const string StateUnreadable = "STATE_UNREADABLE";

    private readonly IBrowserExtensionProvider _provider;
    private readonly BrowserExtensionWatchdogOptions _options;
    private readonly ILogger<BrowserExtensionWatchdog> _logger;
    private readonly IAlertPublisher? _alerts;
    private readonly TimeProvider _time;
    private readonly Regex[] _ignored;
    private Dictionary<string, BrowserExtensionFinding> _active = new();
    private BrowserExtensionState? _state;
    private string? _saveError;
    private ScanLogWriter? _alertLog;
    private bool _alertLogOpened;
    private bool _summaryLogged;

    public BrowserExtensionWatchdog(
        IBrowserExtensionProvider provider,
        IOptions<BrowserExtensionWatchdogOptions> options,
        ILogger<BrowserExtensionWatchdog> logger,
        IAlertPublisher? alerts = null,
        TimeProvider? time = null)
    {
        _provider = provider;
        _options = options.Value;
        _logger = logger;
        _alerts = alerts;
        _time = time ?? TimeProvider.System;
        _ignored = (_options.IgnoredExtensionIds ?? Array.Empty<string>())
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Select(p => new Regex("^" + Regex.Escape(p.Trim()).Replace(@"\*", ".*").Replace(@"\?", ".") + "$",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100)))
            .ToArray();
    }

    /// <summary>Raised when a new standing problem appears (not on every check while it persists).</summary>
    public event Action<BrowserExtensionFinding>? AlertRaised;

    /// <summary>Raised when a previously reported standing problem clears.</summary>
    public event Action<BrowserExtensionFinding>? AlertCleared;

    /// <summary>Raised for each one-off change: the baseline, an extension or policy added or removed, a profile added or removed.</summary>
    public event Action<BrowserExtensionChange>? ChangeDetected;

    /// <summary>Raised after every check, with the standing findings.</summary>
    public event Action<IReadOnlyList<BrowserExtensionFinding>>? CheckCompleted;

    public BrowserExtensionSnapshot? LastSnapshot { get; private set; }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        var interval = TimeSpan.FromSeconds(Math.Max(60, _options.CheckIntervalSeconds));
        var browsers = _options.EnabledBrowsers();
        _logger.LogInformation("Browser extension watchdog starting: checking {Browsers}{Policies} every {Interval}.",
            browsers.Count == 0 ? "no browsers" : string.Join(", ", browsers.Select(Browsers.DisplayName)),
            _options.WatchPolicies ? " and extension policies" : "",
            interval);

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                await CheckOnceAsync(cancellationToken);
                await Task.Delay(interval, _time, cancellationToken);
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown.
        }
    }

    /// <summary>Runs one check, raises alerts for new, cleared and changed state, and returns the standing findings.</summary>
    public async Task<IReadOnlyList<BrowserExtensionFinding>> CheckOnceAsync(CancellationToken cancellationToken)
    {
        var state = LoadState();

        BrowserExtensionSnapshot snapshot;
        string? readError = null;
        try
        {
            snapshot = await _provider.ReadAsync(cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Nothing could be read, so nothing is compared; say why.
            readError = ex.Message;
            snapshot = new BrowserExtensionSnapshot { PolicyError = _options.WatchPolicies ? ex.Message : null };
        }
        LastSnapshot = snapshot;

        TrackChanges(state, snapshot);

        var current = new Dictionary<string, BrowserExtensionFinding>();
        var unreadable = snapshot.Users
            .SelectMany(u => u.BrowserErrors.Select(e => $"{Browsers.DisplayName(e.Key)} for {u.UserName}: {e.Value}")
                .Concat(u.Profiles.Where(p => p.Error is not null).Select(p => $"{p.Describe()}: {p.Error}")))
            .ToList();
        if (readError is not null)
        {
            unreadable.Insert(0, $"browser profiles could not be listed: {readError}");
        }
        if (unreadable.Count > 0)
        {
            current[ProfileUnreadable] = new BrowserExtensionFinding(ProfileUnreadable, AlertSeverity.Warning,
                $"{Count(unreadable.Count, "browser profile")} could not be read, so extension changes there are not reported until it can: "
                + Limit(unreadable));
        }
        if (snapshot.PolicyError is not null)
        {
            current[PolicyUnavailable] = new BrowserExtensionFinding(PolicyUnavailable, AlertSeverity.Warning,
                $"Browser extension policies could not be read: {snapshot.PolicyError}");
        }
        if (_saveError is not null)
        {
            current[StateSaveFailed] = new BrowserExtensionFinding(StateSaveFailed, AlertSeverity.Warning,
                $"Browser extension changes are tracked in memory but will not survive a restart: {_saveError}");
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
            _logger.LogInformation("{BrowserExtensionSummary}", current.Count == 0
                ? "Browser extensions: nothing needs attention."
                : "Browser extensions: " + string.Join("; ", current.Values.Select(f => f.Message)));
        }
        var findings = current.Values.ToList();
        CheckCompleted?.Invoke(findings);
        return findings;
    }

    private void TrackChanges(BrowserExtensionState state, BrowserExtensionSnapshot snapshot)
    {
        var dirty = false;
        var baseline = new List<string>();
        var browsers = new HashSet<string>(_options.EnabledBrowsers(), StringComparer.Ordinal);

        // Forget browsers that are no longer watched, so turning one back on
        // starts fresh instead of reporting everything changed in between.
        if (state.Profiles is not null)
        {
            foreach (var key in state.Profiles.Where(p => !browsers.Contains(p.Value.Browser)).Select(p => p.Key).ToList())
            {
                state.Profiles.Remove(key);
                dirty = true;
            }
        }

        var readable = snapshot.Users.SelectMany(u => u.Profiles).Where(p => p.Extensions is not null).ToList();
        if (state.Profiles is null)
        {
            if (snapshot.Users.Count > 0)
            {
                state.Profiles = readable.ToDictionary(p => p.Key, ProfileRecord.From, StringComparer.OrdinalIgnoreCase);
                baseline.Add(DescribeInventory(readable));
                dirty = true;
            }
        }
        else
        {
            dirty |= CompareProfiles(state.Profiles, snapshot, readable);
        }

        if (!_options.WatchPolicies)
        {
            dirty |= state.Policies is not null;
            state.Policies = null;
        }
        else if (snapshot.Policies is { } entries)
        {
            var now = entries.Where(e => browsers.Contains(e.Browser)).DistinctBy(e => e.Key).ToDictionary(e => e.Key, StringComparer.OrdinalIgnoreCase);
            if (state.Policies is null)
            {
                state.Policies = now;
                baseline.Add(now.Count == 0
                    ? "no extension install policies or registrations"
                    : $"{Count(now.Count, "extension install policy or registration", "extension install policies or registrations")} ({Limit(now.Values.Select(e => e.Describe()).ToList())})");
                dirty = true;
            }
            else
            {
                dirty |= ComparePolicies(state.Policies, now, snapshot.PolicyScopes, browsers);
            }
        }

        if (baseline.Count > 0)
        {
            ReportChange(new BrowserExtensionChange(BaselineCreated, AlertSeverity.Info, "Browser extension baseline recorded",
                $"Recorded {string.Join(" and ", baseline)}. This is an inventory, not a safety verdict; only changes from now on are reported."));
        }

        if (dirty || _saveError is not null)
        {
            SaveState(state);
        }
    }

    private bool CompareProfiles(Dictionary<string, ProfileRecord> known, BrowserExtensionSnapshot snapshot, List<BrowserProfile> readable)
    {
        var dirty = false;
        var added = new List<(BrowserProfile Profile, InstalledExtension Extension)>();
        var removed = new List<(BrowserProfile Profile, InstalledExtension Extension)>();

        foreach (var profile in readable)
        {
            if (!known.TryGetValue(profile.Key, out var before))
            {
                var extensions = profile.Extensions!;
                ReportChange(new BrowserExtensionChange(ProfileAdded, AlertSeverity.Info, "New browser profile",
                    $"New {profile.Describe()}, with {Count(extensions.Count, "extension")}"
                    + (extensions.Count == 0 ? "." : ": " + Limit(extensions.Select(DescribeShort).ToList()) + ".")
                    + " Its extensions are recorded; only changes from now on are reported.",
                    Resource(profile)));
                known[profile.Key] = ProfileRecord.From(profile);
                dirty = true;
                continue;
            }

            var now = profile.Extensions!.ToDictionary(e => e.Id, StringComparer.Ordinal);
            added.AddRange(now.Values.Where(e => !before.Extensions.ContainsKey(e.Id)).Select(e => (profile, e)));
            removed.AddRange(before.Extensions.Values.Where(e => !now.ContainsKey(e.Id)).Select(e => (profile, e)));

            var record = ProfileRecord.From(profile);
            if (!SameRecord(before, record))
            {
                known[profile.Key] = record;
                dirty = true;
            }
        }

        // A profile that is gone from a user and browser that were read
        // without error was deleted (or the browser's data was cleared).
        var scanned = snapshot.Users.ToDictionary(u => u.UserId, StringComparer.OrdinalIgnoreCase);
        var present = new HashSet<string>(snapshot.Users.SelectMany(u => u.Profiles).Select(p => p.Key), StringComparer.OrdinalIgnoreCase);
        foreach (var (key, record) in known.Where(p => !present.Contains(p.Key)).ToList())
        {
            if (!scanned.TryGetValue(record.UserId, out var user) || user.BrowserErrors.ContainsKey(record.Browser))
            {
                continue;
            }
            var profile = record.ToProfile(key);
            ReportChange(new BrowserExtensionChange(ProfileRemoved, AlertSeverity.Info, "Browser profile removed",
                $"The {profile.Describe()} is gone, with the {Count(record.Extensions.Count, "extension")} it had"
                + (record.Extensions.Count == 0 ? "." : ": " + Limit(record.Extensions.Values.Select(DescribeShort).ToList()) + "."),
                Resource(profile)));
            known.Remove(key);
            dirty = true;
        }

        added.RemoveAll(c => IsIgnored(c.Extension.Id));
        removed.RemoveAll(c => IsIgnored(c.Extension.Id));
        ReportExtensions(added, true);
        if (_options.ReportRemovals)
        {
            ReportExtensions(removed, false);
        }
        return dirty;
    }

    private void ReportExtensions(List<(BrowserProfile Profile, InstalledExtension Extension)> changes, bool added)
    {
        if (changes.Count == 0)
        {
            return;
        }

        if (changes.Count <= Math.Max(1, _options.MaxIndividualAlerts))
        {
            foreach (var (profile, extension) in changes)
            {
                var severity = !added || extension.Source == ExtensionSource.Default ? AlertSeverity.Info : AlertSeverity.Warning;
                ReportChange(new BrowserExtensionChange(added ? ExtensionAdded : ExtensionRemoved, severity,
                    added ? $"New browser extension: {extension.Name}" : $"Browser extension removed: {extension.Name}",
                    $"{DescribeShort(extension)} was {(added ? "added to" : "removed from")} the {profile.Describe()}. "
                    + $"Installed by policy: {(extension.ByPolicy ? "yes" : "no")}."
                    + (added ? Advice(extension) : ""),
                    Resource(profile, extension)));
            }
            return;
        }

        var lines = changes.Select(c => $"{DescribeShort(c.Extension)}, {(c.Extension.ByPolicy ? "by policy, " : "")}in the {c.Profile.Describe()}").ToList();
        ReportChange(new BrowserExtensionChange(added ? ExtensionsAdded : ExtensionsRemoved,
            !added || changes.All(c => c.Extension.Source == ExtensionSource.Default) ? AlertSeverity.Info : AlertSeverity.Warning,
            added ? $"{changes.Count} new browser extensions" : $"{changes.Count} browser extensions removed",
            $"{Count(changes.Count, "browser extension")} {(added ? "added" : "removed")}: {Limit(lines)}."
            + (added ? " If you did not install these, review them in each browser's extensions page." : "")));
    }

    private bool ComparePolicies(Dictionary<string, PolicyEntry> known, Dictionary<string, PolicyEntry> now, IReadOnlyList<string> scopes, HashSet<string> browsers)
    {
        var read = new HashSet<string>(scopes, StringComparer.OrdinalIgnoreCase);
        var added = now.Values.Where(e => !known.ContainsKey(e.Key)).ToList();
        // Entries of a scope that was not read this time (a signed-out user) are kept, not removed.
        var removed = known.Values.Where(e => !now.ContainsKey(e.Key) && (read.Contains(e.Scope) || !browsers.Contains(e.Browser))).ToList();
        if (added.Count == 0 && removed.Count == 0)
        {
            return false;
        }

        foreach (var entry in added)
        {
            known[entry.Key] = entry;
        }
        foreach (var entry in removed)
        {
            known.Remove(entry.Key);
        }

        ReportPolicies(added.Where(e => !IsIgnored(e.ExtensionId)).ToList(), true);
        if (_options.ReportRemovals)
        {
            ReportPolicies(removed.Where(e => !IsIgnored(e.ExtensionId) && browsers.Contains(e.Browser)).ToList(), false);
        }
        return true;
    }

    private void ReportPolicies(List<PolicyEntry> changes, bool added)
    {
        if (changes.Count == 0)
        {
            return;
        }
        var severity = added ? AlertSeverity.Warning : AlertSeverity.Info;
        if (changes.Count <= Math.Max(1, _options.MaxIndividualAlerts))
        {
            foreach (var entry in changes)
            {
                var external = entry.Kind == WindowsExtensionPolicyReader.ExternalKind;
                ReportChange(new BrowserExtensionChange(added ? PolicyAdded : PolicyRemoved, severity,
                    added ? "Browser extension policy added" : "Browser extension policy removed",
                    $"{(added ? "Added" : "Removed")}: {entry.Describe()}."
                    + (!added ? ""
                        : external
                            ? $" Another program registered this extension, so {Browsers.DisplayName(entry.Browser)} offers or installs it in every profile. If you did not install software that adds it, check what wrote the key."
                            : $" {Browsers.DisplayName(entry.Browser)} installs it without asking{(entry.Kind == WindowsExtensionPolicyReader.SettingsNormalKind ? "" : ", and users can't remove it")}. Expected on a managed PC; on a personal one, malware and adware use this to keep an extension installed."),
                    $"{entry.Browser}/{entry.Scope}/{entry.ExtensionId}"));
            }
            return;
        }

        ReportChange(new BrowserExtensionChange(added ? PoliciesAdded : PoliciesRemoved, severity,
            added ? $"{changes.Count} browser extension policies added" : $"{changes.Count} browser extension policies removed",
            $"{Count(changes.Count, "extension install policy or registration", "extension install policies or registrations")} {(added ? "added" : "removed")}: "
            + Limit(changes.Select(e => e.Describe()).ToList()) + "."));
    }

    private static bool SameRecord(ProfileRecord a, ProfileRecord b) =>
        a.ProfileName == b.ProfileName && a.UserName == b.UserName && a.ProfileFolder == b.ProfileFolder
        && a.Extensions.Count == b.Extensions.Count
        && a.Extensions.All(e => b.Extensions.TryGetValue(e.Key, out var other) && other == e.Value);

    private bool IsIgnored(string id) => _ignored.Any(r => r.IsMatch(id));

    private static string Advice(InstalledExtension extension) => extension.Source switch
    {
        ExtensionSource.Sideloaded => " Another program installed it, not the browser's store. If you don't recognize it, remove it from the browser's extensions page and find what added it.",
        ExtensionSource.Unpacked => " Unpacked extensions are normally only used by developers; malware loads them this way to avoid the store's review.",
        ExtensionSource.Policy => " It is installed by an enterprise policy (see the browser's policy page); expected on a managed PC.",
        ExtensionSource.Default => "",
        _ => " If you did not install it, review it in the browser's extensions page.",
    };

    private static string DescribeShort(InstalledExtension e) =>
        $"\"{e.Name}\" ({e.Id}{(e.Version is null ? "" : $", version {e.Version}")}, {e.SourceDetail ?? e.Source.ToString().ToLowerInvariant()}{(e.Enabled ? "" : ", disabled")})";

    private static string DescribeInventory(IReadOnlyList<BrowserProfile> profiles)
    {
        if (profiles.Count == 0)
        {
            return "no browser profiles";
        }
        var byBrowser = profiles.GroupBy(p => p.Browser).OrderBy(g => g.Key, StringComparer.Ordinal)
            .Select(g => $"{Browsers.DisplayName(g.Key)}: {Count(g.Count(), "profile")}, {Count(g.Sum(p => p.Extensions!.Count), "extension")}");
        return $"{Count(profiles.Sum(p => p.Extensions!.Count), "extension")} in {Count(profiles.Count, "browser profile")} ({string.Join("; ", byBrowser)})";
    }

    private static string Resource(BrowserProfile profile, InstalledExtension? extension = null) =>
        $"{profile.Browser}/{profile.UserName}/{profile.ProfileFolder}" + (extension is null ? "" : "/" + extension.Id);

    private static string Count(int count, string singular, string? plural = null) =>
        $"{count} {(count == 1 ? singular : plural ?? singular + "s")}";

    private string Limit(IReadOnlyList<string> items)
    {
        var max = Math.Max(1, _options.MaxChangesPerAlert);
        return string.Join("; ", items.Take(max)) + (items.Count > max ? $"; and {items.Count - max} more" : "");
    }

    private BrowserExtensionState LoadState()
    {
        if (_state is not null)
        {
            return _state;
        }

        try
        {
            var loaded = AtomicJsonFile.Read<BrowserExtensionState>(_options.ResolveStatePath());
            if (!loaded.IsValid())
            {
                throw new InvalidDataException("Invalid or unsupported browser extension state file.");
            }
            if (loaded.Profiles is not null)
            {
                loaded.Profiles = loaded.Profiles.ToDictionary(p => p.Key, p =>
                {
                    p.Value.Extensions = new(p.Value.Extensions, StringComparer.Ordinal);
                    return p.Value;
                }, StringComparer.OrdinalIgnoreCase);
            }
            if (loaded.Policies is not null)
            {
                // Keyed by content, so a hand-edited key can't hide an entry.
                loaded.Policies = loaded.Policies.Values.DistinctBy(e => e.Key).ToDictionary(e => e.Key, StringComparer.OrdinalIgnoreCase);
            }
            _state = loaded;
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            _state = new BrowserExtensionState();
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or JsonException)
        {
            // The state only enables change reports, so start over rather than
            // stop watching; say so once, because changes made while the hub
            // was stopped can't be reported this time.
            _state = new BrowserExtensionState();
            ReportChange(new BrowserExtensionChange(StateUnreadable, AlertSeverity.Warning, "Browser extension watchdog state reset",
                $"The saved browser extension inventory could not be read, so extensions added while the hub was stopped can't be reported: {ex.Message}"));
        }
        return _state;
    }

    private void SaveState(BrowserExtensionState state)
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

    private void RaiseAlert(BrowserExtensionFinding finding)
    {
        _alerts?.Publish(ModuleId, finding.Code, finding.Severity, "Browser extension watchdog needs attention", finding.Message, finding.Resource);
        var line = $"BROWSER EXTENSION ALERT {finding}";
        _logger.LogWarning("{BrowserExtensionAlert}", line);
        AlertLog()?.WriteLine(line);
        AlertRaised?.Invoke(finding);
    }

    private void ClearAlert(BrowserExtensionFinding finding)
    {
        _alerts?.Publish(ModuleId, finding.Code + "_CLEARED", AlertSeverity.Info,
            "Browser extension watchdog recovered", finding.Message + " This is no longer reported.", finding.Resource);
        var line = $"Browser extensions recovered: {finding.Message} This is no longer reported.";
        _logger.LogInformation("{BrowserExtensionRecovered}", line);
        AlertLog()?.WriteLine(line);
        AlertCleared?.Invoke(finding);
    }

    private void ReportChange(BrowserExtensionChange change)
    {
        _alerts?.Publish(ModuleId, change.Code, change.Severity, change.Title, change.Message, change.Resource);
        var line = $"BROWSER EXTENSION CHANGE {change}";
        _logger.Log(change.Severity switch
        {
            AlertSeverity.Critical => LogLevel.Critical,
            AlertSeverity.Warning => LogLevel.Warning,
            _ => LogLevel.Information,
        }, "{BrowserExtensionChange}", line);
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
                _logger.LogWarning("Could not open browser extension watchdog log: {Error}", ex.Message);
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

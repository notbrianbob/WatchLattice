using System.IO.Enumeration;
using WatchLattice.Common.Alerts;

namespace WatchLattice.HostsProxyWatchdog;

/// <summary>
/// Pure rules that turn a <see cref="HostsProxySnapshot"/> into standing
/// findings, and two snapshots into changes. No I/O, so every rule is
/// unit-tested without Windows.
/// </summary>
public static class HostsProxyEvaluator
{
    public const string HostsUnavailable = "HOSTS_UNAVAILABLE";
    public const string ProtectedHostOverridden = "PROTECTED_HOST_OVERRIDDEN";
    public const string HostsPathMoved = "HOSTS_PATH_MOVED";
    public const string HostsChanged = "HOSTS_CHANGED";
    public const string ProxyUnavailable = "PROXY_UNAVAILABLE";
    public const string ProxyChanged = "PROXY_CHANGED";
    public const string BaselineCreated = "BASELINE_CREATED";

    private const string NotSet = "(not set)";

    // Changes to these only narrow or describe a proxy (bypass lists,
    // auto-detection, which is on by default), so they are informational.
    private static readonly string[] InfoOnlySuffixes = { "ProxyOverride", "ProxyBypass", "NO_PROXY", "AutoDetect" };

    // Any change to these moves where proxy settings come from.
    private static readonly string[] AlwaysWarnSuffixes = { "ProxySettingsPerUser" };

    public static IReadOnlyList<HostsProxyFinding> Evaluate(HostsProxySnapshot snapshot, HostsProxyWatchdogOptions options)
    {
        var findings = new List<HostsProxyFinding>();

        if (snapshot.Hosts is { } hosts)
        {
            if (hosts.Error is not null)
            {
                findings.Add(new(HostsUnavailable, AlertSeverity.Warning,
                    $"Could not read the hosts file {hosts.Path}: {hosts.Error}", hosts.Path));
            }
            else if (hosts.Entries is { } entries)
            {
                var overridden = ProtectedEntries(entries, options).ToList();
                if (overridden.Count > 0)
                {
                    findings.Add(new(ProtectedHostOverridden, AlertSeverity.Critical,
                        $"The hosts file overrides {overridden.Count} security or update host{(overridden.Count == 1 ? "" : "s")}, " +
                        "which can stop Windows Update, Defender or WatchLattice from getting updates: " +
                        List(overridden.Select(e => Describe(e.Key, e.Value)), options) + ".",
                        hosts.Path));
                }
            }

            if (hosts.DatabasePathMoved && hosts.DatabasePath is { } moved)
            {
                findings.Add(new(HostsPathMoved, AlertSeverity.Warning,
                    $"Windows reads its hosts file from a non-default folder, {Excerpt(moved)}. Malware can move it to hide a modified hosts file.",
                    moved));
            }
        }

        var unreadable = new List<string>();
        if (snapshot.ProxyError is not null)
        {
            unreadable.Add(snapshot.ProxyError);
        }
        unreadable.AddRange((snapshot.Proxy ?? Array.Empty<ProxyScope>())
            .Where(s => s.Error is not null)
            .Select(s => $"{s.DisplayName}: {s.Error}"));
        if (unreadable.Count > 0)
        {
            findings.Add(new(ProxyUnavailable, AlertSeverity.Warning,
                "Could not read proxy settings. " + string.Join("; ", unreadable.Select(Excerpt))));
        }

        return findings;
    }

    /// <summary>Entries for a protected domain, minus ignored ones, sorted by host.</summary>
    public static IEnumerable<KeyValuePair<string, IReadOnlyList<string>>> ProtectedEntries(
        IReadOnlyDictionary<string, IReadOnlyList<string>> entries, HostsProxyWatchdogOptions options)
    {
        var protectedDomains = options.EffectiveProtectedDomains();
        return entries
            .Where(e => IsProtected(e.Key, protectedDomains) && !IsIgnored(e.Key, options))
            .OrderBy(e => e.Key, StringComparer.Ordinal);
    }

    /// <summary>
    /// Reports hosts entries that were added, changed (pinned to different
    /// addresses) or removed since the baseline, as one alert. Critical when a
    /// protected host was added or changed, Warning for other additions and
    /// changes, Info when entries were only removed. Null when nothing changed.
    /// </summary>
    public static HostsProxyChange? CompareHosts(
        IReadOnlyDictionary<string, string[]> baseline,
        IReadOnlyDictionary<string, IReadOnlyList<string>> current,
        string path,
        HostsProxyWatchdogOptions options)
    {
        var protectedDomains = options.EffectiveProtectedDomains();
        var added = new List<string>();
        var changed = new List<string>();
        var removed = new List<string>();
        var touchesProtected = false;

        // Protected hosts first, so a long list never hides them in "and N more".
        foreach (var (host, addresses) in current
                     .OrderBy(e => IsProtected(e.Key, protectedDomains) ? 0 : 1)
                     .ThenBy(e => e.Key, StringComparer.Ordinal))
        {
            if (IsIgnored(host, options))
            {
                continue;
            }
            if (!baseline.TryGetValue(host, out var before))
            {
                added.Add(Describe(host, addresses));
            }
            else if (!before.SequenceEqual(addresses, StringComparer.Ordinal))
            {
                changed.Add($"{Describe(host, addresses)} (was {string.Join(", ", before)})");
            }
            else
            {
                continue;
            }
            touchesProtected |= IsProtected(host, protectedDomains);
        }
        foreach (var (host, before) in baseline.OrderBy(e => e.Key, StringComparer.Ordinal))
        {
            if (!current.ContainsKey(host) && !IsIgnored(host, options))
            {
                removed.Add($"{Excerpt(host)} (was {string.Join(", ", before)})");
            }
        }

        var total = added.Count + changed.Count + removed.Count;
        if (total == 0)
        {
            return null;
        }

        var severity = touchesProtected ? AlertSeverity.Critical
            : added.Count + changed.Count > 0 ? AlertSeverity.Warning
            : AlertSeverity.Info;
        var items = added.Select(a => "added " + a)
            .Concat(changed.Select(c => "changed " + c))
            .Concat(removed.Select(r => "removed " + r));

        return new HostsProxyChange(HostsChanged, severity, "Hosts file changed",
            $"The hosts file changed ({added.Count} added, {changed.Count} changed, {removed.Count} removed): " +
            List(items, options) + ".",
            path);
    }

    /// <summary>
    /// Reports how a proxy scope's settings differ from the baseline, as one
    /// alert per scope. Warning when a proxy, auto-config script or proxy
    /// policy was turned on or pointed somewhere new; Info when settings were
    /// only cleared or turned off, or only bypass lists or auto-detection changed.
    /// </summary>
    public static HostsProxyChange? CompareProxy(
        IReadOnlyDictionary<string, string> baseline, ProxyScope current, HostsProxyWatchdogOptions options)
    {
        var differences = new List<string>();
        var severity = AlertSeverity.Info;

        foreach (var name in baseline.Keys.Union(current.Values.Keys).OrderBy(n => n, StringComparer.Ordinal))
        {
            var before = baseline.GetValueOrDefault(name);
            var after = current.Values.GetValueOrDefault(name);
            if (string.Equals(before, after, StringComparison.Ordinal))
            {
                continue;
            }

            differences.Add($"{name}: {Show(before)} → {Show(after)}");
            if (RaisesConcern(name, after))
            {
                severity = AlertSeverity.Warning;
            }
        }

        if (differences.Count == 0)
        {
            return null;
        }

        return new HostsProxyChange(ProxyChanged, severity, "Proxy settings changed",
            $"Proxy settings changed for {current.DisplayName}: {List(differences, options)}. " +
            "A proxy or auto-config script set by malware can watch or alter web traffic.",
            current.Id);
    }

    /// <summary>A short, readable inventory for the baseline alert.</summary>
    public static string DescribeProxyScopes(IEnumerable<ProxyScope> scopes, HostsProxyWatchdogOptions options)
    {
        var active = scopes
            .Where(s => s.Error is null)
            .Select(s => (Scope: s, Settings: s.Values
                .Where(v => !IsInfoOnly(v.Key) && IsActive(v.Value) && !v.Key.EndsWith("Enabled", StringComparison.Ordinal)
                            && !v.Key.EndsWith("ProxyEnable", StringComparison.Ordinal))
                .Select(v => $"{v.Key} = {Excerpt(v.Value)}")
                .ToList()))
            .Where(s => s.Settings.Count > 0)
            .Select(s => $"{s.Scope.DisplayName} ({string.Join(", ", s.Settings)})")
            .ToList();
        return active.Count == 0 ? "no proxy server or auto-config script is set" : "proxy settings found for " + List(active, options);
    }

    public static bool IsProtected(string host, IReadOnlyList<string> protectedDomains) =>
        protectedDomains.Any(d => HostsFileParser.IsWithin(host, d));

    public static bool IsIgnored(string host, HostsProxyWatchdogOptions options) => (options.IgnoredHosts ?? Array.Empty<string>())
        .Where(p => !string.IsNullOrWhiteSpace(p))
        .Any(p => FileSystemName.MatchesSimpleExpression(p.Trim(), host, ignoreCase: true));

    private static bool RaisesConcern(string name, string? after) =>
        AlwaysWarnSuffixes.Any(s => name.EndsWith(s, StringComparison.Ordinal))
        || (!IsInfoOnly(name) && IsActive(after));

    private static bool IsInfoOnly(string name) => InfoOnlySuffixes.Any(s => name.EndsWith(s, StringComparison.OrdinalIgnoreCase));

    private static bool IsActive(string? value) => !string.IsNullOrWhiteSpace(value) && value.Trim() != "0";

    private static string Describe(string host, IReadOnlyList<string> addresses)
    {
        var target = addresses.All(HostsFileParser.IsBlockingAddress)
            ? $"blocked ({string.Join(", ", addresses)})"
            : $"→ {string.Join(", ", addresses)}";
        return $"{Excerpt(host)} {target}";
    }

    private static string Show(string? value) => value is null ? NotSet : $"\"{Excerpt(value)}\"";

    private static string List(IEnumerable<string> items, HostsProxyWatchdogOptions options)
    {
        var limit = Math.Max(1, options.MaxChangesPerAlert);
        var all = items.ToList();
        var listed = string.Join("; ", all.Take(limit));
        return all.Count > limit ? $"{listed}; and {all.Count - limit} more" : listed;
    }

    private static string Excerpt(string value) => value.Length <= 200 ? value : value[..200] + "…";
}

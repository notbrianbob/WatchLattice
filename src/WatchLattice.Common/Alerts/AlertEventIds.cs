namespace WatchLattice.Common.Alerts;

/// <summary>
/// Stable Windows Event Log IDs for alerts. SIEM rules and event forwarding
/// subscriptions key on these, so an ID never changes meaning once released:
/// add new codes with new IDs, and never reuse a retired one.
/// Documented in docs/event-log.md; EventLogAlertTests keeps the two in step.
/// </summary>
public static class AlertEventIds
{
    /// <summary>Added to a finding's ID for its "_CLEARED" recovery event.</summary>
    public const int ClearedOffset = 500;

    /// <summary>Added to a module's base for a code this table does not know (+0 Info, +1 Warning, +2 Critical).</summary>
    public const int UnclassifiedOffset = 900;

    /// <summary>Base for alerts from a module this table does not know.</summary>
    public const int UnknownModuleBase = 9000;

    /// <summary>Written by the Event Log sink itself when alerts arrived faster than it could write them.</summary>
    public const int AlertsDropped = 1004;

    public const string ClearedSuffix = "_CLEARED";

    private static readonly Dictionary<string, int> ModuleBases = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Hub"] = 1000,
        ["Canary"] = 2000,
        ["DefenderWatchdog"] = 3000,
        ["FirewallWatchdog"] = 4000,
        ["Persistence"] = 5000,
        ["Updater"] = 6000,
        ["InstallIntegrity"] = 7000,
        ["HostsProxyWatchdog"] = 8000,
    };

    // The supervisor raises these under each module's own ID.
    private static readonly Dictionary<string, int> AnyModule = new(StringComparer.Ordinal)
    {
        ["MODULE_FAILED"] = 1001,
        ["MODULE_FINISHED"] = 1002,
    };

    private static readonly Dictionary<(string Module, string Code), int> Exact = new(ModuleCodeComparer.Instance)
    {
        [("Hub", "ALERT_HISTORY_UNAVAILABLE")] = 1003,
        [("Hub", "EVENTLOG_UNAVAILABLE")] = 1005,
        [("Hub", "EVENTLOG_WRITE_FAILED")] = 1006,
        [("Hub", "DAILY_SUMMARY")] = 1007,

        [("Canary", "CANARY_MODIFIED")] = 2001,
        [("Canary", "CANARY_DELETED")] = 2002,
        [("Canary", "CANARY_RENAMED")] = 2003,

        [("DefenderWatchdog", "STATUS_UNAVAILABLE")] = 3001,
        [("DefenderWatchdog", "NOT_RUNNING")] = 3002,
        [("DefenderWatchdog", "PASSIVE_MODE")] = 3003,
        [("DefenderWatchdog", "SERVICE_DISABLED")] = 3004,
        [("DefenderWatchdog", "ANTIVIRUS_DISABLED")] = 3005,
        [("DefenderWatchdog", "REALTIME_OFF")] = 3006,
        [("DefenderWatchdog", "BEHAVIOR_MONITOR_OFF")] = 3007,
        [("DefenderWatchdog", "IOAV_OFF")] = 3008,
        [("DefenderWatchdog", "ON_ACCESS_OFF")] = 3009,
        [("DefenderWatchdog", "TAMPER_PROTECTION_OFF")] = 3010,
        [("DefenderWatchdog", "SIGNATURES_STALE")] = 3011,
        [("DefenderWatchdog", "SIGNATURES_VERY_STALE")] = 3012,
        [("DefenderWatchdog", "SIGNATURE_DATE_UNKNOWN")] = 3013,
        [("DefenderWatchdog", "STATE_SAVE_FAILED")] = 3014,
        [("DefenderWatchdog", "STATE_UNREADABLE")] = 3015,
        [("DefenderWatchdog", "SETTINGS_UNAVAILABLE")] = 3020,
        [("DefenderWatchdog", "EXCLUSIONS_HIDDEN")] = 3021,
        [("DefenderWatchdog", "CLOUD_PROTECTION_OFF")] = 3022,
        [("DefenderWatchdog", "BLOCK_AT_FIRST_SEEN_OFF")] = 3023,
        [("DefenderWatchdog", "EXCLUSION_ADDED")] = 3030,
        [("DefenderWatchdog", "EXCLUSIONS_ADDED")] = 3031,
        [("DefenderWatchdog", "EXCLUSION_REMOVED")] = 3032,
        [("DefenderWatchdog", "EXCLUSIONS_REMOVED")] = 3033,
        [("DefenderWatchdog", "ASR_RULE_WEAKENED")] = 3034,
        [("DefenderWatchdog", "ASR_RULES_WEAKENED")] = 3035,
        [("DefenderWatchdog", "ASR_RULE_STRENGTHENED")] = 3036,
        [("DefenderWatchdog", "CLOUD_BLOCK_LEVEL_LOWERED")] = 3037,
        [("DefenderWatchdog", "CLOUD_BLOCK_LEVEL_RAISED")] = 3038,
        [("DefenderWatchdog", "SETTINGS_BASELINE_CREATED")] = 3039,

        [("FirewallWatchdog", "STATUS_UNAVAILABLE")] = 4001,
        [("FirewallWatchdog", "PROFILE_DISABLED_DOMAIN")] = 4002,
        [("FirewallWatchdog", "PROFILE_DISABLED_PRIVATE")] = 4003,
        [("FirewallWatchdog", "PROFILE_DISABLED_PUBLIC")] = 4004,
        [("FirewallWatchdog", "INBOUND_DEFAULT_ALLOW_DOMAIN")] = 4005,
        [("FirewallWatchdog", "INBOUND_DEFAULT_ALLOW_PRIVATE")] = 4006,
        [("FirewallWatchdog", "INBOUND_DEFAULT_ALLOW_PUBLIC")] = 4007,
        [("FirewallWatchdog", "INBOUND_DEFAULT_CHANGED_DOMAIN")] = 4008,
        [("FirewallWatchdog", "INBOUND_DEFAULT_CHANGED_PRIVATE")] = 4009,
        [("FirewallWatchdog", "INBOUND_DEFAULT_CHANGED_PUBLIC")] = 4010,
        [("FirewallWatchdog", "RULES_UNAVAILABLE")] = 4011,
        [("FirewallWatchdog", "INBOUND_ALLOW_RULE_ADDED")] = 4012,
        [("FirewallWatchdog", "INBOUND_ALLOW_RULES_ADDED")] = 4013,
        [("FirewallWatchdog", "RULE_BASELINE_CREATED")] = 4014,
        [("FirewallWatchdog", "STATE_SAVE_FAILED")] = 4015,
        [("FirewallWatchdog", "STATE_UNREADABLE")] = 4016,

        [("Persistence", "BASELINE_CREATED")] = 5001,
        [("Persistence", "ENTRY_ADDED")] = 5002,
        [("Persistence", "ENTRY_CHANGED")] = 5003,
        [("Persistence", "ENTRY_REMOVED")] = 5004,
        [("Persistence", "SOURCE_UNAVAILABLE")] = 5005,
        [("Persistence", "SOURCE_RECOVERED")] = 5006,
        [("Persistence", "VERIFY_PASSED")] = 5010,
        [("Persistence", "VERIFY_NEEDS_REVIEW")] = 5011,
        [("Persistence", "VERIFY_SUSPICIOUS")] = 5012,
        [("Persistence", "VERIFICATION_STORE_FAILED")] = 5013,

        [("Updater", "UPDATE_AVAILABLE")] = 6001,

        [("InstallIntegrity", "INSTALL_MODIFIED")] = 7001,
        [("InstallIntegrity", "MANIFEST_UNAVAILABLE")] = 7002,

        [("HostsProxyWatchdog", "HOSTS_UNAVAILABLE")] = 8001,
        [("HostsProxyWatchdog", "PROTECTED_HOST_OVERRIDDEN")] = 8002,
        [("HostsProxyWatchdog", "HOSTS_PATH_MOVED")] = 8003,
        [("HostsProxyWatchdog", "HOSTS_CHANGED")] = 8004,
        [("HostsProxyWatchdog", "PROXY_UNAVAILABLE")] = 8005,
        [("HostsProxyWatchdog", "PROXY_CHANGED")] = 8006,
        [("HostsProxyWatchdog", "BASELINE_CREATED")] = 8007,
        [("HostsProxyWatchdog", "STATE_SAVE_FAILED")] = 8008,
        [("HostsProxyWatchdog", "STATE_UNREADABLE")] = 8009,
    };

    // Codes that carry a variable part after a fixed prefix, e.g. BROAD_EXCLUSION:Path:C:\.
    private static readonly (string Module, string Prefix, int Id)[] Prefixes =
    {
        ("DefenderWatchdog", "BROAD_EXCLUSION:", 3024),
    };

    /// <summary>Every classified (module, code) and its ID, for documentation and tests.</summary>
    public static IEnumerable<(string Module, string Code, int Id)> Classified =>
        AnyModule.Select(p => ("(any)", p.Key, p.Value))
            .Concat(Exact.Select(p => (p.Key.Module, p.Key.Code, p.Value)))
            .Concat(Prefixes.Select(p => (p.Module, p.Prefix + "*", p.Id)));

    public static IReadOnlyDictionary<string, int> Bases => ModuleBases;

    /// <summary>The event ID for an alert. Always in 1..65535; never throws.</summary>
    public static int For(string module, string code, AlertSeverity severity)
    {
        // Recovery first: a prefix code's variable part could otherwise swallow the suffix.
        if (code.EndsWith(ClearedSuffix, StringComparison.Ordinal)
            && TryClassify(module, code[..^ClearedSuffix.Length], out var finding))
            return finding + ClearedOffset;
        if (TryClassify(module, code, out var id)) return id;
        var severityOffset = severity switch
        {
            AlertSeverity.Critical => 2,
            AlertSeverity.Warning => 1,
            _ => 0,
        };
        var moduleBase = ModuleBases.TryGetValue(module, out var b) ? b : UnknownModuleBase;
        return moduleBase + UnclassifiedOffset + severityOffset;
    }

    /// <summary>True when the alert has its own ID rather than an unclassified fallback.</summary>
    public static bool IsClassified(string module, string code) =>
        For(module, code, AlertSeverity.Info) % 1000 < UnclassifiedOffset;

    private static bool TryClassify(string module, string code, out int id)
    {
        if (AnyModule.TryGetValue(code, out id) || Exact.TryGetValue((module, code), out id)) return true;
        foreach (var prefix in Prefixes)
        {
            if (string.Equals(prefix.Module, module, StringComparison.OrdinalIgnoreCase)
                && code.StartsWith(prefix.Prefix, StringComparison.Ordinal) && code.Length > prefix.Prefix.Length)
            {
                id = prefix.Id;
                return true;
            }
        }
        id = 0;
        return false;
    }

    private sealed class ModuleCodeComparer : IEqualityComparer<(string Module, string Code)>
    {
        public static readonly ModuleCodeComparer Instance = new();

        public bool Equals((string Module, string Code) x, (string Module, string Code) y) =>
            string.Equals(x.Module, y.Module, StringComparison.OrdinalIgnoreCase) && string.Equals(x.Code, y.Code, StringComparison.Ordinal);

        public int GetHashCode((string Module, string Code) obj) =>
            HashCode.Combine(StringComparer.OrdinalIgnoreCase.GetHashCode(obj.Module), StringComparer.Ordinal.GetHashCode(obj.Code));
    }
}

namespace WatchLattice.HostsProxyWatchdog;

/// <summary>
/// The watchdog's memory between checks and across restarts: the hosts
/// entries and proxy settings it last saw. Kept on disk so a change made while
/// the hub was stopped is still reported at the next start.
/// </summary>
public sealed class HostsProxyState
{
    public const int CurrentVersion = 1;

    public int Version { get; set; } = CurrentVersion;

    /// <summary>Host → sorted addresses. Null until the hosts file is first read.</summary>
    public Dictionary<string, string[]>? Hosts { get; set; }

    /// <summary>
    /// Scope ID → setting name → value. Null until proxy settings are first
    /// read. A scope that is missing from a later check (a user who signed out)
    /// keeps its last values, so signing back in is not reported as a change.
    /// </summary>
    public Dictionary<string, Dictionary<string, string>>? Proxy { get; set; }

    public bool IsValid() =>
        Version == CurrentVersion
        && (Hosts is null || Hosts.All(h => h.Key.Length > 0 && h.Value is not null && h.Value.All(a => a is not null)))
        && (Proxy is null || Proxy.All(s => s.Key.Length > 0 && s.Value is not null && s.Value.All(v => v.Value is not null)));
}

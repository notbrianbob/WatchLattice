namespace WatchLattice.HostsProxyWatchdog;

/// <summary>
/// The hosts file as one check saw it. <see cref="Entries"/> maps each host
/// name (lower case) to the addresses it is pinned to, sorted; it is null when
/// the file could not be read.
/// </summary>
public sealed record HostsFileSnapshot
{
    public string Path { get; init; } = "";

    /// <summary>
    /// The folder Windows reads hosts from (Tcpip's DataBasePath, expanded),
    /// or null when it was not read (unknown, or <see cref="HostsProxyWatchdogOptions.HostsFilePath"/> overrides it).
    /// </summary>
    public string? DatabasePath { get; init; }

    /// <summary>True when <see cref="DatabasePath"/> is not the Windows default.</summary>
    public bool DatabasePathMoved { get; init; }

    public IReadOnlyDictionary<string, IReadOnlyList<string>>? Entries { get; init; }

    public string? Error { get; init; }

    public static HostsFileSnapshot Unavailable(string path, string error) => new() { Path = path, Error = error };
}

/// <summary>
/// One place that holds proxy settings: a user's WinINET settings, the
/// machine-wide ones, or WinHTTP. <see cref="Values"/> holds only settings
/// that exist, by stable name (for example <c>ProxyServer</c> or
/// <c>Connection.AutoConfigURL</c>). <see cref="Error"/> is set when the
/// place could not be read, and then <see cref="Values"/> means nothing.
/// </summary>
public sealed record ProxyScope(string Id, string DisplayName, IReadOnlyDictionary<string, string> Values, string? Error = null);

/// <summary>Everything one check read. A part is null when it is turned off.</summary>
public sealed record HostsProxySnapshot
{
    public HostsFileSnapshot? Hosts { get; init; }

    /// <summary>Proxy scopes that were present. Null when proxy watching is off or nothing could be read.</summary>
    public IReadOnlyList<ProxyScope>? Proxy { get; init; }

    /// <summary>Why no proxy settings could be read at all.</summary>
    public string? ProxyError { get; init; }
}

/// <summary>A standing problem. <see cref="Code"/> is stable, for de-duplication.</summary>
public sealed record HostsProxyFinding(string Code, Common.Alerts.AlertSeverity Severity, string Message, string? Resource = null)
{
    public override string ToString() => $"[{Severity}] {Message}";
}

/// <summary>A one-off change between two checks.</summary>
public sealed record HostsProxyChange(string Code, Common.Alerts.AlertSeverity Severity, string Title, string Message, string? Resource = null)
{
    public override string ToString() => $"[{Severity}] {Message}";
}

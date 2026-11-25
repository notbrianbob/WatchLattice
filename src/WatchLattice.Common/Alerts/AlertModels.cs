namespace WatchLattice.Common.Alerts;

public enum AlertSeverity { Info, Warning, Critical }
public enum ModuleRunState { Disabled, Starting, Running, Restarting, Finished, Failed, Stopped }

/// <summary>A display-only alert. Resource and Message must never be executed as commands.</summary>
public sealed record ProtectionAlert(Guid Id, DateTimeOffset At, string Module, string Code,
    AlertSeverity Severity, string Title, string Message, string? Resource = null);

public sealed record ModuleStatus(string Id, ModuleRunState State, DateTimeOffset UpdatedAt);

/// <summary>Versioned, bounded snapshot consumed by the tray without a control channel.</summary>
public sealed record AlertSnapshot(int Version, Guid SessionId, DateTimeOffset HeartbeatAt,
    bool Online, IReadOnlyList<ModuleStatus> Modules, IReadOnlyList<ProtectionAlert> Alerts, long Revision = 0,
    UpdateNotice? Update = null)
{
    public const int CurrentVersion = 1;

    public bool IsFresh(DateTimeOffset now) => Online && HeartbeatAt <= now.AddSeconds(10)
        && now - HeartbeatAt <= TimeSpan.FromSeconds(20);

    public static AlertSnapshot Read(string path, bool includeHeartbeat = true)
    {
        var snapshot = AtomicJsonFile.Read<AlertSnapshot>(path);
        if (snapshot.Version != CurrentVersion || snapshot.SessionId == Guid.Empty
            || snapshot.Modules is null || snapshot.Alerts is null
            || snapshot.Modules.Count > 100 || snapshot.Alerts.Count > 1000
            || snapshot.Modules.Any(m => m is null || string.IsNullOrEmpty(m.Id) || !Enum.IsDefined(m.State))
            || snapshot.Alerts.Any(a => a is null || a.Id == Guid.Empty || a.Module is null
                || a.Code is null || a.Title is null || a.Message is null || !Enum.IsDefined(a.Severity)))
            throw new InvalidDataException("Unsupported or invalid alert feed.");
        if (snapshot.Update is { } update && !update.IsWellFormed())
            snapshot = snapshot with { Update = null };
        if (includeHeartbeat)
        {
            try
            {
                var heartbeat = AtomicJsonFile.Read<AlertHeartbeat>(path + ".heartbeat.json");
                if (heartbeat.SessionId == snapshot.SessionId)
                    snapshot = snapshot with { HeartbeatAt = heartbeat.At, Online = snapshot.Online && heartbeat.Online };
            }
            catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException) { }
        }
        return snapshot;
    }
}

/// <summary>
/// A newer release the hub's update checker found. Display-only: the tray never
/// downloads or runs anything named here. Installing re-checks the release
/// source from the hub's own install directory.
/// </summary>
public sealed record UpdateNotice(string CurrentVersion, string LatestVersion, string ReleaseName, string ReleaseUrl,
    DateTimeOffset? PublishedAt, DateTimeOffset CheckedAt, bool Installable, string? Problem = null)
{
    public bool IsWellFormed() => IsShortText(CurrentVersion, 64) && IsShortText(LatestVersion, 64)
        && IsShortText(ReleaseName, 200) && IsShortText(ReleaseUrl, 512) && (Problem is null || Problem.Length <= 512);

    /// <summary>The release page, only when it is an https link on github.com.</summary>
    public bool TryGetReleasePage(out Uri page)
    {
        page = null!;
        if (ReleaseUrl is null || !ReleaseUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
            || !Uri.TryCreate(ReleaseUrl, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps
            || !string.Equals(uri.Host, "github.com", StringComparison.OrdinalIgnoreCase) || !uri.IsDefaultPort
            || !string.IsNullOrEmpty(uri.UserInfo)) return false;
        page = uri;
        return true;
    }

    private static bool IsShortText(string? value, int max) => !string.IsNullOrWhiteSpace(value) && value.Length <= max;
}

/// <summary>Lets the update checker show its result next to the alert history.</summary>
public interface IUpdateStatusPublisher
{
    void SetUpdate(UpdateNotice? notice);
}

/// <summary>A small sidecar refreshed while an unchanged alert snapshot remains on disk.</summary>
public sealed record AlertHeartbeat(Guid SessionId, DateTimeOffset At, bool Online);

public interface IAlertPublisher
{
    void Publish(string module, string code, AlertSeverity severity, string title, string message, string? resource = null);
}

/// <summary>
/// Receives each new alert once, after burst de-duplication. Restored history is
/// not replayed. Called on the publisher's thread, so it must return quickly and
/// be safe to call concurrently, and must not throw.
/// </summary>
public interface IAlertSink
{
    void Accept(ProtectionAlert alert);
}

public sealed class AlertDeliveryOptions
{
    public bool Enabled { get; set; } = true;
    public string? FeedPath { get; set; }
    public int HistoryLimit { get; set; } = 200;

    public string ResolveFeedPath() => Path.GetFullPath(Environment.ExpandEnvironmentVariables(
        string.IsNullOrWhiteSpace(FeedPath) ? DefaultFeedPath : FeedPath));

    public static string DefaultFeedPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ScanAlways", "alerts.json");
}

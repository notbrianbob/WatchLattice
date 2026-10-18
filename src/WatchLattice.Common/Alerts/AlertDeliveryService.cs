using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WatchLattice.Common.Activity;

namespace WatchLattice.Common.Alerts;

/// <summary>
/// Writes a local heartbeat, alert history and the hub's recent activity every
/// two seconds; failures never stop monitoring.
/// </summary>
public sealed class AlertDeliveryService : BackgroundService
{
    private readonly AlertHub _alerts;
    private readonly AlertDeliveryOptions _options;
    private readonly ILogger<AlertDeliveryService> _logger;
    private bool _writeFailed;
    private long _lastWrittenRevision = -1;
    private readonly ActivityLog? _activity;
    private long _lastWrittenActivity = -1;

    public AlertDeliveryService(AlertHub alerts, IOptions<AlertDeliveryOptions> options, ILogger<AlertDeliveryService> logger,
        ActivityLog? activity = null)
    {
        _alerts = alerts;
        _options = options.Value;
        _logger = logger;
        _activity = activity;
    }

    private string? _path;

    /// <summary>
    /// Restores history and writes the first feed before the hub's modules start, so their
    /// first alerts land on top of the restored history. Since Microsoft.Extensions.Hosting 10,
    /// <see cref="BackgroundService"/> starts ExecuteAsync on the thread pool, so this cannot
    /// rely on ExecuteAsync running synchronously up to its first await.
    /// </summary>
    public override Task StartAsync(CancellationToken cancellationToken)
    {
        if (_options.Enabled) Prepare();
        return base.StartAsync(cancellationToken);
    }

    private void Prepare()
    {
        string path;
        try { path = _options.ResolveFeedPath(); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or IOException)
        {
            _logger.LogError("Shared alert delivery has an invalid path: {Error}", ex.Message);
            return;
        }
        try
        {
            _alerts.RestoreHistory(AlertSnapshot.Read(path, includeHeartbeat: false).Alerts);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException) { }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or JsonException)
        {
            _logger.LogWarning("Could not restore alert history: {Error}", ex.Message);
            _alerts.Publish("Hub", "ALERT_HISTORY_UNAVAILABLE", AlertSeverity.Warning,
                "Previous alert history unavailable", ex.Message);
        }
        try
        {
            _activity?.Restore(ActivitySnapshot.Read(ActivitySnapshot.PathFor(path)).Entries);
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or JsonException)
        {
            // Activity is a convenience; starting with an empty list is fine.
        }
        Write(path, online: true);
        _path = path;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (_path is not { } path) return;
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                Write(path, online: true);
                await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
    }

    /// <summary>
    /// Marks the feed offline once the loop has ended. Done here rather than in ExecuteAsync,
    /// which Hosting 10 never runs when the hub stops before the thread pool got to it, and
    /// which would then have left the feed looking online.
    /// </summary>
    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(cancellationToken);
        if (_path is { } path) Write(path, online: false);
    }

    private void Write(string path, bool online)
    {
        try
        {
            var snapshot = _alerts.Snapshot(online);
            if (snapshot.Revision != _lastWrittenRevision || !online || !File.Exists(path))
            {
                AtomicJsonFile.Write(path, snapshot);
                _lastWrittenRevision = snapshot.Revision;
            }
            AtomicJsonFile.Write(path + ".heartbeat.json", new AlertHeartbeat(snapshot.SessionId, snapshot.HeartbeatAt, online));
            if (_activity is not null && (_activity.Revision != _lastWrittenActivity || !online))
            {
                var revision = _activity.Revision;
                AtomicJsonFile.Write(ActivitySnapshot.PathFor(path), _activity.Snapshot());
                _lastWrittenActivity = revision;
            }
            if (_writeFailed) _logger.LogInformation("Shared alert delivery recovered.");
            _writeFailed = false;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
        {
            if (!_writeFailed) _logger.LogWarning("Shared alerts cannot be written to {Path}: {Error}", path, ex.Message);
            _writeFailed = true;
            _lastWrittenRevision = -1;
            _lastWrittenActivity = -1;
        }
    }
}

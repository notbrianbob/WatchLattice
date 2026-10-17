using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WatchLattice.Common.Alerts;

namespace WatchLattice.Updater;

/// <summary>
/// Checks for a newer release when the hub starts and then periodically. A
/// newer release is shown in the tray (status plus one informational alert per
/// version). It never downloads or installs anything; installing is a separate,
/// user-started, elevated step.
/// </summary>
public sealed class UpdateMonitor
{
    public const string ModuleId = "Updater";
    public const string UpdateAvailableCode = "UPDATE_AVAILABLE";

    /// <summary>
    /// First wait after a failed check. It doubles on each further failure up to
    /// the normal interval, so a hub that starts before the network is up (at
    /// boot, say) still checks within minutes instead of half a day later.
    /// </summary>
    public static readonly TimeSpan FirstRetryDelay = TimeSpan.FromMinutes(1);

    private readonly IReleaseSource _source;
    private readonly UpdaterOptions _options;
    private readonly ILogger<UpdateMonitor> _logger;
    private readonly IAlertPublisher? _alerts;
    private readonly IUpdateStatusPublisher? _status;
    private readonly Func<DateTimeOffset> _clock;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;
    private ReleaseVersion? _announced;
    private bool _failing;

    public UpdateMonitor(IReleaseSource source, IOptions<UpdaterOptions> options, ILogger<UpdateMonitor> logger,
        ReleaseVersion current, IAlertPublisher? alerts = null, IUpdateStatusPublisher? status = null,
        Func<DateTimeOffset>? clock = null, Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        _source = source;
        _options = options.Value;
        _logger = logger;
        Current = current;
        _alerts = alerts;
        _status = status;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        _delay = delay ?? Task.Delay;
    }

    public ReleaseVersion Current { get; }

    public UpdateCandidate? Latest { get; private set; }

    /// <summary>True when the most recent check could not reach the release source.</summary>
    public bool LastCheckFailed => _failing;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        try
        {
            if (Current.IsDevelopmentBuild && !_options.CheckDevelopmentBuilds)
            {
                _logger.LogInformation("Update checks are off for development build {Version}.", Current);
                await Task.Delay(Timeout.Infinite, cancellationToken);
                return;
            }

            var interval = TimeSpan.FromHours(Math.Max(1, _options.CheckIntervalHours));
            _logger.LogInformation("Update checker starting: WatchLattice {Version}, checking every {Interval}.", Current, interval);
            await _delay(TimeSpan.FromSeconds(Math.Max(0, _options.InitialDelaySeconds)), cancellationToken);
            var retry = FirstRetryDelay;
            while (!cancellationToken.IsCancellationRequested)
            {
                await CheckOnceAsync(cancellationToken);
                TimeSpan wait;
                if (_failing)
                {
                    wait = retry < interval ? retry : interval;
                    retry = wait * 2;
                }
                else
                {
                    wait = interval;
                    retry = FirstRetryDelay;
                }
                await _delay(wait, cancellationToken);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Normal shutdown.
        }
    }

    /// <summary>Runs one check. Network problems are logged and leave the last result in place.</summary>
    public async Task<UpdateCandidate?> CheckOnceAsync(CancellationToken cancellationToken)
    {
        UpdateCandidate? candidate;
        try
        {
            var repository = _options.ResolveRepository();
            candidate = UpdateEvaluator.FindNewer(Current, await _source.GetLatestAsync(cancellationToken), repository);
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidDataException or JsonException
            or TaskCanceledException && !cancellationToken.IsCancellationRequested)
        {
            // An offline machine is not a protection problem, so this is a log line, not an alert.
            if (!_failing) _logger.LogWarning("Update check failed: {Error}", ex.Message);
            _failing = true;
            return Latest;
        }
        if (_failing) _logger.LogInformation("Update checks are working again.");
        _failing = false;

        Latest = candidate;
        if (candidate is null)
        {
            _status?.SetUpdate(null);
            _logger.LogDebug("WatchLattice {Version} is up to date.", Current);
            return null;
        }

        _status?.SetUpdate(new UpdateNotice(Current.ToString(), candidate.Version.ToString(), candidate.Release.Name,
            candidate.Release.HtmlUrl.ToString(), candidate.Release.PublishedAt, _clock(), candidate.Installable,
            candidate.Problem));
        if (_announced != candidate.Version)
        {
            _announced = candidate.Version;
            _logger.LogInformation("WatchLattice {Latest} is available (running {Current}).", candidate.Version, Current);
            _alerts?.Publish(ModuleId, UpdateAvailableCode, AlertSeverity.Info,
                $"Update available: WatchLattice {candidate.Version}",
                candidate.Installable
                    ? $"You are running {Current}. Open the tray's alerts window and choose Install update, "
                      + "or run the hub with --apply-update from an administrator prompt. Nothing is installed until you do."
                    : $"You are running {Current}. {candidate.Problem}",
                candidate.Release.HtmlUrl.ToString());
        }
        return candidate;
    }
}

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WatchLattice.Common.Alerts;

namespace WatchLattice.Updater;

/// <summary>
/// Re-checks the installed files against the release manifest when the hub
/// starts and then periodically, and raises one alert when the set of
/// changed, missing or unexpected files changes (plus a recovery alert when it
/// is clean again). Detection only: nothing is repaired.
/// </summary>
public sealed class InstallIntegrityMonitor
{
    public const string ModuleId = "InstallIntegrity";
    public const string ModifiedCode = "INSTALL_MODIFIED";
    public const string ManifestUnavailableCode = "MANIFEST_UNAVAILABLE";
    public const int MaxListedFiles = 10;

    /// <summary>
    /// A check that finds problems is repeated once after this pause before it
    /// alerts, so files caught halfway through an update or reinstall (which
    /// rewrite them one by one) don't raise a false alarm.
    /// </summary>
    public static readonly TimeSpan ConfirmDelay = TimeSpan.FromSeconds(30);

    private readonly InstallIntegrityOptions _options;
    private readonly ILogger<InstallIntegrityMonitor> _logger;
    private readonly string _hubDirectory;
    private readonly IAlertPublisher? _alerts;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;
    private IReadOnlyList<string>? _reported;
    private bool _manifestReported;
    private ReleaseVersion? _mismatchLogged;
    private string? _unreadableLogged;

    public InstallIntegrityMonitor(IOptions<InstallIntegrityOptions> options, ILogger<InstallIntegrityMonitor> logger,
        ReleaseVersion current, string hubDirectory, IAlertPublisher? alerts = null,
        Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        _options = options.Value;
        _logger = logger;
        Current = current;
        _hubDirectory = hubDirectory;
        _alerts = alerts;
        _delay = delay ?? Task.Delay;
    }

    public ReleaseVersion Current { get; }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        try
        {
            if (Current.IsDevelopmentBuild)
            {
                // Development builds have no release manifest to compare with.
                _logger.LogInformation("Install integrity checks are off for development build {Version}.", Current);
                await Task.Delay(Timeout.Infinite, cancellationToken);
                return;
            }

            var interval = TimeSpan.FromMinutes(Math.Max(5, _options.CheckIntervalMinutes));
            _logger.LogInformation("Install integrity check starting for {Folder}, every {Interval}.", _hubDirectory, interval);
            await _delay(TimeSpan.FromSeconds(Math.Max(0, _options.InitialDelaySeconds)), cancellationToken);
            while (!cancellationToken.IsCancellationRequested)
            {
                await CheckOnceAsync(cancellationToken);
                await _delay(interval, cancellationToken);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Normal shutdown.
        }
    }

    /// <summary>Runs one check, confirming any problem once before alerting.</summary>
    public async Task<IntegrityReport> CheckOnceAsync(CancellationToken cancellationToken)
    {
        var report = InstallIntegrityChecker.Check(_hubDirectory, Current, _options);
        if (report.State is not (IntegrityState.Verified or IntegrityState.VersionMismatch))
        {
            await _delay(ConfirmDelay, cancellationToken);
            report = InstallIntegrityChecker.Check(_hubDirectory, Current, _options);
        }
        Apply(report);
        return report;
    }

    private void Apply(IntegrityReport report)
    {
        if (report.State == IntegrityState.VersionMismatch)
        {
            // The updater swaps files while the service is stopped and then starts the new
            // version, so this only lasts until the hub restarts. Nothing to alert on.
            if (_mismatchLogged != report.ManifestVersion)
                _logger.LogInformation("Skipping the install integrity check: {Problem}", report.Problem);
            _mismatchLogged = report.ManifestVersion;
            return;
        }
        _mismatchLogged = null;

        if (report.State is IntegrityState.ManifestMissing or IntegrityState.ManifestInvalid)
        {
            if (!_manifestReported)
            {
                _logger.LogWarning("Install integrity cannot be checked: {Problem}", report.Problem);
                _alerts?.Publish(ModuleId, ManifestUnavailableCode, AlertSeverity.Warning,
                    "Install integrity cannot be checked",
                    report.Problem + " Every release since 0.5.0 ships this file next to the hub, so it may have been "
                    + "removed or edited. Reinstall WatchLattice from the release page to restore it.",
                    report.InstallRoot);
            }
            _manifestReported = true;
            return;
        }

        if (_manifestReported)
        {
            _manifestReported = false;
            _alerts?.Publish(ModuleId, ManifestUnavailableCode + AlertEventIds.ClearedSuffix, AlertSeverity.Info,
                "Install integrity can be checked again", "The release file list next to the hub is readable again.",
                report.InstallRoot);
        }

        var unreadable = string.Join(", ", report.Unreadable);
        if (unreadable.Length > 0 && unreadable != _unreadableLogged)
            _logger.LogWarning("Install integrity check could not read: {Files}", unreadable);
        _unreadableLogged = unreadable;

        if (report.State == IntegrityState.Verified)
        {
            if (_reported is not null)
            {
                _alerts?.Publish(ModuleId, ModifiedCode + AlertEventIds.ClearedSuffix, AlertSeverity.Info,
                    "WatchLattice's files match the release again",
                    $"All {report.FilesChecked} checked file(s) match WatchLattice {Current}.", report.InstallRoot);
                _logger.LogInformation("Installed files match WatchLattice {Version} again.", Current);
            }
            else
            {
                _logger.LogDebug("Installed files match WatchLattice {Version} ({Count} checked).", Current, report.FilesChecked);
            }
            _reported = null;
            return;
        }

        var findings = report.Findings;
        if (_reported is not null && _reported.SequenceEqual(findings, StringComparer.OrdinalIgnoreCase)) return;
        _reported = findings;
        _logger.LogWarning("Installed WatchLattice files differ from release {Version}: {Findings}", Current,
            string.Join(", ", findings));
        _alerts?.Publish(ModuleId, ModifiedCode,
            report.AffectsBinaries ? AlertSeverity.Critical : AlertSeverity.Warning,
            "WatchLattice's installed files were changed",
            Describe(report, findings), report.InstallRoot);
    }

    private string Describe(IntegrityReport report, IReadOnlyList<string> findings)
    {
        var counts = new List<string>();
        if (report.Changed.Count > 0) counts.Add($"{report.Changed.Count} changed");
        if (report.Missing.Count > 0) counts.Add($"{report.Missing.Count} missing");
        if (report.Unexpected.Count > 0) counts.Add($"{report.Unexpected.Count} not part of the release");
        var listed = string.Join("; ", findings.Take(MaxListedFiles));
        if (findings.Count > MaxListedFiles) listed += $"; and {findings.Count - MaxListedFiles} more";
        return $"Compared with WatchLattice {Current}: {string.Join(", ", counts)}. {listed}. "
            + "Nothing was repaired. If you did not change these files, treat the PC as possibly tampered with, "
            + "and reinstall WatchLattice from the release page.";
    }
}

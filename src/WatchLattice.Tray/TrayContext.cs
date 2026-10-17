using System.ComponentModel;
using System.Diagnostics;
using System.Text.Json;
using WatchLattice.Common.Activity;
using WatchLattice.Common.Alerts;
using WatchLattice.Updater;

namespace WatchLattice.Tray;

/// <summary>
/// A per-user reader: the tray itself cannot change the hub's configuration.
/// It can start two things, both from the folders installed next to it (never
/// a path from the feed) and both elevated through Windows' consent prompt:
/// the hub's own updater when the user chooses Install update, and its own
/// settings editor when the user chooses to change a setting.
/// </summary>
internal sealed class TrayContext : ApplicationContext
{
    private const int ErrorCancelled = 1223;
    private readonly string _path;
    private readonly NotifyIcon _icon;
    private readonly ContextMenuStrip _menu = new();
    private readonly ToolStripMenuItem _status = new("Waiting for hub…") { Enabled = false };
    private readonly ToolStripMenuItem _update = new() { Visible = false };
    private readonly System.Windows.Forms.Timer _timer = new() { Interval = 2000 };
    private readonly AlertNotificationCursor _cursor = new();
    private readonly ReleaseVersion _version = ReleaseVersion.FromAssembly(typeof(TrayContext).Assembly);
    private DateTime _nextReplacementCheck;
    private AlertSnapshot? _snapshot;
    private DashboardWindow? _window;
    private DateTime _activityStamp;
    private string _statusText = "Waiting for the hub's alert feed.";
    private string? _announcedUpdate;
    private bool _reading;
    private bool _installing;
    private bool _exiting;

    public TrayContext(string path)
    {
        _path = path;
        _update.Click += (_, _) => OpenWindow();
        _menu.Items.Add(_status);
        _menu.Items.Add(_update);
        _menu.Items.Add("Open dashboard", null, (_, _) => OpenWindow());
        _menu.Items.Add(new ToolStripSeparator());
        _menu.Items.Add("Exit tray companion", null, (_, _) => ExitThread());
        _icon = new NotifyIcon { Icon = SystemIcons.Shield, Text = "WatchLattice: waiting for hub", ContextMenuStrip = _menu, Visible = true };
        _icon.DoubleClick += (_, _) => OpenWindow();
        _icon.BalloonTipClicked += (_, _) => OpenWindow(alerts: true);
        _timer.Tick += async (_, _) =>
        {
            if (RestartIfReplaced()) return;
            await PollAsync();
        };
        _timer.Start();
    }

    private async Task PollAsync()
    {
        if (_reading || _exiting) return;
        _reading = true;
        try
        {
            var watching = _window is { IsDisposed: false, Visible: true };
            var stamp = _activityStamp;
            var (snapshot, activity, activityProblem, newStamp) = await Task.Run(() =>
            {
                var feed = AlertSnapshot.Read(_path);
                var (lines, problem, written) = watching ? ReadActivity(stamp) : (null, null, stamp);
                return (feed, lines, problem, written);
            });
            if (_exiting) return;
            _activityStamp = newStamp;
            if (activity is not null || activityProblem is not null) _window?.UpdateActivity(activity, activityProblem);
            _snapshot = snapshot;
            var fresh = snapshot.IsFresh(DateTimeOffset.UtcNow);
            var running = snapshot.Modules.Count(m => m.State == ModuleRunState.Running);
            var attention = snapshot.Modules.Any(m => m.State is ModuleRunState.Failed or ModuleRunState.Restarting or ModuleRunState.Finished);
            _statusText = fresh ? $"Hub connected • {running} module(s) running" + (attention ? " • module needs attention" : "")
                : $"Hub offline or feed stale • last update {snapshot.HeartbeatAt.ToLocalTime():g}";
            _status.Text = fresh ? "Hub connected" : "Hub offline or feed stale";
            _icon.Text = (fresh ? "WatchLattice: hub connected" : "WatchLattice: hub offline")
                + (snapshot.Update is null ? "" : " • update available");
            _icon.Icon = fresh && !attention ? SystemIcons.Shield : SystemIcons.Warning;

            var alerts = _cursor.Observe(snapshot);
            if (alerts.Count > 0)
            {
                var mostSevere = alerts.OrderByDescending(a => a.Severity).ThenByDescending(a => a.At).First();
                var title = alerts.Count == 1 ? mostSevere.Title : $"{alerts.Count} new WatchLattice alerts";
                var message = alerts.Count == 1 ? mostSevere.Message : mostSevere.Title + ". Open the dashboard to review all new alerts.";
                _icon.ShowBalloonTip(8000, Clip(title, 63), Clip(message, 240),
                    mostSevere.Severity == AlertSeverity.Critical ? ToolTipIcon.Error : ToolTipIcon.Warning);
            }
            // Protection alerts take the balloon first; the update notice waits for the next poll.
            ShowUpdate(snapshot.Update, balloonFree: alerts.Count == 0);
            UpdateWindow();
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or JsonException)
        {
            if (_exiting) return;
            _statusText = "Alert feed unavailable: " + ex.Message;
            _status.Text = "Alert feed unavailable";
            _icon.Text = "WatchLattice: alert feed unavailable";
            _icon.Icon = SystemIcons.Warning;
            UpdateWindow();
        }
        finally { _reading = false; }
    }

    /// <summary>
    /// An update can replace the tray's files without restarting it (an update
    /// run from an administrator prompt, or by an older updater), which would
    /// leave the old tray running until the next sign-in. Every 30 seconds the
    /// tray compares its own version with the copy on disk and, if they differ,
    /// restarts on the new copy. It waits while the dashboard is open.
    /// </summary>
    private bool RestartIfReplaced()
    {
        if (_installing || _exiting || DateTime.UtcNow < _nextReplacementCheck) return false;
        _nextReplacementCheck = DateTime.UtcNow.AddSeconds(30);
        if (_window is { IsDisposed: false, Visible: true }) return false;
        var onDisk = ReleaseVersion.FromFile(Path.Combine(AppContext.BaseDirectory, ReleaseLayout.TrayAssembly));
        if (!ReleaseLayout.TrayWasReplaced(_version, onDisk)) return false;
        Program.RestartRequested = true;
        ExitThread();
        return true;
    }

    private void ShowUpdate(UpdateNotice? notice, bool balloonFree)
    {
        _update.Visible = notice is not null;
        if (notice is null) return;
        _update.Text = $"Update available: {notice.LatestVersion}…";
        if (!balloonFree || _announcedUpdate == notice.LatestVersion) return;
        _announcedUpdate = notice.LatestVersion;
        _icon.ShowBalloonTip(8000, Clip($"WatchLattice {notice.LatestVersion} is available", 63),
            Clip(notice.Installable
                ? $"You have {notice.CurrentVersion}. Open the dashboard to install it; nothing changes until you choose to."
                : $"You have {notice.CurrentVersion}. Open the dashboard for details.", 240),
            ToolTipIcon.Info);
    }

    private async Task InstallUpdateAsync()
    {
        if (_installing || _snapshot?.Update is not { Installable: true } notice) return;
        var hub = ReleaseLayout.FindHubExecutable(AppContext.BaseDirectory);
        if (hub is null)
        {
            MessageBox.Show(_window, "This tray is not installed next to the hub (…\\Hub and …\\Tray), so it cannot start the updater.\n\n"
                + "From an administrator prompt in the hub's folder, run:\nScanAlways.Protection.Service.exe --apply-update",
                "Install update", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var confirm = MessageBox.Show(_window, $"Install WatchLattice {notice.LatestVersion}? You have {notice.CurrentVersion}.\n\n"
            + "Windows will ask for administrator permission. The updater downloads the release from GitHub, checks its SHA-256 "
            + "checksum, and stops and restarts the hub service. Your appsettings.json is kept. If anything fails to verify, "
            + "nothing is changed.\n\nThe tray restarts when the update finishes.",
            "Install update", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
        if (confirm != DialogResult.Yes) return;

        _installing = true;
        _window?.SetInstalling(true);
        try
        {
            using var process = Process.Start(new ProcessStartInfo(hub)
            {
                UseShellExecute = true,
                Verb = "runas",
                Arguments = "--apply-update --pause-on-failure",
                WorkingDirectory = Path.GetDirectoryName(hub)!,
            }) ?? throw new InvalidOperationException("The updater did not start.");
            await process.WaitForExitAsync();
            switch ((UpdateOutcome)process.ExitCode)
            {
                case UpdateOutcome.Installed:
                    Program.RestartRequested = true;
                    ExitThread();
                    return;
                case UpdateOutcome.UpToDate:
                    MessageBox.Show(_window, "WatchLattice is already up to date.", "Install update", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    break;
                case UpdateOutcome.VerificationFailed:
                    MessageBox.Show(_window, "The download did not pass verification, so nothing was changed.", "Update not installed",
                        MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    break;
                default:
                    MessageBox.Show(_window, $"The update did not complete (code {process.ExitCode}). The updater window explained why.",
                        "Update not installed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    break;
            }
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == ErrorCancelled)
        {
            // The user declined the administrator prompt.
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException)
        {
            MessageBox.Show(_window, "The updater could not start: " + ex.Message, "Update not installed", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            _installing = false;
            if (!_exiting) _window?.SetInstalling(false);
        }
    }

    /// <summary>Reads the hub's activity file when it changed since <paramref name="stamp"/>.</summary>
    private (ActivitySnapshot? Snapshot, string? Problem, DateTime Stamp) ReadActivity(DateTime stamp)
    {
        var path = ActivitySnapshot.PathFor(_path);
        try
        {
            var written = File.GetLastWriteTimeUtc(path);
            if (!File.Exists(path)) return (null, "The hub has not written an activity log yet.", stamp);
            if (written == stamp) return (null, null, stamp);
            return (ActivitySnapshot.Read(path), null, written);
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or JsonException)
        {
            return (null, "Activity unavailable: " + ex.Message, DateTime.MinValue);
        }
    }

    private void OpenWindow(bool alerts = false)
    {
        var created = false;
        if (_window is null || _window.IsDisposed)
        {
            _window = new DashboardWindow(_path);
            _window.InstallRequested += async () => await InstallUpdateAsync();
            _window.SetInstalling(_installing);
            _activityStamp = DateTime.MinValue;
            created = true;
        }
        if (alerts) _window.ShowAlertsTab();
        UpdateWindow();
        _window.Show();
        if (_window.WindowState == FormWindowState.Minimized) _window.WindowState = FormWindowState.Normal;
        _window.Activate();
        // Fill the Activity tab now rather than at the next poll.
        if (created) _ = PollAsync();
    }

    private void UpdateWindow()
    {
        if (_window is { IsDisposed: false }) _window.UpdateSnapshot(_snapshot, _statusText);
    }

    protected override void ExitThreadCore()
    {
        _exiting = true;
        _timer.Stop();
        _timer.Dispose();
        _icon.Visible = false;
        _icon.Dispose();
        _menu.Dispose();
        _window?.Dispose();
        base.ExitThreadCore();
    }

    private static string Clip(string value, int length) => value.Length <= length ? value : value[..(length - 1)] + "…";
}

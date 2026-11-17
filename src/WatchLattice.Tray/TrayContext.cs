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
/// The icon's colour and shape follow <see cref="TrayStatus"/>; a critical
/// alert also opens <see cref="CriticalAlertWindow"/>, and the first start
/// shows <see cref="WelcomeWindow"/>.
/// </summary>
internal sealed class TrayContext : ApplicationContext
{
    private const int ErrorCancelled = 1223;
    private readonly string _path;
    private readonly NotifyIcon _icon;
    private readonly ContextMenuStrip _menu = new();
    private readonly ToolStripMenuItem _status = new("Waiting for hub…") { Enabled = false };
    private readonly ToolStripMenuItem _update = new() { Visible = false };
    private readonly ToolStripMenuItem _popUpCritical = new("Open a window for critical alerts") { CheckOnClick = true };
    private readonly TrayIcons _icons = new();
    private readonly AlertReviewStore _reviewStore = new();
    private TrayPreferences _preferences;
    private AlertReviewSet _review = AlertReviewSet.Empty;
    private CriticalAlertWindow? _critical;
    private WelcomeWindow? _welcome;
    private bool _welcomeChecked;
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
        (_preferences, _) = TrayPreferences.Load();
        _popUpCritical.Checked = _preferences.PopUpCriticalAlerts;
        _popUpCritical.CheckedChanged += (_, _) => SetPopUp(_popUpCritical.Checked);
        _update.Click += (_, _) => OpenWindow();
        _menu.Items.Add(_status);
        _menu.Items.Add(_update);
        _menu.Items.Add("Open dashboard", null, (_, _) => OpenWindow());
        _menu.Items.Add(new ToolStripSeparator());
        _menu.Items.Add(_popUpCritical);
        _menu.Items.Add("About WatchLattice…", null, (_, _) => ShowWelcome());
        _menu.Items.Add(new ToolStripSeparator());
        _menu.Items.Add("Exit tray companion", null, (_, _) => ExitThread());
        var waiting = TrayStatus.Evaluate(null, AlertReviewSet.Empty, DateTimeOffset.UtcNow);
        _icon = new NotifyIcon { Icon = _icons.For(waiting.Level), Text = waiting.Tooltip, ContextMenuStrip = _menu, Visible = true };
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
            var (snapshot, review, activity, activityProblem, newStamp) = await Task.Run(() =>
            {
                var review = _reviewStore.Refresh();
                var feed = AlertSnapshot.Read(_path);
                var (lines, problem, written) = watching ? ReadActivity(stamp) : (null, null, stamp);
                return (feed, review, lines, problem, written);
            });
            if (_exiting) return;
            _review = review;
            _activityStamp = newStamp;
            if (activity is not null || activityProblem is not null) _window?.UpdateActivity(activity, activityProblem);
            _snapshot = snapshot;
            var fresh = snapshot.IsFresh(DateTimeOffset.UtcNow);
            var running = snapshot.Modules.Count(m => m.State == ModuleRunState.Running);
            var attention = snapshot.Modules.Any(m => m.State is ModuleRunState.Failed or ModuleRunState.Restarting or ModuleRunState.Finished);
            _statusText = fresh ? $"Hub connected • {running} module(s) running" + (attention ? " • module needs attention" : "")
                : $"Hub offline or feed stale • last update {snapshot.HeartbeatAt.ToLocalTime():g}";
            _status.Text = fresh ? "Hub connected" : "Hub offline or feed stale";
            ShowStatus(TrayStatus.Evaluate(snapshot, review, DateTimeOffset.UtcNow));

            var alerts = _cursor.Observe(snapshot);
            _critical?.Prune(IsNew);
            var critical = alerts.Where(a => a.Severity == AlertSeverity.Critical && IsNew(a)).ToArray();
            if (critical.Length > 0 && _preferences.PopUpCriticalAlerts)
            {
                // The window replaces the balloon: it says more, and Focus assist can't hide it.
                ShowCritical(critical);
            }
            else if (alerts.Count > 0)
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
            // A critical alert from the last good read still shows red.
            ShowStatus(TrayStatus.Evaluate(_snapshot, _review, DateTimeOffset.UtcNow, ex.Message));
            UpdateWindow();
        }
        finally
        {
            _reading = false;
            if (!_exiting && !_welcomeChecked)
            {
                _welcomeChecked = true;
                if (!_preferences.WelcomeSeen) ShowWelcome();
            }
        }
    }

    private void ShowStatus(TrayStatus status)
    {
        _icon.Icon = _icons.For(status.Level);
        _icon.Text = status.Tooltip;
    }

    /// <summary>True while the user hasn't acknowledged or dismissed this occurrence.</summary>
    private bool IsNew(ProtectionAlert alert) =>
        _review.Find(AlertGrouping.KeyFor(alert)) is not { } mark || alert.At > mark.ReviewedThrough;

    private void ShowCritical(IReadOnlyList<ProtectionAlert> alerts)
    {
        if (_critical is null || _critical.IsDisposed)
        {
            _critical = new CriticalAlertWindow();
            _critical.DashboardRequested += () => OpenWindow(alerts: true);
            _critical.AcknowledgeRequested += async shown => await AcknowledgeAsync(shown);
            _critical.PopUpChanged += on => _popUpCritical.Checked = on;
        }
        _critical.Add(alerts, _preferences.PopUpCriticalAlerts);
    }

    /// <summary>Marks the window's alerts as seen, the same way the dashboard's Acknowledge does.</summary>
    private async Task AcknowledgeAsync(IReadOnlyList<ProtectionAlert> shown)
    {
        var groups = shown.GroupBy(AlertGrouping.KeyFor).Select(g => (g.Key, g.Max(a => a.At))).ToArray();
        try
        {
            _review = await Task.Run(() => _reviewStore.Update(set => set.Mark(groups, dismiss: false, DateTimeOffset.UtcNow)));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            if (_exiting) return;
            MessageBox.Show(_critical, ex.Message, "Could not save acknowledged alerts", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }
        if (_exiting) return;
        _critical?.Prune(IsNew);
        if (_snapshot is not null) ShowStatus(TrayStatus.Evaluate(_snapshot, _review, DateTimeOffset.UtcNow));
    }

    private void SetPopUp(bool on)
    {
        if (_preferences.PopUpCriticalAlerts == on) return;
        _preferences = _preferences with { PopUpCriticalAlerts = on };
        SavePreferences();
    }

    private void ShowWelcome()
    {
        if (_welcome is null || _welcome.IsDisposed)
        {
            _welcome = new WelcomeWindow(_icons);
            _welcome.DashboardRequested += () => OpenWindow();
            _welcome.FormClosed += (_, _) =>
            {
                if (_preferences.WelcomeSeen || _exiting) return;
                _preferences = _preferences with { WelcomeSeen = true };
                SavePreferences();
            };
        }
        _welcome.ShowModules(_snapshot);
        _welcome.Show();
        if (_welcome.WindowState == FormWindowState.Minimized) _welcome.WindowState = FormWindowState.Normal;
        _welcome.Activate();
    }

    private void SavePreferences()
    {
        if (_preferences.Save() is { } problem)
            _icon.ShowBalloonTip(8000, "WatchLattice", Clip(problem, 240), ToolTipIcon.Warning);
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
        var onDisk = ReleaseVersion.FromFile(Path.Join(AppContext.BaseDirectory, ReleaseLayout.TrayAssembly));
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
        _critical?.Dispose();
        _welcome?.Dispose();
        _icons.Dispose();
        base.ExitThreadCore();
    }

    private static string Clip(string value, int length) => value.Length <= length ? value : value[..(length - 1)] + "…";
}

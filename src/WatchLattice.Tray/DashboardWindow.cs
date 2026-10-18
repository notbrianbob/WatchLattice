using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using WatchLattice.Common.Activity;
using WatchLattice.Common.Alerts;
using WatchLattice.Common.Settings;
using WatchLattice.Persistence.Verification;

namespace WatchLattice.Tray;

/// <summary>
/// The dashboard: hub and module status, alerts, the hub's recent activity,
/// and its settings. It runs as the signed-in user and changes nothing itself;
/// changing a setting opens the elevated settings editor. Verify entry runs a
/// read-only persistence verification here, with the user's own rights.
/// </summary>
internal sealed class DashboardWindow : Form
{
    private const string WarningsFilter = "Warnings and errors";
    private const string ErrorsFilter = "Errors only";
    private const string AllFilter = "Everything";

    private readonly TabControl _tabs = new() { Dock = DockStyle.Fill };
    private readonly Label _status = new() { Dock = DockStyle.Top, Height = 34, Padding = new Padding(10, 10, 10, 0), AutoEllipsis = true };

    // Overview
    private readonly ListView _modules = NewList("Modules");
    private readonly Button _toggle = new() { Text = "Turn off…", AutoSize = true, Enabled = false, FlatStyle = FlatStyle.System };
    private readonly Button _editModules = new() { Text = "Change settings…", AutoSize = true, FlatStyle = FlatStyle.System };
    private readonly Label _modulesNote = new() { AutoSize = true, Margin = new Padding(0, 8, 0, 0) };

    // Alerts
    private readonly ListView _alerts = NewList("Recent alerts");
    private readonly TextBox _alertDetails = NewDetails("Selected alert details", "Select an alert to see its details.");
    private readonly Button _verifyEntry = new() { Text = "Verify entry", AutoSize = true, Enabled = false };
    private readonly Button _viewVerification = new() { Text = "View verification details…", AutoSize = true, Enabled = false };
    private readonly Label _verificationNote = new() { AutoSize = true, Margin = new Padding(12, 7, 0, 0), MaximumSize = new Size(640, 0) };
    private readonly CheckBox _groupRepeats = new() { Text = "Group repeats", AutoSize = true, Checked = true, Margin = new Padding(3, 6, 12, 0) };
    private readonly CheckBox _showDismissed = new() { Text = "Show dismissed", AutoSize = true, Margin = new Padding(3, 6, 12, 0) };
    private readonly Label _alertCount = new() { AutoSize = true, Margin = new Padding(12, 7, 0, 0), MaximumSize = new Size(640, 0) };
    private readonly Button _acknowledge = new() { Text = "Acknowledge", AutoSize = true, Enabled = false };
    private readonly Button _dismiss = new() { Text = "Dismiss", AutoSize = true, Enabled = false };
    private readonly Button _acknowledgeAll = new() { Text = "Acknowledge all", AutoSize = true, Enabled = false };

    // Activity
    private readonly ListView _activity = NewList("Hub activity");
    private readonly TextBox _activityDetails = NewDetails("Selected activity details", "Select a line to see all of it.");
    private readonly Label _activityLevelLabel = new() { Text = "Show:", AutoSize = true, Margin = new Padding(0, 7, 4, 0) };
    private readonly ComboBox _activityLevel = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 170 };
    private readonly TextBox _activitySearch = new() { Width = 260, PlaceholderText = "Filter by text", AccessibleName = "Filter activity" };
    private readonly Label _activityCount = new() { AutoSize = true, Margin = new Padding(12, 7, 0, 0) };

    // Settings
    private readonly ListView _settings = NewList("Current settings");
    private readonly Button _editSettings = new() { Text = "Change settings…", AutoSize = true, FlatStyle = FlatStyle.System };
    private readonly Button _refreshSettings = new() { Text = "Refresh", AutoSize = true };
    private readonly Label _settingsNote = new() { AutoSize = true, Margin = new Padding(12, 7, 0, 0), MaximumSize = new Size(640, 0) };

    // Update banner
    private readonly FlowLayoutPanel _update = new()
    {
        Dock = DockStyle.Top, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, WrapContents = true,
        Padding = new Padding(10, 8, 10, 4), Visible = false, AccessibleName = "Update available",
    };
    private readonly Label _updateText = new() { AutoSize = true, MaximumSize = new Size(620, 0), Margin = new Padding(0, 7, 12, 0) };
    private readonly Button _install = new() { Text = "Install update", AutoSize = true };
    private readonly Button _notes = new() { Text = "Release notes", AutoSize = true };

    private string _displayedAlerts = "";
    private IReadOnlyList<AlertGroup> _alertRows = Array.Empty<AlertGroup>();
    private IReadOnlyList<ActivityEntry> _activityEntries = Array.Empty<ActivityEntry>();
    private string? _activityProblem;
    private AlertSnapshot? _snapshot;
    private UpdateNotice? _notice;
    private SettingsDescription? _description;
    private string? _settingsProblem;
    private bool _installing;
    private bool _loadingSettings;
    private bool _editing;

    // Verification findings for persistence alerts
    private readonly VerificationFindings _findings;
    private readonly Dictionary<Guid, VerificationRecord> _verification = new();
    private readonly HashSet<Guid> _verifying = new();
    private readonly Dictionary<Guid, VerificationWindow> _verificationWindows = new();
    private readonly CancellationTokenSource _closing = new();
    private PersistenceVerificationEngine? _engine;
    private string[]? _engineFamiliar;
    private bool _refreshingFindings;

    // Acknowledged and dismissed alerts, kept in the user's own profile
    private readonly AlertReviewStore _reviewStore = new();
    private AlertReviewSet _review = AlertReviewSet.Empty;
    private bool _refreshingReview;
    private bool _savingReview;
    private Font? _bold;

    /// <summary>The user chose Install update; the tray confirms and starts the elevated updater.</summary>
    public event Action? InstallRequested;

    public DashboardWindow(string path)
    {
        _findings = new VerificationFindings(VerificationStore.PathForFeed(path));
        Text = "WatchLattice";
        Icon = SystemIcons.Shield;
        Size = new Size(1040, 700);
        MinimumSize = new Size(720, 480);
        StartPosition = FormStartPosition.CenterScreen;
        AutoScaleMode = AutoScaleMode.Dpi;

        _tabs.TabPages.Add(BuildOverview());
        _tabs.TabPages.Add(BuildAlerts());
        _tabs.TabPages.Add(BuildActivity());
        _tabs.TabPages.Add(BuildSettings());
        _tabs.SelectedIndexChanged += async (_, _) =>
        {
            if (_tabs.SelectedTab?.Text == "Settings" && _description is null) await LoadSettingsAsync();
        };

        Controls.Add(_tabs);
        Controls.Add(_status);
        _updateText.Font = new Font(Font, FontStyle.Bold);
        _install.Click += (_, _) => InstallRequested?.Invoke();
        _notes.Click += (_, _) => OpenReleaseNotes();
        _update.Controls.AddRange(new Control[] { _updateText, _install, _notes });
        Controls.Add(_update);
        Controls.Add(new TextBox
        {
            Dock = DockStyle.Bottom, ReadOnly = true, Text = "Feed: " + path,
            AccessibleName = "Alert feed path",
        });
        HandleCreated += (_, _) =>
        {
            Shield(_toggle);
            Shield(_editModules);
            Shield(_editSettings);
        };
        Shown += async (_, _) => await LoadSettingsAsync();
        FormClosed += (_, _) =>
        {
            _closing.Cancel();
            _bold?.Dispose();
        };
    }

    public void ShowAlertsTab() => _tabs.SelectedIndex = 1;

    private TabPage BuildOverview()
    {
        _modules.Columns.Add("Module", 220);
        _modules.Columns.Add("Running state", 110);
        _modules.Columns.Add("Setting", 80);
        _modules.Columns.Add("What it does", 560);
        _modules.SelectedIndexChanged += (_, _) => UpdateToggle();
        _modules.DoubleClick += async (_, _) => await EditAsync(SelectedModule(), toggle: false);
        _toggle.Click += async (_, _) => await EditAsync(SelectedModule(), toggle: true);
        _editModules.Click += async (_, _) => await EditAsync(SelectedModule() ?? "Modules", toggle: false);

        var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, Padding = new Padding(6), WrapContents = true };
        buttons.Controls.AddRange(new Control[] { _toggle, _editModules, _modulesNote });
        _modulesNote.Text = "Changes need administrator permission: Windows asks once when the settings editor opens.";
        var page = new TabPage("Overview");
        page.Controls.Add(_modules);
        page.Controls.Add(buttons);
        page.Controls.Add(new Label
        {
            Dock = DockStyle.Top, Height = 28, Padding = new Padding(6, 8, 6, 0),
            Text = "Running describes the module's process state, not a guarantee that protection is healthy. Check Alerts for problems it found.",
        });
        return page;
    }

    private TabPage BuildAlerts()
    {
        _alerts.Columns.Add("Last seen", 140);
        _alerts.Columns.Add("Severity", 75);
        _alerts.Columns.Add("Module", 120);
        _alerts.Columns.Add("Alert", 330);
        _alerts.Columns.Add("Count", 55, HorizontalAlignment.Right);
        _alerts.Columns.Add("Status", 105);
        _alerts.Columns.Add("Verification", 130);
        _alerts.MultiSelect = true;
        _alerts.SelectedIndexChanged += (_, _) => ShowAlertDetails();
        _alerts.DoubleClick += (_, _) => ViewVerification();
        _alerts.KeyDown += async (_, e) =>
        {
            if (e.KeyCode == Keys.Delete && SelectedRows().Any(r => r.State != AlertReviewState.Dismissed))
                await ReviewSelectedAsync(dismiss: true);
            else if (e.KeyCode == Keys.A && e.Control) { foreach (ListViewItem item in _alerts.Items) item.Selected = true; }
        };
        _verifyEntry.Click += async (_, _) => { if (SelectedAlert() is { } alert) await VerifyAsync(alert); };
        _viewVerification.Click += (_, _) => ViewVerification();
        _verificationNote.Text = "Verify entry checks a changed scheduled task's current state without running it, then keeps the result with the alert.";
        _groupRepeats.CheckedChanged += (_, _) => ShowAlerts();
        _showDismissed.CheckedChanged += (_, _) => ShowAlerts();
        _acknowledge.Click += async (_, _) => await ReviewSelectedAsync(dismiss: false);
        _dismiss.Click += async (_, _) => await ReviewSelectedAsync(dismiss: true);
        _acknowledgeAll.Click += async (_, _) => await AcknowledgeAllAsync();

        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(6), WrapContents = true };
        bar.Controls.AddRange(new Control[] { _groupRepeats, _showDismissed, _acknowledge, _dismiss, _acknowledgeAll, _alertCount });
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, Padding = new Padding(6), WrapContents = true };
        buttons.Controls.AddRange(new Control[] { _verifyEntry, _viewVerification, _verificationNote });
        var page = new TabPage("Alerts");
        page.Controls.Add(Split(_alerts, _alertDetails));
        page.Controls.Add(bar);
        page.Controls.Add(buttons);
        return page;
    }

    private TabPage BuildActivity()
    {
        _activity.Columns.Add("Time", 150);
        _activity.Columns.Add("Level", 80);
        _activity.Columns.Add("Source", 170);
        _activity.Columns.Add("Message", 560);
        _activity.SelectedIndexChanged += (_, _) => ShowActivityDetails();
        _activityLevel.Items.AddRange(new object[] { AllFilter, WarningsFilter, ErrorsFilter });
        _activityLevel.SelectedIndex = 0;
        _activityLevel.AccessibleName = "Show";
        _activityLevel.SelectedIndexChanged += (_, _) => ShowActivity(force: true);
        _activitySearch.TextChanged += (_, _) => ShowActivity(force: true);

        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(6), WrapContents = true };
        bar.Controls.AddRange(new Control[]
        {
            _activityLevelLabel, _activityLevel, _activitySearch, _activityCount,
        });
        var page = new TabPage("Activity");
        page.Controls.Add(Split(_activity, _activityDetails));
        page.Controls.Add(bar);
        return page;
    }

    private TabPage BuildSettings()
    {
        _settings.Columns.Add("Setting", 280);
        _settings.Columns.Add("Value", 600);
        _settings.ShowGroups = true;
        _settings.DoubleClick += async (_, _) => await EditAsync(SelectedSettingsSection(), toggle: false);
        _editSettings.Click += async (_, _) => await EditAsync(SelectedSettingsSection(), toggle: false);
        _refreshSettings.Click += async (_, _) => await LoadSettingsAsync();
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(6), WrapContents = true };
        bar.Controls.AddRange(new Control[] { _editSettings, _refreshSettings, _settingsNote });
        var page = new TabPage("Settings");
        page.Controls.Add(_settings);
        page.Controls.Add(bar);
        return page;
    }

    public void UpdateSnapshot(AlertSnapshot? snapshot, string status)
    {
        _snapshot = snapshot;
        _status.Text = status;
        ShowUpdate(snapshot?.Update);
        ShowModules();
        if (snapshot is null) return;
        _ = RefreshFindingsAsync();
        _ = RefreshReviewAsync();
        ShowAlerts();
    }

    /// <summary>
    /// Fills the alert list: repeats of one alert as a single row (unless
    /// Group repeats is off), with what the user acknowledged greyed out and
    /// what they dismissed hidden. Only the display changes; the feed and the
    /// Event Log keep every alert.
    /// </summary>
    private void ShowAlerts()
    {
        var all = AlertGrouping.Build(_snapshot?.Alerts ?? Array.Empty<ProtectionAlert>(), _review, _groupRepeats.Checked);
        var rows = all.Where(g => _showDismissed.Checked || g.State != AlertReviewState.Dismissed).ToArray();
        var newRows = all.Count(g => g.State == AlertReviewState.New);
        var hidden = all.Count - rows.Length;
        var total = _snapshot?.Alerts.Count ?? 0;
        _alertCount.Text = _reviewStore.Problem ?? $"{rows.Length} row(s) for {total} alert(s) • {newRows} new"
            + (hidden > 0 ? $" • {hidden} dismissed and hidden" : "");
        _tabs.TabPages[1].Text = newRows > 0 ? $"Alerts ({newRows} new)" : "Alerts";
        _acknowledgeAll.Enabled = !_savingReview && rows.Any(g => g.State == AlertReviewState.New);

        var signature = string.Join('|', rows.Select(g => $"{g.Latest.Id}:{g.Count}:{g.State}:{g.NewCount}"));
        if (signature == _displayedAlerts)
        {
            UpdateReviewButtons();
            return;
        }
        // Keep the selection by the newest alert's id, or by group when a repeat replaced it.
        var selected = SelectedRows().SelectMany(g => new[] { g.Latest.Id.ToString(), g.Key }).ToHashSet();
        _alertRows = rows;
        _alerts.BeginUpdate();
        _alerts.Items.Clear();
        foreach (var row in rows)
        {
            var alert = row.Latest;
            var item = new ListViewItem(new[]
            {
                row.LastSeen.ToLocalTime().ToString("g"), row.Severity.ToString(), alert.Module, alert.Title,
                row.Count.ToString(), StatusText(row), "",
            })
            {
                Tag = row, UseItemStyleForSubItems = false,
            };
            var reviewed = row.State != AlertReviewState.New;
            for (var i = 0; i < 6; i++) item.SubItems[i].ForeColor = reviewed ? SystemColors.GrayText : SystemColors.WindowText;
            if (!reviewed) item.SubItems[5].Font = _bold ??= new Font(_alerts.Font, FontStyle.Bold);
            ShowVerificationCell(item);
            _alerts.Items.Add(item);
            if (selected.Contains(alert.Id.ToString()) || (_groupRepeats.Checked && selected.Contains(row.Key))) item.Selected = true;
        }
        _alerts.EndUpdate();
        _displayedAlerts = signature;
        if (rows.Length == 0)
            _alertDetails.Text = total == 0 ? "No alerts have been recorded yet."
                : "Every alert has been dismissed. Turn on Show dismissed to see them again.";
        else if (_alerts.SelectedItems.Count == 0) _alertDetails.Text = "Select an alert to see its details.";
        else ShowAlertDetails();
        UpdateVerificationButtons();
        UpdateReviewButtons();
    }

    private static string StatusText(AlertGroup row) => row.State switch
    {
        AlertReviewState.New when row.NewCount < row.Count => $"{row.NewCount} new",
        AlertReviewState.New => "New",
        AlertReviewState.Acknowledged => "Acknowledged",
        _ => "Dismissed",
    };

    private AlertGroup[] SelectedRows() => _alerts.SelectedItems.Cast<ListViewItem>().Select(i => i.Tag).OfType<AlertGroup>().ToArray();

    private void UpdateReviewButtons()
    {
        var rows = SelectedRows();
        var restore = rows.Length > 0 && rows.All(r => r.State == AlertReviewState.Dismissed);
        _acknowledge.Enabled = !_savingReview && rows.Any(r => r.State != AlertReviewState.Acknowledged);
        _dismiss.Enabled = !_savingReview && rows.Length > 0;
        _dismiss.Text = restore ? "Show again" : "Dismiss";
    }

    /// <summary>Re-reads the review file off the UI thread, in case another dashboard changed it.</summary>
    private async Task RefreshReviewAsync()
    {
        if (_refreshingReview || _savingReview || IsDisposed) return;
        _refreshingReview = true;
        try
        {
            var review = await Task.Run(() => _reviewStore.Refresh());
            if (IsDisposed || ReferenceEquals(review, _review)) return;
            _review = review;
            ShowAlerts();
        }
        finally { _refreshingReview = false; }
    }

    /// <summary>
    /// Acknowledges or dismisses the selected rows through their newest alert,
    /// or shows dismissed rows again. A later repeat makes a row new again.
    /// </summary>
    private async Task ReviewSelectedAsync(bool dismiss)
    {
        var rows = SelectedRows();
        if (rows.Length == 0) return;
        if (dismiss && rows.All(r => r.State == AlertReviewState.Dismissed))
            await SaveReviewAsync(set => set.Restore(rows.Select(r => r.Key), DateTimeOffset.UtcNow));
        else
            await SaveReviewAsync(set => set.Mark(rows.Select(r => (r.Key, r.LastSeen)), dismiss, DateTimeOffset.UtcNow));
    }

    private async Task AcknowledgeAllAsync()
    {
        var rows = _alertRows.Where(r => r.State == AlertReviewState.New).ToArray();
        if (rows.Length == 0) return;
        await SaveReviewAsync(set => set.Mark(rows.Select(r => (r.Key, r.LastSeen)), dismiss: false, DateTimeOffset.UtcNow));
    }

    private async Task SaveReviewAsync(Func<AlertReviewSet, AlertReviewSet> change)
    {
        if (_savingReview) return;
        _savingReview = true;
        UpdateReviewButtons();
        try
        {
            _review = await Task.Run(() => _reviewStore.Update(change));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            if (IsDisposed) return;
            MessageBox.Show(this, ex.Message, "Could not save acknowledged alerts", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        finally { _savingReview = false; }
        if (!IsDisposed) ShowAlerts();
    }

    /// <summary>New activity lines from the hub, or why they cannot be read.</summary>
    public void UpdateActivity(ActivitySnapshot? snapshot, string? problem)
    {
        if (snapshot is not null) _activityEntries = snapshot.Entries;
        _activityProblem = problem;
        ShowActivity(force: snapshot is not null);
    }

    private void ShowModules()
    {
        var states = _snapshot?.Modules.ToDictionary(m => m.Id, StringComparer.OrdinalIgnoreCase)
            ?? new Dictionary<string, ModuleStatus>(StringComparer.OrdinalIgnoreCase);
        var rows = _description?.Modules.Select(m => (m.Id, Name: m.DisplayName, m.Description)).ToList()
            ?? new List<(string Id, string Name, string Description)>();
        foreach (var id in states.Keys.Where(id => rows.All(r => !string.Equals(r.Id, id, StringComparison.OrdinalIgnoreCase))))
            rows.Add((id, id, ""));

        var selected = SelectedModule();
        _modules.BeginUpdate();
        _modules.Items.Clear();
        foreach (var row in rows.OrderBy(r => r.Name, StringComparer.CurrentCultureIgnoreCase))
        {
            var state = states.TryGetValue(row.Id, out var status) ? status.State.ToString() : _snapshot is null ? "Unknown" : "Not reported";
            var enabled = ModuleEnabled(row.Id) switch { true => "On", false => "Off", null => "?" };
            var item = new ListViewItem(new[] { row.Name, state, enabled, row.Description }) { Tag = row.Id };
            if (status?.State is ModuleRunState.Failed or ModuleRunState.Restarting or ModuleRunState.Finished)
                item.ForeColor = Color.Firebrick;
            _modules.Items.Add(item);
            if (row.Id == selected) item.Selected = true;
        }
        if (rows.Count == 0)
            _modules.Items.Add(new ListViewItem(new[] { _snapshot is null ? "Start the WatchLattice hub to see its modules." : "No modules reported.", "", "", "" }));
        _modules.EndUpdate();
        UpdateToggle();
    }

    private bool? ModuleEnabled(string id)
    {
        if (_description is null) return null;
        var field = _description.Sections.SelectMany(s => s.Fields)
            .FirstOrDefault(f => string.Equals(f.Path, $"Modules:{id}:Enabled", StringComparison.OrdinalIgnoreCase));
        if (field is null) return null;
        return SettingValues.Effective(_description.Values, field) is JsonValue v
            && (v.TryGetValue<bool>(out var on) ? on : v.TryGetValue<string>(out var s) && bool.TryParse(s, out var p) && p);
    }

    private string? SelectedModule() => _modules.SelectedItems.Count == 0 ? null : _modules.SelectedItems[0].Tag as string;

    private string? SelectedSettingsSection() => _settings.SelectedItems.Count == 0 ? null : _settings.SelectedItems[0].Group?.Name;

    private void UpdateToggle()
    {
        var id = SelectedModule();
        var enabled = id is null ? null : ModuleEnabled(id);
        var available = HubSettings.HubExecutable is not null && !_editing;
        _toggle.Enabled = available && enabled is not null;
        _toggle.Text = enabled == false ? "Turn on…" : "Turn off…";
        _editModules.Enabled = available;
        _editSettings.Enabled = available && _description is not null;
    }

    private void ShowActivity(bool force)
    {
        var level = _activityLevel.SelectedItem as string;
        var minimum = level == ErrorsFilter ? LogLevel.Error : level == WarningsFilter ? LogLevel.Warning : LogLevel.Information;
        var search = _activitySearch.Text.Trim();
        var shown = _activityEntries.Where(e => e.Level >= minimum)
            .Where(e => search.Length == 0 || e.Message.Contains(search, StringComparison.CurrentCultureIgnoreCase)
                || e.Source.Contains(search, StringComparison.CurrentCultureIgnoreCase))
            .Reverse()
            .ToArray();
        _activityCount.Text = _activityProblem ?? $"{shown.Length} of {_activityEntries.Count} line(s)";
        if (!force) return;
        _activity.BeginUpdate();
        _activity.Items.Clear();
        foreach (var entry in shown)
        {
            var item = new ListViewItem(new[] { entry.At.ToLocalTime().ToString("g"), LevelName(entry.Level), entry.Source, FirstLine(entry.Message) }) { Tag = entry };
            if (entry.Level >= LogLevel.Error) item.ForeColor = Color.Firebrick;
            else if (entry.Level == LogLevel.Warning) item.ForeColor = Color.DarkGoldenrod;
            _activity.Items.Add(item);
        }
        _activity.EndUpdate();
        if (_activityEntries.Count == 0)
            _activityDetails.Text = _activityProblem ?? "The hub has not reported any activity yet. Hubs older than v0.3.0 do not report it.";
    }

    private void ShowActivityDetails()
    {
        if (_activity.SelectedItems.Count == 0 || _activity.SelectedItems[0].Tag is not ActivityEntry entry) return;
        _activityDetails.Text = $"{entry.At.ToLocalTime():F} • {LevelName(entry.Level)} • {entry.Source}\r\n\r\n" + entry.Message.Replace("\n", "\r\n");
    }

    private async Task LoadSettingsAsync()
    {
        if (_loadingSettings) return;
        if (HubSettings.HubExecutable is null)
        {
            _settingsProblem = HubSettings.NotInstalledMessage;
            ShowSettings();
            return;
        }
        _loadingSettings = true;
        _settingsNote.Text = "Reading the hub's settings…";
        try
        {
            _description = await HubSettings.DescribeAsync();
            _settingsProblem = null;
        }
        catch (Exception ex) when (ex is InvalidOperationException or InvalidDataException or TimeoutException
            or System.ComponentModel.Win32Exception or System.Text.Json.JsonException or IOException)
        {
            _settingsProblem = "The hub's settings could not be read: " + ex.Message;
        }
        finally { _loadingSettings = false; }
        if (IsDisposed) return;
        ShowSettings();
        ShowModules();
    }

    private void ShowSettings()
    {
        _settings.BeginUpdate();
        _settings.Items.Clear();
        _settings.Groups.Clear();
        if (_description is not null)
        {
            foreach (var section in _description.Sections)
            {
                var group = new ListViewGroup(section.Path, section.Title);
                _settings.Groups.Add(group);
                foreach (var field in section.Fields)
                {
                    var inFile = SettingValues.TryGet(_description.Values, field.Path, out var value);
                    var text = SettingValues.Format(field, inFile ? value : field.Default).Replace(Environment.NewLine, "; ");
                    if (text.Length == 0) text = field.Nullable ? "(not set)" : "(empty)";
                    if (!inFile) text += "  (built-in default)";
                    if (field.Locked) text += "  (locked)";
                    _settings.Items.Add(new ListViewItem(new[] { field.Label, text }, group) { ToolTipText = field.Path });
                }
            }
        }
        _settings.ShowItemToolTips = true;
        _settings.EndUpdate();
        _settingsNote.Text = _settingsProblem ?? (_description is null ? ""
            : "Read-only here. Change settings… asks Windows for administrator permission once, then opens the editor. "
              + "Each save keeps a backup in the hub's settings-backups folder.");
        UpdateToggle();
    }

    private async Task EditAsync(string? section, bool toggle)
    {
        if (_editing) return;
        if (HubSettings.HubExecutable is null)
        {
            MessageBox.Show(this, HubSettings.NotInstalledMessage, "WatchLattice settings", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        var module = toggle ? section : null;
        // A module row opens that module's own page, when it has one.
        if (section is not null && _description?.Sections.Any(s => string.Equals(s.Path, section, StringComparison.OrdinalIgnoreCase)) != true)
            section = "Modules";
        if (toggle) section = "Modules";

        _editing = true;
        UpdateToggle();
        try
        {
            // The editor is a separate elevated process; this window stays unprivileged.
            if (await HubSettings.OpenEditorElevatedAsync(this, section, module)) await LoadSettingsAsync();
        }
        finally
        {
            _editing = false;
            if (!IsDisposed) UpdateToggle();
        }
    }

    public void SetInstalling(bool installing)
    {
        _installing = installing;
        _install.Enabled = !installing;
        _install.Text = installing ? "Installing…" : "Install update";
    }

    private void ShowUpdate(UpdateNotice? notice)
    {
        _notice = notice;
        _update.Visible = notice is not null;
        if (notice is null) return;
        _updateText.Text = notice.Installable
            ? $"Update available: WatchLattice {notice.LatestVersion} (you have {notice.CurrentVersion})."
            : $"WatchLattice {notice.LatestVersion} is available (you have {notice.CurrentVersion}). {notice.Problem}";
        _install.Visible = notice.Installable;
        _install.Enabled = !_installing;
        _notes.Visible = notice.TryGetReleasePage(out _);
    }

    private void OpenReleaseNotes()
    {
        // Only an https link on github.com is opened, in the default browser.
        if (_notice is null || !_notice.TryGetReleasePage(out var page)) return;
        try { Process.Start(new ProcessStartInfo(page.AbsoluteUri) { UseShellExecute = true })?.Dispose(); }
        catch (System.ComponentModel.Win32Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Could not open the release page", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private void ShowAlertDetails()
    {
        UpdateVerificationButtons();
        UpdateReviewButtons();
        var rows = SelectedRows();
        if (rows.Length > 1)
        {
            _alertDetails.Text = $"{rows.Length} rows selected ({rows.Sum(r => r.Count)} alerts). Acknowledge or Dismiss applies to all of them.";
            return;
        }
        if (rows.Length == 0) return;
        var row = rows[0];
        var alert = row.Latest;
        _alertDetails.Text = $"{alert.Title}\r\n{alert.At.ToLocalTime():F} • {alert.Module} • {alert.Severity}\r\nCode: {alert.Code}\r\n"
            + (alert.Resource is null ? "" : $"Source: {alert.Resource}\r\n") + "\r\n" + alert.Message.Replace("\n", "\r\n")
            + VerificationSummary(alert) + Occurrences(row);
    }

    /// <summary>The details pane's list of a grouped row's earlier alerts.</summary>
    private static string Occurrences(AlertGroup row)
    {
        if (row.Count < 2) return "";
        const int Shown = 25;
        var text = new System.Text.StringBuilder()
            .Append($"\r\n\r\nREPEATS\r\nSeen {row.Count} times, first {row.FirstSeen.ToLocalTime():g}, last {row.LastSeen.ToLocalTime():g}. ")
            .Append("The details above are from the newest. Earlier:\r\n");
        foreach (var earlier in row.Alerts.Skip(1).Take(Shown))
            text.Append($"  {earlier.At.ToLocalTime():g} • {earlier.Severity} • {earlier.Title}\r\n");
        if (row.Count - 1 > Shown) text.Append($"  …and {row.Count - 1 - Shown} more. Turn off Group repeats to see each one.\r\n");
        return text.ToString();
    }

    private ProtectionAlert? SelectedAlert() =>
        _alerts.SelectedItems.Count == 1 && _alerts.SelectedItems[0].Tag is AlertGroup row ? row.Latest : null;

    private VerificationRecord? RecordFor(ProtectionAlert alert) =>
        VerificationFindings.LinkedAlertId(alert) is { } id && _verification.TryGetValue(id, out var record) ? record : null;

    private bool IsVerifying(ProtectionAlert alert) => VerificationFindings.LinkedAlertId(alert) is { } id && _verifying.Contains(id);

    /// <summary>The verification part of the details pane, with the logged and the current state named apart.</summary>
    private string VerificationSummary(ProtectionAlert alert)
    {
        if (VerificationFindings.LinkedAlertId(alert) is null) return "";
        var text = "\r\n\r\nVERIFICATION\r\n";
        if (IsVerifying(alert)) return text + "Checking the entry's current state now. This only reads; nothing is run or changed.";
        if (RecordFor(alert) is not { } record)
            return text + (PersistenceVerificationCoordinator.IsEntryAlert(alert.Code)
                ? "No evidence was stored for this alert, so it cannot be verified here. Alerts from before v0.3.0 and removed entries have none."
                : "The findings this alert refers to are no longer stored.");
        if (record.Latest is not { } run)
            return text + "Not verified yet. Choose Verify entry to check the current state against the evidence logged with the alert.";
        text += $"{VerificationFindings.OutcomeText(run.Outcome)} ({run.Trigger.ToString().ToLowerInvariant()}, {run.CompletedAt.ToLocalTime():g}, as {run.CheckedAs}).\r\n{run.Summary}\r\n";
        foreach (var check in run.Checks.Where(c => c.Status != CheckStatus.Pass))
            text += $"  [{check.Status}] {check.Title}: {check.Detail}\r\n";
        if (run.LoggedChanges.Count > 0)
            text += "Logged change (at alert time): " + string.Join(", ", run.LoggedChanges.Select(c => c.Field)) + "\r\n";
        if (run.ChangesSinceAlert.Count > 0)
            text += "Changed since the alert: " + string.Join(", ", run.ChangesSinceAlert.Select(c => c.Field)) + "\r\n";
        return text + "View verification details… shows every check and the evidence.";
    }

    private void ShowVerificationCell(ListViewItem item)
    {
        if (item.Tag is not AlertGroup row || item.SubItems.Count < 7) return;
        var alert = row.Latest;
        var cell = item.SubItems[6];
        var record = RecordFor(alert);
        cell.ForeColor = SystemColors.WindowText;
        if (VerificationFindings.LinkedAlertId(alert) is null) cell.Text = "";
        else if (IsVerifying(alert)) cell.Text = "Verifying…";
        else if (record is null) cell.Text = PersistenceVerificationCoordinator.IsEntryAlert(alert.Code) ? "No evidence" : "";
        else if (record.Latest is not { } run) cell.Text = "Not verified";
        else
        {
            cell.Text = VerificationFindings.OutcomeText(run.Outcome) + (run.Trigger == VerificationTrigger.Manual ? " (manual)" : "");
            cell.ForeColor = VerificationWindow.OutcomeColor(run.Outcome);
        }
    }

    private void UpdateVerificationButtons()
    {
        var alert = SelectedAlert();
        var record = alert is null ? null : RecordFor(alert);
        _verifyEntry.Enabled = alert is not null && record is not null && !IsVerifying(alert);
        _viewVerification.Enabled = record is not null;
        if (_findings.Problem is { } problem) _verificationNote.Text = problem;
    }

    /// <summary>Re-reads the stored findings off the UI thread and updates the Verification column.</summary>
    private async Task RefreshFindingsAsync()
    {
        if (_refreshingFindings || IsDisposed) return;
        _refreshingFindings = true;
        try
        {
            var alerts = _snapshot?.Alerts.ToArray() ?? Array.Empty<ProtectionAlert>();
            var records = await Task.Run(() =>
            {
                _findings.Refresh();
                return alerts.Where(a => VerificationFindings.LinkedAlertId(a) is not null)
                    .Select(a => (Id: VerificationFindings.LinkedAlertId(a)!.Value, Record: _findings.For(a)))
                    .DistinctBy(x => x.Id)
                    .ToArray();
            });
            if (IsDisposed) return;
            var changed = false;
            foreach (var (id, record) in records)
            {
                if (record is null) changed |= _verification.Remove(id);
                else if (!_verification.TryGetValue(id, out var known) || !SameRuns(known, record))
                {
                    _verification[id] = record;
                    changed = true;
                    if (_verificationWindows.TryGetValue(id, out var window) && !window.IsDisposed) window.ShowRecord(record);
                }
            }
            if (changed) ShowVerificationState();
            else UpdateVerificationButtons();
        }
        finally { _refreshingFindings = false; }
    }

    private static bool SameRuns(VerificationRecord a, VerificationRecord b) =>
        a.Runs.Select(r => r.Id).SequenceEqual(b.Runs.Select(r => r.Id));

    private void ShowVerificationState()
    {
        _alerts.BeginUpdate();
        foreach (ListViewItem item in _alerts.Items) ShowVerificationCell(item);
        _alerts.EndUpdate();
        ShowAlertDetails();
    }

    /// <summary>
    /// Verifies the alert's entry again now. It runs here as the signed-in
    /// user (no elevation), only reads, and keeps the result in the user's
    /// own findings file; the hub's findings are never written from here.
    /// </summary>
    private async Task VerifyAsync(ProtectionAlert alert)
    {
        if (VerificationFindings.LinkedAlertId(alert) is not { } id || !_verifying.Add(id)) return;
        _verificationWindows.TryGetValue(id, out var window);
        window?.SetVerifying(true);
        ShowVerificationState();
        string? problem = null;
        try
        {
            var engine = Engine();
            await Task.Run(() => _findings.VerifyAsync(alert, engine, _closing.Token));
        }
        catch (OperationCanceledException) when (_closing.IsCancellationRequested) { return; }
        catch (Exception ex) when (ex is InvalidOperationException or IOException or UnauthorizedAccessException or System.Text.Json.JsonException)
        {
            problem = "Verification could not be completed: " + ex.Message;
        }
        finally { _verifying.Remove(id); }
        if (IsDisposed) return;
        if (window is { IsDisposed: false }) window.SetVerifying(false, problem);
        if (problem is not null) _verificationNote.Text = problem;
        ShowVerificationState();
        await RefreshFindingsAsync();
    }

    /// <summary>The engine, built with the hub's familiar publishers so manual and automatic runs judge alike.</summary>
    private PersistenceVerificationEngine Engine()
    {
        var familiar = _description is not null && SettingValues.Get(_description.Values, "Persistence:FamiliarPublishers") is JsonArray list
            ? list.Select(n => n is JsonValue v && v.TryGetValue<string>(out var s) ? s : null).OfType<string>().ToArray()
            : Array.Empty<string>();
        if (_engine is null || _engineFamiliar is null || !_engineFamiliar.SequenceEqual(familiar))
        {
            _engine = VerificationFactory.CreateEngine(familiar);
            _engineFamiliar = familiar;
        }
        return _engine;
    }

    private void ViewVerification()
    {
        if (SelectedAlert() is not { } alert || RecordFor(alert) is not { } record) return;
        if (_verificationWindows.TryGetValue(record.AlertId, out var open) && !open.IsDisposed)
        {
            open.Activate();
            return;
        }
        var window = new VerificationWindow(alert, record, () => VerifyAsync(alert));
        window.FormClosed += (_, _) => _verificationWindows.Remove(record.AlertId);
        _verificationWindows[record.AlertId] = window;
        if (IsVerifying(alert)) window.SetVerifying(true);
        window.Show(this);
    }

    private static ListView NewList(string name) => new()
    {
        Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, MultiSelect = false,
        HideSelection = false, AccessibleName = name,
    };

    private static TextBox NewDetails(string name, string text) => new()
    {
        Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both,
        AccessibleName = name, Text = text,
    };

    private static SplitContainer Split(Control top, Control bottom)
    {
        var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, Size = new Size(900, 420), SplitterDistance = 280 };
        split.Panel1.Controls.Add(top);
        split.Panel2.Controls.Add(bottom);
        return split;
    }

    private static string LevelName(LogLevel level) => level switch
    {
        LogLevel.Information => "Info",
        LogLevel.Critical => "Critical",
        _ => level.ToString(),
    };

    private static string FirstLine(string text)
    {
        var end = text.IndexOfAny(new[] { '\r', '\n' });
        return end < 0 ? text : text[..end] + " …";
    }

    // Shows the Windows shield on buttons that lead to an administrator prompt.
    private static void Shield(Button button) => SendMessage(button.Handle, BcmSetShield, IntPtr.Zero, new IntPtr(1));

    private const int BcmSetShield = 0x160C;

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr SendMessage(IntPtr window, int message, IntPtr wParam, IntPtr lParam);
}

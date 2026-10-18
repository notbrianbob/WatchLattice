using System.Text.Json.Nodes;
using WatchLattice.Common.Alerts;
using WatchLattice.Common.Settings;

namespace WatchLattice.Tray;

/// <summary>
/// The settings editor. It runs as its own elevated copy of the tray
/// (<c>--edit-settings</c>), started through Windows' administrator prompt the
/// first time someone wants to change a setting, so only an administrator can
/// change anything. Edits are checked as you type; Save hands them to the hub,
/// which checks them again, keeps a backup, saves, and restarts the service.
/// </summary>
internal sealed class SettingsEditorWindow : Form
{
    private readonly ListBox _sections = new() { Dock = DockStyle.Left, Width = 230, IntegralHeight = false, AccessibleName = "Settings sections" };
    private readonly Panel _page = new() { Dock = DockStyle.Fill, AutoScroll = true, Padding = new Padding(12, 8, 12, 8) };
    private readonly Label _summary = new() { Dock = DockStyle.Top, Height = 24, Padding = new Padding(4, 4, 4, 0), AutoEllipsis = true };
    private readonly TextBox _output = new()
    {
        Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical,
        AccessibleName = "Changes and results",
    };
    private readonly Button _save = new() { Text = "Save and restart hub", AutoSize = true };
    private readonly Button _revert = new() { Text = "Undo all changes", AutoSize = true };
    private readonly Button _close = new() { Text = "Close", AutoSize = true };
    private readonly ToolTip _tips = new();
    private readonly Dictionary<string, string> _errors = new(StringComparer.OrdinalIgnoreCase);
    private readonly string? _startSection;
    private string? _toggleModule;
    private IReadOnlyList<BaselineApproval> _approvals;
    private SettingsDescription? _description;
    private JsonObject _proposed = new();
    private bool _saving;

    public SettingsEditorWindow(string? section, string? toggleModule, IReadOnlyList<BaselineApproval>? approvals = null)
    {
        _startSection = section;
        _toggleModule = toggleModule;
        _approvals = approvals ?? Array.Empty<BaselineApproval>();
        Text = "WatchLattice — Settings (administrator)";
        Icon = SystemIcons.Shield;
        Size = new Size(980, 700);
        MinimumSize = new Size(720, 480);
        StartPosition = FormStartPosition.CenterScreen;
        AutoScaleMode = AutoScaleMode.Dpi;

        _sections.DisplayMember = nameof(SectionItem.Text);
        _sections.SelectedIndexChanged += (_, _) => ShowSection();

        var buttons = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom, AutoSize = true, FlowDirection = FlowDirection.RightToLeft,
            Padding = new Padding(8), WrapContents = false,
        };
        buttons.Controls.AddRange(new Control[] { _close, _save, _revert });
        _save.Click += async (_, _) => await SaveAsync();
        _revert.Click += (_, _) => Revert();
        _close.Click += (_, _) => Close();
        AcceptButton = null;
        CancelButton = _close;

        var results = new Panel { Dock = DockStyle.Bottom, Height = 150 };
        results.Controls.Add(_output);
        results.Controls.Add(_summary);

        Controls.Add(_page);
        Controls.Add(new Splitter { Dock = DockStyle.Left, Width = 4 });
        Controls.Add(_sections);
        Controls.Add(results);
        Controls.Add(buttons);
        Controls.Add(new Label
        {
            Dock = DockStyle.Top, Height = 40, Padding = new Padding(10, 6, 10, 0),
            Text = "You are changing the hub's settings as an administrator. Nothing is saved until you choose Save; "
                + "the hub then checks the changes, keeps a backup of the current settings, and restarts.",
        });
        Shown += async (_, _) => await LoadAsync();
        FormClosing += OnClosing;
        UpdateSummary();
    }

    private sealed record SectionItem(SettingsSection Section, string Text);

    private async Task LoadAsync()
    {
        UseWaitCursor = true;
        _save.Enabled = _revert.Enabled = false;
        _output.Text = "Reading the hub's settings…";
        try
        {
            _description = await HubSettings.DescribeAsync();
        }
        catch (Exception ex) when (ex is InvalidOperationException or InvalidDataException or TimeoutException
            or System.ComponentModel.Win32Exception or System.Text.Json.JsonException or IOException)
        {
            _output.Text = "The hub's settings could not be read: " + ex.Message;
            UseWaitCursor = false;
            return;
        }
        UseWaitCursor = false;
        _proposed = SettingValues.Clone(_description.Values);
        _errors.Clear();
        _output.Text = "Settings file: " + _description.SettingsPath;

        // A module switch chosen in the dashboard arrives as a staged, unsaved change.
        if (_toggleModule is not null)
        {
            var field = _description.Sections.SelectMany(s => s.Fields)
                .FirstOrDefault(f => string.Equals(f.Path, $"Modules:{_toggleModule}:Enabled", StringComparison.OrdinalIgnoreCase));
            if (field is not null && SettingValues.Effective(_proposed, field) is JsonValue v && v.TryGetValue<bool>(out var on))
                SettingValues.Set(_proposed, field.Path, JsonValue.Create(!on));
            _toggleModule = null;
        }

        // So do approvals chosen with Approve as baseline: each is one more line in a list setting.
        var fields = _description.Sections.SelectMany(s => s.Fields).Select(f => f.Path).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var approval in _approvals)
        {
            var staged = fields.Contains(approval.SettingPath) && BaselineApprovals.Stage(_proposed, approval);
            _output.AppendText(Environment.NewLine + (staged ? "Staged to approve: " : "Already approved or not available: ") + approval.Description);
        }
        if (_approvals.Count > 0)
            _output.AppendText(Environment.NewLine + "Choose Save to approve, or Undo all changes. Remove a line from the list to revoke an approval later.");
        _approvals = Array.Empty<BaselineApproval>();

        var previous = (_sections.SelectedItem as SectionItem)?.Section.Path ?? _startSection;
        _sections.BeginUpdate();
        _sections.Items.Clear();
        foreach (var section in _description.Sections) _sections.Items.Add(new SectionItem(section, section.Title));
        _sections.EndUpdate();
        var index = _description.Sections.ToList().FindIndex(s => string.Equals(s.Path, previous, StringComparison.OrdinalIgnoreCase));
        _sections.SelectedIndex = Math.Max(0, index);
        RefreshSectionNames();
        UpdateSummary();
    }

    private void ShowSection()
    {
        if (_description is null || _sections.SelectedItem is not SectionItem item) return;
        var section = item.Section;
        _page.SuspendLayout();
        var old = _page.Controls.Cast<Control>().ToArray();
        _page.Controls.Clear();
        foreach (var control in old) control.Dispose();

        var table = new TableLayoutPanel
        {
            Dock = DockStyle.Top, AutoSize = true, ColumnCount = 2, GrowStyle = TableLayoutPanelGrowStyle.AddRows,
        };
        table.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 260));
        table.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        var heading = new Label { Text = section.Title, AutoSize = true, Font = new Font(Font.FontFamily, Font.Size + 3, FontStyle.Bold), Margin = new Padding(0, 0, 0, 4) };
        table.Controls.Add(heading, 0, 0);
        table.SetColumnSpan(heading, 2);
        var module = section.ModuleId is null ? null : _description.Modules.FirstOrDefault(m => m.Id == section.ModuleId);
        var intro = section.Path == "Modules"
            ? "Turn each part of WatchLattice on or off. A module that is off does not run at all."
            : module?.Description ?? "";
        if (intro.Length > 0)
        {
            var about = new Label { Text = intro, AutoSize = true, MaximumSize = new Size(640, 0), Margin = new Padding(0, 0, 0, 10) };
            table.Controls.Add(about);
            table.SetColumnSpan(about, 2);
        }

        foreach (var field in section.Fields) AddField(table, field);
        _page.Controls.Add(table);
        _page.ResumeLayout();
    }

    private void AddField(TableLayoutPanel table, SettingField field)
    {
        var label = new Label
        {
            Text = field.Label, AutoSize = true, MaximumSize = new Size(250, 0), Margin = new Padding(0, 6, 8, 6),
        };
        _tips.SetToolTip(label, field.Path);
        var error = new Label { AutoSize = true, ForeColor = Color.Firebrick, Margin = new Padding(0, 0, 0, 6), MaximumSize = new Size(560, 0) };
        var original = SettingValues.Effective(_description!.Values, field);
        var current = SettingValues.Effective(_proposed, field);
        Control editor;

        if (field.Locked || field.Kind == SettingKind.Unsupported)
        {
            editor = new TextBox { ReadOnly = true, Text = SettingValues.Format(field, current), Width = 520 };
            error.ForeColor = SystemColors.GrayText;
            error.Text = field.LockedReason ?? "This setting can only be changed in appsettings.json.";
        }
        else
        {
            switch (field.Kind)
            {
                case SettingKind.Boolean:
                    var box = new CheckBox { Text = "On", AutoSize = true, Checked = IsTrue(current), Margin = new Padding(0, 4, 0, 4) };
                    box.CheckedChanged += (_, _) => Edit(field, box.Checked ? "true" : "false", error);
                    editor = box;
                    if (ModuleFor(field) is { } module)
                    {
                        error.ForeColor = SystemColors.GrayText;
                        error.Text = module.Description;
                    }
                    break;
                case SettingKind.Choice:
                    var list = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 240 };
                    if (field.Nullable) list.Items.Add("");
                    list.Items.AddRange(field.Choices!.Cast<object>().ToArray());
                    list.SelectedItem = field.Choices!.FirstOrDefault(c => string.Equals(c, SettingValues.Format(field, current), StringComparison.OrdinalIgnoreCase)) ?? "";
                    list.SelectedIndexChanged += (_, _) => Edit(field, list.SelectedItem as string ?? "", error);
                    editor = list;
                    break;
                case SettingKind.TextList:
                    var lines = new TextBox
                    {
                        Multiline = true, AcceptsReturn = true, ScrollBars = ScrollBars.Vertical, Width = 520, Height = 84,
                        Text = SettingValues.Format(field, current), PlaceholderText = "One per line. Leave empty for the built-in default.",
                    };
                    lines.TextChanged += (_, _) => Edit(field, lines.Text, error);
                    editor = lines;
                    break;
                default:
                    var text = new TextBox
                    {
                        Width = field.Kind == SettingKind.Text ? 520 : 160, Text = SettingValues.Format(field, current),
                        PlaceholderText = field.Nullable ? "Not set: the built-in default is used" : "",
                    };
                    text.TextChanged += (_, _) => Edit(field, text.Text, error);
                    editor = text;
                    break;
            }
            if (_errors.TryGetValue(field.Path, out var problem)) error.Text = problem;
        }

        editor.AccessibleName = field.Label;
        editor.Margin = new Padding(0, 3, 0, 2);
        var cell = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, WrapContents = false, Margin = new Padding(0) };
        cell.Controls.Add(editor);
        if (!SettingValues.TryGet(_description.Values, field.Path, out _) && field.Default is not null && !field.Locked)
        {
            var hint = new Label { AutoSize = true, ForeColor = SystemColors.GrayText, Text = "Built-in default: " + Show(field, original) };
            cell.Controls.Add(hint);
        }
        cell.Controls.Add(error);
        table.Controls.Add(label);
        table.Controls.Add(cell);
    }

    private void Edit(SettingField field, string text, Label error)
    {
        if (_description is null) return;
        if (!SettingValues.TryParse(field, text, out var value, out var problem))
        {
            _errors[field.Path] = problem!;
            error.ForeColor = Color.Firebrick;
            error.Text = problem;
        }
        else
        {
            _errors.Remove(field.Path);
            error.Text = "";
            var inFile = SettingValues.TryGet(_description.Values, field.Path, out var before);
            if (inFile && SettingValues.Same(before, value)) SettingValues.Set(_proposed, field.Path, before?.DeepClone());
            else if (!inFile && (SettingValues.Same(field.Default, value) || value is null)) SettingValues.Remove(_proposed, field.Path);
            else SettingValues.Set(_proposed, field.Path, value);
        }
        RefreshSectionNames();
        UpdateSummary();
    }

    private IReadOnlyList<SettingChange> Changes() =>
        _description is null ? Array.Empty<SettingChange>() : SettingsValidator.Diff(_description.Values, _proposed);

    private void UpdateSummary()
    {
        var changes = Changes();
        _summary.Text = _errors.Count > 0 ? $"{_errors.Count} value(s) need fixing before you can save."
            : changes.Count == 0 ? "No unsaved changes." : $"{changes.Count} unsaved change(s).";
        _save.Enabled = !_saving && _description is not null && _errors.Count == 0 && changes.Count > 0;
        _revert.Enabled = !_saving && (changes.Count > 0 || _errors.Count > 0);
    }

    private void RefreshSectionNames()
    {
        if (_description is null) return;
        var changed = Changes().Select(c => c.Path).ToArray();
        for (var i = 0; i < _sections.Items.Count; i++)
        {
            var item = (SectionItem)_sections.Items[i];
            var dirty = item.Section.Fields.Any(f => changed.Contains(f.Path, StringComparer.OrdinalIgnoreCase) || _errors.ContainsKey(f.Path));
            var text = item.Section.Title + (dirty ? "  •" : "");
            if (item.Text != text) _sections.Items[i] = item with { Text = text };
        }
    }

    private void Revert()
    {
        if (_description is null) return;
        _proposed = SettingValues.Clone(_description.Values);
        _errors.Clear();
        ShowSection();
        RefreshSectionNames();
        UpdateSummary();
    }

    private async Task SaveAsync()
    {
        if (_description is null || _saving) return;
        var check = SettingsValidator.Check(_description.Sections, _description.Values, _proposed);
        if (!check.IsValid)
        {
            _output.Text = "These settings cannot be saved:\r\n" + string.Join("\r\n", check.Errors);
            return;
        }
        var confirm = MessageBox.Show(this, "Save these changes and restart the hub?\n\n"
            + string.Join("\n", check.Changes.Take(15).Select(c => "• " + c)) + (check.Changes.Count > 15 ? $"\n…and {check.Changes.Count - 15} more" : "")
            + "\n\nThe current settings are backed up first. If the hub does not keep running with the new settings, "
            + "the backup is put back automatically.",
            "Save settings", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
        if (confirm != DialogResult.Yes) return;

        _saving = true;
        UpdateSummary();
        UseWaitCursor = true;
        _output.Text = "Saving and restarting the hub…";
        try
        {
            var (outcome, output) = await HubSettings.ApplyAsync(_proposed);
            _output.Text = output.Replace("\n", "\r\n").Replace("\r\r\n", "\r\n");
            switch (outcome)
            {
                case SettingsOutcome.Applied:
                case SettingsOutcome.NoChanges:
                    _saving = false;
                    await LoadAsync();
                    _output.Text = output.Replace("\n", "\r\n").Replace("\r\r\n", "\r\n");
                    _summary.Text = outcome == SettingsOutcome.Applied ? "Saved." : "Nothing needed saving.";
                    break;
                case SettingsOutcome.RolledBack:
                    MessageBox.Show(this, "The hub did not keep running with the new settings, so the previous settings were put back. "
                        + "Your edits are still here; see the details below.", "Settings not kept", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    break;
                default:
                    MessageBox.Show(this, "The settings were not saved. See the details below.", "Settings not saved",
                        MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    break;
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException or UnauthorizedAccessException
            or TimeoutException or System.ComponentModel.Win32Exception or InvalidDataException)
        {
            _output.Text = "The settings were not saved: " + ex.Message;
        }
        finally
        {
            _saving = false;
            UseWaitCursor = false;
            UpdateSummary();
        }
    }

    private void OnClosing(object? sender, FormClosingEventArgs e)
    {
        if (_saving)
        {
            e.Cancel = true;
            return;
        }
        if (Changes().Count == 0 && _errors.Count == 0) return;
        var answer = MessageBox.Show(this, "You have unsaved changes. Close without saving them?", "Unsaved changes",
            MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
        if (answer != DialogResult.Yes) e.Cancel = true;
    }

    private ModuleDescription? ModuleFor(SettingField field) => _description!.Modules
        .FirstOrDefault(m => $"Modules:{m.Id}:Enabled".Equals(field.Path, StringComparison.OrdinalIgnoreCase));

    private static bool IsTrue(JsonNode? value) =>
        value is JsonValue v && (v.TryGetValue<bool>(out var b) ? b : v.TryGetValue<string>(out var s) && bool.TryParse(s, out var p) && p);

    private static string Show(SettingField field, JsonNode? value)
    {
        var text = SettingValues.Format(field, value).Replace(Environment.NewLine, "; ");
        return text.Length == 0 ? "(empty)" : text;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _tips.Dispose();
        base.Dispose(disposing);
    }
}

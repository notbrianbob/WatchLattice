using WatchLattice.Common.Alerts;

namespace WatchLattice.Tray;

/// <summary>
/// Opens over other windows when a critical alert arrives, because a balloon
/// is easy to miss and Focus assist hides it. It does not take the keyboard
/// focus, so it cannot swallow what the user is typing. It shows the newest
/// critical alert with its guidance and safe actions; acknowledging marks
/// every critical alert it holds as seen, the same as in the dashboard.
/// </summary>
internal sealed class CriticalAlertWindow : Form
{
    private const int TopMostStyle = 0x00000008; // WS_EX_TOPMOST
    private readonly List<ProtectionAlert> _alerts = new();
    private readonly Label _heading = new() { AutoSize = true, ForeColor = Color.White, Margin = new Padding(0) };
    private readonly Label _title = new() { AutoSize = true, MaximumSize = new Size(520, 0), Margin = new Padding(0, 10, 0, 0) };
    private readonly Label _source = new() { AutoSize = true, MaximumSize = new Size(520, 0), Margin = new Padding(0, 4, 0, 6) };
    private readonly TextBox _details = new()
    {
        Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill,
        AccessibleName = "Critical alert details", TabStop = true,
    };
    private readonly Label _more = new() { AutoSize = true, MaximumSize = new Size(520, 0), Margin = new Padding(0, 6, 0, 0), Visible = false };
    private readonly FlowLayoutPanel _actions = new() { AutoSize = true, Dock = DockStyle.Fill, WrapContents = true, Visible = false };
    private readonly CheckBox _popUp = new() { Text = "Open this window for critical alerts", AutoSize = true, Checked = true, Margin = new Padding(0, 8, 0, 0) };
    private readonly Button _acknowledge = new() { Text = "Acknowledge", AutoSize = true };
    private readonly Button _dashboard = new() { Text = "Open dashboard", AutoSize = true };
    private readonly Button _close = new() { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel };
    private bool _loading;

    /// <summary>The user chose Open dashboard.</summary>
    public event Action? DashboardRequested;

    /// <summary>The user acknowledged these alerts.</summary>
    public event Action<IReadOnlyList<ProtectionAlert>>? AcknowledgeRequested;

    /// <summary>The user turned the pop-up on or off.</summary>
    public event Action<bool>? PopUpChanged;

    public CriticalAlertWindow()
    {
        Text = "WatchLattice: critical alert";
        Icon = SystemIcons.Error;
        AutoScaleMode = AutoScaleMode.Dpi;
        FormBorderStyle = FormBorderStyle.Sizable;
        MinimizeBox = false;
        MaximizeBox = false;
        ShowInTaskbar = true;
        Size = new Size(600, 520);
        MinimumSize = new Size(460, 380);
        StartPosition = FormStartPosition.Manual;
        CancelButton = _close;

        var header = new Panel { Dock = DockStyle.Top, Height = 44, BackColor = Color.FromArgb(0xB3, 0x26, 0x1E), Padding = new Padding(14, 12, 14, 0) };
        _heading.Font = new Font(Font.FontFamily, Font.Size + 2, FontStyle.Bold);
        header.Controls.Add(_heading);

        _title.Font = new Font(Font.FontFamily, Font.Size + 1, FontStyle.Bold);
        var body = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, Padding = new Padding(14, 4, 14, 8) };
        body.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        body.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        body.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        body.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        body.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        body.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        body.Controls.Add(_title, 0, 0);
        body.Controls.Add(_source, 0, 1);
        body.Controls.Add(_details, 0, 2);
        body.Controls.Add(_more, 0, 3);
        body.Controls.Add(_actions, 0, 4);
        body.Controls.Add(_popUp, 0, 5);

        var buttons = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom, AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(10, 6, 10, 10),
        };
        buttons.Controls.AddRange(new Control[] { _close, _dashboard, _acknowledge });

        Controls.Add(body);
        Controls.Add(buttons);
        Controls.Add(header);

        _acknowledge.Click += (_, _) => AcknowledgeRequested?.Invoke(_alerts.ToArray());
        _dashboard.Click += (_, _) => DashboardRequested?.Invoke();
        _close.Click += (_, _) => Close();
        _popUp.CheckedChanged += (_, _) =>
        {
            if (!_loading) PopUpChanged?.Invoke(_popUp.Checked);
        };
    }

    /// <summary>Opens on top of other windows without taking the keyboard focus.</summary>
    protected override bool ShowWithoutActivation => true;

    protected override CreateParams CreateParams
    {
        get
        {
            var parameters = base.CreateParams;
            parameters.ExStyle |= TopMostStyle;
            return parameters;
        }
    }

    /// <summary>The alerts the window holds, newest first.</summary>
    public IReadOnlyList<ProtectionAlert> Alerts => _alerts;

    /// <summary>Adds new critical alerts and shows the newest, opening the window if it is closed.</summary>
    public void Add(IEnumerable<ProtectionAlert> alerts, bool popUpEnabled)
    {
        foreach (var alert in alerts)
        {
            if (_alerts.All(a => a.Id != alert.Id)) _alerts.Add(alert);
        }
        _alerts.Sort((a, b) => b.At.CompareTo(a.At));
        _loading = true;
        _popUp.Checked = popUpEnabled;
        _loading = false;
        ShowNewest();
        if (!Visible)
        {
            var area = Screen.PrimaryScreen?.WorkingArea ?? new Rectangle(0, 0, 1280, 800);
            Location = new Point(Math.Max(area.Left, area.Right - Width - 16), Math.Max(area.Top, area.Bottom - Height - 16));
            Show();
        }
    }

    /// <summary>Drops alerts that were acknowledged elsewhere. Closes the window when none is left.</summary>
    public void Prune(Func<ProtectionAlert, bool> stillNew)
    {
        if (_alerts.RemoveAll(a => !stillNew(a)) == 0) return;
        if (_alerts.Count == 0) Close();
        else ShowNewest();
    }

    private void ShowNewest()
    {
        if (_alerts.Count == 0) return;
        var alert = _alerts[0];
        var guidance = AlertGuidanceCatalog.For(alert);
        _heading.Text = _alerts.Count == 1 ? "Critical alert" : $"{_alerts.Count} critical alerts";
        _title.Text = alert.Title;
        _source.Text = $"{alert.At.ToLocalTime():F} • {alert.Module}" + (alert.Resource is null ? "" : $"\n{alert.Resource}");
        _details.Text = $"WHAT THIS MEANS\r\n{guidance.Meaning}\r\n\r\nWHAT TO DO\r\n{guidance.WhatToDo}\r\n\r\nDETAILS\r\n"
            + alert.Message.Replace("\r\n", "\n").Replace("\n", "\r\n");
        _details.SelectionStart = 0;
        _more.Visible = _alerts.Count > 1;
        _more.Text = _alerts.Count > 1
            ? $"…and {_alerts.Count - 1} more critical alert{(_alerts.Count == 2 ? "" : "s")}. Open the dashboard to see each one. Acknowledge marks all of them as seen."
            : "";
        SafeActionUi.Fill(_actions, guidance, this);
    }
}

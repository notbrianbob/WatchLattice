using System.Diagnostics;
using System.Text.RegularExpressions;
using WatchLattice.Common.Alerts;

namespace WatchLattice.Tray;

/// <summary>
/// Shown the first time the tray starts, and from the tray menu after that:
/// what WatchLattice watches, what each icon colour means, and where to look
/// next. It changes nothing.
/// </summary>
internal sealed partial class WelcomeWindow : Form
{
    /// <summary>A fixed page: nothing from the feed or the settings is ever opened as a link.</summary>
    private const string ThreatModelPage = "https://github.com/notbrianbob/WatchLattice/blob/main/docs/threat-model.md";

    private readonly ListView _modules = new()
    {
        View = View.Details, FullRowSelect = true, HeaderStyle = ColumnHeaderStyle.Nonclickable, Dock = DockStyle.Fill,
        AccessibleName = "Modules", MinimumSize = new Size(0, 110),
    };

    /// <summary>The user chose Open dashboard.</summary>
    public event Action? DashboardRequested;

    public WelcomeWindow(TrayIcons icons)
    {
        Text = "Welcome to WatchLattice";
        Icon = SystemIcons.Shield;
        AutoScaleMode = AutoScaleMode.Dpi;
        Size = new Size(640, 640);
        MinimumSize = new Size(520, 520);
        StartPosition = FormStartPosition.CenterScreen;
        MaximizeBox = false;

        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, Padding = new Padding(16, 12, 16, 8), AutoScroll = true };
        var heading = new Label { Text = "WatchLattice is running", AutoSize = true, Margin = new Padding(0, 0, 0, 6) };
        heading.Font = new Font(Font.FontFamily, Font.Size + 4, FontStyle.Bold);
        layout.Controls.Add(heading);
        layout.Controls.Add(Paragraph(
            "WatchLattice watches for signs of tampering and persistence on this PC: decoy files that ransomware tends to touch, "
            + "changes to Microsoft Defender and the firewall, and new programs set to start automatically. It works alongside "
            + "Defender and never replaces it. It does not delete, quarantine or block anything; it tells you, and you decide."));

        layout.Controls.Add(Subheading("What the tray icon means"));
        var legend = new TableLayoutPanel { AutoSize = true, ColumnCount = 2, Margin = new Padding(0, 0, 0, 6) };
        legend.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        legend.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        foreach (var (level, meaning) in new[]
        {
            (TrayLevel.Ok, "Green tick: everything is running and there is nothing new to look at."),
            (TrayLevel.Attention, "Amber dot: a warning to review, or a module that stopped."),
            (TrayLevel.Critical, "Red exclamation mark: a critical alert. A window also opens so you don't miss it."),
            (TrayLevel.Offline, "Grey dash: the WatchLattice service isn't reporting, so nothing is being watched."),
        })
        {
            legend.Controls.Add(new PictureBox
            {
                Image = icons.For(level).ToBitmap(), SizeMode = PictureBoxSizeMode.CenterImage, Size = new Size(24, 24),
                Margin = new Padding(0, 2, 8, 2), AccessibleName = level.ToString(),
            });
            legend.Controls.Add(new Label { Text = meaning, AutoSize = true, MaximumSize = new Size(540, 0), Margin = new Padding(0, 6, 0, 2) });
        }
        layout.Controls.Add(legend);
        layout.Controls.Add(Paragraph(
            "Hover over the icon for a one-line summary, and double-click it for the dashboard. Acknowledging an alert there turns "
            + "the icon back to green until something new arrives. To keep the icon in view, drag it out of the hidden icons, or turn "
            + "it on in Settings > Personalization > Taskbar > Other system tray icons."));

        layout.Controls.Add(Subheading("Modules on this PC"));
        _modules.Columns.Add("Module", 260);
        _modules.Columns.Add("State", 160);
        layout.Controls.Add(_modules);

        var link = new LinkLabel { Text = "How WatchLattice protects itself (threat model, on GitHub)", AutoSize = true, Margin = new Padding(0, 8, 0, 0) };
        link.LinkClicked += (_, _) =>
        {
            try { Process.Start(new ProcessStartInfo(ThreatModelPage) { UseShellExecute = true })?.Dispose(); }
            catch (System.ComponentModel.Win32Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Could not open the page", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        };
        layout.Controls.Add(link);

        var close = new Button { Text = "Got it", AutoSize = true, DialogResult = DialogResult.OK };
        var dashboard = new Button { Text = "Open dashboard", AutoSize = true };
        close.Click += (_, _) => Close();
        dashboard.Click += (_, _) =>
        {
            DashboardRequested?.Invoke();
            Close();
        };
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(10, 6, 10, 10) };
        buttons.Controls.AddRange(new Control[] { close, dashboard });
        AcceptButton = close;
        CancelButton = close;

        Controls.Add(layout);
        Controls.Add(buttons);
    }

    /// <summary>Lists the hub's modules and their states, or says the hub hasn't reported yet.</summary>
    public void ShowModules(AlertSnapshot? snapshot)
    {
        _modules.BeginUpdate();
        _modules.Items.Clear();
        if (snapshot is null || snapshot.Modules.Count == 0)
        {
            _modules.Items.Add(new ListViewItem(new[] { "The service hasn't reported yet", "" }));
        }
        else
        {
            foreach (var module in snapshot.Modules.OrderBy(m => m.Id, StringComparer.OrdinalIgnoreCase))
                _modules.Items.Add(new ListViewItem(new[] { Words(module.Id), Words(module.State.ToString()) }));
        }
        _modules.EndUpdate();
    }

    /// <summary>"DefenderWatchdog" reads as "Defender watchdog".</summary>
    internal static string Words(string id)
    {
        var spaced = CamelBoundary().Replace(id, " ");
        return spaced.Length == 0 ? spaced : spaced[0] + spaced[1..].ToLowerInvariant();
    }

    [GeneratedRegex("(?<=[a-z0-9])(?=[A-Z])")]
    private static partial Regex CamelBoundary();

    private static Label Subheading(string text)
    {
        var label = new Label { Text = text, AutoSize = true, Margin = new Padding(0, 10, 0, 4) };
        label.Font = new Font(label.Font, FontStyle.Bold);
        return label;
    }

    private static Label Paragraph(string text) =>
        new() { Text = text, AutoSize = true, MaximumSize = new Size(580, 0), Margin = new Padding(0, 0, 0, 6) };
}

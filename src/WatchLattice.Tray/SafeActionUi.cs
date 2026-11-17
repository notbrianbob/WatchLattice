using WatchLattice.Common.Alerts;

namespace WatchLattice.Tray;

/// <summary>
/// Runs an alert's safe action from any window. Each one opens a built-in
/// Windows screen (see SafeActionLauncher); starting a Defender scan asks first.
/// </summary>
internal static class SafeActionUi
{
    public static void Run(IWin32Window? owner, SafeAction action)
    {
        if (SafeActionLauncher.NeedsConfirmation(action.Kind)
            && MessageBox.Show(owner,
                "Start a Microsoft Defender quick scan now? A console window shows its progress and result. It usually takes a few minutes and you can keep working.",
                "Run a Defender quick scan", MessageBoxButtons.OKCancel, MessageBoxIcon.Question) != DialogResult.OK)
        {
            return;
        }
        if (SafeActionLauncher.Launch(action) is { } problem)
            MessageBox.Show(owner, problem, action.Label, MessageBoxButtons.OK, MessageBoxIcon.Warning);
    }

    /// <summary>Fills <paramref name="panel"/> with one button per action, after a short label.</summary>
    public static void Fill(FlowLayoutPanel panel, AlertGuidance? guidance, IWin32Window owner, string label = "Help with this alert:")
    {
        panel.SuspendLayout();
        foreach (Control old in panel.Controls.Cast<Control>().ToArray())
        {
            panel.Controls.Remove(old);
            old.Dispose();
        }
        if (guidance is { Actions.Count: > 0 })
        {
            panel.Controls.Add(new Label { Text = label, AutoSize = true, Margin = new Padding(3, 7, 3, 0) });
            foreach (var action in guidance.Actions)
            {
                var button = new Button { Text = action.Label, AutoSize = true };
                button.Click += (_, _) => Run(owner, action);
                panel.Controls.Add(button);
            }
        }
        panel.Visible = panel.Controls.Count > 0;
        panel.ResumeLayout();
    }
}

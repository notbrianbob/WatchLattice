using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using WatchLattice.Common.Alerts;
using WatchLattice.Updater;

namespace WatchLattice.Tray;

internal static class Program
{
    private const string Usage = "Usage: ScanAlways.Tray.exe [--feed <full path to alerts.json>]\n"
        + "       ScanAlways.Tray.exe --edit-settings [--section <name>] [--toggle-module <id>]";

    /// <summary>Set after an update was installed, so the new tray starts once this one has exited.</summary>
    public static bool RestartRequested { get; set; }

    [STAThread]
    private static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        if (args.Length > 0 && args[0] == "--edit-settings")
        {
            EditSettings(args);
            return;
        }
        if (args.Length != 0 && (args.Length != 2 || args[0] != "--feed"))
        {
            MessageBox.Show(Usage, "WatchLattice", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        string path;
        try { path = Path.GetFullPath(Environment.ExpandEnvironmentVariables(args.Length == 2 ? args[1] : AlertDeliveryOptions.DefaultFeedPath)); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            MessageBox.Show(ex.Message, "Invalid alert feed path", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        var suffix = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(path.ToUpperInvariant())))[..24];
        using (var instance = new Mutex(initiallyOwned: true, @"Local\ScanAlways.Tray." + suffix, out var created))
        {
            if (!created) return;
            try { Application.Run(new TrayContext(path)); }
            finally { instance.ReleaseMutex(); }
        }

        // The single-instance mutex is closed by now, so the updated tray can claim it.
        // Start the copy at the install path: an update moves the running files aside.
        var installed = Path.Join(AppContext.BaseDirectory, ReleaseLayout.TrayExecutable);
        if (RestartRequested && (File.Exists(installed) ? installed : Environment.ProcessPath) is { } executable)
        {
            var start = new ProcessStartInfo(executable) { UseShellExecute = false };
            foreach (var arg in args) start.ArgumentList.Add(arg);
            Process.Start(start)?.Dispose();
        }
    }

    /// <summary>
    /// The settings editor, which the dashboard starts elevated. The arguments
    /// only choose the first page and a module switch to stage; nothing is
    /// saved until an administrator chooses Save.
    /// </summary>
    private static void EditSettings(string[] args)
    {
        string? section = null, toggle = null;
        for (var i = 1; i < args.Length; i += 2)
        {
            if (i + 1 >= args.Length || args[i] is not ("--section" or "--toggle-module"))
            {
                MessageBox.Show(Usage, "WatchLattice", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            if (args[i] == "--section") section = args[i + 1];
            else toggle = args[i + 1];
        }
        if (HubSettings.HubExecutable is null)
        {
            MessageBox.Show(HubSettings.NotInstalledMessage, "WatchLattice settings", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        // One editor at a time, so two saves cannot race each other.
        using var instance = new Mutex(initiallyOwned: true, @"Local\WatchLattice.SettingsEditor", out var created);
        if (!created)
        {
            MessageBox.Show("The WatchLattice settings editor is already open.", "WatchLattice settings", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        try { Application.Run(new SettingsEditorWindow(section, toggle)); }
        finally { instance.ReleaseMutex(); }
    }
}

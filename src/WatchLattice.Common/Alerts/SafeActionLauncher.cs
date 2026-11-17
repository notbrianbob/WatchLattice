using System.Diagnostics;
using System.Text.RegularExpressions;

namespace WatchLattice.Common.Alerts;

/// <summary>
/// Turns a <see cref="SafeAction"/> into the process the dashboard starts.
/// Every action opens a built-in Windows screen with fixed arguments. Text
/// from an alert never reaches a command line, except a file path for
/// "Open file location", and only after <see cref="IsLocalPath"/> accepts it:
/// that path goes to Explorer's /select, which highlights the file and never
/// opens or runs it.
/// </summary>
public static partial class SafeActionLauncher
{
    // A drive letter, a colon, a backslash, then path characters. No quotes,
    // no wildcards, no control characters, no forward slashes, no "..".
    [GeneratedRegex(@"^[A-Za-z]:\\[^""*?<>|\x00-\x1f/]*$", RegexOptions.CultureInvariant)]
    private static partial Regex LocalPathPattern();

    /// <summary>
    /// True when the text is a plain absolute path on a local drive, such as
    /// C:\Users\me\Documents\file.docx. Network paths (\\server\share), device
    /// paths (\\?\, \\.\), relative paths, quotes and ".." segments are refused,
    /// as is anything longer than Windows' extended path limit.
    /// </summary>
    public static bool IsLocalPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Length > 32_000) return false;
        if (!LocalPathPattern().IsMatch(path)) return false;
        foreach (var segment in path[3..].Split('\\'))
        {
            if (segment is "." or "..") return false;
        }
        return true;
    }

    /// <summary>
    /// The process to start for an action, or null when it can't be done here
    /// (a file location whose path was refused, or whose file and folder are
    /// both gone). <paramref name="exists"/> tells whether a file or folder
    /// exists; it is a parameter so tests don't touch the disk.
    /// </summary>
    public static ProcessStartInfo? StartInfo(SafeAction action, Func<string, bool>? exists = null)
    {
        exists ??= p => File.Exists(p) || Directory.Exists(p);
        return action.Kind switch
        {
            SafeActionKind.OpenWindowsSecurity => Shell("windowsdefender:"),
            SafeActionKind.OpenVirusProtectionSettings => Shell("windowsdefender://threatsettings"),
            SafeActionKind.OpenFirewallSettings => Shell("windowsdefender://network"),
            SafeActionKind.DefenderQuickScan => QuickScan(),
            SafeActionKind.OpenFileLocation => FileLocation(action.Path, exists),
            SafeActionKind.OpenApplicationLog => Program("eventvwr.exe", "/c:Application"),
            SafeActionKind.OpenSecurityLog => Program("eventvwr.exe", "/c:Security"),
            SafeActionKind.OpenStartupApps => Shell("ms-settings:startupapps"),
            SafeActionKind.OpenTaskScheduler => Shell("taskschd.msc"),
            SafeActionKind.OpenServices => Shell("services.msc"),
            SafeActionKind.OpenProxySettings => Shell("ms-settings:network-proxy"),
            SafeActionKind.OpenDeviceSecurity => Shell("windowsdefender://devicesecurity"),
            SafeActionKind.OpenAppAndBrowserControl => Shell("windowsdefender://appbrowser"),
            SafeActionKind.OpenWindowsUpdate => Shell("ms-settings:windowsupdate"),
            SafeActionKind.OpenRemoteDesktopSettings => Shell("ms-settings:remotedesktop"),
            _ => null,
        };
    }

    /// <summary>True for actions that start something rather than only open a screen, so the dashboard asks first.</summary>
    public static bool NeedsConfirmation(SafeActionKind kind) => kind == SafeActionKind.DefenderQuickScan;

    /// <summary>Starts the action. Returns null on success, or a short reason it couldn't be done.</summary>
    public static string? Launch(SafeAction action)
    {
        var info = StartInfo(action);
        if (info is null)
        {
            return action.Kind == SafeActionKind.OpenFileLocation
                ? "The file and its folder are no longer there."
                : "This action isn't available here.";
        }
        try
        {
            using var _ = Process.Start(info);
            return null;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or FileNotFoundException)
        {
            return ex.Message;
        }
    }

    private static ProcessStartInfo Shell(string target) => new(target) { UseShellExecute = true };

    private static ProcessStartInfo Program(string fileName, string arguments) =>
        new(Path.Join(Environment.GetFolderPath(Environment.SpecialFolder.System), fileName), arguments) { UseShellExecute = false };

    /// <summary>Defender's own command-line scanner, which ships with Windows.</summary>
    public static string DefenderCommandLine =>
        Path.Join(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");

    private static ProcessStartInfo QuickScan()
    {
        // -ScanType 1 is the quick scan. It runs in a console window that stays
        // open (cmd /k) so the result can be read. Every part of the command is
        // fixed; nothing comes from the alert.
        var cmd = Path.Join(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
        return new ProcessStartInfo(cmd, $"/k \"\"{DefenderCommandLine}\" -Scan -ScanType 1\"")
        {
            UseShellExecute = false,
            CreateNoWindow = false,
        };
    }

    private static ProcessStartInfo? FileLocation(string? path, Func<string, bool> exists)
    {
        if (!IsLocalPath(path)) return null;
        var explorer = Path.Join(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
        if (exists(path!)) return new ProcessStartInfo(explorer, $"/select,\"{path}\"") { UseShellExecute = false };

        // A deleted or renamed canary: open the folder it was in, if that is still there.
        var folder = path!.TrimEnd('\\');
        var cut = folder.LastIndexOf('\\');
        if (cut < 2) return null;
        folder = folder[..cut];
        if (folder.Length == 2) folder += "\\";
        return exists(folder) ? new ProcessStartInfo(explorer, $"\"{folder}\"") { UseShellExecute = false } : null;
    }
}

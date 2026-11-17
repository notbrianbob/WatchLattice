using System.Text.Json;

namespace WatchLattice.Common.Alerts;

/// <summary>
/// The signed-in user's own tray choices. They live in the user's profile,
/// next to their acknowledged alerts, and change nothing about what the hub
/// watches, so no administrator is needed.
/// </summary>
public sealed record TrayPreferences
{
    /// <summary>Open a window, on top of other windows, when a critical alert arrives. Balloons alone are easy to miss, and Focus assist hides them.</summary>
    public bool PopUpCriticalAlerts { get; init; } = true;

    /// <summary>Set once the first-run welcome has been closed.</summary>
    public bool WelcomeSeen { get; init; }

    /// <summary>In the same per-user folder as the other WatchLattice data.</summary>
    public static string DefaultPath => Path.Join(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ScanAlways", "tray-preferences.json");

    /// <summary>The saved preferences, or the defaults when there are none. A damaged file also gives the defaults, with the reason.</summary>
    public static (TrayPreferences Preferences, string? Problem) Load(string? path = null)
    {
        path ??= DefaultPath;
        try
        {
            return File.Exists(path) ? (AtomicJsonFile.Read<TrayPreferences>(path), null) : (new TrayPreferences(), null);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or JsonException)
        {
            // Defaults show the welcome again and keep critical pop-ups on: the safe side.
            return (new TrayPreferences(), "Tray preferences could not be read: " + ex.Message);
        }
    }

    /// <summary>Saves the preferences. Returns null, or why they could not be saved.</summary>
    public string? Save(string? path = null)
    {
        try
        {
            AtomicJsonFile.Write(path ?? DefaultPath, this);
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            return "Tray preferences could not be saved: " + ex.Message;
        }
    }
}

namespace WatchLattice.Updater;

/// <summary>Configuration for the install integrity check ("InstallIntegrity" section).</summary>
public sealed class InstallIntegrityOptions
{
    public const string SectionName = "InstallIntegrity";

    /// <summary>Minutes between checks. Minimum 5.</summary>
    public int CheckIntervalMinutes { get; set; } = 60;

    /// <summary>Seconds to wait after the hub starts before the first check.</summary>
    public int InitialDelaySeconds { get; set; } = 120;

    /// <summary>
    /// Also report .exe and .dll files in Hub\ and Tray\ that the release does
    /// not contain, such as a planted DLL next to the hub.
    /// </summary>
    public bool ReportUnexpectedBinaries { get; set; } = true;

    /// <summary>Paths relative to the install folder to leave out, such as Hub/Extra.dll.</summary>
    public string[] IgnoredFiles { get; set; } = Array.Empty<string>();
}

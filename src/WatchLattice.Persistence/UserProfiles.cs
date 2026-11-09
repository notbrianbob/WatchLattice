using WatchLattice.Persistence.Verification;

namespace WatchLattice.Persistence;

/// <summary>
/// Which user accounts the auditor reads per-user autostarts for, and where.
/// The hub normally runs as LocalSystem, whose HKCU and Startup folder are
/// the system account's, not the signed-in person's. So the auditor also
/// reads each loaded user hive under HKEY_USERS (every signed-in local,
/// domain or Entra ID account) and that user's Startup folder.
/// Pure logic only, so it can be tested off Windows.
/// </summary>
public static class UserProfiles
{
    /// <summary>The default per-user Startup folder below a profile, as Windows creates it.</summary>
    public const string DefaultStartupSuffix = @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup";

    /// <summary>
    /// The accounts to read: the hub's own account first (read through HKCU),
    /// then every loaded user hive. Class hives (<c>_Classes</c>), service
    /// accounts and the default profile are left out; Windows does not run
    /// their Run keys at sign-in.
    /// </summary>
    public static IReadOnlyList<UserAccount> Select(IEnumerable<string> loadedHives, string? self)
    {
        var accounts = new List<UserAccount>();
        if (!string.IsNullOrEmpty(self)) accounts.Add(new(self, IsSelf: true));
        foreach (var name in loadedHives
                     .Where(IsSignedInUserHive)
                     .Distinct(StringComparer.OrdinalIgnoreCase)
                     .OrderBy(n => n, StringComparer.OrdinalIgnoreCase))
        {
            if (!accounts.Any(a => string.Equals(a.Sid, name, StringComparison.OrdinalIgnoreCase)))
                accounts.Add(new(name, IsSelf: false));
        }
        return accounts;
    }

    /// <summary>A real user's loaded hive: local or domain (S-1-5-21-…) or Entra ID (S-1-12-1-…).</summary>
    public static bool IsSignedInUserHive(string? name) =>
        Accounts.IsSid(name)
        && (name!.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) || name.StartsWith("S-1-12-1-", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// The source ID for a user's Run or RunOnce key. Unchanged from earlier
    /// versions, so the hub's own account keeps its existing baseline and
    /// approvals, and a user's entries keep theirs if the hub's account changes.
    /// </summary>
    public static string RunSourceId(string account, string keyName) => $"Registry/HKCU-{account}/Default/{keyName}";

    /// <summary>
    /// A user's Startup folder from their unexpanded <c>User Shell Folders</c>
    /// values and profile path. Only <c>%USERPROFILE%</c> and <c>%APPDATA%</c>
    /// are expanded, with that user's values; anything else (another variable,
    /// a relative path) falls back to the default folder in the profile,
    /// because the hub's own environment is not the user's.
    /// </summary>
    public static string? StartupFolder(string? startupValue, string? appDataValue, string? profilePath)
    {
        if (string.IsNullOrWhiteSpace(profilePath) || profilePath.Contains('%') || !IsRooted(profilePath.Trim())) return null;
        var profile = profilePath.Trim().TrimEnd('\\');
        var fallback = profile + @"\" + DefaultStartupSuffix;
        var appData = Expand(appDataValue, profile, null) ?? profile + @"\AppData\Roaming";
        return Expand(startupValue, profile, appData) ?? fallback;
    }

    private static string? Expand(string? value, string profile, string? appData)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var text = value.Trim().Replace("%USERPROFILE%", profile, StringComparison.OrdinalIgnoreCase);
        if (appData is not null) text = text.Replace("%APPDATA%", appData, StringComparison.OrdinalIgnoreCase);
        text = text.TrimEnd('\\');
        return text.Contains('%') || !IsRooted(text) ? null : text;
    }

    /// <summary>A drive path (C:\…) or UNC path (\\server\share\…), checked the Windows way on any OS.</summary>
    private static bool IsRooted(string path) =>
        (path.Length >= 3 && char.IsAsciiLetter(path[0]) && path[1] == ':' && path[2] == '\\')
        || (path.Length > 2 && path.StartsWith(@"\\", StringComparison.Ordinal) && path[2] != '?' && path[2] != '.');
}

/// <summary>A user account whose per-user autostarts are read. The hub's own account is read through HKCU.</summary>
public sealed record UserAccount(string Sid, bool IsSelf);

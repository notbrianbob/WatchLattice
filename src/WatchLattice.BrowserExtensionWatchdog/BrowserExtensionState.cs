namespace WatchLattice.BrowserExtensionWatchdog;

/// <summary>
/// The watchdog's memory between checks and across restarts: the extensions
/// it last saw in each browser profile and the extension policies. Kept on
/// disk so an extension added while the hub was stopped is still reported at
/// the next start.
/// </summary>
public sealed class BrowserExtensionState
{
    public const int CurrentVersion = 1;

    public int Version { get; set; } = CurrentVersion;

    /// <summary>Profile key → what was installed there. Null until profiles are first read.</summary>
    public Dictionary<string, ProfileRecord>? Profiles { get; set; }

    /// <summary>Policy entry key → entry. Null until policies are first read.</summary>
    public Dictionary<string, PolicyEntry>? Policies { get; set; }

    public bool IsValid() =>
        Version == CurrentVersion
        && (Profiles is null || Profiles.All(p => p.Key.Length > 0 && p.Value is { Extensions: not null, Browser.Length: > 0 }
                                                   && p.Value.Extensions.All(e => e.Key.Length > 0 && e.Value is not null)))
        && (Policies is null || Policies.All(p => p.Key.Length > 0 && p.Value is { Browser.Length: > 0, Scope.Length: > 0 }));
}

public sealed class ProfileRecord
{
    public string Browser { get; set; } = "";

    public string UserId { get; set; } = "";

    public string UserName { get; set; } = "";

    public string ProfileFolder { get; set; } = "";

    public string ProfileName { get; set; } = "";

    /// <summary>Extension ID → what it was.</summary>
    public Dictionary<string, InstalledExtension> Extensions { get; set; } = new(StringComparer.Ordinal);

    public static ProfileRecord From(BrowserProfile profile) => new()
    {
        Browser = profile.Browser,
        UserId = profile.UserId,
        UserName = profile.UserName,
        ProfileFolder = profile.ProfileFolder,
        ProfileName = profile.ProfileName,
        Extensions = (profile.Extensions ?? Array.Empty<InstalledExtension>()).ToDictionary(e => e.Id, StringComparer.Ordinal),
    };

    public BrowserProfile ToProfile(string key) =>
        new(key, Browser, UserId, UserName, ProfileFolder, ProfileName, "", Extensions.Values.ToList());
}

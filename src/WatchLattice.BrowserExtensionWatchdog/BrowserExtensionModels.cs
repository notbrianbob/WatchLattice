using System.Text.Json.Serialization;
using WatchLattice.Common.Alerts;

namespace WatchLattice.BrowserExtensionWatchdog;

public static class Browsers
{
    public const string Edge = "Edge";
    public const string Chrome = "Chrome";
    public const string Firefox = "Firefox";

    public static string DisplayName(string browser) => browser switch
    {
        Edge => "Microsoft Edge",
        Chrome => "Google Chrome",
        Firefox => "Mozilla Firefox",
        _ => browser,
    };
}

/// <summary>How an extension got into a profile, as the browser recorded it.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<ExtensionSource>))]
public enum ExtensionSource
{
    /// <summary>From the browser's own add-on store.</summary>
    Store,

    /// <summary>Installed by an enterprise policy.</summary>
    Policy,

    /// <summary>Registered by another program (a registry key, a preferences file or a shared folder), not by the user in the browser.</summary>
    Sideloaded,

    /// <summary>Loaded unpacked from a folder in developer mode, or from the command line.</summary>
    Unpacked,

    /// <summary>Bundled with the browser by its vendor.</summary>
    Default,

    /// <summary>Anything else, including a source this version does not recognize.</summary>
    Other,
}

/// <summary>An installed extension in one browser profile.</summary>
public sealed record InstalledExtension(
    string Id,
    string Name,
    string? Version,
    ExtensionSource Source,
    bool Enabled = true,
    string? SourceDetail = null)
{
    [JsonIgnore]
    public bool ByPolicy => Source == ExtensionSource.Policy;
}

/// <summary>
/// One browser profile as a check saw it. <see cref="Key"/> is stable across
/// checks (browser, user and profile folder). <see cref="Extensions"/> is null
/// when the profile could not be read, and then <see cref="Error"/> says why.
/// </summary>
public sealed record BrowserProfile(
    string Key,
    string Browser,
    string UserId,
    string UserName,
    string ProfileFolder,
    string ProfileName,
    string Path,
    IReadOnlyList<InstalledExtension>? Extensions,
    string? Error = null)
{
    public string Describe() =>
        $"{Browsers.DisplayName(Browser)} profile \"{ProfileName}\"{(ProfileName == ProfileFolder ? "" : $" ({ProfileFolder})")} of {UserName}";
}

/// <summary>
/// One Windows user whose browser profiles were read. A user missing from a
/// snapshot was not read at all (signed out of a roaming profile, removed, or
/// off limits without administrator rights), which is not a change.
/// </summary>
public sealed record UserScan(string UserId, string UserName, IReadOnlyList<BrowserProfile> Profiles)
{
    /// <summary>Browsers whose list of profiles could not be read for this user; their profiles are kept as they were.</summary>
    public IReadOnlyDictionary<string, string> BrowserErrors { get; init; } = new Dictionary<string, string>();
}

/// <summary>
/// One extension an enterprise policy installs or force-installs: a value of
/// <c>ExtensionInstallForcelist</c>, an <c>ExtensionSettings</c> entry with an
/// install mode, or a Firefox <c>Extensions\Install</c> URL.
/// </summary>
public sealed record PolicyEntry(string Browser, string Scope, string ScopeName, string Kind, string ExtensionId, string? Location = null)
{
    [JsonIgnore]
    public string Key => $"{Browser}|{Scope}|{Kind}|{ExtensionId}|{Location}";

    public string Describe() =>
        $"{Browsers.DisplayName(Browser)} {Kind} policy for {ScopeName}: {ExtensionId}{(Location is null ? "" : $" from {Location}")}";
}

/// <summary>Everything one check read.</summary>
public sealed record BrowserExtensionSnapshot
{
    public IReadOnlyList<UserScan> Users { get; init; } = Array.Empty<UserScan>();

    /// <summary>Policy entries. Null when policies are not watched or could not be read.</summary>
    public IReadOnlyList<PolicyEntry>? Policies { get; init; }

    /// <summary>The policy scopes (<c>Machine</c>, <c>User:&lt;SID&gt;</c>) that were read; entries of other scopes are kept as they were.</summary>
    public IReadOnlyList<string> PolicyScopes { get; init; } = Array.Empty<string>();

    /// <summary>Why policies could not be read.</summary>
    public string? PolicyError { get; init; }
}

/// <summary>A standing problem. <see cref="Code"/> is stable, for de-duplication.</summary>
public sealed record BrowserExtensionFinding(string Code, AlertSeverity Severity, string Message, string? Resource = null)
{
    public override string ToString() => $"[{Severity}] {Message}";
}

/// <summary>A one-off change between two checks.</summary>
public sealed record BrowserExtensionChange(string Code, AlertSeverity Severity, string Title, string Message, string? Resource = null)
{
    public override string ToString() => $"[{Severity}] {Message}";
}

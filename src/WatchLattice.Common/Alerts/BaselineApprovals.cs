using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using WatchLattice.Common.Settings;

namespace WatchLattice.Common.Alerts;

/// <summary>
/// An autostart entry an administrator approved: the entry (its alert
/// resource, <c>source/entry</c>) and the SHA-256 of its exact recorded value.
/// Written in <c>Persistence:ApprovedEntries</c> as <c>sha256:&lt;64 hex&gt; &lt;resource&gt;</c>,
/// hash first, so a resource may contain any character.
/// </summary>
public sealed record ApprovedEntry(string Resource, string Sha256)
{
    public const string Prefix = "sha256:";
    public const int MaxResourceLength = 512;

    /// <summary>Lower-case hex SHA-256 of the value's UTF-8 bytes.</summary>
    public static string Fingerprint(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    public static ApprovedEntry For(string resource, string value) => new(resource, Fingerprint(value));

    public bool Matches(string resource, string value) =>
        string.Equals(Resource, resource, StringComparison.OrdinalIgnoreCase)
        && string.Equals(Sha256, Fingerprint(value), StringComparison.OrdinalIgnoreCase);

    public override string ToString() => $"{Prefix}{Sha256} {Resource}";

    public static bool TryParse(string? text, out ApprovedEntry entry)
    {
        entry = null!;
        if (text is null || text.Length < Prefix.Length + 66 || !text.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase)) return false;
        var hash = text.Substring(Prefix.Length, 64);
        var resource = text[(Prefix.Length + 65)..];
        if (!IsHex(hash) || text[Prefix.Length + 64] != ' ' || resource.Trim().Length == 0 || resource.Length > MaxResourceLength
            || resource.Any(char.IsControl)) return false;
        entry = new(resource, hash.ToLowerInvariant());
        return true;
    }

    internal static bool IsHex(string text) => text.Length == 64 && text.All(char.IsAsciiHexDigit);
}

/// <summary>What approving an alert adds to the hub's settings.</summary>
/// <param name="SettingPath">The list setting the value is added to.</param>
/// <param name="Description">One line for the person approving it.</param>
public sealed record BaselineApproval(string SettingPath, string Value, string Description);

/// <summary>
/// "Approve as baseline": turns an alert about an autostart entry, a browser
/// extension or a script host launch into a line for the settings the module already reads, so the
/// same thing does not alert again. Approvals live in appsettings.json, which
/// only an administrator can change (through the elevated settings editor),
/// and are viewed and revoked there.
/// </summary>
public static partial class BaselineApprovals
{
    public const string PersistenceModule = "Persistence";
    public const string PersistenceSetting = "Persistence:ApprovedEntries";
    public const string ExtensionModule = "BrowserExtensionWatchdog";
    public const string ExtensionSetting = "BrowserExtensionWatchdog:IgnoredExtensionIds";
    public const string ExtensionAddedCode = "EXTENSION_ADDED";
    public const string ScriptHostModule = "ScriptHostAudit";
    public const string ScriptHostSetting = "ScriptHostAudit:ApprovedLaunches";
    public const string ScriptHostLaunchedCode = "SCRIPT_HOST_LAUNCHED";

    /// <summary>
    /// The last line of every <c>ENTRY_ADDED</c> and <c>ENTRY_CHANGED</c> message, and of a
    /// <c>SCRIPT_HOST_LAUNCHED</c> message with a command line: <c>Fingerprint: sha256:&lt;hex&gt;</c>.
    /// </summary>
    public const string FingerprintLabel = "Fingerprint: ";

    /// <summary>At most this many approvals are passed to the settings editor at once.</summary>
    public const int MaxPerEdit = 20;

    public static IReadOnlyList<string> SettingPaths { get; } = new[] { PersistenceSetting, ExtensionSetting, ScriptHostSetting };

    public static string FingerprintLine(string value) => FingerprintLabel + ApprovedEntry.Prefix + ApprovedEntry.Fingerprint(value);

    public static bool IsEntryAlert(string code) => code is "ENTRY_ADDED" or "ENTRY_CHANGED";

    /// <summary>
    /// What approving this alert would add, or null when it cannot be
    /// approved: only a Persistence entry added or changed (approving its
    /// current value), a single browser extension added (approving its ID),
    /// and a single script host launch with a recorded command line
    /// (approving that parent, host and exact command line).
    /// The fingerprint must be the message's last line, which the modules
    /// always write after any text taken from the entry itself.
    /// </summary>
    public static BaselineApproval? For(ProtectionAlert alert)
    {
        if (alert.Resource is not { Length: > 0 and <= ApprovedEntry.MaxResourceLength } resource) return null;
        var setting = alert.Module == PersistenceModule && IsEntryAlert(alert.Code) ? PersistenceSetting
            : alert.Module == ScriptHostModule && alert.Code == ScriptHostLaunchedCode ? ScriptHostSetting
            : null;
        if (setting is not null)
        {
            var last = alert.Message[(alert.Message.LastIndexOf('\n') + 1)..];
            var prefix = FingerprintLabel + ApprovedEntry.Prefix;
            if (!last.StartsWith(prefix, StringComparison.Ordinal) || !ApprovedEntry.IsHex(last[prefix.Length..])) return null;
            var line = ApprovedEntry.Prefix + last[prefix.Length..].ToLowerInvariant() + " " + resource;
            return ApprovedEntry.TryParse(line, out var entry)
                ? new(setting, entry.ToString(), Describe(setting, entry))
                : null;
        }
        if (alert.Module == ExtensionModule && alert.Code == ExtensionAddedCode)
        {
            var id = resource[(resource.LastIndexOf('/') + 1)..];
            return IsExtensionId(id)
                ? new(ExtensionSetting, id, $"Browser extension {id}, in every browser profile")
                : null;
        }
        return null;
    }

    /// <summary>An extension ID without wildcards, so ignoring it ignores only that extension.</summary>
    public static bool IsExtensionId(string id) => ExtensionId().IsMatch(id);

    /// <summary>Whether a value is a well-formed approval for that setting.</summary>
    public static bool IsValid(string settingPath, string value) => settingPath switch
    {
        PersistenceSetting or ScriptHostSetting => ApprovedEntry.TryParse(value, out var entry) && entry.ToString() == value,
        ExtensionSetting => IsExtensionId(value),
        _ => false,
    };

    /// <summary>Adds the approval to the settings unless it is already there. Returns true when it was added.</summary>
    public static bool Stage(JsonObject settings, BaselineApproval approval)
    {
        if (!IsValid(approval.SettingPath, approval.Value)) throw new ArgumentException("Not a valid approval.", nameof(approval));
        if (IsApproved(settings, approval)) return false;
        var list = SettingValues.Get(settings, approval.SettingPath) is JsonArray existing
            ? new JsonArray(existing.Select(e => e?.DeepClone()).ToArray())
            : new JsonArray();
        list.Add(approval.Value);
        SettingValues.Set(settings, approval.SettingPath, list);
        return true;
    }

    public static bool IsApproved(JsonObject settings, BaselineApproval approval) =>
        SettingValues.Get(settings, approval.SettingPath) is JsonArray list
        && list.Any(e => e is JsonValue v && v.TryGetValue<string>(out var text)
            && string.Equals(text.Trim(), approval.Value, StringComparison.OrdinalIgnoreCase));

    /// <summary>For the settings editor's command line: base64url, so any resource survives quoting.</summary>
    public static string Encode(BaselineApproval approval) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(approval.SettingPath + "\n" + approval.Value))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static bool TryDecode(string? token, out BaselineApproval approval)
    {
        approval = null!;
        if (string.IsNullOrEmpty(token) || token.Length > 2048 || !token.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_')) return false;
        var padded = token.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - padded.Length % 4) % 4);
        string text;
        try { text = new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(Convert.FromBase64String(padded)); }
        catch (Exception ex) when (ex is FormatException or ArgumentException) { return false; }
        var split = text.IndexOf('\n');
        if (split < 0) return false;
        var path = text[..split];
        var value = text[(split + 1)..];
        if (!IsValid(path, value)) return false;
        approval = new(path, value, path != ExtensionSetting && ApprovedEntry.TryParse(value, out var entry)
            ? Describe(path, entry)
            : $"Browser extension {value}, in every browser profile");
        return true;
    }

    private static string Describe(string settingPath, ApprovedEntry entry) => settingPath == ScriptHostSetting
        ? "Script host launch, with exactly this command line: " + entry.Resource.Replace("|", " starting ")
        : "Autostart entry, exactly as it is now: " + entry.Resource;

    // Chromium IDs are 32 letters a-p; Firefox IDs are an email-like name or a {GUID}.
    [GeneratedRegex(@"^[A-Za-z0-9@._{}+-]{1,200}$", RegexOptions.CultureInvariant)]
    private static partial Regex ExtensionId();
}

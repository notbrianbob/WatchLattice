using System.Globalization;
using System.Text.Json;

namespace WatchLattice.DefenderWatchdog;

/// <summary>
/// A snapshot of Microsoft Defender's state, as reported by
/// <c>Get-MpComputerStatus</c>. Every field is nullable because a field can be
/// missing on older platform versions; the evaluator treats "unknown" as
/// "don't alert on this field" rather than guessing.
/// </summary>
public sealed record DefenderStatus
{
    /// <summary>False when the status could not be read at all.</summary>
    public bool Available { get; init; } = true;

    /// <summary>Why the status could not be read, when <see cref="Available"/> is false.</summary>
    public string? Error { get; init; }

    public bool? AMServiceEnabled { get; init; }
    public bool? AntivirusEnabled { get; init; }
    public bool? RealTimeProtectionEnabled { get; init; }
    public bool? BehaviorMonitorEnabled { get; init; }
    public bool? IoavProtectionEnabled { get; init; }
    public bool? OnAccessProtectionEnabled { get; init; }
    public bool? IsTamperProtected { get; init; }

    /// <summary>"Normal", "Passive Mode", "EDR Block Mode", "SxS Passive Mode" or "Not running".</summary>
    public string? RunningMode { get; init; }

    public string? SignatureVersion { get; init; }
    public DateTimeOffset? SignatureLastUpdated { get; init; }

    /// <summary>Exclusions, ASR rules and cloud protection from <c>Get-MpPreference</c>. Null when they could not be read.</summary>
    public DefenderSettings? Settings { get; init; }

    /// <summary>Why <see cref="Settings"/> could not be read, when it is null.</summary>
    public string? SettingsError { get; init; }

    public static DefenderStatus Unavailable(string error) => new() { Available = false, Error = error };
}

/// <summary>Parses the JSON emitted by the watchdog's PowerShell query.</summary>
public static class DefenderStatusParser
{
    public static DefenderStatus Parse(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return DefenderStatus.Unavailable("Defender returned no status.");
        }

        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return DefenderStatus.Unavailable("Defender status was not a JSON object.");
            }

            return new DefenderStatus
            {
                AMServiceEnabled = Bool(root, "AMServiceEnabled"),
                AntivirusEnabled = Bool(root, "AntivirusEnabled"),
                RealTimeProtectionEnabled = Bool(root, "RealTimeProtectionEnabled"),
                BehaviorMonitorEnabled = Bool(root, "BehaviorMonitorEnabled"),
                IoavProtectionEnabled = Bool(root, "IoavProtectionEnabled"),
                OnAccessProtectionEnabled = Bool(root, "OnAccessProtectionEnabled"),
                IsTamperProtected = Bool(root, "IsTamperProtected"),
                RunningMode = String(root, "AMRunningMode"),
                SignatureVersion = String(root, "AntivirusSignatureVersion"),
                SignatureLastUpdated = Date(root, "AntivirusSignatureLastUpdated"),
                Settings = root.TryGetProperty("Preferences", out var preferences) && preferences.ValueKind == JsonValueKind.Object
                    ? DefenderSettings.Parse(preferences)
                    : null,
                SettingsError = String(root, "PreferencesError"),
            };
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or ArgumentException)
        {
            // Not JSON, or JSON holding text that cannot be read (half of a surrogate pair, a broken \u escape).
            return DefenderStatus.Unavailable($"Could not parse Defender status: {ex.Message}");
        }
    }

    private static bool? Bool(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) ? value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => null,
        } : null;

    private static string? String(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static DateTimeOffset? Date(JsonElement root, string name)
    {
        var text = String(root, name);
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        // Windows PowerShell 5.1's ConvertTo-Json writes dates as "/Date(ms)/".
        if (text.StartsWith("/Date(", StringComparison.Ordinal))
        {
            var digits = new string(text.Skip(6).TakeWhile(c => char.IsDigit(c) || c == '-').ToArray());
            // FromUnixTimeMilliseconds throws outside the years 1 to 9999.
            return long.TryParse(digits, NumberStyles.Integer, CultureInfo.InvariantCulture, out var ms)
                && ms >= DateTimeOffset.MinValue.ToUnixTimeMilliseconds() && ms <= DateTimeOffset.MaxValue.ToUnixTimeMilliseconds()
                ? DateTimeOffset.FromUnixTimeMilliseconds(ms)
                : null;
        }

        return DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsed)
            ? parsed
            : null;
    }
}

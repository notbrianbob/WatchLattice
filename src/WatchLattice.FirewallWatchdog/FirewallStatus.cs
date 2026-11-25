using System.Text.Json;

namespace WatchLattice.FirewallWatchdog;

/// <summary>One Windows Firewall profile (Domain, Private or Public) as the active policy reports it.</summary>
public sealed record FirewallProfileState(string Name, bool? Enabled, string? DefaultInboundAction)
{
    public bool InboundAllowsByDefault =>
        string.Equals(DefaultInboundAction, "Allow", StringComparison.OrdinalIgnoreCase);
}

/// <summary>An enabled inbound allow rule. <see cref="Id"/> is the rule's unique Name, not its display name.</summary>
public sealed record FirewallRule(string Id, string? DisplayName, string? Profile);

/// <summary>
/// A snapshot of Windows Firewall's effective (active store) policy. Unknown
/// values are null; the evaluator treats "unknown" as "don't alert on this
/// field" rather than guessing.
/// </summary>
public sealed record FirewallStatus
{
    /// <summary>False when the firewall state could not be read at all.</summary>
    public bool Available { get; init; } = true;

    /// <summary>Why the state could not be read, when <see cref="Available"/> is false.</summary>
    public string? Error { get; init; }

    public IReadOnlyList<FirewallProfileState> Profiles { get; init; } = Array.Empty<FirewallProfileState>();

    /// <summary>Profiles that a connected network is using right now. Null when that could not be read.</summary>
    public IReadOnlyList<string>? ActiveProfiles { get; init; }

    /// <summary>Enabled inbound allow rules. Null when they were not requested or could not be read.</summary>
    public IReadOnlyList<FirewallRule>? InboundAllowRules { get; init; }

    /// <summary>Why the rules could not be read, when they were requested.</summary>
    public string? RulesError { get; init; }

    /// <summary>True when the profile is in use, or when that is unknown (so a problem is not downplayed).</summary>
    public bool MayBeActive(string profile) =>
        ActiveProfiles is null || ActiveProfiles.Contains(profile, StringComparer.OrdinalIgnoreCase);

    public static FirewallStatus Unavailable(string error) => new() { Available = false, Error = error };
}

/// <summary>Parses the JSON emitted by the watchdog's PowerShell query.</summary>
public static class FirewallStatusParser
{
    public static FirewallStatus Parse(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return FirewallStatus.Unavailable("The firewall query returned nothing.");
        }

        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return FirewallStatus.Unavailable("Firewall status was not a JSON object.");
            }

            var profiles = Items(root, "Profiles")
                .Where(p => p.ValueKind == JsonValueKind.Object)
                .Select(p => new FirewallProfileState(
                    NormalizeProfile(String(p, "Name")) ?? "",
                    Tristate(String(p, "Enabled")),
                    Configured(String(p, "DefaultInboundAction"))))
                .Where(p => p.Name.Length > 0)
                .DistinctBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();
            if (profiles.Count == 0)
            {
                return FirewallStatus.Unavailable("No firewall profiles were reported.");
            }

            IReadOnlyList<string>? active = null;
            if (root.TryGetProperty("ActiveCategories", out var categories) && categories.ValueKind != JsonValueKind.Null)
            {
                active = Items(root, "ActiveCategories")
                    .Where(c => c.ValueKind == JsonValueKind.String)
                    .Select(c => NormalizeProfile(c.GetString()))
                    .OfType<string>()
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
            }

            IReadOnlyList<FirewallRule>? rules = null;
            if (root.TryGetProperty("Rules", out var rulesElement) && rulesElement.ValueKind != JsonValueKind.Null)
            {
                rules = Items(root, "Rules")
                    .Where(r => r.ValueKind == JsonValueKind.Object)
                    .Select(r => new FirewallRule(String(r, "Id") ?? "", String(r, "DisplayName"), String(r, "Profile")))
                    .Where(r => r.Id.Length > 0)
                    .DistinctBy(r => r.Id, StringComparer.OrdinalIgnoreCase)
                    .ToList();
            }

            return new FirewallStatus
            {
                Profiles = profiles,
                ActiveProfiles = active,
                InboundAllowRules = rules,
                RulesError = String(root, "RulesError"),
            };
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or ArgumentException)
        {
            // Not JSON, or JSON holding text that cannot be read (half of a surrogate pair, a broken \u escape).
            return FirewallStatus.Unavailable($"Could not parse firewall status: {ex.Message}");
        }
    }

    /// <summary>
    /// Maps profile and network-category names onto the three profile names.
    /// Get-NetConnectionProfile reports a domain network as "DomainAuthenticated".
    /// </summary>
    public static string? NormalizeProfile(string? name) => name?.Trim().ToLowerInvariant() switch
    {
        "domain" or "domainauthenticated" => "Domain",
        "private" => "Private",
        "public" => "Public",
        _ => null,
    };

    /// <summary>
    /// Accepts an array, a single object, or Windows PowerShell 5.1's
    /// <c>{"value":[...],"Count":n}</c> wrapper, all of which ConvertTo-Json can emit.
    /// </summary>
    private static IEnumerable<JsonElement> Items(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value))
        {
            return Array.Empty<JsonElement>();
        }
        if (value.ValueKind == JsonValueKind.Object && value.TryGetProperty("value", out var wrapped)
            && wrapped.ValueKind == JsonValueKind.Array)
        {
            value = wrapped;
        }
        return value.ValueKind switch
        {
            JsonValueKind.Array => value.EnumerateArray().ToList(),
            JsonValueKind.Null or JsonValueKind.Undefined => Array.Empty<JsonElement>(),
            _ => new[] { value },
        };
    }

    private static string? String(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static bool? Tristate(string? text) => text?.Trim().ToLowerInvariant() switch
    {
        "true" => true,
        "false" => false,
        _ => null,
    };

    private static string? Configured(string? text) =>
        string.IsNullOrWhiteSpace(text) || text.Trim().Equals("NotConfigured", StringComparison.OrdinalIgnoreCase)
            ? null
            : text.Trim();
}

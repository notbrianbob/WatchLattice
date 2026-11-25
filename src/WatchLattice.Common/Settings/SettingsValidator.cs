using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;

namespace WatchLattice.Common.Settings;

public sealed record SettingChange(string Path, JsonNode? Before, JsonNode? After)
{
    public override string ToString() => $"{Path}: {Show(Before)} -> {Show(After)}";

    private static string Show(JsonNode? value) => value?.ToJsonString() ?? "(not set)";
}

public sealed record SettingsCheck(IReadOnlyList<string> Errors, IReadOnlyList<string> Warnings, IReadOnlyList<SettingChange> Changes)
{
    public bool IsValid => Errors.Count == 0;
}

/// <summary>
/// Checks a proposed appsettings.json against the schema before anything is
/// saved: every known setting has the right type, locked settings are
/// unchanged, and the result still binds to the hub's options classes. The
/// settings editor runs it as you type; the hub runs it again before saving.
/// </summary>
public static class SettingsValidator
{
    public const int MaxBytes = 1024 * 1024;

    public static SettingsCheck Check(IReadOnlyList<SettingsSection> sections, JsonObject current, JsonObject proposed)
    {
        var errors = new List<string>();
        var warnings = new List<string>();
        var fields = sections.SelectMany(s => s.Fields).ToDictionary(f => f.Path, StringComparer.OrdinalIgnoreCase);

        foreach (var field in fields.Values)
        {
            var present = SettingValues.TryGet(proposed, field.Path, out var value);
            if (field.Locked)
            {
                var wasPresent = SettingValues.TryGet(current, field.Path, out var before);
                if (present != wasPresent || !SettingValues.Same(before, value))
                    errors.Add($"{field.Path} can only be changed in appsettings.json by an administrator.");
                continue;
            }
            if (present && CheckValue(field, value) is { } problem) errors.Add($"{field.Path}: {problem}");
        }

        // Keys inside a known section that nothing reads, such as a typo or a setting a newer version removed.
        foreach (var section in sections)
        {
            if (SettingValues.Get(proposed, section.Path) is not JsonObject node) continue;
            foreach (var (key, child) in node)
            {
                var path = $"{section.Path}:{key}";
                if (fields.ContainsKey(path)) continue;
                if (sections.Any(s => string.Equals(s.Path, path, StringComparison.OrdinalIgnoreCase))) continue;
                if (section.Path == Modules.ModuleCatalog.SectionName && child is JsonObject)
                {
                    foreach (var (switchKey, _) in child.AsObject())
                        if (!fields.ContainsKey($"{path}:{switchKey}")) warnings.Add($"{path}:{switchKey} is not used by this version.");
                    continue;
                }
                warnings.Add($"{path} is not used by this version.");
            }
        }

        foreach (var section in sections)
        {
            if (SettingValues.Get(proposed, section.Path) is not null and not JsonObject)
                errors.Add($"{section.Path} must be a section ({{ ... }}), not a single value.");
        }

        return new SettingsCheck(errors, warnings, Diff(current, proposed));
    }

    /// <summary>Why a value cannot be used for this field, or null when it can.</summary>
    public static string? CheckValue(SettingField field, JsonNode? value)
    {
        if (value is null) return field.Nullable ? null : "must have a value.";
        switch (field.Kind)
        {
            case SettingKind.Boolean:
                return value is JsonValue v && (v.TryGetValue<bool>(out _) || v.TryGetValue<string>(out var s) && bool.TryParse(s, out _))
                    ? null : "must be true or false.";
            case SettingKind.Integer:
                return Number(value) is { } whole && whole >= 0 && double.IsInteger(whole) && whole <= long.MaxValue
                    ? null : "must be a whole number, 0 or more.";
            case SettingKind.Number:
                return Number(value) is { } number && number >= 0 && double.IsFinite(number) ? null : "must be a number, 0 or more.";
            case SettingKind.Text:
                return value is JsonValue t && t.TryGetValue<string>(out var text) && (field.Nullable || text.Trim().Length > 0)
                    ? null : "must be text.";
            case SettingKind.TextList:
                return value is JsonArray list && list.All(e => e is JsonValue item && item.TryGetValue<string>(out _))
                    ? null : "must be a list of text values.";
            case SettingKind.Choice:
                return value is JsonValue c && c.TryGetValue<string>(out var choice)
                    && field.Choices!.Any(x => string.Equals(x, choice.Trim(), StringComparison.OrdinalIgnoreCase))
                    ? null : "must be one of " + string.Join(", ", field.Choices ?? Array.Empty<string>()) + ".";
            default:
                return null;
        }
    }

    private static double? Number(JsonNode value)
    {
        if (value is not JsonValue v) return null;
        if (v.TryGetValue<JsonElement>(out var element))
        {
            if (element.ValueKind == JsonValueKind.Number) return element.GetDouble();
            if (element.ValueKind == JsonValueKind.String
                && double.TryParse(element.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed)) return parsed;
            return null;
        }
        if (v.TryGetValue<long>(out var l)) return l;
        if (v.TryGetValue<int>(out var i)) return i;
        if (v.TryGetValue<double>(out var d)) return d;
        if (v.TryGetValue<string>(out var s) && double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var p)) return p;
        return null;
    }

    /// <summary>
    /// Binds each section to its options class the way the hub will at
    /// startup, so a value the binder cannot convert (for example a number too
    /// large for its property) is caught before saving instead of failing the hub.
    /// </summary>
    public static IReadOnlyList<string> CheckBinding(IEnumerable<(string Path, Type Type)> sections, JsonObject proposed)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(ToConfiguration(proposed))
            .Build();
        var errors = new List<string>();
        foreach (var (path, type) in sections)
        {
            try { configuration.GetSection(path).Get(type); }
            catch (InvalidOperationException ex) { errors.Add($"{path}: {(ex.InnerException ?? ex).Message}"); }
        }
        return errors;
    }

    /// <summary>The key/value pairs .NET configuration would read from this JSON.</summary>
    public static IEnumerable<KeyValuePair<string, string?>> ToConfiguration(JsonObject root)
    {
        var values = new List<KeyValuePair<string, string?>>();
        void Walk(JsonNode? node, string? path)
        {
            switch (node)
            {
                case JsonObject o:
                    foreach (var (key, child) in o) Walk(child, path is null ? key : path + ":" + key);
                    break;
                case JsonArray a:
                    for (var i = 0; i < a.Count; i++) Walk(a[i], path + ":" + i.ToString(CultureInfo.InvariantCulture));
                    break;
                case JsonValue v when v.TryGetValue<JsonElement>(out var e):
                    values.Add(new(path!, e.ValueKind switch
                    {
                        JsonValueKind.String => e.GetString(),
                        JsonValueKind.Null => null,
                        JsonValueKind.True => "True",
                        JsonValueKind.False => "False",
                        _ => e.GetRawText(),
                    }));
                    break;
                case JsonValue v:
                    values.Add(new(path!, v.TryGetValue<string>(out var s) ? s
                        : v.TryGetValue<bool>(out var b) ? (b ? "True" : "False") : v.ToJsonString()));
                    break;
                case null:
                    values.Add(new(path!, null));
                    break;
            }
        }
        Walk(root, null);
        return values;
    }

    /// <summary>Every value that differs, by configuration path. Lists compare as one value.</summary>
    public static IReadOnlyList<SettingChange> Diff(JsonObject before, JsonObject after)
    {
        var left = Flatten(before);
        var right = Flatten(after);
        return left.Keys.Union(right.Keys, StringComparer.OrdinalIgnoreCase)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(k => k, StringComparer.OrdinalIgnoreCase)
            .Select(k => (Key: k, Before: left.GetValueOrDefault(k), After: right.GetValueOrDefault(k)))
            .Where(x => !SettingValues.Same(x.Before, x.After))
            .Select(x => new SettingChange(x.Key, x.Before, x.After))
            .ToArray();
    }

    private static Dictionary<string, JsonNode?> Flatten(JsonObject root)
    {
        var values = new Dictionary<string, JsonNode?>(StringComparer.OrdinalIgnoreCase);
        void Walk(JsonObject node, string? prefix)
        {
            foreach (var (key, child) in node)
            {
                var path = prefix is null ? key : prefix + ":" + key;
                if (child is JsonObject o) Walk(o, path);
                else values[path] = child;
            }
        }
        Walk(root, null);
        return values;
    }
}

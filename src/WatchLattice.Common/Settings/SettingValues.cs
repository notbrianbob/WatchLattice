using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace WatchLattice.Common.Settings;

/// <summary>
/// Reads, writes and converts values in an appsettings.json document by
/// configuration path. Keys match case-insensitively, like .NET configuration.
/// </summary>
public static class SettingValues
{
    public static JsonNode? Get(JsonObject root, string path) => TryGet(root, path, out var node) ? node : null;

    /// <summary>False when the path is missing; true with a null node for an explicit JSON null.</summary>
    public static bool TryGet(JsonObject root, string path, out JsonNode? node)
    {
        node = null;
        JsonObject current = root;
        var parts = path.Split(':');
        for (var i = 0; i < parts.Length; i++)
        {
            var key = FindKey(current, parts[i]);
            if (key is null) return false;
            var child = current[key];
            if (i == parts.Length - 1)
            {
                node = child;
                return true;
            }
            if (child is not JsonObject next) return false;
            current = next;
        }
        return false;
    }

    /// <summary>Sets a value, creating sections that do not exist yet and keeping the existing key's spelling.</summary>
    public static void Set(JsonObject root, string path, JsonNode? value)
    {
        var parts = path.Split(':');
        var current = root;
        for (var i = 0; i < parts.Length - 1; i++)
        {
            var key = FindKey(current, parts[i]);
            if (key is null || current[key] is not JsonObject next)
            {
                next = new JsonObject();
                current[key ?? parts[i]] = next;
            }
            current = next;
        }
        current[FindKey(current, parts[^1]) ?? parts[^1]] = value;
    }

    /// <summary>Removes a value, so the hub falls back to its built-in default.</summary>
    public static void Remove(JsonObject root, string path)
    {
        var cut = path.LastIndexOf(':');
        var parent = cut < 0 ? root : Get(root, path[..cut]) as JsonObject;
        if (parent is null) return;
        if (FindKey(parent, path[(cut + 1)..]) is { } key) parent.Remove(key);
    }

    /// <summary>The value the hub will use: the file's, or the built-in default when the file does not set it.</summary>
    public static JsonNode? Effective(JsonObject root, SettingField field) =>
        TryGet(root, field.Path, out var value) ? value : field.Default;

    public static JsonObject Clone(JsonObject root) => (JsonObject)JsonNode.Parse(root.ToJsonString())!;

    private static string? FindKey(JsonObject node, string name) =>
        node.Select(p => p.Key).FirstOrDefault(k => string.Equals(k, name, StringComparison.OrdinalIgnoreCase));

    /// <summary>The text an editor shows for a value. Lists are one entry per line.</summary>
    public static string Format(SettingField field, JsonNode? value)
    {
        if (value is null) return "";
        if (field.Kind == SettingKind.TextList && value is JsonArray list)
            return string.Join(Environment.NewLine, list.Select(e => e is JsonValue v && v.TryGetValue<string>(out var s) ? s : e?.ToJsonString() ?? ""));
        if (value is JsonValue scalar)
        {
            if (scalar.TryGetValue<string>(out var text)) return text;
            if (scalar.TryGetValue<bool>(out var flag)) return flag ? "true" : "false";
            return scalar.ToJsonString();
        }
        return value.ToJsonString();
    }

    /// <summary>
    /// Converts what the user typed into the JSON value to save. Empty text
    /// means "not set" (JSON null) for optional values, and an empty list for lists.
    /// </summary>
    public static bool TryParse(SettingField field, string text, out JsonNode? value, out string? error)
    {
        value = null;
        error = null;
        var trimmed = text.Trim();
        switch (field.Kind)
        {
            case SettingKind.Boolean:
                if (bool.TryParse(trimmed, out var flag)) { value = JsonValue.Create(flag); return true; }
                error = "Must be true or false.";
                return false;
            case SettingKind.Integer:
                if (trimmed.Length == 0 && field.Nullable) return true;
                if (long.TryParse(trimmed, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var whole) && whole >= 0)
                {
                    value = JsonValue.Create(whole);
                    return true;
                }
                error = "Must be a whole number, 0 or more.";
                return false;
            case SettingKind.Number:
                if (trimmed.Length == 0 && field.Nullable) return true;
                if (double.TryParse(trimmed, NumberStyles.Float, CultureInfo.InvariantCulture, out var number)
                    && double.IsFinite(number) && number >= 0)
                {
                    value = JsonValue.Create(number);
                    return true;
                }
                error = "Must be a number, 0 or more.";
                return false;
            case SettingKind.Text:
                if (trimmed.Length == 0 && field.Nullable) return true;
                if (trimmed.Length == 0) { error = "Must not be empty."; return false; }
                value = JsonValue.Create(trimmed);
                return true;
            case SettingKind.TextList:
                value = new JsonArray(text.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0)
                    .Select(l => (JsonNode?)JsonValue.Create(l)).ToArray());
                return true;
            case SettingKind.Choice:
                var choice = field.Choices?.FirstOrDefault(c => string.Equals(c, trimmed, StringComparison.OrdinalIgnoreCase));
                if (choice is not null) { value = JsonValue.Create(choice); return true; }
                if (trimmed.Length == 0 && field.Nullable) return true;
                error = "Must be one of: " + string.Join(", ", field.Choices ?? Array.Empty<string>()) + ".";
                return false;
            default:
                error = "This setting can only be changed in appsettings.json.";
                return false;
        }
    }

    /// <summary>Whether two values are the same JSON (property order and formatting aside).</summary>
    public static bool Same(JsonNode? a, JsonNode? b) => Canonical(a) == Canonical(b);

    private static string Canonical(JsonNode? node) => node switch
    {
        null => "null",
        JsonObject o => "{" + string.Join(",", o.OrderBy(p => p.Key, StringComparer.OrdinalIgnoreCase)
            .Select(p => JsonSerializer.Serialize(p.Key.ToUpperInvariant()) + ":" + Canonical(p.Value))) + "}",
        JsonArray a => "[" + string.Join(",", a.Select(Canonical)) + "]",
        _ => node.ToJsonString(),
    };

    /// <summary>
    /// Reads appsettings.json text. Anything the hub itself could not start
    /// with is refused here, with <see cref="JsonException"/> or
    /// <see cref="InvalidDataException"/>: text that is not JSON, a setting
    /// written twice in one section (in any letter case, which .NET
    /// configuration also refuses), and text spelled with a broken \u escape.
    /// </summary>
    public static JsonObject Parse(string json)
    {
        try
        {
            // Notepad and Windows PowerShell's Set-Content -Encoding UTF8 start the file with a byte order mark.
            // Parsed as UTF-8, because the text overload throws ArgumentException for half of a surrogate pair.
            var node = JsonNode.Parse(System.Text.Encoding.UTF8.GetBytes(json.TrimStart('\uFEFF')), documentOptions: new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
                MaxDepth = 32,
                AllowDuplicateProperties = false,
            });
            var root = node as JsonObject ?? throw new InvalidDataException("The settings file must contain a JSON object.");
            RefuseRepeatedNames(root, null, new HashSet<string>(StringComparer.OrdinalIgnoreCase));
            // Reads every string once, so text that cannot be read is refused now rather than when a setting is checked.
            _ = root.ToJsonString();
            return root;
        }
        catch (InvalidOperationException ex)
        {
            throw new InvalidDataException("The settings file holds text that is not valid: " + ex.Message, ex);
        }
    }

    /// <summary>
    /// One configuration path, one value: "Enabled" and "enabled" in the same
    /// section, or "A:B" beside a section A with a setting B, are the same
    /// path to the hub.
    /// </summary>
    private static void RefuseRepeatedNames(JsonNode? node, string? path, HashSet<string> values)
    {
        switch (node)
        {
            case JsonObject section:
                var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var (key, child) in section)
                {
                    var childPath = path is null ? key : path + ":" + key;
                    if (!names.Add(key)) throw Repeated(childPath);
                    RefuseRepeatedNames(child, childPath, values);
                }
                break;
            case JsonArray list:
                for (var i = 0; i < list.Count; i++) RefuseRepeatedNames(list[i], path + ":" + i.ToString(CultureInfo.InvariantCulture), values);
                break;
            default:
                if (path is not null && !values.Add(path)) throw Repeated(path);
                break;
        }
    }

    private static InvalidDataException Repeated(string path) =>
        new($"The settings file sets \"{path}\" more than once. Names are compared without regard to letter case.");

    public static string Serialize(JsonObject root) =>
        root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }) + Environment.NewLine;
}

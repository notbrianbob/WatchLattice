using System.Globalization;
using System.Reflection;
using System.Text;
using System.Text.Json.Nodes;
using WatchLattice.Common.Alerts;
using WatchLattice.Common.Modules;

namespace WatchLattice.Common.Settings;

public enum SettingKind { Boolean, Integer, Number, Text, TextList, Choice, Unsupported }

/// <summary>
/// One editable value, addressed by its full configuration path
/// (for example <c>Canary:IntegrityCheckSeconds</c>).
/// </summary>
/// <param name="Default">What the hub uses when appsettings.json does not set it.</param>
public sealed record SettingField(string Path, string Label, SettingKind Kind, bool Nullable,
    IReadOnlyList<string>? Choices = null, string? LockedReason = null, JsonNode? Default = null)
{
    public bool Locked => LockedReason is not null;
}

/// <summary>A group of settings, shown as one page in the settings editor.</summary>
public sealed record SettingsSection(string Path, string Title, IReadOnlyList<SettingField> Fields, string? ModuleId = null);

public sealed record ModuleDescription(string Id, string DisplayName, string Description, bool EnabledByDefault);

/// <summary>
/// What <c>--describe-settings</c> prints: every module, every editable
/// section, and the hub's appsettings.json exactly as it is on disk.
/// </summary>
public sealed record SettingsDescription(int Version, string SettingsPath, IReadOnlyList<ModuleDescription> Modules,
    IReadOnlyList<SettingsSection> Sections, JsonObject Values)
{
    public const int CurrentVersion = 1;
}

/// <summary>
/// Builds the settings editor's fields from the options classes the hub and
/// its modules bind, so a new option shows up without any UI work.
/// </summary>
public static class SettingsSchema
{
    /// <summary>
    /// Settings the dashboard shows but never changes, because changing them
    /// from a GUI would be a security risk or would disconnect the tray. They
    /// can still be edited in appsettings.json by an administrator.
    /// </summary>
    public static IReadOnlyDictionary<string, string> LockedSettings { get; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["Updater:Repository"] = "Where updates come from can only be changed in appsettings.json, so a settings change can never point updates at another repository.",
        ["Alerts:FeedPath"] = "The installer gave only your account read access to this feed folder. Moving it would disconnect the tray, so it can only be changed in appsettings.json.",
    };

    /// <summary>The hub's own sections, which are not modules.</summary>
    public static IReadOnlyList<(string Path, string Title, Type Type)> HubSections { get; } = new[]
    {
        (HubOptions.SectionName, "Hub", typeof(HubOptions)),
        ("Alerts", "Alerts", typeof(AlertDeliveryOptions)),
        (EventLogAlertOptions.SectionName, "Alerts: Event Log", typeof(EventLogAlertOptions)),
        (DailySummaryOptions.SectionName, "Alerts: Daily summary", typeof(DailySummaryOptions)),
    };

    public static IReadOnlyList<SettingsSection> Build(ModuleCatalog catalog)
    {
        var sections = new List<SettingsSection>
        {
            new(ModuleCatalog.SectionName, "Modules", catalog.Modules
                .Select(m => new SettingField($"{ModuleCatalog.SectionName}:{m.Id}:Enabled", m.DisplayName, SettingKind.Boolean, false,
                    Default: JsonValue.Create(m.EnabledByDefault)))
                .ToArray()),
        };
        sections.AddRange(HubSections.Select(s => new SettingsSection(s.Path, s.Title, Fields(s.Path, s.Type))));
        sections.AddRange(catalog.Modules.Where(m => m.SettingsType is not null)
            .Select(m => new SettingsSection(m.Id, m.DisplayName, Fields(m.Id, m.SettingsType!), m.Id)));
        return sections;
    }

    /// <summary>Each section and the options class the hub binds it to.</summary>
    public static IReadOnlyList<(string Path, Type Type)> BindableSections(ModuleCatalog catalog) =>
        HubSections.Select(s => (s.Path, s.Type))
            .Concat(catalog.Modules.Where(m => m.SettingsType is not null).Select(m => (m.Id, m.SettingsType!)))
            .ToArray();

    public static SettingsDescription Describe(ModuleCatalog catalog, string settingsPath, JsonObject values) =>
        new(SettingsDescription.CurrentVersion, settingsPath,
            catalog.Modules.Select(m => new ModuleDescription(m.Id, m.DisplayName, m.Description, m.EnabledByDefault)).ToArray(),
            Build(catalog), values);

    /// <summary>One field per public, settable instance property, in declaration order.</summary>
    public static IReadOnlyList<SettingField> Fields(string sectionPath, Type optionsType)
    {
        var nullability = new NullabilityInfoContext();
        var defaults = optionsType.GetConstructor(Type.EmptyTypes) is null ? null : Activator.CreateInstance(optionsType);
        return optionsType.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.CanRead && p.SetMethod is { IsPublic: true } && p.GetIndexParameters().Length == 0)
            .OrderBy(p => p.MetadataToken)
            .Select(p =>
            {
                var path = $"{sectionPath}:{p.Name}";
                var (kind, nullable, choices) = Classify(p, nullability);
                return new SettingField(path, Humanize(p.Name), kind, nullable, choices,
                    LockedSettings.TryGetValue(path, out var reason) ? reason : null,
                    defaults is null || kind == SettingKind.Unsupported ? null : DefaultValue(p.GetValue(defaults)));
            })
            .ToArray();
    }

    private static JsonNode? DefaultValue(object? value) => value switch
    {
        null => null,
        string text => JsonValue.Create(text),
        Enum choice => JsonValue.Create(choice.ToString()),
        bool flag => JsonValue.Create(flag),
        IEnumerable<string> list => new JsonArray(list.Select(e => (JsonNode?)JsonValue.Create(e)).ToArray()),
        int or long or short => JsonValue.Create(Convert.ToInt64(value, CultureInfo.InvariantCulture)),
        _ => JsonValue.Create(Convert.ToDouble(value, CultureInfo.InvariantCulture)),
    };

    private static (SettingKind, bool, IReadOnlyList<string>?) Classify(PropertyInfo property, NullabilityInfoContext nullability)
    {
        var type = property.PropertyType;
        var underlying = System.Nullable.GetUnderlyingType(type);
        if (underlying is not null)
        {
            var (kind, _, choices) = ClassifyValue(underlying);
            return (kind, true, choices);
        }
        if (type == typeof(string))
            return (SettingKind.Text, nullability.Create(property).WriteState == NullabilityState.Nullable, null);
        if (type == typeof(string[]) || type == typeof(List<string>) || type == typeof(IList<string>)
            || type == typeof(IReadOnlyList<string>) || type == typeof(IEnumerable<string>))
            return (SettingKind.TextList, false, null);
        return ClassifyValue(type);
    }

    private static (SettingKind, bool, IReadOnlyList<string>?) ClassifyValue(Type type)
    {
        if (type == typeof(bool)) return (SettingKind.Boolean, false, null);
        if (type == typeof(int) || type == typeof(long) || type == typeof(short)) return (SettingKind.Integer, false, null);
        if (type == typeof(double) || type == typeof(float) || type == typeof(decimal)) return (SettingKind.Number, false, null);
        if (type.IsEnum) return (SettingKind.Choice, false, Enum.GetNames(type));
        return (SettingKind.Unsupported, false, null);
    }

    /// <summary>"CheckIntervalSeconds" becomes "Check interval seconds".</summary>
    public static string Humanize(string name)
    {
        var text = new StringBuilder(name.Length + 8);
        for (var i = 0; i < name.Length; i++)
        {
            var c = name[i];
            var startsWord = i > 0 && char.IsUpper(c)
                && (char.IsLower(name[i - 1]) || (i + 1 < name.Length && char.IsLower(name[i + 1]) && char.IsUpper(name[i - 1])));
            if (startsWord) text.Append(' ');
            // Keep acronyms such as "ASR" in capitals; lower-case the start of ordinary words.
            var acronym = char.IsUpper(c) && ((i + 1 < name.Length && char.IsUpper(name[i + 1])) || (i > 0 && char.IsUpper(name[i - 1]) && !startsWord));
            text.Append(i == 0 || acronym ? c : char.ToLowerInvariant(c));
        }
        return text.ToString();
    }
}

using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml;
using System.Xml.Linq;

namespace WatchLattice.Persistence.Verification;

public static class TaskActionKinds
{
    public const string Exec = "Exec";
    public const string ComHandler = "ComHandler";
    public const string SendEmail = "SendEmail";
    public const string ShowMessage = "ShowMessage";
    public const string Unknown = "Unknown";
}

public sealed record TaskAction(string Kind, string? Execute = null, string? Arguments = null,
    string? WorkingDirectory = null, string? ClassId = null, string? Data = null)
{
    public string Describe() => Kind switch
    {
        TaskActionKinds.Exec => $"Runs {Execute}{(string.IsNullOrEmpty(Arguments) ? "" : " " + Arguments)}",
        TaskActionKinds.ComHandler => $"COM handler {ClassId}{(string.IsNullOrEmpty(Data) ? "" : " with data " + Data)}",
        _ => Kind + " action",
    };
}

/// <summary>
/// The security-relevant parts of a scheduled task, from either the
/// auditor's logged projection (JSON) or the live task XML, normalized so the
/// two can be compared.
/// </summary>
public sealed record TaskFacts(bool? Enabled, string? UserId, string? GroupId, string? RunLevel, string? LogonType,
    IReadOnlyList<TaskAction> Actions, IReadOnlyList<string?> TriggerStarts)
{
    private const string TaskNamespace = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    /// <summary>A real task nests about eight elements deep. Anything far beyond that is not read.</summary>
    private const int MaxXmlDepth = 64;

    /// <summary>Parses the JSON the auditor logged for a task (see <see cref="WindowsPersistenceProvider.ScheduledTaskScript"/>).</summary>
    public static TaskFacts FromProjection(string json)
    {
        try
        {
            return FromProjection(LoggedJson.Parse(json) as JsonObject
                ?? throw new InvalidDataException("The logged task definition is not a JSON object."));
        }
        catch (InvalidOperationException ex)
        {
            throw LoggedJson.NotText(ex);
        }
    }

    private static TaskFacts FromProjection(JsonObject root)
    {
        var actions = Items(Get(root, "Actions")).Select(a =>
        {
            var execute = Text(Get(a, "Execute"));
            var classId = Text(Get(a, "ClassId"));
            var kind = !string.IsNullOrEmpty(classId) ? TaskActionKinds.ComHandler
                : !string.IsNullOrEmpty(execute) ? TaskActionKinds.Exec : TaskActionKinds.Unknown;
            return new TaskAction(kind, Empty(execute), Empty(Text(Get(a, "Arguments"))), Empty(Text(Get(a, "WorkingDirectory"))),
                Empty(classId), Empty(Text(Get(a, "Data"))));
        }).ToArray();
        var triggers = Items(Get(root, "Triggers")).Select(t => Empty(Text(Get(t, "StartBoundary")))).ToArray();
        return new(Get(root, "Enabled") is JsonValue enabled && enabled.TryGetValue<bool>(out var on) ? on : null,
            Empty(Text(Get(root, "UserId"))), Empty(Text(Get(root, "GroupId"))),
            NormalizeRunLevel(Text(Get(root, "RunLevel"))), NormalizeLogonType(Text(Get(root, "LogonType"))), actions, triggers);
    }

    /// <summary>Parses task XML from the Task Scheduler API. DTDs and external entities are refused.</summary>
    public static TaskFacts FromXml(string xml)
    {
        XDocument document;
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 4 * 1024 * 1024 };
        // A task's ComHandler data may hold any XML, and whoever registers the task writes it. Loading a
        // document takes time that grows much faster than its nesting depth (40,000 levels took seconds,
        // 200,000 minutes), so the depth is checked first, in one pass that does not.
        using (var probe = XmlReader.Create(new StringReader(xml), settings))
        {
            while (probe.Read())
            {
                if (probe.Depth > MaxXmlDepth) throw new InvalidDataException($"The task definition is nested more than {MaxXmlDepth} elements deep.");
            }
        }
        using (var reader = XmlReader.Create(new StringReader(xml), settings)) document = XDocument.Load(reader);
        var task = document.Root ?? throw new InvalidDataException("The task definition is empty.");
        if (task.Name.LocalName != "Task") throw new InvalidDataException("The task definition is not a Task element.");

        var actionsElement = Child(task, "Actions");
        var context = actionsElement?.Attribute("Context")?.Value;
        var principals = Child(task, "Principals")?.Elements().Where(e => e.Name.LocalName == "Principal").ToArray() ?? Array.Empty<XElement>();
        var principal = principals.FirstOrDefault(p => context is not null && p.Attribute("id")?.Value == context) ?? principals.FirstOrDefault();

        var actions = (actionsElement?.Elements() ?? Enumerable.Empty<XElement>()).Select(a => a.Name.LocalName switch
        {
            "Exec" => new TaskAction(TaskActionKinds.Exec, Empty(Value(a, "Command")), Empty(Value(a, "Arguments")), Empty(Value(a, "WorkingDirectory"))),
            "ComHandler" => new TaskAction(TaskActionKinds.ComHandler, ClassId: Empty(Value(a, "ClassId")), Data: Empty(Value(a, "Data"))),
            "SendEmail" => new TaskAction(TaskActionKinds.SendEmail),
            "ShowMessage" => new TaskAction(TaskActionKinds.ShowMessage),
            _ => new TaskAction(TaskActionKinds.Unknown),
        }).ToArray();
        var triggers = (Child(task, "Triggers")?.Elements() ?? Enumerable.Empty<XElement>()).Select(t => Empty(Value(t, "StartBoundary"))).ToArray();
        var enabledText = Value(Child(task, "Settings"), "Enabled");
        return new(enabledText is null ? true : string.Equals(enabledText.Trim(), "true", StringComparison.OrdinalIgnoreCase),
            Empty(Value(principal, "UserId")), Empty(Value(principal, "GroupId")),
            NormalizeRunLevel(Value(principal, "RunLevel") ?? "LeastPrivilege"), NormalizeLogonType(Value(principal, "LogonType")),
            actions, triggers);
    }

    public static string? NormalizeRunLevel(string? value) => value?.Trim() switch
    {
        null or "" => null,
        var v when v.Equals("HighestAvailable", StringComparison.OrdinalIgnoreCase) || v.Equals("Highest", StringComparison.OrdinalIgnoreCase) => "Highest",
        var v when v.Equals("LeastPrivilege", StringComparison.OrdinalIgnoreCase) || v.Equals("Limited", StringComparison.OrdinalIgnoreCase) => "Limited",
        var v => v,
    };

    public static string? NormalizeLogonType(string? value) => value?.Trim() switch
    {
        null or "" => null,
        var v when v.Equals("InteractiveToken", StringComparison.OrdinalIgnoreCase) => "Interactive",
        var v when v.Equals("InteractiveTokenOrPassword", StringComparison.OrdinalIgnoreCase) => "InteractiveOrPassword",
        var v => v,
    };

    private static XElement? Child(XElement? parent, string name) => parent?.Elements().FirstOrDefault(e => e.Name.LocalName == name);
    private static string? Value(XElement? parent, string name) => Child(parent, name)?.Value;
    private static string? Empty(string? value) => string.IsNullOrEmpty(value) ? null : value;

    private static JsonNode? Get(JsonNode? node, string name) =>
        node is JsonObject obj ? obj.FirstOrDefault(p => string.Equals(p.Key, name, StringComparison.OrdinalIgnoreCase)).Value : null;

    private static IEnumerable<JsonNode?> Items(JsonNode? node) => node switch
    {
        JsonArray array => array,
        JsonObject single => new[] { single },
        _ => Enumerable.Empty<JsonNode?>(),
    };

    private static string? Text(JsonNode? node) => node switch
    {
        null => null,
        JsonValue value when value.TryGetValue<string>(out var s) => s,
        _ => node.ToJsonString(),
    };
}

/// <summary>Field-by-field differences between task definitions.</summary>
public static class TaskComparison
{
    /// <summary>
    /// Every leaf that differs between two logged JSON definitions, e.g.
    /// <c>Triggers[0].StartBoundary</c>. Throws when either is not valid JSON.
    /// </summary>
    public static IReadOnlyList<FieldChange> CompareLogged(string? before, string? after)
    {
        var left = Flatten(before);
        var right = Flatten(after);
        var changes = new List<FieldChange>();
        foreach (var key in left.Keys.Union(right.Keys, StringComparer.OrdinalIgnoreCase).OrderBy(k => k, StringComparer.Ordinal))
        {
            left.TryGetValue(key, out var a);
            right.TryGetValue(key, out var b);
            if (!string.Equals(a, b, StringComparison.Ordinal)) changes.Add(new(key, AreaOf(key), a, b));
        }
        return changes;
    }

    /// <summary>
    /// Differences between the definition logged with the alert and the
    /// task's current definition. Principals are compared by SID, so
    /// "NETWORK SERVICE" and S-1-5-20 are the same account. A principal that
    /// cannot be resolved is reported in <paramref name="unresolved"/>
    /// rather than as a change.
    /// </summary>
    public static IReadOnlyList<FieldChange> CompareCurrent(TaskFacts logged, TaskFacts current, IAccountResolver accounts, out IReadOnlyList<string> unresolved)
    {
        var changes = new List<FieldChange>();
        var notes = new List<string>();
        if (logged.Enabled is { } was && current.Enabled is { } now && was != now)
            changes.Add(new("Enabled", ChangeArea.Enabled, Bool(was), Bool(now)));
        ComparePrincipal("UserId", logged.UserId, current.UserId, accounts, changes, notes);
        ComparePrincipal("GroupId", logged.GroupId, current.GroupId, accounts, changes, notes);
        if (logged.RunLevel is not null && current.RunLevel is not null && !string.Equals(logged.RunLevel, current.RunLevel, StringComparison.OrdinalIgnoreCase))
            changes.Add(new("RunLevel", ChangeArea.Principal, logged.RunLevel, current.RunLevel));
        if (logged.LogonType is not null && current.LogonType is not null && !string.Equals(logged.LogonType, current.LogonType, StringComparison.OrdinalIgnoreCase))
            changes.Add(new("LogonType", ChangeArea.Principal, logged.LogonType, current.LogonType));

        for (var i = 0; i < Math.Max(logged.Actions.Count, current.Actions.Count); i++)
        {
            var a = i < logged.Actions.Count ? logged.Actions[i] : null;
            var b = i < current.Actions.Count ? current.Actions[i] : null;
            if (a is null || b is null)
            {
                changes.Add(new($"Actions[{i}]", ChangeArea.Action, a?.Describe(), b?.Describe()));
                continue;
            }
            void Field(string name, string? x, string? y, StringComparison comparison)
            {
                if (!string.Equals(x ?? "", y ?? "", comparison)) changes.Add(new($"Actions[{i}].{name}", ChangeArea.Action, x, y));
            }
            Field("Kind", a.Kind, b.Kind, StringComparison.Ordinal);
            Field("Execute", a.Execute, b.Execute, StringComparison.Ordinal);
            Field("Arguments", a.Arguments, b.Arguments, StringComparison.Ordinal);
            Field("WorkingDirectory", a.WorkingDirectory, b.WorkingDirectory, StringComparison.Ordinal);
            Field("ClassId", a.ClassId, b.ClassId, StringComparison.OrdinalIgnoreCase);
            Field("Data", a.Data, b.Data, StringComparison.Ordinal);
        }

        if (logged.TriggerStarts.Count != current.TriggerStarts.Count)
            changes.Add(new("Triggers", ChangeArea.Schedule, $"{logged.TriggerStarts.Count} trigger(s)", $"{current.TriggerStarts.Count} trigger(s)"));
        else
            for (var i = 0; i < logged.TriggerStarts.Count; i++)
                if (!string.Equals(logged.TriggerStarts[i], current.TriggerStarts[i], StringComparison.Ordinal))
                    changes.Add(new($"Triggers[{i}].StartBoundary", ChangeArea.Schedule, logged.TriggerStarts[i], current.TriggerStarts[i]));
        unresolved = notes;
        return changes;
    }

    public static ChangeArea AreaOf(string field)
    {
        var head = field.Split('.', '[')[0];
        return head.ToLowerInvariant() switch
        {
            "actions" => ChangeArea.Action,
            "userid" or "groupid" or "runlevel" or "logontype" => ChangeArea.Principal,
            "enabled" => ChangeArea.Enabled,
            "triggers" => ChangeArea.Schedule,
            _ => ChangeArea.Other,
        };
    }

    /// <summary>Changes to where an action points (the program or COM class), as opposed to its arguments.</summary>
    public static bool IsTargetChange(FieldChange change) => change.Area == ChangeArea.Action
        && (change.Field.EndsWith(".Execute", StringComparison.OrdinalIgnoreCase) || change.Field.EndsWith(".ClassId", StringComparison.OrdinalIgnoreCase)
            || change.Field.EndsWith(".Kind", StringComparison.OrdinalIgnoreCase) || !change.Field.Contains('.'));

    // Trigger fields that only move when an existing trigger fires. A trigger's type, event
    // subscription, user or enabled state changes what starts the task, not just when.
    private static readonly HashSet<string> TimingFields = new(StringComparer.OrdinalIgnoreCase)
    {
        "StartBoundary", "EndBoundary", "Delay", "RandomDelay", "Interval", "Duration",
        "DaysInterval", "WeeksInterval", "DaysOfWeek", "DaysOfMonth", "MonthsOfYear",
    };

    private static readonly System.Text.RegularExpressions.Regex TriggerField =
        new(@"\ATriggers\[\d+\]\.(?<name>[A-Za-z]+)\z", System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    /// <summary>A change to when an existing trigger fires, e.g. <c>Triggers[0].StartBoundary</c>. Adding or removing a trigger is not one.</summary>
    public static bool IsTimingChange(FieldChange change)
    {
        if (change.Area != ChangeArea.Schedule) return false;
        var match = TriggerField.Match(change.Field);
        return match.Success && TimingFields.Contains(match.Groups["name"].Value);
    }

    /// <summary>True when every change is to trigger timing, and there is at least one.</summary>
    public static bool IsTimingOnly(IReadOnlyList<FieldChange> changes) => changes.Count > 0 && changes.All(IsTimingChange);

    /// <summary>
    /// True when two logged definitions differ only in trigger timing. A
    /// definition that cannot be read is never timing-only.
    /// </summary>
    public static bool IsTimingOnlyChange(string? before, string? after)
    {
        if (before is null || after is null) return false;
        try { return IsTimingOnly(CompareLogged(before, after)); }
        catch (Exception ex) when (ex is JsonException or InvalidDataException) { return false; }
    }

    /// <summary>
    /// A principal change that gives the task more power: highest privileges,
    /// or running as SYSTEM or the Administrators group, when it did not before.
    /// </summary>
    public static bool IsPrivilegeGain(FieldChange change, IAccountResolver accounts)
    {
        if (change.Area != ChangeArea.Principal) return false;
        switch (change.Field.ToLowerInvariant())
        {
            case "runlevel":
                return IsHighest(change.After) && !IsHighest(change.Before);
            case "userid" or "groupid":
                var after = Accounts.Normalize(change.After, accounts);
                return after is Accounts.LocalSystem or Accounts.Administrators
                    && !string.Equals(after, Accounts.Normalize(change.Before, accounts), StringComparison.OrdinalIgnoreCase);
            default:
                return false;
        }
    }

    private static bool IsHighest(string? runLevel) =>
        string.Equals(runLevel, "Highest", StringComparison.OrdinalIgnoreCase) || string.Equals(runLevel, "HighestAvailable", StringComparison.OrdinalIgnoreCase);

    private static void ComparePrincipal(string field, string? logged, string? current, IAccountResolver accounts,
        List<FieldChange> changes, List<string> notes)
    {
        if (string.IsNullOrWhiteSpace(logged) && string.IsNullOrWhiteSpace(current)) return;
        if (string.Equals(logged?.Trim(), current?.Trim(), StringComparison.OrdinalIgnoreCase)) return;
        var a = Accounts.Normalize(logged, accounts);
        var b = Accounts.Normalize(current, accounts);
        if (a is not null && b is not null)
        {
            if (!string.Equals(a, b, StringComparison.OrdinalIgnoreCase)) changes.Add(new(field, ChangeArea.Principal, logged, current));
            return;
        }
        if (string.IsNullOrWhiteSpace(logged) || string.IsNullOrWhiteSpace(current))
        {
            changes.Add(new(field, ChangeArea.Principal, logged, current));
            return;
        }
        notes.Add($"{field}: could not tell whether \"{logged}\" and \"{current}\" are the same account.");
    }

    private static Dictionary<string, string?> Flatten(string? json)
    {
        var result = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        if (json is null) return result;
        var root = LoggedJson.Parse(json);
        void Walk(JsonNode? node, string path)
        {
            switch (node)
            {
                case JsonObject obj:
                    foreach (var (key, value) in obj) Walk(value, path.Length == 0 ? key : path + "." + key);
                    break;
                case JsonArray array:
                    if (array.Count == 0) result[path] = "[]";
                    for (var i = 0; i < array.Count; i++) Walk(array[i], $"{path}[{i}]");
                    break;
                case null:
                    result[path] = null;
                    break;
                default:
                    result[path] = node is JsonValue v && v.TryGetValue<string>(out var s) ? s : node.ToJsonString();
                    break;
            }
        }
        try { Walk(root, ""); }
        catch (InvalidOperationException ex) { throw LoggedJson.NotText(ex); }
        return result;
    }

    private static string Bool(bool value) => value ? "true" : "false";
}

/// <summary>
/// Reads the JSON the auditor logged for a task. That JSON carries text chosen
/// by whoever registered the task, so everything that can be wrong with it is
/// reported the same two ways, <see cref="JsonException"/> and
/// <see cref="InvalidDataException"/>, which every caller already handles.
/// </summary>
internal static class LoggedJson
{
    public static JsonNode? Parse(string json)
    {
        try
        {
            // As UTF-8, because the text overload throws ArgumentException for half of a surrogate pair. Repeated
            // property names are refused here, because a JsonObject otherwise throws ArgumentException when first read.
            return JsonNode.Parse(System.Text.Encoding.UTF8.GetBytes(json),
                documentOptions: new JsonDocumentOptions { MaxDepth = 16, AllowDuplicateProperties = false });
        }
        catch (InvalidOperationException ex)
        {
            // Looking for repeated names reads each name, and one with a broken \u escape cannot be read.
            throw NotText(ex);
        }
    }

    /// <summary>A string spelled with a broken \u escape parses, then throws InvalidOperationException when it is read.</summary>
    public static InvalidDataException NotText(InvalidOperationException ex) =>
        new("The logged task definition holds text that is not valid: " + ex.Message, ex);
}

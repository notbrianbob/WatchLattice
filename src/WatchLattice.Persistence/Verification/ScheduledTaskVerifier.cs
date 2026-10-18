using System.Text.Json;
using System.Xml;

namespace WatchLattice.Persistence.Verification;

/// <summary>
/// Verifies a scheduled task named in a persistence alert: reads its current
/// definition from the Task Scheduler, resolves every action (COM handlers
/// through the registry, programs through their paths), inspects each target
/// file's signature and metadata, and compares the task with the definition
/// logged with the alert and with the trusted baseline. Read-only throughout.
/// </summary>
public sealed class ScheduledTaskVerifier : IEntryVerifier
{
    public const string SourcePrefix = "ScheduledTasks/";
    private const int MaxDefinitionChars = 65536;

    /// <summary>
    /// Microsoft-signed programs that run whatever their arguments tell them
    /// to. Their signature says nothing about what a task makes them do.
    /// </summary>
    public static IReadOnlySet<string> HostPrograms { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe", "wscript.exe", "cscript.exe", "mshta.exe",
        "rundll32.exe", "regsvr32.exe", "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "certutil.exe",
        "bitsadmin.exe", "forfiles.exe", "conhost.exe", "hh.exe", "wmic.exe", "msiexec.exe", "msxsl.exe", "odbcconf.exe",
        "cmstp.exe", "bash.exe", "wsl.exe", "curl.exe", "explorer.exe",
    };

    private readonly IScheduledTaskSource _tasks;
    private readonly IComRegistry _registry;
    private readonly IAccountResolver _accounts;
    private readonly IFileInspector _files;
    private readonly SystemPaths _paths;
    private readonly IReadOnlyList<string> _familiarPublishers;

    public ScheduledTaskVerifier(IScheduledTaskSource tasks, IComRegistry registry, IAccountResolver accounts,
        IFileInspector files, SystemPaths paths, IEnumerable<string>? familiarPublishers = null)
    {
        _tasks = tasks;
        _registry = registry;
        _accounts = accounts;
        _files = files;
        _paths = paths;
        _familiarPublishers = (familiarPublishers ?? Array.Empty<string>()).Where(p => !string.IsNullOrWhiteSpace(p)).Select(p => p.Trim()).ToArray();
    }

    public string Mechanism => "Scheduled task";

    public bool AppliesTo(PersistenceObservation observation) =>
        observation.SourceId.StartsWith(SourcePrefix, StringComparison.OrdinalIgnoreCase)
        && observation.Kind is PersistenceChangeKind.Added or PersistenceChangeKind.Changed;

    public async Task<VerifierResult> VerifyAsync(PersistenceObservation observation, CancellationToken cancellationToken)
    {
        var checks = new List<VerificationCheck>();
        var errors = new List<string>();
        var evidence = new List<ActionEvidence>();
        IReadOnlyList<FieldChange> logged = Array.Empty<FieldChange>();
        IReadOnlyList<FieldChange> since = Array.Empty<FieldChange>();

        // 1. What the alert itself recorded: historical state, independent of what the task looks like now.
        TaskFacts? loggedAfter = null;
        try
        {
            loggedAfter = observation.After is null ? null : TaskFacts.FromProjection(observation.After);
            if (observation.Kind == PersistenceChangeKind.Changed)
            {
                if (observation.Before is not null) TaskFacts.FromProjection(observation.Before);
                logged = TaskComparison.CompareLogged(observation.Before, observation.After);
            }
            checks.Add(LoggedChangeCheck(observation, logged));
        }
        catch (Exception ex) when (ex is JsonException or InvalidDataException)
        {
            errors.Add("The definition logged with the alert could not be read: " + ex.Message);
            checks.Add(new("logged-change", "Change in the alert", CheckStatus.Unknown,
                "The definition logged with the alert could not be read, so the change could not be broken down: " + ex.Message));
        }

        // 2. The task as it is now.
        var path = observation.EntryId;
        if (!WindowsPath.IsValidTaskPath(path))
        {
            checks.Add(new("task", "Current task", CheckStatus.Unknown, "The alert does not name a valid task path, so nothing was looked up."));
            return new(checks, logged, since, evidence, null, errors);
        }
        cancellationToken.ThrowIfCancellationRequested();
        var read = _tasks.Read(path);
        switch (read.Status)
        {
            case TaskReadStatus.NotFound:
                checks.Add(new("task", "Current task", CheckStatus.Warning,
                    "The task no longer exists. It may have been removed or renamed after the alert, so its current state cannot be verified."));
                return new(checks, logged, since, evidence, null, errors);
            case TaskReadStatus.AccessDenied:
                checks.Add(new("task", "Current task", CheckStatus.Unknown,
                    $"The task could not be read as {_accounts.CurrentAccount}: access denied. Its current state is unverified."));
                return new(checks, logged, since, evidence, null, errors);
            case TaskReadStatus.Error:
                errors.Add("Task Scheduler: " + read.Error);
                checks.Add(new("task", "Current task", CheckStatus.Unknown, "The task could not be read: " + read.Error));
                return new(checks, logged, since, evidence, null, errors);
        }

        TaskFacts current;
        var definition = read.Xml!.Length <= MaxDefinitionChars ? read.Xml : read.Xml[..MaxDefinitionChars] + "… (truncated)";
        try { current = TaskFacts.FromXml(read.Xml!); }
        catch (Exception ex) when (ex is XmlException or InvalidDataException)
        {
            errors.Add("The current task definition could not be parsed: " + ex.Message);
            checks.Add(new("task", "Current task", CheckStatus.Unknown, "The current definition could not be parsed: " + ex.Message));
            return new(checks, logged, since, evidence, definition, errors);
        }
        checks.Add(new("task", "Current task", CheckStatus.Pass,
            $"Read from the Task Scheduler. {(current.Enabled == false ? "Disabled" : "Enabled")}, runs as {DescribePrincipal(current)}, {current.Actions.Count} action(s)."));

        // 3. Has it changed again since the alert?
        if (loggedAfter is not null)
        {
            since = TaskComparison.CompareCurrent(loggedAfter, current, _accounts, out var unresolved);
            checks.Add(SinceAlertCheck(since, unresolved));
        }

        // 4. Known configuration: the trusted baseline, or unchanged from what was recorded before the alert.
        var trusted = TrustedBaseline.Find(path);
        checks.Add(KnownConfigurationCheck(observation, logged, current, trusted));

        // 5. Every action.
        var runAs = RunAsSids(current, out var principalNote);
        if (current.Actions.Count == 0)
            checks.Add(new("actions", "Actions", CheckStatus.Warning, "The task has no actions."));
        for (var i = 0; i < current.Actions.Count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var expected = trusted is not null && i < trusted.Actions.Count ? trusted.Actions[i] : null;
            evidence.Add(await VerifyActionAsync(i, current.Actions[i], path, current, runAs, principalNote, expected, trusted, checks, cancellationToken)
                .ConfigureAwait(false));
        }
        return new(checks, logged, since, evidence, definition, errors);
    }

    private async Task<ActionEvidence> VerifyActionAsync(int index, TaskAction action, string taskPath, TaskFacts task,
        IReadOnlyList<string> runAs, string? principalNote, TrustedAction? expected, TrustedTask? trusted,
        List<VerificationCheck> checks, CancellationToken cancellationToken)
    {
        var n = index + 1;
        var prefix = $"action{n}.";
        var label = $"(action {n})";
        var notes = new List<string>();
        if (principalNote is not null) notes.Add(principalNote);

        string? rawTarget;
        string? clsid = null;
        string? location = null;
        ResolvedPath resolved;
        var accountVariables = AccountVariables(runAs);

        switch (action.Kind)
        {
            case TaskActionKinds.ComHandler:
                var com = ComResolver.Resolve(_registry, action.ClassId, runAs, _paths.Is64BitOperatingSystem);
                clsid = com.Clsid;
                location = com.Effective?.Location;
                notes.AddRange(com.Notes);
                checks.Add(new(prefix + "registration", $"COM registration {label}", com.Status, com.Detail));
                rawTarget = com.Server;
                if (rawTarget is null) return new(index, action.Kind, action.Describe(), clsid, location, null, null, null, notes);
                resolved = WindowsPath.Resolve(rawTarget, _paths, accountVariables, _files.Exists,
                    defaultExtension: com.Effective?.InprocServer32 is not null ? ".dll" : ".exe");
                break;
            case TaskActionKinds.Exec:
                rawTarget = action.Execute;
                if (rawTarget is null)
                {
                    checks.Add(new(prefix + "target", $"Program {label}", CheckStatus.Warning, "The action has no program."));
                    return new(index, action.Kind, action.Describe(), Notes: notes);
                }
                resolved = WindowsPath.Resolve(rawTarget, _paths, accountVariables, _files.Exists, action.WorkingDirectory);
                break;
            default:
                checks.Add(new(prefix + "kind", $"Action type {label}", CheckStatus.Unknown,
                    $"{action.Kind} actions cannot be verified. Windows no longer runs e-mail and message actions; their presence is unusual."));
                return new(index, action.Kind, action.Describe(), Notes: notes);
        }

        if (resolved.Note.Length > 0) notes.Add(resolved.Note);
        var what = action.Kind == TaskActionKinds.ComHandler ? "Handler file" : "Program";

        if (expected is not null)
            checks.Add(BaselineTargetCheck(prefix, label, action, clsid, resolved, expected));
        else if (trusted is null && taskPath.StartsWith(@"\Microsoft\Windows\", StringComparison.OrdinalIgnoreCase) && resolved.Path is not null)
            checks.Add(WindowsLocationCheck(prefix, label, resolved.Path));

        FileEvidence? file = null;
        switch (resolved.Kind)
        {
            case PathResolution.Invalid:
                checks.Add(new(prefix + "target", $"{what} {label}", CheckStatus.Fail, $"{rawTarget}: {resolved.Note} It was not opened."));
                break;
            case PathResolution.Network:
                checks.Add(new(prefix + "target", $"{what} {label}", CheckStatus.Warning, $"{resolved.Path}: {resolved.Note}"));
                break;
            case PathResolution.Unresolved:
                checks.Add(new(prefix + "target", $"{what} {label}", CheckStatus.Unknown, $"{rawTarget}: {resolved.Note}"));
                break;
            default:
                file = await _files.InspectAsync(resolved.Path!, cancellationToken).ConfigureAwait(false);
                checks.Add(FileChecks.TargetCheck(prefix, $"{what} {label}", resolved, file));
                if (file.Exists && file.Error is null)
                {
                    var signature = file.Signature ?? new SignatureEvidence(SignatureState.Unknown, SignatureKind.None, Problem: "not checked");
                    checks.Add(FileChecks.SignatureCheck(prefix, label, signature));
                    if (signature.State == SignatureState.Valid)
                        checks.Add(FileChecks.PublisherCheck(prefix, label, signature, trusted?.Publisher, _familiarPublishers));
                }
                break;
        }

        var program = WindowsPath.FileName(resolved.Path ?? WindowsPath.Unquote(rawTarget));
        if (!program.Contains('.')) program += ".exe";
        if (action.Kind == TaskActionKinds.Exec && HostPrograms.Contains(program))
        {
            checks.Add(new(prefix + "host", $"Host program {label}", CheckStatus.Warning,
                $"{program} runs whatever its arguments tell it to, so its signature says nothing about what this task does. " +
                $"Arguments: {(string.IsNullOrEmpty(action.Arguments) ? "(none)" : action.Arguments)}"));
        }

        return new(index, action.Kind, action.Describe(), clsid, location, rawTarget, resolved.Path, file, notes);
    }

    private VerificationCheck LoggedChangeCheck(PersistenceObservation observation, IReadOnlyList<FieldChange> changes)
    {
        const string id = "logged-change";
        const string title = "Change in the alert";
        if (observation.Kind == PersistenceChangeKind.Added)
            return new(id, title, CheckStatus.Pass, "A new task. There is no earlier definition to compare with.");
        if (changes.Count == 0)
            return new(id, title, CheckStatus.Pass, "No field differs between the logged definitions.");

        var targets = changes.Where(TaskComparison.IsTargetChange).ToArray();
        if (targets.Length > 0)
            return new(id, title, CheckStatus.Fail, "The alert changed what the task runs: " + Describe(targets) + OtherChanges(changes, targets));
        var gains = changes.Where(c => TaskComparison.IsPrivilegeGain(c, _accounts)).ToArray();
        if (gains.Length > 0)
            return new(id, title, CheckStatus.Fail, "The alert gave the task more privileges (highest privileges, SYSTEM or Administrators): "
                + Describe(gains) + OtherChanges(changes, gains));
        var actions = changes.Where(c => c.Area == ChangeArea.Action).ToArray();
        if (actions.Length > 0)
            return new(id, title, CheckStatus.Warning, "The alert changed an action's arguments or data: " + Describe(actions) + OtherChanges(changes, actions));
        var principal = changes.Where(c => c.Area == ChangeArea.Principal).ToArray();
        if (principal.Length > 0)
            return new(id, title, CheckStatus.Warning, "The alert changed the account or privileges it runs with: " + Describe(principal) + OtherChanges(changes, principal));
        var enabled = changes.FirstOrDefault(c => c.Area == ChangeArea.Enabled && c.After == "true");
        if (enabled is not null)
            return new(id, title, CheckStatus.Warning, "The alert re-enabled a disabled task." + OtherChanges(changes, new[] { enabled }));
        var other = changes.Where(c => c.Area == ChangeArea.Other).ToArray();
        if (other.Length > 0)
            return new(id, title, CheckStatus.Warning, "The alert changed fields this check does not classify: " + Describe(other));
        var triggers = changes.Where(c => c.Area == ChangeArea.Schedule && !TaskComparison.IsTimingChange(c)).ToArray();
        if (triggers.Length > 0)
            return new(id, title, CheckStatus.Warning, "The alert changed what starts the task, not only when (a trigger added, removed, " +
                "or changed in type, event, user or enabled state): " + Describe(triggers) + OtherChanges(changes, triggers));
        return new(id, title, CheckStatus.Pass, "Only the schedule's timing or the enabled setting changed: " + Describe(changes)
            + ". What the task runs, what starts it and the account it runs as did not change.");
    }

    private static VerificationCheck SinceAlertCheck(IReadOnlyList<FieldChange> since, IReadOnlyList<string> unresolved)
    {
        const string id = "since-alert";
        const string title = "Current task vs. alert";
        var targets = since.Where(TaskComparison.IsTargetChange).ToArray();
        if (targets.Length > 0)
            return new(id, title, CheckStatus.Fail, "What the task runs has changed again since the alert: " + Describe(targets));
        var important = since.Where(c => c.Area is ChangeArea.Action or ChangeArea.Principal or ChangeArea.Enabled or ChangeArea.Other).ToArray();
        if (important.Length > 0)
            return new(id, title, CheckStatus.Warning, "The task has changed again since the alert: " + Describe(important));
        if (unresolved.Count > 0)
            return new(id, title, CheckStatus.Unknown, string.Join(" ", unresolved));
        if (since.Count > 0)
            return new(id, title, CheckStatus.Pass, "Unchanged since the alert apart from its schedule: " + Describe(since) + ".");
        return new(id, title, CheckStatus.Pass, "The current task matches the definition logged with the alert.");
    }

    private static VerificationCheck KnownConfigurationCheck(PersistenceObservation observation, IReadOnlyList<FieldChange> logged,
        TaskFacts current, TrustedTask? trusted)
    {
        const string id = "known-configuration";
        const string title = "Known configuration";
        if (trusted is not null)
        {
            var problems = new List<string>();
            if (current.Actions.Count != trusted.Actions.Count)
                problems.Add($"expected {trusted.Actions.Count} action(s), found {current.Actions.Count}");
            for (var i = 0; i < Math.Min(current.Actions.Count, trusted.Actions.Count); i++)
            {
                var expected = trusted.Actions[i];
                var actual = current.Actions[i];
                if (!string.Equals(expected.Kind, actual.Kind, StringComparison.Ordinal))
                    problems.Add($"action {i + 1} is {actual.Kind}, expected {expected.Kind}");
                else if (expected.ClassId is not null && !(WindowsPath.TryNormalizeClsid(actual.ClassId, out var c)
                    && string.Equals(c, expected.ClassId, StringComparison.OrdinalIgnoreCase)))
                    problems.Add($"action {i + 1} uses {actual.ClassId}, expected {expected.ClassId}");
            }
            return problems.Count == 0
                ? new(id, title, CheckStatus.Pass, $"A Windows component in the trusted baseline ({trusted.Reference}). Its actions have the expected type and class.")
                : new(id, title, CheckStatus.Fail, "Differs from the trusted baseline for this Windows component: " + string.Join("; ", problems) + ".");
        }
        if (observation.Kind == PersistenceChangeKind.Changed && observation.Before is not null
            && !logged.Any(c => c.Area is ChangeArea.Action or ChangeArea.Principal or ChangeArea.Other))
            return new(id, title, CheckStatus.Pass,
                "Not in the trusted baseline, but what it runs and its account are unchanged from the definition recorded before this alert. " +
                "That earlier recording was an inventory, not a safety verdict.");
        return new(id, title, CheckStatus.Warning,
            "Not in the trusted baseline and not recorded before in this form, so there is no known configuration to compare with.");
    }

    private VerificationCheck BaselineTargetCheck(string prefix, string label, TaskAction action, string? clsid, ResolvedPath resolved, TrustedAction expected)
    {
        var want = WindowsPath.Resolve(expected.Target, _paths, null, _ => false);
        if (resolved.Kind is PathResolution.Resolved or PathResolution.SearchOrder && WindowsPath.SamePath(resolved.Path, want.Path))
            return new(prefix + "baseline", $"Expected file {label}", CheckStatus.Pass, $"Points at {resolved.Path}, as the trusted baseline expects.");
        var subject = action.Kind == TaskActionKinds.ComHandler ? $"{clsid ?? action.ClassId} is registered to" : "The task runs";
        return new(prefix + "baseline", $"Expected file {label}", CheckStatus.Fail,
            $"{subject} {resolved.Path ?? "(unresolved)"}, but the trusted baseline expects {want.Path ?? expected.Target}.");
    }

    private VerificationCheck WindowsLocationCheck(string prefix, string label, string path)
    {
        var allowed = new[] { _paths.SystemRoot }
            .Concat(new[] { "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432" }.Select(v => _paths.Variables.TryGetValue(v, out var p) ? p : null))
            .Concat(new[] { _paths.Variables.TryGetValue("ProgramData", out var data) ? data + @"\Microsoft\Windows Defender\Platform" : null })
            .Where(p => !string.IsNullOrEmpty(p)).Select(p => p!);
        return allowed.Any(root => WindowsPath.IsUnder(path, root))
            ? new(prefix + "location", $"Location {label}", CheckStatus.Pass, "A task in the \\Microsoft\\Windows folder that runs a file from a Windows or program folder.")
            : new(prefix + "location", $"Location {label}", CheckStatus.Warning,
                $"A task in the \\Microsoft\\Windows folder normally runs Windows' own files, but this one runs {path}. Malware often hides tasks there.");
    }

    /// <summary>
    /// The accounts whose per-user registrations apply: the task's own user,
    /// or every signed-in user for tasks that run as whoever is signed in.
    /// </summary>
    private IReadOnlyList<string> RunAsSids(TaskFacts task, out string? note)
    {
        note = null;
        var user = Accounts.Normalize(task.UserId, _accounts);
        if (user is not null && Accounts.IsUserSid(user)) return new[] { user };
        IReadOnlyList<string> loaded;
        try { loaded = _registry.LoadedUserSids(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            loaded = Array.Empty<string>();
            note = "Signed-in users could not be listed: " + ex.Message;
        }
        if (task.UserId is not null && user is null)
            note = $"The task's account \"{task.UserId}\" could not be resolved, so per-user registrations of every signed-in user were checked.";
        return loaded.Where(Accounts.IsSid).ToArray();
    }

    private Func<string, string?>? AccountVariables(IReadOnlyList<string> runAs)
    {
        if (runAs.Count != 1) return null;
        var profile = _accounts.ProfilePath(runAs[0]);
        if (string.IsNullOrWhiteSpace(profile)) return null;
        profile = profile.TrimEnd('\\');
        return name => name.ToUpperInvariant() switch
        {
            "USERPROFILE" => profile,
            "LOCALAPPDATA" => profile + @"\AppData\Local",
            "APPDATA" => profile + @"\AppData\Roaming",
            _ => null,
        };
    }

    private string DescribePrincipal(TaskFacts task)
    {
        var account = task.UserId ?? task.GroupId ?? "(not set)";
        var sid = Accounts.Normalize(account, _accounts);
        var name = sid is null ? account : Accounts.Describe(sid);
        return task.RunLevel == "Highest" ? $"{name} with highest privileges" : name;
    }

    private static string Describe(IEnumerable<FieldChange> changes) =>
        string.Join("; ", changes.Take(8).Select(c => $"{c.Field}: {Show(c.Before)} → {Show(c.After)}"));

    private static string OtherChanges(IReadOnlyList<FieldChange> all, IReadOnlyCollection<FieldChange> shown)
    {
        var rest = all.Except(shown).ToArray();
        return rest.Length == 0 ? "." : ". Also changed: " + Describe(rest) + ".";
    }

    private static string Show(string? value) => value is null ? "(none)" : value.Length <= 200 ? $"\"{value}\"" : $"\"{value[..200]}…\"";
}

/// <summary>Reads fields from a certificate subject such as <c>CN=Microsoft Windows, O=Microsoft Corporation, …</c>.</summary>
public static class CertificateNames
{
    public static string? CommonName(string? subject) => Field(subject, "CN");

    public static string? Organization(string? subject) => Field(subject, "O");

    public static string? Field(string? subject, string key)
    {
        if (string.IsNullOrEmpty(subject)) return null;
        var parts = new List<string>();
        var current = new System.Text.StringBuilder();
        var quoted = false;
        foreach (var c in subject)
        {
            if (c == '"') quoted = !quoted;
            if ((c == ',' || c == ';') && !quoted)
            {
                parts.Add(current.ToString());
                current.Clear();
                continue;
            }
            current.Append(c);
        }
        parts.Add(current.ToString());
        foreach (var part in parts)
        {
            var equals = part.IndexOf('=');
            if (equals <= 0 || !string.Equals(part[..equals].Trim(), key, StringComparison.OrdinalIgnoreCase)) continue;
            return WindowsPath.Unquote(part[(equals + 1)..].Trim());
        }
        return null;
    }
}

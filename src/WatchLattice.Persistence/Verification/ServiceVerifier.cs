namespace WatchLattice.Persistence.Verification;

/// <summary>
/// Verifies an auto-start service named in a persistence alert: reads its
/// current configuration from the registry, resolves the program or service
/// DLL it runs, inspects that file's location, signature and metadata, and
/// compares the service with the definition logged with the alert.
/// Read-only throughout: it never starts, stops or reconfigures a service.
/// </summary>
public sealed class ServiceVerifier : IEntryVerifier
{
    public const string SourceId = "Services";
    private const string Prefix = "service.";
    private const string Label = "(service)";

    private readonly IServiceSource _services;
    private readonly IFileInspector _files;
    private readonly SystemPaths _paths;
    private readonly IReadOnlyList<string> _familiarPublishers;

    public ServiceVerifier(IServiceSource services, IFileInspector files, SystemPaths paths, IEnumerable<string>? familiarPublishers = null)
    {
        _services = services;
        _files = files;
        _paths = paths;
        _familiarPublishers = (familiarPublishers ?? Array.Empty<string>()).Where(p => !string.IsNullOrWhiteSpace(p)).Select(p => p.Trim()).ToArray();
    }

    public string Mechanism => "Service";

    public bool AppliesTo(PersistenceObservation observation) =>
        string.Equals(observation.SourceId, SourceId, StringComparison.OrdinalIgnoreCase)
        && observation.Kind is PersistenceChangeKind.Added or PersistenceChangeKind.Changed;

    public async Task<VerifierResult> VerifyAsync(PersistenceObservation observation, CancellationToken cancellationToken)
    {
        var checks = new List<VerificationCheck>();
        var errors = new List<string>();
        var evidence = new List<ActionEvidence>();
        IReadOnlyList<FieldChange> logged = Array.Empty<FieldChange>();
        IReadOnlyList<FieldChange> since = Array.Empty<FieldChange>();

        // 1. What the alert itself recorded.
        var loggedAfter = ServiceDefinition.TryParse(observation.After);
        var loggedBefore = ServiceDefinition.TryParse(observation.Before);
        if (loggedAfter is null || (observation.Kind == PersistenceChangeKind.Changed && loggedBefore is null))
        {
            errors.Add("The definition logged with the alert could not be read.");
            checks.Add(new("logged-change", "Change in the alert", CheckStatus.Unknown,
                "The definition logged with the alert is not a readable service definition (the key may have been unreadable), so the change could not be broken down."));
        }
        else
        {
            if (loggedBefore is not null) logged = ServiceAnalysis.Differences(loggedBefore, loggedAfter);
            checks.Add(LoggedChangeCheck(observation.Kind, loggedBefore, loggedAfter, logged));
        }

        // 2. The service as it is now.
        var name = observation.EntryId;
        if (!ServiceAnalysis.IsValidServiceName(name))
        {
            checks.Add(new("service", "Current service", CheckStatus.Unknown, "The alert does not name a valid service, so nothing was looked up."));
            return new(checks, logged, since, evidence, null, errors);
        }
        cancellationToken.ThrowIfCancellationRequested();
        var read = _services.Read(name);
        switch (read.Status)
        {
            case ServiceReadStatus.NotFound:
                checks.Add(new("service", "Current service", CheckStatus.Warning,
                    "The service no longer exists. It may have been removed after the alert, so its current state cannot be verified."));
                return new(checks, logged, since, evidence, null, errors);
            case ServiceReadStatus.AccessDenied:
                checks.Add(new("service", "Current service", CheckStatus.Unknown, "The service's registry key could not be read: access denied. Its current state is unverified."));
                return new(checks, logged, since, evidence, null, errors);
            case ServiceReadStatus.Error:
                errors.Add("Service registry: " + read.Error);
                checks.Add(new("service", "Current service", CheckStatus.Unknown, "The service could not be read: " + read.Error));
                return new(checks, logged, since, evidence, null, errors);
        }

        var current = read.Definition!;
        var definition = current.ToProjection();
        checks.Add(new("service", "Current service", current.Start == ServiceDefinition.AutoStart ? CheckStatus.Pass : CheckStatus.Warning,
            $"Read from the registry. {DescribeStart(current.Start)}, runs as {ServiceAnalysis.DescribeAccount(current.ObjectName)}" +
            (string.IsNullOrWhiteSpace(current.ServiceDll) ? "." : $", hosts {current.ServiceDll}.") +
            (current.Start == ServiceDefinition.AutoStart ? "" : " It no longer starts automatically, so it changed after the alert.")));

        // 3. Has it changed again since the alert?
        if (loggedAfter is not null)
        {
            since = ServiceAnalysis.Differences(loggedAfter, current);
            checks.Add(SinceAlertCheck(loggedAfter, current, since));
        }

        // 4. What it runs.
        evidence.Add(await VerifyTargetAsync(current, checks, cancellationToken).ConfigureAwait(false));
        if (!string.IsNullOrWhiteSpace(current.FailureCommand))
            checks.Add(new(Prefix + "failure-command", "Failure command", CheckStatus.Warning,
                $"Windows runs \"{Show(current.FailureCommand)}\" when this service fails. That command is not inspected; recovery programs are rare and worth a look."));
        return new(checks, logged, since, evidence, definition, errors);
    }

    private async Task<ActionEvidence> VerifyTargetAsync(ServiceDefinition service, List<VerificationCheck> checks, CancellationToken cancellationToken)
    {
        var notes = new List<string>();
        var target = ServiceAnalysis.Target(service, _paths, _files.Exists);
        if (target is null)
        {
            checks.Add(new(Prefix + "target", $"Program {Label}", CheckStatus.Warning, "The service has no ImagePath, so there is nothing for it to run."));
            return new(0, "Service", "(no program)", Notes: notes);
        }
        var what = target.IsServiceDll ? "Service DLL" : "Program";
        var summary = target.IsServiceDll ? $"{service.ImagePath} hosting {target.Raw}" : service.ImagePath ?? target.Raw;
        var resolved = target.Resolved;
        if (resolved.Note.Length > 0) notes.Add(resolved.Note);
        if (target.IsServiceDll && !string.Equals(WindowsPath.FileName(ServiceAnalysis.SplitCommand(service.ImagePath).Program), "svchost.exe", StringComparison.OrdinalIgnoreCase))
            notes.Add("A ServiceDll is set, but the service does not run svchost.exe, so the DLL may not be what runs.");

        checks.Add(LocationCheck(resolved, what));

        FileEvidence? file = null;
        switch (resolved.Kind)
        {
            case PathResolution.Invalid:
                checks.Add(new(Prefix + "target", $"{what} {Label}", CheckStatus.Fail, $"{target.Raw}: {resolved.Note} It was not opened."));
                break;
            case PathResolution.Network:
                checks.Add(new(Prefix + "target", $"{what} {Label}", CheckStatus.Warning, $"{resolved.Path}: {resolved.Note}"));
                break;
            case PathResolution.Unresolved:
                checks.Add(new(Prefix + "target", $"{what} {Label}", CheckStatus.Unknown, $"{target.Raw}: {resolved.Note}"));
                break;
            default:
                file = await _files.InspectAsync(resolved.Path!, cancellationToken).ConfigureAwait(false);
                checks.Add(FileChecks.TargetCheck(Prefix, $"{what} {Label}", resolved, file));
                if (file.Exists && file.Error is null)
                {
                    var signature = file.Signature ?? new SignatureEvidence(SignatureState.Unknown, SignatureKind.None, Problem: "not checked");
                    checks.Add(FileChecks.SignatureCheck(Prefix, Label, signature));
                    if (signature.State == SignatureState.Valid)
                        checks.Add(FileChecks.PublisherCheck(Prefix, Label, signature, null, _familiarPublishers));
                }
                break;
        }

        var program = WindowsPath.FileName(resolved.Path ?? WindowsPath.Unquote(target.Raw));
        if (!target.IsServiceDll && ScheduledTaskVerifier.HostPrograms.Contains(program.Contains('.') ? program : program + ".exe"))
        {
            checks.Add(new(Prefix + "host", $"Host program {Label}", CheckStatus.Warning,
                $"{program} runs whatever its arguments tell it to, so its signature says nothing about what this service does. " +
                $"Arguments: {(target.Arguments.Length == 0 ? "(none)" : Show(target.Arguments))}"));
        }
        return new(0, "Service", summary, RegisteredServer: target.Raw, ResolvedPath: resolved.Path, File: file, Notes: notes);
    }

    private VerificationCheck LocationCheck(ResolvedPath resolved, string what)
    {
        const string id = Prefix + "location";
        var title = $"Location {Label}";
        return ServiceAnalysis.Classify(resolved, _paths) switch
        {
            ServiceLocation.Protected => new(id, title, CheckStatus.Pass, $"The {what.ToLowerInvariant()} is in the Windows or a Program Files folder, which standard users cannot write to."),
            ServiceLocation.UserWritable => new(id, title, CheckStatus.Fail,
                $"The {what.ToLowerInvariant()} is in {resolved.Path}, a folder standard users or other programs can write to. " +
                "Services normally run from the Windows or Program Files folders; malware installs services from user-writable folders."),
            ServiceLocation.Other => new(id, title, CheckStatus.Warning,
                $"The {what.ToLowerInvariant()} is in {resolved.Path}, outside the Windows and Program Files folders. That folder's permissions were not checked."),
            _ => new(id, title, CheckStatus.Unknown, "The path could not be resolved, so its folder is unknown."),
        };
    }

    private VerificationCheck LoggedChangeCheck(PersistenceChangeKind kind, ServiceDefinition? before, ServiceDefinition after, IReadOnlyList<FieldChange> changes)
    {
        const string id = "logged-change";
        const string title = "Change in the alert";
        if (kind == PersistenceChangeKind.Added || before is null)
            return new(id, title, CheckStatus.Pass,
                "A service that now starts automatically. It is new, or it was set to start automatically; there is no earlier auto-start definition to compare with.");
        if (changes.Count == 0)
            return new(id, title, CheckStatus.Pass, "No field differs between the logged definitions.");
        if (ServiceAnalysis.IsRoutineUpdate(before, after, _paths))
            return new(id, title, CheckStatus.Pass,
                "Only the folder of the same program or DLL changed, inside protected folders, as updaters do when they install a new version: " + Describe(changes) + ".");
        if (ServiceAnalysis.ChangesTarget(before, after, _paths))
            return new(id, title, CheckStatus.Fail, "The alert changed what the service runs: " + Describe(changes.Where(c => c.Field is "ImagePath" or "ServiceDll")) + OtherChanges(changes, "ImagePath", "ServiceDll"));
        if (ServiceAnalysis.IsPrivilegeGain(before, after))
            return new(id, title, CheckStatus.Fail, "The alert made the service run as LocalSystem: " + Describe(changes.Where(c => c.Field == "ObjectName")) + OtherChanges(changes, "ObjectName"));
        return new(id, title, CheckStatus.Warning, "The alert changed the service's arguments, account, failure command or type: " + Describe(changes) + ".");
    }

    private VerificationCheck SinceAlertCheck(ServiceDefinition loggedAfter, ServiceDefinition current, IReadOnlyList<FieldChange> since)
    {
        const string id = "since-alert";
        const string title = "Current service vs. alert";
        if (since.Count == 0) return new(id, title, CheckStatus.Pass, "The current service matches the definition logged with the alert.");
        if (ServiceAnalysis.ChangesTarget(loggedAfter, current, _paths))
            return new(id, title, CheckStatus.Fail, "What the service runs has changed again since the alert: " + Describe(since));
        return new(id, title, CheckStatus.Warning, "The service has changed again since the alert: " + Describe(since));
    }

    private static string DescribeStart(int start) => start switch
    {
        0 => "Starts at boot",
        1 => "Starts with the system",
        2 => "Starts automatically",
        3 => "Starts on demand",
        4 => "Disabled",
        _ => $"Start type {start}",
    };

    private static string Describe(IEnumerable<FieldChange> changes) =>
        string.Join("; ", changes.Take(8).Select(c => $"{c.Field}: {Quote(c.Before)} → {Quote(c.After)}"));

    private static string OtherChanges(IReadOnlyList<FieldChange> all, params string[] shown)
    {
        var rest = all.Where(c => !shown.Contains(c.Field)).ToArray();
        return rest.Length == 0 ? "." : ". Also changed: " + Describe(rest) + ".";
    }

    private static string Quote(string? value) => value is null ? "(none)" : $"\"{Show(value)}\"";

    private static string Show(string value) => value.Length <= 200 ? value : value[..200] + "…";
}

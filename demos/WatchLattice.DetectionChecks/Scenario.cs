using WatchLattice.Common.Alerts;

namespace WatchLattice.DetectionChecks;

public enum Outcome { Detected, Missed, Skipped, Error }

/// <summary>Which module code a check runs: one probe is built per module and reused by its checks.</summary>
public enum ProbeKind { Persistence, HostsProxy, Firewall, Defender, BrowserExtensions, ScriptHosts, Canary }

/// <summary>
/// One harmless change of a kind a module watches for. Apply makes it, Revert
/// undoes it, and Cleanup removes it by name whether or not Apply ran, so an
/// interrupted run can be cleaned up later. Every name starts with
/// <see cref="Scenarios.Marker"/>.
/// </summary>
public sealed class Scenario
{
    public required string Name { get; init; }
    public required ProbeKind Probe { get; init; }
    public required string Module { get; init; }

    /// <summary>What Apply changes, in words, for the plan and the report.</summary>
    public required string Change { get; init; }

    /// <summary>How Revert undoes it, in words.</summary>
    public required string Undo { get; init; }

    public required string ExpectedCode { get; init; }

    /// <summary>The resource a matching alert has, as the module names it (used for the plan when nothing ran).</summary>
    public required string SampleResource { get; init; }

    /// <summary>Picks this check's alert out of everything the module raised (another program may change things too).</summary>
    public required Func<string?, bool> ResourceMatches { get; init; }

    /// <summary>The alert expected once the change is undone, if the module reports undoing it.</summary>
    public string? ExpectedRevertCode { get; init; }

    public bool NeedsAdministrator { get; init; }

    /// <summary>Why the check cannot run here (an opt-in flag not given, a setting it must not disturb), or null.</summary>
    public Func<string?> Precondition { get; init; } = () => null;

    public required Func<Task> Apply { get; init; }
    public required Func<Task> Revert { get; init; }
    public required Func<Task> Cleanup { get; init; }

    /// <summary>How long to keep checking after the change, for modules that learn about it from an event log or a file watcher.</summary>
    public int RetrySeconds { get; init; }

    public IReadOnlyList<AttackTag> Techniques(string? resource = null) => AttackMapping.For(Module, ExpectedCode, resource ?? SampleResource);

    public int EventId => AlertEventIds.For(Module, ExpectedCode, AlertSeverity.Warning);
}

public sealed record CheckResult(
    Scenario Scenario,
    Outcome Outcome,
    string Detail,
    ProtectionAlert? Alert,
    TimeSpan? CheckDuration,
    bool? RevertReported,
    string? CleanupProblem);

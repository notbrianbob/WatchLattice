using System.Diagnostics;
using WatchLattice.Common.Alerts;

namespace WatchLattice.DetectionChecks;

/// <summary>
/// Runs the checks one at a time: for each module, one check to record its
/// baseline, then per scenario: make the change, check, undo the change,
/// check again. Undo always runs, even when the check failed or threw.
/// </summary>
public sealed class Runner
{
    private readonly string _workDir;
    private readonly bool _elevated;

    public Runner(string workDir, bool elevated)
    {
        _workDir = workDir;
        _elevated = elevated;
    }

    public async Task<IReadOnlyList<CheckResult>> RunAsync(IReadOnlyList<Scenario> scenarios, CancellationToken cancellationToken)
    {
        var results = new List<CheckResult>();
        foreach (var group in scenarios.GroupBy(s => s.Probe))
        {
            var runnable = new List<Scenario>();
            foreach (var scenario in group)
            {
                var skip = SkipReason(scenario);
                if (skip is null) runnable.Add(scenario);
                else results.Add(new(scenario, Outcome.Skipped, skip, null, null, null, null));
            }
            if (runnable.Count == 0) continue;

            Probe probe;
            try
            {
                probe = Probe.Create(group.Key, _workDir);
                Console.WriteLine($"[{group.Key}] recording a baseline");
                await probe.CheckAsync(cancellationToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                results.AddRange(runnable.Select(s => new CheckResult(s, Outcome.Error, "The module could not record a baseline: " + ex.Message, null, null, null, null)));
                continue;
            }

            using (probe)
            {
                foreach (var scenario in runnable)
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        results.Add(new(scenario, Outcome.Skipped, "the run was cancelled", null, null, null, null));
                        continue;
                    }
                    Console.WriteLine($"[{group.Key}] {scenario.Name}");
                    results.Add(await RunOneAsync(probe, scenario, cancellationToken));
                }
            }
        }
        // Keep the plan's order in the report.
        return results.OrderBy(r => scenarios.ToList().IndexOf(r.Scenario)).ToList();
    }

    private string? SkipReason(Scenario scenario)
    {
        if (scenario.NeedsAdministrator && !_elevated) return "needs an elevated (administrator) prompt";
        try
        {
            return scenario.Precondition();
        }
        catch (Exception ex)
        {
            return "could not check whether it can run: " + ex.Message;
        }
    }

    private static async Task<CheckResult> RunOneAsync(Probe probe, Scenario scenario, CancellationToken cancellationToken)
    {
        Outcome outcome;
        string detail;
        ProtectionAlert? found = null;
        TimeSpan? duration = null;
        bool? revertReported = null;
        string? cleanupProblem = null;
        var applied = false;

        try
        {
            await scenario.Apply();
            applied = true;
            var clock = Stopwatch.StartNew();
            var seen = new List<ProtectionAlert>();
            do
            {
                // Detection checks never pass a cancelled token to a module mid-change; the undo below must run.
                seen.AddRange(await probe.CheckAsync(CancellationToken.None));
                found = seen.FirstOrDefault(a => a.Code == scenario.ExpectedCode && scenario.ResourceMatches(a.Resource));
                if (found is not null || clock.Elapsed.TotalSeconds >= scenario.RetrySeconds) break;
                await Task.Delay(1000, CancellationToken.None);
            }
            while (true);
            duration = clock.Elapsed;

            if (found is not null)
            {
                outcome = Outcome.Detected;
                detail = $"{found.Severity}: {found.Title}";
            }
            else
            {
                outcome = Outcome.Missed;
                detail = seen.Count == 0
                    ? "the module raised nothing"
                    : "the module raised only: " + string.Join(", ", seen.Select(a => a.Code).Distinct());
            }
        }
        catch (Exception ex)
        {
            outcome = Outcome.Error;
            detail = (applied ? "The check failed: " : "The change could not be made: ") + ex.Message;
        }

        try
        {
            await scenario.Revert();
            if (applied)
            {
                var after = await probe.CheckAsync(CancellationToken.None);
                if (scenario.ExpectedRevertCode is { } revertCode)
                    revertReported = after.Any(a => a.Code == revertCode && scenario.ResourceMatches(a.Resource));
            }
        }
        catch (Exception ex)
        {
            cleanupProblem = ex.Message;
        }
        if (cleanupProblem is not null)
        {
            // Last resort: remove by name.
            try
            {
                await scenario.Cleanup();
                cleanupProblem += " (removed afterwards by name)";
            }
            catch (Exception ex)
            {
                cleanupProblem += "; removing it by name also failed: " + ex.Message + $". Run `cleanup` from an elevated prompt.";
            }
        }
        _ = cancellationToken;
        return new(scenario, outcome, detail, found, duration, revertReported, cleanupProblem);
    }
}

using System.Diagnostics;

namespace WatchLattice.Persistence.Verification;

/// <summary>What one mechanism's verifier found.</summary>
public sealed record VerifierResult(IReadOnlyList<VerificationCheck> Checks, IReadOnlyList<FieldChange> LoggedChanges,
    IReadOnlyList<FieldChange> ChangesSinceAlert, IReadOnlyList<ActionEvidence> Actions, string? CurrentDefinition,
    IReadOnlyList<string> Errors);

/// <summary>
/// Verifies one kind of persistence entry (scheduled tasks and services today;
/// Run keys, Startup folders and WMI subscriptions can each add their own).
/// Implementations must be read-only: they look entries up through
/// structured APIs and never execute, load, register, disable or delete
/// anything, and never pass entry data to a shell.
/// </summary>
public interface IEntryVerifier
{
    /// <summary>A short name shown with results, e.g. "Scheduled task".</summary>
    string Mechanism { get; }

    bool AppliesTo(PersistenceObservation observation);

    Task<VerifierResult> VerifyAsync(PersistenceObservation observation, CancellationToken cancellationToken);
}

/// <summary>
/// Picks the verifier for an entry, runs it off the caller's thread with a
/// time limit, and turns its checks into an overall assessment. A verifier
/// that throws or times out produces a "needs review" result with the error
/// recorded, never a pass.
/// </summary>
public sealed class PersistenceVerificationEngine
{
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(90);

    private readonly IEntryVerifier[] _verifiers;
    private readonly IAccountResolver _accounts;
    private readonly TimeProvider _time;
    private readonly TimeSpan _timeout;

    public PersistenceVerificationEngine(IEnumerable<IEntryVerifier> verifiers, IAccountResolver accounts,
        TimeProvider? time = null, TimeSpan? timeout = null)
    {
        _verifiers = verifiers.ToArray();
        _accounts = accounts;
        _time = time ?? TimeProvider.System;
        _timeout = timeout ?? DefaultTimeout;
    }

    public bool CanVerify(PersistenceObservation observation) => Find(observation) is not null;

    public async Task<VerificationRun> VerifyAsync(PersistenceObservation observation, VerificationTrigger trigger, CancellationToken cancellationToken)
    {
        var verifier = Find(observation) ?? throw new InvalidOperationException("No verifier applies to " + observation.Resource);
        var started = _time.GetUtcNow();
        string checkedAs;
        try { checkedAs = _accounts.CurrentAccount; }
        catch (Exception ex) when (ex is not OperationCanceledException) { checkedAs = "(unknown account)"; }

        VerifierResult result;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_timeout);
        try
        {
            // The probes are synchronous Windows calls; keep them off a UI or alert thread, and
            // stop waiting at the time limit even if a call is stuck and cannot be cancelled.
            var work = Task.Run(() => verifier.VerifyAsync(observation, timeout.Token), CancellationToken.None);
            var finished = await Task.WhenAny(work, Task.Delay(Timeout.Infinite, timeout.Token)).ConfigureAwait(false);
            if (finished != work)
            {
                _ = work.ContinueWith(t => t.Exception, TaskContinuationOptions.OnlyOnFaulted);
                cancellationToken.ThrowIfCancellationRequested();
                throw new OperationCanceledException(timeout.Token);
            }
            result = await work.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            result = Failed($"Verification did not finish within {_timeout.TotalSeconds:0} seconds.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Trace.TraceWarning("Persistence verification failed: {0}", ex);
            result = Failed($"Verification failed: {ex.GetType().Name}: {ex.Message}");
        }

        var (outcome, summary) = Assess(result.Checks);
        return new VerificationRun(Guid.NewGuid(), trigger, checkedAs, started, _time.GetUtcNow(), verifier.Mechanism,
            outcome, summary, result.Checks, result.LoggedChanges, result.ChangesSinceAlert, result.Actions,
            result.CurrentDefinition, result.Errors);
    }

    /// <summary>
    /// Suspicious if any check failed; needs review if any check warned or
    /// could not be completed; checks passed only if every check passed.
    /// The summary always says that passing checks are not proof of safety.
    /// </summary>
    public static (VerificationOutcome Outcome, string Summary) Assess(IReadOnlyList<VerificationCheck> checks)
    {
        const string caveat = " This is evidence, not proof: a valid signature shows who published a file, not that the entry is harmless.";
        var failed = checks.Where(c => c.Status == CheckStatus.Fail).ToArray();
        var attention = checks.Where(c => c.Status is CheckStatus.Warning or CheckStatus.Unknown).ToArray();
        if (checks.Count == 0)
            return (VerificationOutcome.NeedsReview, "Needs review: no checks could be run." + caveat);
        if (failed.Length > 0)
            return (VerificationOutcome.Suspicious, $"Suspicious: {Join(failed)}." + (attention.Length > 0 ? $" Also needs review: {Join(attention)}." : "") + caveat);
        if (attention.Length > 0)
            return (VerificationOutcome.NeedsReview, $"Needs review: {Join(attention)}." + caveat);
        return (VerificationOutcome.ChecksPassed,
            "Checks passed: known configuration, expected files, valid signatures and no unexpected changes." + caveat);
    }

    private static string Join(IEnumerable<VerificationCheck> checks) =>
        string.Join("; ", checks.Select(c => $"{c.Title} ({c.Status.ToString().ToLowerInvariant()})"));

    private IEntryVerifier? Find(PersistenceObservation observation) => _verifiers.FirstOrDefault(v => v.AppliesTo(observation));

    private static VerifierResult Failed(string error) => new(
        new[] { new VerificationCheck("verification", "Verification", CheckStatus.Unknown, error + " The result is inconclusive.") },
        Array.Empty<FieldChange>(), Array.Empty<FieldChange>(), Array.Empty<ActionEvidence>(), null, new[] { error });
}

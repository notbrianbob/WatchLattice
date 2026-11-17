using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using WatchLattice.Common.Alerts;

namespace WatchLattice.DetectionChecks;

/// <summary>Writes the plan (what each check changes) and the results as Markdown and JSON.</summary>
public static class Plan
{
    public static string Describe(IReadOnlyList<Scenario> scenarios, CheckArgs args)
    {
        var md = new StringBuilder()
            .AppendLine("# WatchLattice detection checks: plan")
            .AppendLine()
            .AppendLine("`run` makes each change below, runs the module once, undoes the change and runs it again.")
            .AppendLine("Nothing here runs malware or weakens protection, except the opt-in Defender exclusion for a folder that does not exist.")
            .AppendLine()
            .AppendLine("| Check | Module | Changes | Undo | Expected alert | ATT&CK | Needs |")
            .AppendLine("|---|---|---|---|---|---|---|");
        foreach (var s in scenarios)
        {
            var needs = new List<string>();
            if (s.NeedsAdministrator) needs.Add("administrator");
            if (s.Name.Contains("Defender", StringComparison.Ordinal)) needs.Add(args.IncludeDefender ? "--include-defender (given)" : "--include-defender");
            if (s.Probe == ProbeKind.ScriptHosts) needs.Add("process creation auditing, or --include-audit-policy");
            md.AppendLine($"| {s.Name} | {s.Module} | {Cell(s.Change)} | {Cell(s.Undo)} | `{s.ExpectedCode}` ({s.EventId}) | {Techniques(s.Techniques())} | {(needs.Count == 0 ? "-" : string.Join(", ", needs))} |");
        }
        return md.ToString();
    }

    public static string Summarize(IReadOnlyList<CheckResult> results, CheckArgs args, bool elevated)
    {
        var detected = results.Count(r => r.Outcome == Outcome.Detected);
        var ran = results.Count(r => r.Outcome != Outcome.Skipped);
        var md = new StringBuilder()
            .AppendLine("## Detection checks")
            .AppendLine()
            .AppendLine(Inv($"- Date (UTC): {DateTimeOffset.UtcNow:yyyy-MM-dd HH:mm}"))
            .AppendLine($"- OS: {RuntimeInformation.OSDescription}")
            .AppendLine($"- Elevated: {(elevated ? "yes" : "no")}; --include-defender: {(args.IncludeDefender ? "yes" : "no")}; --include-audit-policy: {(args.IncludeAuditPolicy ? "yes" : "no")}")
            .AppendLine(Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true"
                ? $"- Host: GitHub Actions runner, commit {Environment.GetEnvironmentVariable("GITHUB_SHA")?[..7]}"
                : "- Host: local machine")
            .AppendLine($"- ATT&CK version: {AttackMapping.AttackVersion}")
            .AppendLine()
            .AppendLine(Inv($"**{detected} of {ran} checks that ran raised the expected alert** ({results.Count - ran} skipped)."))
            .AppendLine()
            .AppendLine("| Check | ATT&CK | Expected alert (Event ID) | Result | Found by one check in | Hub checks every | Undo reported |")
            .AppendLine("|---|---|---|---|---|---|---|");
        foreach (var r in results)
        {
            var result = r.Outcome switch
            {
                Outcome.Detected => "✅ detected",
                Outcome.Missed => "❌ missed: " + Cell(r.Detail),
                Outcome.Error => "⚠️ error: " + Cell(r.Detail),
                _ => "skipped: " + Cell(r.Detail),
            };
            var undo = r.RevertReported switch
            {
                true => $"yes (`{r.Scenario.ExpectedRevertCode}`)",
                false => $"no `{r.Scenario.ExpectedRevertCode}`",
                null => r.Scenario.ExpectedRevertCode is null ? "not reported by design" : "-",
            };
            if (r.CleanupProblem is not null) undo += " ⚠️ " + Cell(r.CleanupProblem);
            md.AppendLine($"| {r.Scenario.Name} | {Techniques(r.Scenario.Techniques(r.Alert?.Resource))} | `{r.Scenario.ExpectedCode}` ({r.Scenario.EventId}) | {result} "
                + $"| {(r.CheckDuration is { } d ? Inv($"{d.TotalSeconds:F1} s") : "-")} | {HubInterval(r.Scenario.Probe)} | {undo} |");
        }
        md.AppendLine()
            .AppendLine("*Found by one check in* is how long the module's own check took once the change was made. In the hub the change is found at the next check, so up to *Hub checks every* later.")
            .AppendLine("A detected check shows that the module's real code reports that kind of change on this machine. It does not measure how WatchLattice does against real malware, which can be stopped or hidden from by an attacker with administrator rights.");
        return md.ToString();
    }

    public static string ToJson(IReadOnlyList<CheckResult> results) => JsonSerializer.Serialize(results.Select(r => new
    {
        check = r.Scenario.Name,
        module = r.Scenario.Module,
        expectedCode = r.Scenario.ExpectedCode,
        eventId = r.Scenario.EventId,
        attack = r.Scenario.Techniques(r.Alert?.Resource).Select(t => new { id = t.Technique.Id, name = t.Technique.Name, fit = t.Fit.ToString() }),
        outcome = r.Outcome.ToString(),
        detail = r.Detail,
        alert = r.Alert is null ? null : new { r.Alert.Code, Severity = r.Alert.Severity.ToString(), r.Alert.Title, r.Alert.Message, r.Alert.Resource },
        seconds = r.CheckDuration?.TotalSeconds,
        revertReported = r.RevertReported,
        cleanupProblem = r.CleanupProblem,
    }), new JsonSerializerOptions { WriteIndented = true });

    /// <summary>The module's default check interval in the hub.</summary>
    private static string HubInterval(ProbeKind kind) => kind switch
    {
        ProbeKind.Persistence => Seconds(new WatchLattice.Persistence.PersistenceOptions().CheckIntervalSeconds),
        ProbeKind.HostsProxy => Seconds(new WatchLattice.HostsProxyWatchdog.HostsProxyWatchdogOptions().CheckIntervalSeconds),
        ProbeKind.Firewall => Seconds(new WatchLattice.FirewallWatchdog.FirewallWatchdogOptions().CheckIntervalSeconds),
        ProbeKind.Defender => Seconds(new WatchLattice.DefenderWatchdog.DefenderWatchdogOptions().CheckIntervalSeconds),
        ProbeKind.BrowserExtensions => Seconds(new WatchLattice.BrowserExtensionWatchdog.BrowserExtensionWatchdogOptions().CheckIntervalSeconds),
        ProbeKind.ScriptHosts => Seconds(new WatchLattice.ScriptHostAudit.ScriptHostAuditOptions().CheckIntervalSeconds),
        _ => "immediate (file events)",
    };

    private static string Seconds(int seconds) => seconds >= 60 && seconds % 60 == 0 ? Inv($"{seconds / 60} min") : Inv($"{seconds} s");

    private static string Techniques(IReadOnlyList<AttackTag> tags) => tags.Count == 0
        ? "-"
        : string.Join("<br>", tags.Select(t => $"[{t.Technique.Id}]({t.Technique.Url}){(t.Fit == AttackFit.Related ? " (related)" : "")}"));

    private static string Cell(string text) => text.Replace("|", "\\|").Replace("\r", " ").Replace("\n", " ");

    private static string Inv(FormattableString text) => text.ToString(CultureInfo.InvariantCulture);
}

using System.Runtime.Versioning;
using System.Security.Principal;
using WatchLattice.DetectionChecks;

// Detection checks: for each kind of change a WatchLattice module watches for,
// make one harmless, clearly named change on this machine, run the real
// module code once, and record whether it raised the expected alert. Every
// change is undone straight away, and checked again after it is undone.
// See demos/detection-checks.md for what each check changes and why it is safe.

var parsed = CheckArgs.Parse(args);
if (parsed is null)
{
    Console.Error.WriteLine(CheckArgs.Usage);
    return 2;
}

var scenarios = Scenarios.All(parsed);
if (parsed.Command == "list")
{
    Console.WriteLine(Plan.Describe(scenarios, parsed));
    return 0;
}

if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("Detection checks change real Windows settings, so they only run on Windows. Use `list` to see the plan.");
    return 2;
}

return await RunWindowsAsync(parsed, scenarios);

[SupportedOSPlatform("windows")]
static async Task<int> RunWindowsAsync(CheckArgs parsed, IReadOnlyList<Scenario> scenarios)
{
    using var identity = WindowsIdentity.GetCurrent();
    var elevated = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);

    if (parsed.Command == "cleanup")
    {
        var failures = 0;
        foreach (var scenario in scenarios)
        {
            var problem = await Safely(() => scenario.Cleanup());
            Console.WriteLine(problem is null ? $"cleaned: {scenario.Name}" : $"could not clean {scenario.Name}: {problem}");
            if (problem is not null) failures++;
        }
        return failures == 0 ? 0 : 1;
    }

    using var cts = new CancellationTokenSource();
    Console.CancelKeyPress += (_, e) =>
    {
        // Let the current check finish its clean-up instead of stopping mid-change.
        e.Cancel = true;
        cts.Cancel();
    };

    Directory.CreateDirectory(parsed.OutputDir);
    var work = Path.Combine(Path.GetTempPath(), "watchlattice-detection-checks-" + Guid.NewGuid().ToString("N")[..8]);
    Directory.CreateDirectory(work);
    var runner = new Runner(work, elevated);
    var results = await runner.RunAsync(scenarios, cts.Token);
    var summary = Plan.Summarize(results, parsed, elevated);
    File.WriteAllText(Path.Combine(parsed.OutputDir, "summary.md"), summary);
    File.WriteAllText(Path.Combine(parsed.OutputDir, "results.json"), Plan.ToJson(results));
    Console.WriteLine();
    Console.WriteLine(summary);
    try { Directory.Delete(work, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }

    return results.Any(r => r.Outcome is Outcome.Missed or Outcome.Error || r.CleanupProblem is not null) ? 1 : 0;
}

static async Task<string?> Safely(Func<Task> action)
{
    try
    {
        await action();
        return null;
    }
    catch (Exception ex)
    {
        return ex.Message;
    }
}

namespace WatchLattice.DetectionChecks
{
    public sealed record CheckArgs
    {
        public const string Usage = """
            usage: dotnet run -c Release --project demos/WatchLattice.DetectionChecks -- <list|run|cleanup> [options]

              list                   show every check, what it changes and how it is undone (default; changes nothing)
              run                    make each change, run the module once, undo the change (Windows, elevated for most checks)
              cleanup                remove anything an interrupted run left behind (only items named WatchLatticeDetectionTest)

              --include-defender     also add and remove a Microsoft Defender exclusion for a folder that does not exist
              --include-audit-policy also turn on process creation auditing for the script host check, if it is off,
                                     and set it back afterwards
              --out DIR              results folder (default ./detection-results)
            """;

        public string Command { get; init; } = "list";
        public bool IncludeDefender { get; init; }
        public bool IncludeAuditPolicy { get; init; }
        public string OutputDir { get; init; } = "detection-results";

        public static CheckArgs? Parse(string[] args)
        {
            var result = new CheckArgs();
            var i = 0;
            if (args.Length > 0 && !args[0].StartsWith("--", StringComparison.Ordinal))
            {
                if (args[0] is not ("list" or "run" or "cleanup")) return null;
                result = result with { Command = args[0] };
                i = 1;
            }
            for (; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--include-defender": result = result with { IncludeDefender = true }; break;
                    case "--include-audit-policy": result = result with { IncludeAuditPolicy = true }; break;
                    case "--out" when i + 1 < args.Length: result = result with { OutputDir = args[++i] }; break;
                    default:
                        Console.Error.WriteLine($"unknown option {args[i]}");
                        return null;
                }
            }
            return result;
        }
    }
}

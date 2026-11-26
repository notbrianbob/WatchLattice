using System.Xml.Linq;
using Xunit;

namespace WatchLattice.Common.Tests;

/// <summary>Build settings that docs/threat-model.md relies on.</summary>
public sealed class HardeningTests
{
    [Theory]
    [InlineData("src/WatchLattice.Hub/WatchLattice.Hub.csproj")]
    [InlineData("src/WatchLattice.Tray/WatchLattice.Tray.csproj")]
    public void PrivilegedExecutables_IgnoreStartupHooks(string project)
    {
        // The hub runs as LocalSystem and the tray's settings editor runs elevated:
        // DOTNET_STARTUP_HOOKS in the environment must not load code into them.
        var xml = XDocument.Load(Path.Join(RepoRoot(), project));
        var value = xml.Descendants("StartupHookSupport").Select(e => e.Value.Trim()).SingleOrDefault();
        Assert.Equal("false", value);
    }

    [Fact]
    public void ThreatModel_ListsEveryFinding_AsFixedOrAccepted()
    {
        var text = File.ReadAllText(Path.Join(RepoRoot(), "docs", "threat-model.md"));
        Assert.Contains("| Status |", text);
        Assert.DoesNotContain("| Open |", text);
    }

    [Fact]
    public void EveryWorkflowAction_IsPinnedToACommit()
    {
        // docs/supply-chain.md: a moved tag must not change what CI or a release runs.
        var unpinned = Directory.EnumerateFiles(Path.Join(RepoRoot(), ".github", "workflows"), "*.yml")
            .SelectMany(file => File.ReadLines(file).Select((line, i) => (file, line, i)))
            .Where(x => System.Text.RegularExpressions.Regex.IsMatch(x.line, @"^\s*-?\s*uses:\s"))
            .Where(x => !System.Text.RegularExpressions.Regex.IsMatch(x.line, @"uses:\s+\S+@[0-9a-f]{40}\s+#\s+v\d"))
            .Select(x => $"{Path.GetFileName(x.file)}:{x.i + 1}: {x.line.Trim()}")
            .ToList();
        Assert.True(unpinned.Count == 0, "Pin these to a full commit SHA with a version comment:\n" + string.Join("\n", unpinned));
    }

    [Fact]
    public void EveryProject_HasAPackageLockFile()
    {
        // docs/supply-chain.md: each NuGet package is pinned by content hash.
        var root = RepoRoot();
        var missing = new[] { "src", "tests", "demos", "packaging" }
            .SelectMany(folder => Directory.EnumerateFiles(Path.Join(root, folder), "*.*proj", SearchOption.AllDirectories))
            .Where(project => !IsBuildOutput(Path.GetRelativePath(root, project)))
            .Where(project => !File.Exists(Path.Join(Path.GetDirectoryName(project), "packages.lock.json")))
            .Select(project => Path.GetRelativePath(root, project))
            .ToList();
        Assert.True(missing.Count == 0, "Run `dotnet restore` and commit packages.lock.json for:\n" + string.Join("\n", missing));
    }

    [Fact]
    public void EveryLockFile_CoversTheRuntimeReleasesArePublishedFor()
    {
        // A locked restore refuses a runtime the lock file doesn't list, and
        // the hub and tray are published with -r win-x64.
        var root = RepoRoot();
        var withoutRuntime = new[] { "src", "tests", "demos", "packaging" }
            .SelectMany(folder => Directory.EnumerateFiles(Path.Join(root, folder), "packages.lock.json", SearchOption.AllDirectories))
            .Where(file => !IsBuildOutput(Path.GetRelativePath(root, file)))
            .Where(file => !File.ReadAllText(file).Contains("/win-x64\"", StringComparison.Ordinal))
            .Select(file => Path.GetRelativePath(root, file))
            .ToList();
        Assert.True(withoutRuntime.Count == 0, "These lock files have no win-x64 section:\n" + string.Join("\n", withoutRuntime));
    }

    [Fact]
    public void EveryWorkflowJobThatBuilds_RestoresInLockedMode()
    {
        // A job that installs the .NET SDK restores packages, and must accept
        // only what packages.lock.json lists.
        var unlocked = new List<string>();
        foreach (var file in Directory.EnumerateFiles(Path.Join(RepoRoot(), ".github", "workflows"), "*.yml"))
        {
            foreach (var (name, body) in WorkflowJobs(File.ReadAllLines(file)))
            {
                if (body.Contains("actions/setup-dotnet@", StringComparison.Ordinal)
                    && !System.Text.RegularExpressions.Regex.IsMatch(body, @"(?m)^\s+RestoreLockedMode:\s+true\b"))
                {
                    unlocked.Add($"{Path.GetFileName(file)}: {name}");
                }
            }
        }
        Assert.True(unlocked.Count == 0, "Add `RestoreLockedMode: true` to the env of:\n" + string.Join("\n", unlocked));
    }

    /// <summary>Each job under <c>jobs:</c> with its text. Jobs are the keys indented two spaces.</summary>
    private static IEnumerable<(string Name, string Body)> WorkflowJobs(string[] lines)
    {
        var start = Array.FindIndex(lines, line => line.TrimEnd() == "jobs:");
        Assert.True(start >= 0, "A workflow without a jobs: section.");
        string? name = null;
        var body = new System.Text.StringBuilder();
        foreach (var line in lines.Skip(start + 1))
        {
            var match = System.Text.RegularExpressions.Regex.Match(line, @"^  ([A-Za-z0-9_-]+):\s*(#.*)?$");
            if (match.Success)
            {
                if (name is not null) yield return (name, body.ToString());
                name = match.Groups[1].Value;
                body.Clear();
            }
            else
            {
                body.AppendLine(line);
            }
        }
        if (name is not null) yield return (name, body.ToString());
    }

    private static bool IsBuildOutput(string relativePath) =>
        relativePath.Split('/', '\\').Any(part => part is "bin" or "obj");

    private static string RepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Join(dir.FullName, "WatchLattice.sln"))) return dir.FullName;
        }
        throw new DirectoryNotFoundException("Could not find WatchLattice.sln above the test output folder.");
    }
}

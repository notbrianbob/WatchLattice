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

    private static string RepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Join(dir.FullName, "WatchLattice.sln"))) return dir.FullName;
        }
        throw new DirectoryNotFoundException("Could not find WatchLattice.sln above the test output folder.");
    }
}

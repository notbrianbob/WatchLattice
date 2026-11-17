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

    private static string RepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Join(dir.FullName, "WatchLattice.sln"))) return dir.FullName;
        }
        throw new DirectoryNotFoundException("Could not find WatchLattice.sln above the test output folder.");
    }
}

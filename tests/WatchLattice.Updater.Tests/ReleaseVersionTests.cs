using System.Reflection;
using Xunit;

namespace WatchLattice.Updater.Tests;

public class ReleaseVersionTests
{
    [Theory]
    [InlineData("v1.2.3", 1, 2, 3, null)]
    [InlineData("1.2.3", 1, 2, 3, null)]
    [InlineData("0.4.0-beta.2", 0, 4, 0, "beta.2")]
    [InlineData("1.0.0-rc.1+abc123", 1, 0, 0, "rc.1")]
    [InlineData("0.0.0-dev+9e90e1a50cfc8fe5c871d252be48d11ec07d6229", 0, 0, 0, "dev")]
    public void TryParse_AcceptsTagsAndInformationalVersions(string text, int major, int minor, int patch, string? pre)
    {
        Assert.True(ReleaseVersion.TryParse(text, out var version));
        Assert.Equal(new ReleaseVersion(major, minor, patch, pre), version);
    }

    [Theory]
    [InlineData("")]
    [InlineData("1.2")]
    [InlineData("01.2.3")]
    [InlineData("v1.2.3.4")]
    [InlineData("latest")]
    [InlineData("1.2.3-")]
    public void TryParse_RejectsAnythingElse(string text) => Assert.False(ReleaseVersion.TryParse(text, out _));

    [Theory]
    [InlineData("1.0.0-alpha", "1.0.0-alpha.1")]
    [InlineData("1.0.0-alpha.1", "1.0.0-alpha.beta")]
    [InlineData("1.0.0-beta.2", "1.0.0-beta.11")]
    [InlineData("1.0.0-rc.1", "1.0.0")]
    [InlineData("1.9.0", "1.10.0")]
    [InlineData("0.9.9", "1.0.0")]
    public void CompareTo_FollowsSemVerPrecedence(string lower, string higher)
    {
        Assert.True(ReleaseVersion.Parse(lower) < ReleaseVersion.Parse(higher));
        Assert.True(ReleaseVersion.Parse(higher) > ReleaseVersion.Parse(lower));
    }

    [Fact]
    public void FromAssembly_ReadsTheStampedVersion_AndSpotsDevelopmentBuilds()
    {
        // Local builds are 0.0.0-dev and release builds carry the tag, so only
        // check that the stamped version parses and round-trips.
        var assembly = typeof(UpdaterModule).Assembly;
        var stamped = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion;
        Assert.Equal(ReleaseVersion.Parse(stamped), ReleaseVersion.FromAssembly(assembly));

        Assert.True(ReleaseVersion.Parse("0.0.0-dev+abc123").IsDevelopmentBuild);
        Assert.False(ReleaseVersion.Parse("1.0.0").IsDevelopmentBuild);
        Assert.False(ReleaseVersion.Parse("1.0.0-beta.1").IsDevelopmentBuild);
    }

    [Fact]
    public void FromFile_ReadsTheVersionStampedIntoTheFileOnDisk()
    {
        var assembly = typeof(UpdaterModule).Assembly;

        Assert.Equal(ReleaseVersion.FromAssembly(assembly), ReleaseVersion.FromFile(assembly.Location));
        Assert.Null(ReleaseVersion.FromFile(Path.Combine(AppContext.BaseDirectory, "no-such-assembly.dll")));
    }

    [Theory]
    [InlineData("0.2.0", "0.4.0", true)]
    [InlineData("0.4.0", "0.4.0", false)]
    [InlineData("0.4.1", "0.4.0", true)]
    [InlineData("0.0.0-dev", "0.4.0", false)]
    [InlineData("0.4.0", "0.0.0-dev", false)]
    [InlineData("0.4.0", null, false)]
    public void TrayWasReplaced_OnlyWhenTheCopyOnDiskIsADifferentRelease(string running, string? onDisk, bool replaced) =>
        Assert.Equal(replaced, ReleaseLayout.TrayWasReplaced(ReleaseVersion.Parse(running),
            onDisk is null ? null : ReleaseVersion.Parse(onDisk)));
}

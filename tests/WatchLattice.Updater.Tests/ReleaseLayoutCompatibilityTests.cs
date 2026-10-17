using System.Xml.Linq;
using Xunit;

namespace WatchLattice.Updater.Tests;

/// <summary>
/// Installed v0.1.0 hubs (released as ScanAlways) only accept a package that
/// contains these exact files, and their services point at the hub file. The
/// rename to WatchLattice must not change them; see docs/releasing.md.
/// </summary>
public class ReleaseLayoutCompatibilityTests
{
    [Fact]
    public void PackageExecutables_KeepTheNamesInstalledUpdatersRequire()
    {
        Assert.Equal("ScanAlways.Protection.Service.exe", ReleaseLayout.HubExecutable);
        Assert.Equal("ScanAlways.Tray.exe", ReleaseLayout.TrayExecutable);
        Assert.Equal("ScanAlways.Tray.dll", ReleaseLayout.TrayAssembly);
        Assert.Equal("Hub", ReleaseLayout.HubFolder);
        Assert.Equal("Tray", ReleaseLayout.TrayFolder);
    }

    [Theory]
    [InlineData("src/WatchLattice.Hub/WatchLattice.Hub.csproj", "ScanAlways.Protection.Service.exe")]
    [InlineData("src/WatchLattice.Tray/WatchLattice.Tray.csproj", "ScanAlways.Tray.exe")]
    public void Projects_BuildTheExecutablesThePackageMustContain(string project, string executable)
    {
        var assemblyName = XDocument.Load(Path.Combine(RepositoryRoot(), project))
            .Descendants("AssemblyName").Select(e => e.Value.Trim()).SingleOrDefault();

        Assert.Equal(Path.GetFileNameWithoutExtension(executable), assemblyName);
    }

    private static string RepositoryRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Combine(dir.FullName, "WatchLattice.sln")))
            {
                return dir.FullName;
            }
        }
        throw new DirectoryNotFoundException("Could not find WatchLattice.sln above the test output folder.");
    }
}

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
        var assemblyName = XDocument.Load(Path.Join(RepositoryRoot(), project))
            .Descendants("AssemblyName").Select(e => e.Value.Trim()).SingleOrDefault();

        Assert.Equal(Path.GetFileNameWithoutExtension(executable), assemblyName);
    }

    [Fact]
    public void Msi_KeepsTheNamesAndUpgradeCodeInstalledCopiesRequire()
    {
        XNamespace wix = "http://wixtoolset.org/schemas/v4/wxs";
        var package = XDocument.Load(Path.Join(RepositoryRoot(), "packaging/msi/Package.wxs"));

        // Changing the UpgradeCode would install a second copy instead of upgrading.
        Assert.Equal("21E8E3ED-618D-4DCD-8E14-79555B2974AD", package.Descendants(wix + "Package").Single().Attribute("UpgradeCode")?.Value);

        var service = package.Descendants(wix + "ServiceInstall").Single();
        Assert.Equal("ScanAlways Protection", service.Attribute("Name")?.Value);
        Assert.Equal("auto", service.Attribute("Start")?.Value);
        Assert.Null(service.Attribute("Account"));  // LocalSystem
        Assert.Equal("ScanAlways Protection", package.Descendants(wix + "ServiceControl").Single().Attribute("Name")?.Value);

        var serviceFile = service.Parent!.Elements(wix + "File").Single();
        Assert.EndsWith($@"\{ReleaseLayout.HubFolder}\{ReleaseLayout.HubExecutable}", serviceFile.Attribute("Source")?.Value);
        Assert.EndsWith($@"\{ReleaseLayout.TrayFolder}\{ReleaseLayout.TrayExecutable}",
            package.Descendants(wix + "File").Single(f => f.Attribute("Id")?.Value == "TrayExe").Attribute("Source")?.Value);
    }

    private static string RepositoryRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Join(dir.FullName, "WatchLattice.sln")))
            {
                return dir.FullName;
            }
        }
        throw new DirectoryNotFoundException("Could not find WatchLattice.sln above the test output folder.");
    }
}

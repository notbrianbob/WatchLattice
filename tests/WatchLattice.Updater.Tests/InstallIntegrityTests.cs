using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using WatchLattice.Common.Alerts;
using WatchLattice.Common.Modules;
using Xunit;

namespace WatchLattice.Updater.Tests;

public sealed class InstallManifestTests
{
    [Fact]
    public void Create_ListsHubAndTrayFiles_WithoutTheUserSettings_AndParsesBack()
    {
        using var install = Installs.Create("1.2.3");

        var manifest = InstallManifest.Read(install.Combine("Hub", ReleaseLayout.FileManifestName));

        Assert.Equal(ReleaseVersion.Parse("1.2.3"), manifest.Version);
        Assert.Equal(new[] { "Hub/ScanAlways.Protection.Service.exe", "Hub/WatchLattice.Common.dll", "Hub/runtimes/win/native.dll",
            "Tray/ScanAlways.Tray.dll", "Tray/ScanAlways.Tray.exe" }, manifest.Files.Keys.Order(StringComparer.Ordinal));
        Assert.DoesNotContain("Hub/appsettings.json", manifest.Files.Keys);
    }

    [Theory]
    [InlineData("Other/file.dll")]
    [InlineData("Hub/../outside.dll")]
    [InlineData("Hub/./file.dll")]
    [InlineData("Hub\\file.dll")]
    [InlineData("C:/Hub/file.dll")]
    [InlineData("Hub//file.dll")]
    public void Parse_RejectsPathsOutsideTheInstall(string path)
    {
        var text = $"# WatchLattice 1.0.0\n{new string('a', 64)}  {path}\n";
        Assert.Throws<InvalidDataException>(() => InstallManifest.Parse(text));
    }

    [Theory]
    [InlineData("")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  Hub/a.dll\n")]
    [InlineData("# WatchLattice not-a-version\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  Hub/a.dll\n")]
    [InlineData("# WatchLattice 1.0.0\n")]
    public void Parse_RequiresAVersionHeader_AndAtLeastOneFile(string text) =>
        Assert.Throws<InvalidDataException>(() => InstallManifest.Parse(text));

    [Fact]
    public void Parse_AcceptsTheReleaseWorkflowsFormat()
    {
        // Set-Content writes CRLF line endings on Windows.
        var text = "# WatchLattice 0.5.0\r\n" + new string('A', 64) + "  Hub/ScanAlways.Protection.Service.exe\r\n";

        var manifest = InstallManifest.Parse(text);

        Assert.Equal(new string('a', 64), manifest.Files["hub/scanalways.protection.service.exe"]);
    }

    [Fact]
    public void ReleaseWorkflow_WritesTheManifestTheHubReads()
    {
        var root = Installs.RepositoryRoot();
        var script = File.ReadAllText(Path.Combine(root, ".github", "scripts", "Write-InstallManifest.ps1"));
        Assert.Contains($"Hub/{ReleaseLayout.FileManifestName}", script);
        Assert.Contains($"Hub/{ReleaseLayout.HubSettingsFile}", script);
        Assert.Contains(InstallManifest.HeaderPrefix.Trim(), script);
        Assert.Contains("Write-InstallManifest.ps1", File.ReadAllText(Path.Combine(root, ".github", "workflows", "release.yml")));
    }
}

public sealed class InstallIntegrityCheckerTests
{
    private static readonly ReleaseVersion Version = ReleaseVersion.Parse("1.2.3");

    private static IntegrityReport Check(TempDirectory install, InstallIntegrityOptions? options = null) =>
        InstallIntegrityChecker.Check(install.Combine("Hub"), Version, options ?? new InstallIntegrityOptions());

    [Fact]
    public void UntouchedInstall_Verifies_EvenAfterTheUserEditsTheirSettings()
    {
        using var install = Installs.Create("1.2.3");
        install.Write("Hub/appsettings.json", "{ \"edited\": true }");
        install.Write("Hub/appsettings.json.default", "{ }");
        install.Write("Hub/settings-backups/appsettings-20261018.json", "{ }");

        var report = Check(install);

        Assert.Equal(IntegrityState.Verified, report.State);
        Assert.Equal(5, report.FilesChecked);
        Assert.Empty(report.Findings);
    }

    [Fact]
    public void ReportsChangedAndMissingFiles()
    {
        using var install = Installs.Create("1.2.3");
        install.Write("Hub/WatchLattice.Common.dll", "patched");
        File.Delete(install.Combine("Tray", "ScanAlways.Tray.dll"));

        var report = Check(install);

        Assert.Equal(IntegrityState.Modified, report.State);
        Assert.Equal(new[] { "Hub/WatchLattice.Common.dll" }, report.Changed);
        Assert.Equal(new[] { "Tray/ScanAlways.Tray.dll" }, report.Missing);
        Assert.True(report.AffectsBinaries);
        Assert.Equal(new[] { "Hub/WatchLattice.Common.dll (changed)", "Tray/ScanAlways.Tray.dll (missing)" }, report.Findings);
    }

    [Fact]
    public void ReportsUnexpectedBinaries_ButNotTheUpdatersOrSettingsEditorsFolders()
    {
        using var install = Installs.Create("1.2.3");
        install.Write("Hub/version.dll", "planted");
        install.Write("Tray/runtimes/extra.exe", "planted");
        install.Write("Hub/notes.txt", "not a program");
        install.Write($"Hub/{UpdateInstaller.BackupPrefix}20261018-abcd/WatchLattice.Old.dll", "previous release");
        install.Write($"Hub/{UpdateApplier.StagingPrefix}abcd/package/Hub/WatchLattice.New.dll", "next release");

        var report = Check(install);

        Assert.Equal(IntegrityState.Modified, report.State);
        Assert.Equal(new[] { "Hub/version.dll", "Tray/runtimes/extra.exe" }, report.Unexpected);
        Assert.Empty(report.Changed);
    }

    [Fact]
    public void IgnoredFiles_AndTurningOffTheBinaryScan_LeaveFindingsOut()
    {
        using var install = Installs.Create("1.2.3");
        install.Write("Hub/version.dll", "planted");
        install.Write("Hub/WatchLattice.Common.dll", "patched");

        Assert.Equal(IntegrityState.Verified, Check(install, new InstallIntegrityOptions
        {
            ReportUnexpectedBinaries = false,
            IgnoredFiles = new[] { "Hub\\WatchLattice.Common.dll" },
        }).State);
        Assert.Equal(new[] { "Hub/version.dll" }, Check(install, new InstallIntegrityOptions
        {
            IgnoredFiles = new[] { "hub/watchlattice.common.dll" },
        }).Unexpected);
    }

    [Fact]
    public void ChangedDataFile_IsAWarningNotABinaryChange()
    {
        using var install = Installs.Create("1.2.3", extra: new Dictionary<string, string> { ["Hub/ScanAlways.Protection.Service.deps.json"] = "{}" });
        install.Write("Hub/ScanAlways.Protection.Service.deps.json", "{ \"changed\": true }");

        var report = Check(install);

        Assert.Equal(IntegrityState.Modified, report.State);
        Assert.False(report.AffectsBinaries);
    }

    [Fact]
    public void HubOnlyLayout_ChecksTheHubOnly()
    {
        using var install = Installs.Create("1.2.3");
        Directory.Delete(install.Combine("Tray"), recursive: true);

        var report = Check(install);

        Assert.Equal(IntegrityState.Verified, report.State);
        Assert.Equal(3, report.FilesChecked);
    }

    [Fact]
    public void ManifestFromAnotherRelease_IsAVersionMismatch_NotAFinding()
    {
        using var install = Installs.Create("1.2.4");
        install.Write("Hub/WatchLattice.Common.dll", "half-way through an update");

        var report = Check(install);

        Assert.Equal(IntegrityState.VersionMismatch, report.State);
        Assert.Equal(ReleaseVersion.Parse("1.2.4"), report.ManifestVersion);
        Assert.Empty(report.Findings);
    }

    [Fact]
    public void MissingOrBrokenManifest_IsReported()
    {
        using var install = Installs.Create("1.2.3");
        var manifest = install.Combine("Hub", ReleaseLayout.FileManifestName);

        File.WriteAllText(manifest, "garbage");
        Assert.Equal(IntegrityState.ManifestInvalid, Check(install).State);

        File.Delete(manifest);
        var report = Check(install);
        Assert.Equal(IntegrityState.ManifestMissing, report.State);
        Assert.Contains(ReleaseLayout.FileManifestName, report.Problem);
    }
}

public sealed class InstallIntegrityMonitorTests
{
    private sealed class Recorder : IAlertPublisher
    {
        public List<(string Code, AlertSeverity Severity, string Message, string? Resource)> Alerts { get; } = new();

        public void Publish(string module, string code, AlertSeverity severity, string title, string message, string? resource = null)
        {
            Assert.Equal(InstallIntegrityMonitor.ModuleId, module);
            Alerts.Add((code, severity, message, resource));
        }
    }

    private static InstallIntegrityMonitor Create(TempDirectory install, Recorder recorder, string current = "1.2.3",
        Func<TimeSpan, CancellationToken, Task>? delay = null) =>
        new(Options.Create(new InstallIntegrityOptions()), NullLogger<InstallIntegrityMonitor>.Instance,
            ReleaseVersion.Parse(current), install.Combine("Hub"), recorder, delay ?? ((_, _) => Task.CompletedTask));

    [Fact]
    public async Task AlertsOncePerSetOfFindings_ThenClearsWhenTheFilesMatchAgain()
    {
        using var install = Installs.Create("1.2.3");
        var original = File.ReadAllText(install.Combine("Hub", "WatchLattice.Common.dll"));
        var recorder = new Recorder();
        var monitor = Create(install, recorder);

        await monitor.CheckOnceAsync(default);
        Assert.Empty(recorder.Alerts);

        install.Write("Hub/WatchLattice.Common.dll", "patched");
        await monitor.CheckOnceAsync(default);
        await monitor.CheckOnceAsync(default);
        var alert = Assert.Single(recorder.Alerts);
        Assert.Equal(InstallIntegrityMonitor.ModifiedCode, alert.Code);
        Assert.Equal(AlertSeverity.Critical, alert.Severity);
        Assert.Contains("Hub/WatchLattice.Common.dll (changed)", alert.Message);
        Assert.Equal(Path.GetFullPath(install.Path), alert.Resource);

        install.Write("Hub/version.dll", "planted");
        await monitor.CheckOnceAsync(default);
        Assert.Equal(2, recorder.Alerts.Count);
        Assert.Contains("Hub/version.dll (not part of the release)", recorder.Alerts[^1].Message);

        install.Write("Hub/WatchLattice.Common.dll", original);
        File.Delete(install.Combine("Hub", "version.dll"));
        await monitor.CheckOnceAsync(default);
        await monitor.CheckOnceAsync(default);
        Assert.Equal(3, recorder.Alerts.Count);
        Assert.Equal(InstallIntegrityMonitor.ModifiedCode + AlertEventIds.ClearedSuffix, recorder.Alerts[^1].Code);
        Assert.Equal(AlertSeverity.Info, recorder.Alerts[^1].Severity);
    }

    [Fact]
    public async Task AProblemThatGoesAwayBeforeTheConfirmingCheck_RaisesNothing()
    {
        using var install = Installs.Create("1.2.3");
        var original = File.ReadAllText(install.Combine("Hub", "WatchLattice.Common.dll"));
        install.Write("Hub/WatchLattice.Common.dll", "being replaced");
        var waits = new List<TimeSpan>();
        var recorder = new Recorder();
        var monitor = Create(install, recorder, delay: (wait, _) =>
        {
            waits.Add(wait);
            install.Write("Hub/WatchLattice.Common.dll", original);
            return Task.CompletedTask;
        });

        var report = await monitor.CheckOnceAsync(default);

        Assert.Equal(IntegrityState.Verified, report.State);
        Assert.Equal(new[] { InstallIntegrityMonitor.ConfirmDelay }, waits);
        Assert.Empty(recorder.Alerts);
    }

    [Fact]
    public async Task ACleanInstall_IsNotRecheckedOrAnnounced()
    {
        using var install = Installs.Create("1.2.3");
        var waits = 0;
        var recorder = new Recorder();

        await Create(install, recorder, delay: (_, _) => { waits++; return Task.CompletedTask; }).CheckOnceAsync(default);

        Assert.Equal(0, waits);
        Assert.Empty(recorder.Alerts);
    }

    [Fact]
    public async Task UpdateAwaitingRestart_RaisesNothing()
    {
        using var install = Installs.Create("1.3.0");
        install.Write("Hub/version.dll", "new in 1.3.0");
        var recorder = new Recorder();

        var report = await Create(install, recorder, current: "1.2.3").CheckOnceAsync(default);

        Assert.Equal(IntegrityState.VersionMismatch, report.State);
        Assert.Empty(recorder.Alerts);
    }

    [Fact]
    public async Task MissingManifest_WarnsOnce_AndRecovers()
    {
        using var install = Installs.Create("1.2.3");
        var manifest = install.Combine("Hub", ReleaseLayout.FileManifestName);
        var saved = File.ReadAllText(manifest);
        File.Delete(manifest);
        var recorder = new Recorder();
        var monitor = Create(install, recorder);

        await monitor.CheckOnceAsync(default);
        await monitor.CheckOnceAsync(default);
        var alert = Assert.Single(recorder.Alerts);
        Assert.Equal(InstallIntegrityMonitor.ManifestUnavailableCode, alert.Code);
        Assert.Equal(AlertSeverity.Warning, alert.Severity);

        File.WriteAllText(manifest, saved);
        await monitor.CheckOnceAsync(default);
        Assert.Equal(InstallIntegrityMonitor.ManifestUnavailableCode + AlertEventIds.ClearedSuffix, recorder.Alerts[^1].Code);
    }

    [Fact]
    public async Task Run_ChecksNothing_ForDevelopmentBuilds()
    {
        using var install = Installs.Create("1.2.3");
        File.Delete(install.Combine("Hub", ReleaseLayout.FileManifestName));
        var recorder = new Recorder();
        var delays = 0;
        var monitor = Create(install, recorder, current: "0.0.0-dev", delay: (_, _) => { delays++; return Task.CompletedTask; });
        using var cancel = new CancellationTokenSource();

        var run = monitor.RunAsync(cancel.Token);
        Assert.False(run.IsCompleted);
        cancel.Cancel();
        await run;

        Assert.Equal(0, delays);
        Assert.Empty(recorder.Alerts);
    }

    [Fact]
    public async Task Run_ChecksAfterTheInitialDelay_ThenEveryInterval_AndStopsCleanly()
    {
        using var install = Installs.Create("1.2.3");
        install.Write("Hub/WatchLattice.Common.dll", "patched");
        var recorder = new Recorder();
        var waits = new List<TimeSpan>();
        using var cancel = new CancellationTokenSource();
        var monitor = new InstallIntegrityMonitor(
            Options.Create(new InstallIntegrityOptions { InitialDelaySeconds = 7, CheckIntervalMinutes = 1 }),
            NullLogger<InstallIntegrityMonitor>.Instance, ReleaseVersion.Parse("1.2.3"), install.Combine("Hub"), recorder,
            (wait, token) =>
            {
                waits.Add(wait);
                if (waits.Count == 5) cancel.Cancel();
                token.ThrowIfCancellationRequested();
                return Task.CompletedTask;
            });

        await monitor.RunAsync(cancel.Token);

        // Initial delay, confirm, interval (clamped to 5 minutes), confirm, interval.
        Assert.Equal(new[] { TimeSpan.FromSeconds(7), InstallIntegrityMonitor.ConfirmDelay, TimeSpan.FromMinutes(5),
            InstallIntegrityMonitor.ConfirmDelay, TimeSpan.FromMinutes(5) }, waits);
        Assert.Single(recorder.Alerts);
    }

    [Fact]
    public void Module_IsDiscovered_AndBindsItsOptions()
    {
        var modules = ModuleCatalog.Discover(typeof(InstallIntegrityModule).Assembly).Modules;
        var module = Assert.Single(modules, m => m.Id == InstallIntegrityMonitor.ModuleId);
        Assert.IsType<InstallIntegrityModule>(module);
        Assert.True(module.EnabledByDefault);

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["InstallIntegrity:CheckIntervalMinutes"] = "30",
                ["InstallIntegrity:IgnoredFiles:0"] = "Hub/Extra.dll",
            })
            .Build();
        var services = new ServiceCollection().AddLogging();
        module.ConfigureServices(services, configuration);
        using var provider = services.BuildServiceProvider();

        Assert.Equal(ReleaseVersion.FromAssembly(typeof(InstallIntegrityModule).Assembly),
            provider.GetRequiredService<InstallIntegrityMonitor>().Current);
        var options = provider.GetRequiredService<IOptions<InstallIntegrityOptions>>().Value;
        Assert.Equal(30, options.CheckIntervalMinutes);
        Assert.Equal(new[] { "Hub/Extra.dll" }, options.IgnoredFiles);
    }

    [Theory]
    [InlineData(InstallIntegrityMonitor.ModifiedCode)]
    [InlineData(InstallIntegrityMonitor.ManifestUnavailableCode)]
    public void EveryAlert_HasItsOwnEventLogId(string code)
    {
        Assert.True(AlertEventIds.IsClassified(InstallIntegrityMonitor.ModuleId, code));
        Assert.True(AlertEventIds.IsClassified(InstallIntegrityMonitor.ModuleId, code + AlertEventIds.ClearedSuffix));
    }
}

internal static class Installs
{
    /// <summary>An install folder laid out like the release zip, with a manifest for <paramref name="version"/>.</summary>
    public static TempDirectory Create(string version, IDictionary<string, string>? extra = null)
    {
        var install = new TempDirectory();
        install.Write("Hub/ScanAlways.Protection.Service.exe", "hub");
        install.Write("Hub/WatchLattice.Common.dll", "common");
        install.Write("Hub/runtimes/win/native.dll", "native");
        install.Write("Hub/appsettings.json", "{ }");
        install.Write("Tray/ScanAlways.Tray.exe", "tray");
        install.Write("Tray/ScanAlways.Tray.dll", "tray dll");
        foreach (var (name, content) in extra ?? new Dictionary<string, string>()) install.Write(name, content);
        File.WriteAllText(install.Combine("Hub", ReleaseLayout.FileManifestName),
            InstallManifest.Create(ReleaseVersion.Parse(version), install.Path));
        return install;
    }

    public static string RepositoryRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Combine(dir.FullName, "WatchLattice.sln"))) return dir.FullName;
        }
        throw new DirectoryNotFoundException("Could not find WatchLattice.sln above the test output folder.");
    }
}

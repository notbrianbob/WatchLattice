using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using WatchLattice.Common.Modules;
using Xunit;

namespace WatchLattice.Persistence.Tests;

public sealed class PersistenceProviderTests
{
    [Fact]
    public void Diff_IgnoresIdentityCase_ButPreservesCommandChanges()
    {
        Assert.Empty(PersistenceDiff.Compare(new[] { new PersistenceEntry("App", "app.exe") }, new[] { new PersistenceEntry("APP", "app.exe") }));
        Assert.Equal(PersistenceChangeKind.Changed, Assert.Single(PersistenceDiff.Compare(
            new[] { new PersistenceEntry("App", "app.exe") }, new[] { new PersistenceEntry("APP", "app.exe --extra") })).Kind);
    }

    [Fact]
    public void TaskParser_AcceptsEmptyInventory_AndPreservesLiteralCommands()
    {
        Assert.Empty(WindowsPersistenceProvider.ParseScheduledTasks("[]"));
        var entry = Assert.Single(WindowsPersistenceProvider.ParseScheduledTasks("[{\"Id\":\"Task\",\"Command\":\"tool.exe --value quoted\"}]"));
        Assert.Equal("tool.exe --value quoted", entry.Command);
    }

    [Theory]
    [InlineData("null")]
    [InlineData("[{}]")]
    [InlineData("[{\"Id\":\"A\",\"Command\":\"x\"},{\"Id\":\"a\",\"Command\":\"y\"}]")]
    public void TaskParser_RejectsIncompleteInventory(string json) =>
        Assert.Throws<InvalidDataException>(() => WindowsPersistenceProvider.ParseScheduledTasks(json));

    [Fact]
    public async Task Module_IsDiscoverable_AndRunsWithInjectedProvider()
    {
        var module = Assert.Single(ModuleCatalog.Discover(typeof(PersistenceModule).Assembly).Modules);
        Assert.Equal("Persistence", module.Id);
        Assert.True(module.EnabledByDefault);
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IPersistenceProvider, EmptyProvider>();
        module.ConfigureServices(services, new ConfigurationBuilder().Build());
        using var provider = services.BuildServiceProvider();
        Assert.IsType<EmptyProvider>(provider.GetRequiredService<IPersistenceProvider>());
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await module.RunAsync(provider, cts.Token);
    }

    [Fact]
    public async Task Provider_ObservesStartupFilesWithoutChangingThem_OrReportsUnsupportedPlatform()
    {
        var folder = Path.Combine(Path.GetTempPath(), "watchlattice-startup-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            var path = Path.Combine(folder, "example.cmd");
            File.WriteAllText(path, "echo test");
            var provider = new WindowsPersistenceProvider(Options.Create(new PersistenceOptions
            {
                WatchRegistry = false, WatchScheduledTasks = false, WatchServices = false, WatchWmiSubscriptions = false, StartupFolders = new[] { folder },
            }));
            var result = Assert.Single(await provider.ReadAsync(default));
            if (OperatingSystem.IsWindows())
            {
                Assert.Null(result.Error);
                Assert.Contains("SHA256", Assert.Single(result.Entries).Command);
                File.WriteAllText(path, "echo updated");
                var updated = Assert.Single(await provider.ReadAsync(default));
                Assert.NotEqual(result.Entries[0].Command, updated.Entries[0].Command);
                Assert.Equal("echo updated", File.ReadAllText(path));
                File.Delete(path);
                Assert.Empty(Assert.Single(await provider.ReadAsync(default)).Entries);
            }
            else Assert.Contains("only available on Windows", result.Error);
        }
        finally { Directory.Delete(folder, recursive: true); }
    }

    private sealed class EmptyProvider : IPersistenceProvider
    {
        public Task<IReadOnlyList<PersistenceSource>> ReadAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<PersistenceSource>>(Array.Empty<PersistenceSource>());
    }
}

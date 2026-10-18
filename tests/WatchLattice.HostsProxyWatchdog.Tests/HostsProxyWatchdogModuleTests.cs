using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using WatchLattice.Common.Modules;
using Xunit;

namespace WatchLattice.HostsProxyWatchdog.Tests;

public class HostsProxyWatchdogModuleTests
{
    [Fact]
    public void Discover_FindsTheWatchdogModule_EnabledByDefault()
    {
        var catalog = ModuleCatalog.Discover(typeof(HostsProxyWatchdogModule).Assembly);

        var module = Assert.Single(catalog.Modules);
        Assert.Equal("HostsProxyWatchdog", module.Id);
        Assert.True(module.EnabledByDefault);
    }

    [Fact]
    public void ConfigureServices_RegistersTheWatchdog_WithItsOptions()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["HostsProxyWatchdog:CheckIntervalSeconds"] = "30",
                ["HostsProxyWatchdog:WatchProxySettings"] = "false",
                ["HostsProxyWatchdog:ProtectedDomains:0"] = "corp.example",
                ["HostsProxyWatchdog:IgnoredHosts:0"] = "*.lan",
            })
            .Build();

        var services = new ServiceCollection().AddLogging();
        new HostsProxyWatchdogModule().ConfigureServices(services, configuration);
        using var provider = services.BuildServiceProvider();

        Assert.NotNull(provider.GetRequiredService<HostsProxyWatchdog>());
        var options = provider.GetRequiredService<IOptions<HostsProxyWatchdogOptions>>().Value;
        Assert.Equal(30, options.CheckIntervalSeconds);
        Assert.False(options.WatchProxySettings);
        Assert.True(options.WatchHostsFile);
        Assert.Equal(new[] { "corp.example" }, options.ProtectedDomains);
        Assert.Equal(new[] { "*.lan" }, options.IgnoredHosts);
        Assert.Contains("corp.example", options.EffectiveProtectedDomains());
        Assert.Contains("windowsupdate.com", options.EffectiveProtectedDomains());
    }

    [Fact]
    public async Task RealProvider_ReadsAConfiguredHostsFile_OnAnyOs()
    {
        var path = Path.Join(Path.GetTempPath(), $"watchlattice-hosts-{Guid.NewGuid():N}");
        await File.WriteAllTextAsync(path, "10.0.0.5 nas.home # mine\n");
        try
        {
            var provider = new WindowsHostsProxyProvider(Microsoft.Extensions.Options.Options.Create(
                new HostsProxyWatchdogOptions { HostsFilePath = path }));

            var snapshot = await provider.ReadAsync(hosts: true, proxy: false, default);

            Assert.NotNull(snapshot.Hosts?.Entries);
            Assert.Equal(new[] { "10.0.0.5" }, snapshot.Hosts.Entries["nas.home"]);
            Assert.Null(snapshot.Proxy);
            Assert.False(snapshot.Hosts.DatabasePathMoved);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task RealProvider_OversizedOrMissingHostsFiles()
    {
        var path = Path.Join(Path.GetTempPath(), $"watchlattice-hosts-{Guid.NewGuid():N}");
        await File.WriteAllTextAsync(path, new string('#', 2048));
        try
        {
            var small = new WindowsHostsProxyProvider(Microsoft.Extensions.Options.Options.Create(
                new HostsProxyWatchdogOptions { HostsFilePath = path, MaxHostsFileBytes = 1024 }));
            Assert.Contains("MaxHostsFileBytes", (await small.ReadAsync(true, false, default)).Hosts?.Error);

            var missing = new WindowsHostsProxyProvider(Microsoft.Extensions.Options.Options.Create(
                new HostsProxyWatchdogOptions { HostsFilePath = path + ".missing" }));
            Assert.Empty((await missing.ReadAsync(true, false, default)).Hosts?.Entries!);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task RealProvider_ReadsThisMachine_WithoutThrowing()
    {
        var provider = new WindowsHostsProxyProvider(Microsoft.Extensions.Options.Options.Create(new HostsProxyWatchdogOptions()));

        var snapshot = await provider.ReadAsync(hosts: true, proxy: true, default);

        Assert.NotNull(snapshot.Hosts);
        if (OperatingSystem.IsWindows())
        {
            Assert.Null(snapshot.Hosts.Error);
            Assert.NotNull(snapshot.Proxy);
            Assert.Contains(snapshot.Proxy, s => s.Id == "Machine");
            Assert.Contains(snapshot.Proxy, s => s.Id == "WinHTTP");
            Assert.Contains(snapshot.Proxy, s => s.Id.StartsWith("User:", StringComparison.Ordinal));
        }
        else
        {
            Assert.NotNull(snapshot.Hosts.Error);
            Assert.NotNull(snapshot.ProxyError);
        }
    }
}

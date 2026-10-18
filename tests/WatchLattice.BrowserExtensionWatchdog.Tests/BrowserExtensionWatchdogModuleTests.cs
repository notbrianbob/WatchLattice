using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using WatchLattice.Common.Modules;
using Xunit;

namespace WatchLattice.BrowserExtensionWatchdog.Tests;

public class BrowserExtensionWatchdogModuleTests
{
    [Fact]
    public void Discover_FindsTheWatchdogModule_EnabledByDefault()
    {
        var catalog = ModuleCatalog.Discover(typeof(BrowserExtensionWatchdogModule).Assembly);

        var module = Assert.Single(catalog.Modules);
        Assert.Equal("BrowserExtensionWatchdog", module.Id);
        Assert.True(module.EnabledByDefault);
    }

    [Fact]
    public void ConfigureServices_RegistersTheWatchdog_WithItsOptions()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["BrowserExtensionWatchdog:CheckIntervalSeconds"] = "600",
                ["BrowserExtensionWatchdog:WatchFirefox"] = "false",
                ["BrowserExtensionWatchdog:IgnoredExtensionIds:0"] = "aapbdbdomjkkjkaonfhkkikfgjllcleb",
            })
            .Build();

        var services = new ServiceCollection().AddLogging();
        new BrowserExtensionWatchdogModule().ConfigureServices(services, configuration);
        using var provider = services.BuildServiceProvider();

        Assert.NotNull(provider.GetRequiredService<BrowserExtensionWatchdog>());
        Assert.IsType<BrowserExtensionProvider>(provider.GetRequiredService<IBrowserExtensionProvider>());
        var options = provider.GetRequiredService<IOptions<BrowserExtensionWatchdogOptions>>().Value;
        Assert.Equal(600, options.CheckIntervalSeconds);
        Assert.Equal(new[] { Browsers.Edge, Browsers.Chrome }, options.EnabledBrowsers());
        Assert.Equal(new[] { "aapbdbdomjkkjkaonfhkkikfgjllcleb" }, options.IgnoredExtensionIds);
        Assert.True(options.WatchPolicies);
    }

    [Fact]
    public async Task RealProvider_ReadsThisMachine_WithoutThrowing()
    {
        var provider = new BrowserExtensionProvider(Options.Create(new BrowserExtensionWatchdogOptions()));

        var snapshot = await provider.ReadAsync(default);

        Assert.NotEmpty(snapshot.Users);
        if (OperatingSystem.IsWindows())
        {
            Assert.Null(snapshot.PolicyError);
            Assert.Contains("Machine", snapshot.PolicyScopes);
        }
        else
        {
            Assert.NotNull(snapshot.PolicyError);
        }
    }
}

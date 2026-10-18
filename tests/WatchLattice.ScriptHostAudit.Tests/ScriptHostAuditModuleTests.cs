using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using WatchLattice.Common.Alerts;
using WatchLattice.Common.Modules;
using Xunit;

namespace WatchLattice.ScriptHostAudit.Tests;

public class ScriptHostAuditModuleTests
{
    [Fact]
    public void Discover_FindsTheModule_OffByDefault()
    {
        var catalog = ModuleCatalog.Discover(typeof(ScriptHostAuditModule).Assembly);

        var module = Assert.Single(catalog.Modules);
        Assert.Equal("ScriptHostAudit", module.Id);
        Assert.False(module.EnabledByDefault);
    }

    [Fact]
    public void ConfigureServices_RegistersTheAuditor_WithItsOptions()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ScriptHostAudit:CheckIntervalSeconds"] = "60",
                ["ScriptHostAudit:ScriptHosts:0"] = "python.exe",
                ["ScriptHostAudit:IncludeBuiltInSuspiciousParents"] = "false",
                ["ScriptHostAudit:MinimumSeverity"] = "Info",
            })
            .Build();

        var services = new ServiceCollection().AddLogging();
        new ScriptHostAuditModule().ConfigureServices(services, configuration);
        using var provider = services.BuildServiceProvider();

        Assert.NotNull(provider.GetRequiredService<ScriptHostAuditor>());
        Assert.IsType<WindowsProcessCreationSource>(provider.GetRequiredService<IProcessCreationSource>());
        var options = provider.GetRequiredService<IOptions<ScriptHostAuditOptions>>().Value;
        Assert.Equal(60, options.CheckIntervalSeconds);
        Assert.Equal(AlertSeverity.Info, options.MinimumSeverity);
        // Configured names add to the built-in list rather than replacing it.
        Assert.Contains("python.exe", options.WatchedHosts());
        Assert.Contains("powershell.exe", options.WatchedHosts());
        Assert.Empty(options.SuspiciousParentNames());
    }

    [Fact]
    public void RealSource_DoesNotThrow_ForTheAuditPolicy()
    {
        var status = new WindowsProcessCreationSource().ReadAuditStatus();

        if (!OperatingSystem.IsWindows())
        {
            Assert.Null(status.ProcessCreationAudited);
            Assert.NotNull(status.Error);
            Assert.Throws<PlatformNotSupportedException>(() => new WindowsProcessCreationSource().ReadRange());
        }
        else if (status.ProcessCreationAudited is null)
        {
            Assert.NotNull(status.Error);
        }
    }
}

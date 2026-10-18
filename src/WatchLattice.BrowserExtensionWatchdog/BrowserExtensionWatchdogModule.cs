using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using WatchLattice.Common.Modules;

namespace WatchLattice.BrowserExtensionWatchdog;

/// <summary>
/// Registers the browser extension watchdog with the hub. The behavior lives
/// in <see cref="BrowserExtensionWatchdog"/>; this class only wires it up and
/// runs it, and its settings stay in the top-level "BrowserExtensionWatchdog" config section.
/// </summary>
public sealed class BrowserExtensionWatchdogModule : IWatchLatticeModule
{
    public string Id => BrowserExtensionWatchdog.ModuleId;

    public string DisplayName => "Browser Extension Watchdog";

    public string Description =>
        "Reports extensions added to or removed from Edge, Chrome and Firefox profiles, and extension install policies (read-only).";

    public bool EnabledByDefault => true;

    public Type SettingsType => typeof(BrowserExtensionWatchdogOptions);

    public void ConfigureServices(IServiceCollection services, IConfiguration configuration) =>
        services.AddWatchLatticeBrowserExtensionWatchdog(configuration);

    public async Task RunAsync(IServiceProvider services, CancellationToken cancellationToken)
    {
        services.GetRequiredService<ILogger<BrowserExtensionWatchdogModule>>().LogInformation("WatchLattice browser extension watchdog online.");
        await services.GetRequiredService<BrowserExtensionWatchdog>().RunAsync(cancellationToken);
    }
}

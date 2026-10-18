using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using WatchLattice.Common.Modules;

namespace WatchLattice.HostsProxyWatchdog;

/// <summary>
/// Registers the hosts file and proxy watchdog with the hub. The behavior
/// lives in <see cref="HostsProxyWatchdog"/>; this class only wires it up and
/// runs it, and its settings stay in the top-level "HostsProxyWatchdog" config section.
/// </summary>
public sealed class HostsProxyWatchdogModule : IWatchLatticeModule
{
    public string Id => HostsProxyWatchdog.ModuleId;

    public string DisplayName => "Hosts File & Proxy Watchdog";

    public string Description =>
        "Reports changes to the hosts file and to WinINET, WinHTTP and environment proxy settings, and hosts entries that block security updates (read-only).";

    public bool EnabledByDefault => true;

    public Type SettingsType => typeof(HostsProxyWatchdogOptions);

    public void ConfigureServices(IServiceCollection services, IConfiguration configuration) =>
        services.AddWatchLatticeHostsProxyWatchdog(configuration);

    public async Task RunAsync(IServiceProvider services, CancellationToken cancellationToken)
    {
        services.GetRequiredService<ILogger<HostsProxyWatchdogModule>>().LogInformation("WatchLattice hosts file and proxy watchdog online.");
        await services.GetRequiredService<HostsProxyWatchdog>().RunAsync(cancellationToken);
    }
}

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WatchLattice.Common.Alerts;

namespace WatchLattice.HostsProxyWatchdog;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the hosts file and proxy watchdog and binds
    /// <see cref="HostsProxyWatchdogOptions"/> from the "HostsProxyWatchdog"
    /// configuration section. <see cref="HostsProxyWatchdogModule"/> runs it
    /// inside the hub.
    /// </summary>
    public static IServiceCollection AddWatchLatticeHostsProxyWatchdog(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.AddOptions<HostsProxyWatchdogOptions>()
            .Bind(configuration.GetSection(HostsProxyWatchdogOptions.SectionName));

        services.TryAddSingleton<IHostsProxyProvider, WindowsHostsProxyProvider>();
        services.AddSingleton(sp => new HostsProxyWatchdog(
            sp.GetRequiredService<IHostsProxyProvider>(),
            sp.GetRequiredService<IOptions<HostsProxyWatchdogOptions>>(),
            sp.GetRequiredService<ILogger<HostsProxyWatchdog>>(),
            sp.GetService<IAlertPublisher>()));
        return services;
    }
}

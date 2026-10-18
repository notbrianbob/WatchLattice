using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WatchLattice.Common.Alerts;

namespace WatchLattice.BrowserExtensionWatchdog;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the browser extension watchdog and binds
    /// <see cref="BrowserExtensionWatchdogOptions"/> from the
    /// "BrowserExtensionWatchdog" configuration section.
    /// <see cref="BrowserExtensionWatchdogModule"/> runs it inside the hub.
    /// </summary>
    public static IServiceCollection AddWatchLatticeBrowserExtensionWatchdog(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.AddOptions<BrowserExtensionWatchdogOptions>()
            .Bind(configuration.GetSection(BrowserExtensionWatchdogOptions.SectionName));

        services.TryAddSingleton<IExtensionPolicyReader, WindowsExtensionPolicyReader>();
        services.TryAddSingleton<IBrowserExtensionProvider>(sp => new BrowserExtensionProvider(
            sp.GetRequiredService<IOptions<BrowserExtensionWatchdogOptions>>(),
            sp.GetRequiredService<IExtensionPolicyReader>()));
        services.AddSingleton(sp => new BrowserExtensionWatchdog(
            sp.GetRequiredService<IBrowserExtensionProvider>(),
            sp.GetRequiredService<IOptions<BrowserExtensionWatchdogOptions>>(),
            sp.GetRequiredService<ILogger<BrowserExtensionWatchdog>>(),
            sp.GetService<IAlertPublisher>(),
            sp.GetService<TimeProvider>()));
        return services;
    }
}

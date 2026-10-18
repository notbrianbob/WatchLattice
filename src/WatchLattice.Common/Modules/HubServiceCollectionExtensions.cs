using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using WatchLattice.Common.Activity;
using WatchLattice.Common.Alerts;

namespace WatchLattice.Common.Modules;

public static class HubServiceCollectionExtensions
{
    /// <summary>
    /// Wires up the hub: binds <see cref="HubOptions"/>, lets each enabled
    /// module register its services, and adds the <see cref="ModuleSupervisor"/>
    /// that runs them. Disabled modules are never configured, so they cost
    /// nothing at runtime.
    /// </summary>
    public static IServiceCollection AddWatchLatticeHub(
        this IServiceCollection services,
        IConfiguration configuration,
        ModuleCatalog catalog)
    {
        services.AddOptions<HubOptions>()
            .Bind(configuration.GetSection(HubOptions.SectionName));

        var enabled = catalog.ResolveEnabled(configuration);
        services.AddOptions<AlertDeliveryOptions>().Bind(configuration.GetSection("Alerts"));
        services.AddSingleton<AlertHub>();
        services.AddSingleton<ActivityLog>(_ => new ActivityLog());
        services.AddSingleton<ILoggerProvider, ActivityLoggerProvider>();
        services.AddSingleton<IAlertPublisher>(sp => sp.GetRequiredService<AlertHub>());
        services.AddSingleton<IUpdateStatusPublisher>(sp => sp.GetRequiredService<AlertHub>());
        services.AddHostedService<AlertDeliveryService>();
        services.AddOptions<EventLogAlertOptions>().Bind(configuration.GetSection(EventLogAlertOptions.SectionName));
        if (OperatingSystem.IsWindows()) services.AddSingleton<IEventLogWriter, WindowsEventLogWriter>();
        else services.AddSingleton<IEventLogWriter, UnsupportedEventLogWriter>();
        services.AddSingleton<EventLogAlertService>();
        services.AddSingleton<IAlertSink>(sp => sp.GetRequiredService<EventLogAlertService>());
        services.AddHostedService(sp => sp.GetRequiredService<EventLogAlertService>());
        services.TryAddSingleton(TimeProvider.System);
        services.AddOptions<DailySummaryOptions>().Bind(configuration.GetSection(DailySummaryOptions.SectionName));
        services.AddHostedService<DailySummaryService>();
        foreach (var module in enabled)
        {
            module.ConfigureServices(services, configuration);
        }

        services.AddSingleton(catalog);
        services.AddSingleton(new EnabledModules(enabled));
        services.AddHostedService<ModuleSupervisor>();
        return services;
    }
}

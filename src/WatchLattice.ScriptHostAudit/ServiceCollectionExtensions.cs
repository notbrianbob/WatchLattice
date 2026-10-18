using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WatchLattice.Common.Alerts;

namespace WatchLattice.ScriptHostAudit;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the script host auditor and binds
    /// <see cref="ScriptHostAuditOptions"/> from the "ScriptHostAudit"
    /// configuration section. <see cref="ScriptHostAuditModule"/> runs it
    /// inside the hub.
    /// </summary>
    public static IServiceCollection AddWatchLatticeScriptHostAudit(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.AddOptions<ScriptHostAuditOptions>()
            .Bind(configuration.GetSection(ScriptHostAuditOptions.SectionName));

        services.TryAddSingleton<IProcessCreationSource, WindowsProcessCreationSource>();
        services.AddSingleton(sp => new ScriptHostAuditor(
            sp.GetRequiredService<IProcessCreationSource>(),
            sp.GetRequiredService<IOptions<ScriptHostAuditOptions>>(),
            sp.GetRequiredService<ILogger<ScriptHostAuditor>>(),
            sp.GetService<IAlertPublisher>(),
            sp.GetService<TimeProvider>()));
        return services;
    }
}

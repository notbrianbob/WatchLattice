using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using WatchLattice.Common.Alerts;
using WatchLattice.Common.Modules;
using WatchLattice.Persistence.Verification;

namespace WatchLattice.Persistence;

public sealed class PersistenceModule : IWatchLatticeModule
{
    public string Id => "Persistence";
    public string DisplayName => "Persistence & Autostart Auditor";
    public string Description => "Reports changes to Run keys, Startup folders, scheduled tasks, auto-start services and WMI event subscriptions, and verifies changed tasks and services (read-only).";
    public bool EnabledByDefault => true;
    public Type SettingsType => typeof(PersistenceOptions);

    public void ConfigureServices(IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<PersistenceOptions>().Bind(configuration.GetSection(Id));
        services.TryAddSingleton<IPersistenceProvider, WindowsPersistenceProvider>();
        services.TryAddSingleton(sp => VerificationFactory.CreateEngine(
            sp.GetRequiredService<IOptions<PersistenceOptions>>().Value.FamiliarPublishers));
        services.TryAddSingleton(sp => new VerificationStore(VerificationStore.PathForFeed(
            (sp.GetService<IOptions<AlertDeliveryOptions>>()?.Value ?? new AlertDeliveryOptions()).ResolveFeedPath())));
        services.AddSingleton<PersistenceVerificationCoordinator>();
        services.AddSingleton<IAlertSink>(sp => sp.GetRequiredService<PersistenceVerificationCoordinator>());
        services.AddSingleton<IChangeEvidenceSink>(sp => sp.GetRequiredService<PersistenceVerificationCoordinator>());
        services.AddSingleton<PersistenceAuditor>();
    }

    public async Task RunAsync(IServiceProvider services, CancellationToken cancellationToken)
    {
        // The auditor and the verifier run side by side; if either stops, stop both so the supervisor restarts the module.
        using var both = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var tasks = new[]
        {
            services.GetRequiredService<PersistenceAuditor>().RunAsync(both.Token),
            services.GetRequiredService<PersistenceVerificationCoordinator>().RunAsync(both.Token),
        };
        var first = await Task.WhenAny(tasks);
        both.Cancel();
        try { await Task.WhenAll(tasks); }
        catch (OperationCanceledException) when (!first.IsFaulted && cancellationToken.IsCancellationRequested) { }
        await first;
    }
}

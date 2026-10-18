using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using WatchLattice.Common.Modules;

namespace WatchLattice.Updater;

/// <summary>
/// Checks WatchLattice's own installed files against the hashes its release
/// shipped, and alerts when one is changed or missing. Settings live in the
/// top-level "InstallIntegrity" config section.
/// </summary>
public sealed class InstallIntegrityModule : IWatchLatticeModule
{
    public string Id => InstallIntegrityMonitor.ModuleId;

    public string DisplayName => "Install Integrity Check";

    public string Description =>
        "Checks that WatchLattice's own installed files still match the release, and alerts if one is changed or missing (read-only).";

    public bool EnabledByDefault => true;

    public Type SettingsType => typeof(InstallIntegrityOptions);

    public void ConfigureServices(IServiceCollection services, IConfiguration configuration) =>
        services.AddWatchLatticeInstallIntegrity(configuration);

    public Task RunAsync(IServiceProvider services, CancellationToken cancellationToken) =>
        services.GetRequiredService<InstallIntegrityMonitor>().RunAsync(cancellationToken);
}

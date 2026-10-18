using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using WatchLattice.Common.Modules;

namespace WatchLattice.ScriptHostAudit;

/// <summary>
/// Registers script host launch auditing with the hub. The behavior lives in
/// <see cref="ScriptHostAuditor"/>; this class only wires it up and runs it,
/// and its settings stay in the top-level "ScriptHostAudit" config section.
/// Off by default: it needs Windows process creation auditing, which is off
/// on most PCs, and it never turns that on itself.
/// </summary>
public sealed class ScriptHostAuditModule : IWatchLatticeModule
{
    public string Id => ScriptHostAuditor.ModuleId;

    public string DisplayName => "Script Host Audit";

    public string Description =>
        "Reports PowerShell, mshta, wscript, rundll32 and similar launches from Security log event 4688, when process creation auditing is already on (read-only).";

    public bool EnabledByDefault => false;

    public Type SettingsType => typeof(ScriptHostAuditOptions);

    public void ConfigureServices(IServiceCollection services, IConfiguration configuration) =>
        services.AddWatchLatticeScriptHostAudit(configuration);

    public async Task RunAsync(IServiceProvider services, CancellationToken cancellationToken)
    {
        services.GetRequiredService<ILogger<ScriptHostAuditModule>>().LogInformation("WatchLattice script host audit online.");
        await services.GetRequiredService<ScriptHostAuditor>().RunAsync(cancellationToken);
    }
}

using System.Reflection;
using WatchLattice.BrowserExtensionWatchdog;
using WatchLattice.Canary;
using WatchLattice.Decoy;
using WatchLattice.DefenderWatchdog;
using WatchLattice.FirewallWatchdog;
using WatchLattice.HostsProxyWatchdog;
using WatchLattice.Persistence;
using WatchLattice.Updater;

namespace WatchLattice.Hub;

/// <summary>
/// The tool assemblies the hub searches for modules. Adding a tool to the
/// suite means a ProjectReference in WatchLattice.Hub.csproj plus one line here.
/// </summary>
internal static class ModuleAssemblies
{
    public static readonly Assembly[] All =
    {
        typeof(DecoyModule).Assembly,
        typeof(CanaryModule).Assembly,
        typeof(DefenderWatchdogModule).Assembly,
        typeof(FirewallWatchdogModule).Assembly,
        typeof(HostsProxyWatchdogModule).Assembly,
        typeof(BrowserExtensionWatchdogModule).Assembly,
        typeof(PersistenceModule).Assembly,
        typeof(UpdaterModule).Assembly,
    };
}

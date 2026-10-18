# Adding a new tool to the suite

Every WatchLattice tool is a **module** that runs inside the hub
(`ScanAlways.Protection.Service`). The hub owns the process, logging,
configuration, and Windows-service plumbing; a module only has to describe
itself, register its services, and run until it is told to stop.

## 1. Create the project

- Add a class library under `src/` named `WatchLattice.<Tool>` (for example
  `WatchLattice.Canary`), targeting `net8.0` with nullable enabled. Use
  `src/WatchLattice.Decoy/WatchLattice.Decoy.csproj` as the template.
- Reference `WatchLattice.Common`.
- Add it to the solution: `dotnet sln add src/WatchLattice.<Tool> --solution-folder src`.

## 2. Implement the module contract

Implement `WatchLattice.Common.Modules.IWatchLatticeModule` with a public
parameterless constructor. A trimmed version of the canary module
(`src/WatchLattice.Canary/CanaryModule.cs`):

```csharp
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using WatchLattice.Common.Modules;

namespace WatchLattice.Canary;

public sealed class CanaryModule : IWatchLatticeModule
{
    public string Id => "Canary";                       // config key: Modules:Canary
    public string DisplayName => "Canary File Watcher";
    public string Description => "Plants decoy files and alerts when anything touches them.";
    public bool EnabledByDefault => true;
    public Type SettingsType => typeof(CanaryOptions);  // the dashboard's settings page

    // AddWatchLatticeCanary binds CanaryOptions from the "Canary" section and
    // registers CanaryWatcher.
    public void ConfigureServices(IServiceCollection services, IConfiguration configuration) =>
        services.AddWatchLatticeCanary(configuration);

    public Task RunAsync(IServiceProvider services, CancellationToken cancellationToken) =>
        services.GetRequiredService<CanaryWatcher>().RunAsync(cancellationToken);
}
```

What the hub guarantees, and what it expects back:

| Member | Contract |
|--------|----------|
| `Id` | Stable and unique (case-insensitive). Letters, digits, `-`, `_`, starting with a letter. Used as the config key `Modules:<Id>:Enabled`, so **never rename it once shipped**. |
| `DisplayName`, `Description` | Shown in logs and by `--list-modules`. |
| `EnabledByDefault` | Used when the config does not set `Modules:<Id>:Enabled`. Default to `true` only for modules that are safe and cheap for everyone. |
| `SettingsType` | Optional. The options class your `"<Id>"` section binds to. The dashboard builds the module's settings page from its public settable properties (`bool`, whole numbers, numbers, `string`, `string[]`/`List<string>`, enums, and nullable versions of those), shows each one's built-in default, and checks edits against it before saving. Add a `SettingsSchemaTests` like the existing modules' so the shipped `appsettings.json` keeps passing. |
| `ConfigureServices` | Called once at startup, **only if the module is enabled**. Register your services and bind your options here. Keep your settings in a top-level section named after the module (for example `"Canary": { ... }`). |
| `RunAsync` | Runs until the token is cancelled. Await rather than block. Returning early means "finished" and the module is not restarted. Throwing means "failed": the hub logs it and, if `Hub:RestartFailedModules` is on, restarts it with exponential back-off. A failing module never affects the others. |

## 3. Register it with the hub

Modules are discovered at compile time; nothing is loaded from disk at runtime.

1. Add a `ProjectReference` to your project in `src/WatchLattice.Hub/WatchLattice.Hub.csproj`.
2. Add your assembly to `src/WatchLattice.Hub/ModuleAssemblies.cs`:

   ```csharp
   public static readonly Assembly[] All =
   {
       typeof(DecoyModule).Assembly,
       typeof(CanaryModule).Assembly,
       typeof(DefenderWatchdogModule).Assembly,
       typeof(FirewallWatchdogModule).Assembly,
       typeof(HostsProxyWatchdogModule).Assembly,
       typeof(PersistenceModule).Assembly,
       typeof(UpdaterModule).Assembly,
       typeof(YourModule).Assembly,
   };
   ```

3. Add the switch and your defaults to `src/WatchLattice.Hub/appsettings.json`:

   ```json
   "Modules": {
     "Decoy":    { "Enabled": true },
     "YourTool": { "Enabled": true }
   },
   "YourTool": { }
   ```

Check it with `dotnet run --project src/WatchLattice.Hub -- --list-modules`.

## 4. Test it

For user-visible findings, accept an optional
`WatchLattice.Common.Alerts.IAlertPublisher` in the engine constructor and call
`Publish` with the module ID, stable finding code, severity, title, detail, and
optional resource identity. The hub registers the shared publisher before
configuring modules. Keep existing logs, publish only meaningful changes, and
use informational alerts for recovery. Do not send routine scan narration to
the alert feed. A module can still run independently without a publisher.

The [tray companion](alerts-and-tray.md) consumes these alerts automatically;
modules do not need to know about Windows Forms or notification APIs.

Create `tests/WatchLattice.<Tool>.Tests` (copy `tests/WatchLattice.Decoy.Tests` or `tests/WatchLattice.Canary.Tests`)
and add it with `dotnet sln add ... --solution-folder tests`. At minimum:

- `ModuleCatalog.Discover(typeof(YourModule).Assembly)` finds your module with
  the expected `Id`.
- `ConfigureServices` followed by `RunAsync` with a short cancellation timeout
  does the job and stops cleanly when cancelled.
- Your core logic has unit tests that do not need Windows, where possible.

## 5. Document it

- Ship a `README.md` in the project that states plainly what the module does,
  which concrete signal or behavior it adds, its configuration keys, and its
  **honest limits** (what it does *not* protect against).
- Add a row to the Tools table and update the Roadmap in the top-level
  [README](../README.md).

## Guardrails for every module

These are non-negotiable for the suite's "harmless, complementary" promise:

- User mode only; no kernel drivers.
- Don't modify, quarantine, or delete user files unless that is explicitly the
  module's stated job and the README says so loudly.
- Never disable, impersonate, or hook Microsoft Defender's components in a way
  that could break real protection. WatchLattice runs *alongside* Defender.
- Keep overhead modest and configurable (CPU, disk, memory). The hub runs every
  module in one process, so a greedy module slows the whole suite.
- Put code in `WatchLattice.Common` only once a second module needs it.

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using WatchLattice.Common.Modules;
using WatchLattice.Hub;

const string ListModulesSwitch = "--list-modules";
const string CheckUpdateSwitch = "--check-update";
const string ApplyUpdateSwitch = "--apply-update";
const string PauseOnFailureSwitch = "--pause-on-failure";
const string RemoveCanariesSwitch = "--remove-canaries";
const string DescribeSettingsSwitch = "--describe-settings";
const string ApplySettingsSwitch = "--apply-settings";
const string VerifyInstallSwitch = "--verify-install";
string[] commandSwitches =
{
    ListModulesSwitch, CheckUpdateSwitch, ApplyUpdateSwitch, PauseOnFailureSwitch, RemoveCanariesSwitch,
    DescribeSettingsSwitch, ApplySettingsSwitch, VerifyInstallSwitch,
};

bool HasSwitch(string name) => args.Any(a => string.Equals(a, name, StringComparison.OrdinalIgnoreCase));

var listOnly = HasSwitch(ListModulesSwitch);
var export = ExportCommand.Parse(args, out var otherArgs);
var hostArgs = otherArgs.Where(a => !commandSwitches.Contains(a, StringComparer.OrdinalIgnoreCase)).ToArray();

var catalog = ModuleCatalog.Discover(ModuleAssemblies.All);

// Always read appsettings.json from next to the binary, whether started from
// a console, `dotnet run`, or the Windows service manager.
var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
{
    Args = hostArgs,
    ContentRootPath = AppContext.BaseDirectory,
});

if (listOnly)
{
    foreach (var module in catalog.Modules)
    {
        var state = ModuleCatalog.IsEnabled(module, builder.Configuration) ? "enabled " : "disabled";
        Console.WriteLine($"{state}  {module.Id,-16} {module.DisplayName}: {module.Description}");
    }
    return 0;
}

// One-shot update commands: they never start the hub's modules.
if (HasSwitch(CheckUpdateSwitch) || HasSwitch(ApplyUpdateSwitch))
{
    return await UpdateCommand.RunAsync(builder.Configuration, apply: HasSwitch(ApplyUpdateSwitch),
        pauseOnFailure: HasSwitch(PauseOnFailureSwitch));
}

// Writes the alert history to a CSV or JSON file once; read-only.
if (export is not null)
{
    return ExportCommand.Run(export, builder.Configuration);
}

// Compares the installed files with the release's file list once and prints the result.
if (HasSwitch(VerifyInstallSwitch))
{
    return IntegrityCommand.Run(builder.Configuration);
}

// Used by the dashboard: read the settings schema, or save what its editor staged.
if (HasSwitch(DescribeSettingsSwitch))
{
    return SettingsCommand.Describe(catalog);
}
if (HasSwitch(ApplySettingsSwitch))
{
    return await SettingsCommand.ApplyAsync(catalog);
}

// Used by uninstall.ps1 once the service is stopped.
if (HasSwitch(RemoveCanariesSwitch))
{
    return CanaryCommand.Run(builder.Configuration);
}

// Let the same binary run as a Windows service or a plain console process.
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = UpdateCommand.ServiceName;
});

builder.Services.AddWatchLatticeHub(builder.Configuration, catalog);

var host = builder.Build();
host.Run();
return 0;

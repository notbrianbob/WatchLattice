using System.Reflection;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Configuration;

namespace WatchLattice.Common.Modules;

/// <summary>
/// The set of modules the hub knows about, and which of them are enabled.
///
/// Discovery is deliberately compile-time: the hub hands in the assemblies it
/// was built against and the catalog finds every <see cref="IWatchLatticeModule"/>
/// in them. Nothing is loaded from a plugins folder at runtime, so there is no
/// way to plant a DLL next to the service and have it executed — the right
/// trade-off for a security tool.
/// </summary>
public sealed partial class ModuleCatalog
{
    /// <summary>Root config section holding per-module switches.</summary>
    public const string SectionName = "Modules";

    public ModuleCatalog(IEnumerable<IWatchLatticeModule> modules)
    {
        var list = modules.ToList();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var module in list)
        {
            if (string.IsNullOrEmpty(module.Id) || !IdPattern().IsMatch(module.Id))
            {
                throw new ArgumentException(
                    $"Module {module.GetType().FullName} has invalid id '{module.Id}'. " +
                    "Use letters, digits, '-' or '_', starting with a letter.");
            }

            if (!seen.Add(module.Id))
            {
                throw new ArgumentException($"More than one module uses the id '{module.Id}'.");
            }
        }

        Modules = list.OrderBy(m => m.Id, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>Every known module, ordered by id.</summary>
    public IReadOnlyList<IWatchLatticeModule> Modules { get; }

    /// <summary>
    /// Finds and instantiates every concrete <see cref="IWatchLatticeModule"/>
    /// with a public parameterless constructor in the given assemblies.
    /// </summary>
    public static ModuleCatalog Discover(params Assembly[] assemblies)
    {
        var modules = assemblies
            .Distinct()
            .SelectMany(a => a.GetTypes())
            .Where(t => t is { IsClass: true, IsAbstract: false }
                        && typeof(IWatchLatticeModule).IsAssignableFrom(t)
                        && t.GetConstructor(Type.EmptyTypes) is not null)
            .Select(t => (IWatchLatticeModule)Activator.CreateInstance(t)!);

        return new ModuleCatalog(modules);
    }

    /// <summary>
    /// Reads <c>Modules:&lt;Id&gt;:Enabled</c>; falls back to the module's
    /// <see cref="IWatchLatticeModule.EnabledByDefault"/> when the value is
    /// missing or not a boolean.
    /// </summary>
    public static bool IsEnabled(IWatchLatticeModule module, IConfiguration configuration)
    {
        var raw = configuration[$"{SectionName}:{module.Id}:Enabled"];
        return bool.TryParse(raw, out var enabled) ? enabled : module.EnabledByDefault;
    }

    /// <summary>The modules that should run under the given configuration.</summary>
    public IReadOnlyList<IWatchLatticeModule> ResolveEnabled(IConfiguration configuration) =>
        Modules.Where(m => IsEnabled(m, configuration)).ToList();

    [GeneratedRegex(@"\A[A-Za-z][A-Za-z0-9_-]*\z")]
    private static partial Regex IdPattern();
}

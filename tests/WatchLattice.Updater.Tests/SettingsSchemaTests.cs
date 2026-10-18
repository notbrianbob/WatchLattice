using WatchLattice.Common.Modules;
using WatchLattice.Common.Settings;
using Xunit;

namespace WatchLattice.Updater.Tests;

/// <summary>The dashboard's settings editor can show and check every setting this module reads.</summary>
public sealed class SettingsSchemaTests
{
    public static TheoryData<IWatchLatticeModule, Type> Modules => new()
    {
        { new UpdaterModule(), typeof(UpdaterOptions) },
        { new InstallIntegrityModule(), typeof(InstallIntegrityOptions) },
    };

    [Theory]
    [MemberData(nameof(Modules))]
    public void EverySetting_HasAnEditor_AndTheShippedDefaultsPassValidation(IWatchLatticeModule module, Type settingsType)
    {
        Assert.Equal(settingsType, module.SettingsType);
        var catalog = new ModuleCatalog(new IWatchLatticeModule[] { module });
        var section = SettingsSchema.Build(catalog).Single(s => s.Path == module.Id);
        Assert.DoesNotContain(section.Fields, f => f.Kind == SettingKind.Unsupported);

        var shipped = SettingValues.Parse(File.ReadAllText(ShippedSettings()));
        var check = SettingsValidator.Check(SettingsSchema.Build(catalog), shipped, shipped);
        Assert.Empty(check.Errors);
        Assert.DoesNotContain(check.Warnings, w => w.StartsWith(module.Id + ":", StringComparison.Ordinal));
        Assert.Empty(SettingsValidator.CheckBinding(SettingsSchema.BindableSections(catalog), shipped));
    }

    private static string ShippedSettings()
    {
        var folder = new DirectoryInfo(AppContext.BaseDirectory);
        while (folder is not null && !File.Exists(Path.Combine(folder.FullName, "WatchLattice.sln"))) folder = folder.Parent;
        return Path.Combine(folder?.FullName ?? throw new InvalidOperationException("Run the tests from the repository."),
            "src", "WatchLattice.Hub", "appsettings.json");
    }
}

using System.Text.Json.Nodes;
using WatchLattice.Common.Modules;
using WatchLattice.Common.Settings;
using Xunit;

namespace WatchLattice.Common.Tests;

public enum SampleMode { Quiet, Loud }

public sealed class SampleOptions
{
    public bool Flag { get; set; } = true;
    public int Count { get; set; } = 3;
    public long Big { get; set; } = 5_000_000_000;
    public double Ratio { get; set; } = 1.5;
    public string Name { get; set; } = "sample";
    public string? OptionalPath { get; set; }
    public List<string> Folders { get; set; } = new() { "a" };
    public string[] Ignored { get; set; } = Array.Empty<string>();
    public SampleMode Mode { get; set; } = SampleMode.Loud;
    public int? Seed { get; set; }
    public TimeSpan Unusual { get; set; }
    public int ReadOnly => 1;
}

public sealed class SettingsModule : FakeModule, IWatchLatticeModule
{
    public SettingsModule() : base("Sample")
    {
    }

    public Type SettingsType => typeof(SampleOptions);
}

public sealed class SettingsSchemaTests
{
    [Fact]
    public void Fields_FollowThePropertyTypes_AndKeepDeclarationOrder()
    {
        var fields = SettingsSchema.Fields("Sample", typeof(SampleOptions)).ToDictionary(f => f.Path[7..]);

        Assert.Equal(new[] { "Flag", "Count", "Big", "Ratio", "Name", "OptionalPath", "Folders", "Ignored", "Mode", "Seed", "Unusual" },
            fields.Keys);
        Assert.Equal(SettingKind.Boolean, fields["Flag"].Kind);
        Assert.Equal(SettingKind.Integer, fields["Count"].Kind);
        Assert.Equal(SettingKind.Integer, fields["Big"].Kind);
        Assert.Equal(SettingKind.Number, fields["Ratio"].Kind);
        Assert.Equal(SettingKind.Text, fields["Name"].Kind);
        Assert.False(fields["Name"].Nullable);
        Assert.True(fields["OptionalPath"].Nullable);
        Assert.Equal(SettingKind.TextList, fields["Folders"].Kind);
        Assert.Equal(SettingKind.TextList, fields["Ignored"].Kind);
        Assert.Equal(new[] { "Quiet", "Loud" }, fields["Mode"].Choices);
        Assert.Equal(SettingKind.Integer, fields["Seed"].Kind);
        Assert.True(fields["Seed"].Nullable);
        Assert.Equal(SettingKind.Unsupported, fields["Unusual"].Kind);
    }

    [Fact]
    public void Fields_CarryTheBuiltInDefaults()
    {
        var fields = SettingsSchema.Fields("Sample", typeof(SampleOptions)).ToDictionary(f => f.Path[7..]);

        Assert.Equal("true", fields["Flag"].Default!.ToJsonString());
        Assert.Equal("5000000000", fields["Big"].Default!.ToJsonString());
        Assert.Equal("1.5", fields["Ratio"].Default!.ToJsonString());
        Assert.Equal("\"Loud\"", fields["Mode"].Default!.ToJsonString());
        Assert.Equal("[\"a\"]", fields["Folders"].Default!.ToJsonString());
        Assert.Null(fields["OptionalPath"].Default);
    }

    [Fact]
    public void Build_ListsModuleSwitches_HubSections_AndEachModulesSettings()
    {
        var catalog = new ModuleCatalog(new IWatchLatticeModule[] { new SettingsModule(), new FakeModule("Plain", enabledByDefault: false) });

        var sections = SettingsSchema.Build(catalog);

        Assert.Equal(new[] { "Modules", "Hub", "Alerts", "Alerts:EventLog", "Alerts:DailySummary", "Sample" }, sections.Select(s => s.Path));
        var switches = sections[0].Fields;
        Assert.Equal(new[] { "Modules:Plain:Enabled", "Modules:Sample:Enabled" }, switches.Select(f => f.Path));
        Assert.Equal("false", switches[0].Default!.ToJsonString());
        Assert.Equal("Sample", sections[^1].ModuleId);
        Assert.Contains(SettingsSchema.BindableSections(catalog), s => s.Path == "Sample" && s.Type == typeof(SampleOptions));
    }

    [Fact]
    public void UpdateSourceAndFeedPath_AreLocked()
    {
        var alerts = SettingsSchema.Fields("Alerts", typeof(Alerts.AlertDeliveryOptions));
        Assert.True(alerts.Single(f => f.Path == "Alerts:FeedPath").Locked);
        Assert.False(alerts.Single(f => f.Path == "Alerts:HistoryLimit").Locked);
        Assert.True(SettingsSchema.LockedSettings.ContainsKey("Updater:Repository"));
    }

    [Theory]
    [InlineData("CheckIntervalSeconds", "Check interval seconds")]
    [InlineData("MaxFileSizeBytes", "Max file size bytes")]
    [InlineData("Enabled", "Enabled")]
    [InlineData("ASRRules", "ASR rules")]
    public void Humanize_SplitsWords(string name, string expected) => Assert.Equal(expected, SettingsSchema.Humanize(name));

    [Fact]
    public void Describe_IncludesTheFileAsIs()
    {
        var catalog = new ModuleCatalog(new IWatchLatticeModule[] { new SettingsModule() });
        var values = SettingValues.Parse("{ \"Sample\": { \"Count\": 9, \"Extra\": true } }");

        var description = SettingsSchema.Describe(catalog, "C:\\hub\\appsettings.json", values);

        Assert.Equal(SettingsDescription.CurrentVersion, description.Version);
        Assert.Equal("Sample module", Assert.Single(description.Modules).DisplayName);
        Assert.Equal(9, description.Values["Sample"]!["Count"]!.GetValue<int>());
    }

    [Fact]
    public void Description_SurvivesTheTripFromHubToTray()
    {
        // The hub prints this with AtomicJsonFile.JsonOptions; the tray reads it back the same way.
        var catalog = new ModuleCatalog(new IWatchLatticeModule[] { new SettingsModule() });
        var sent = SettingsSchema.Describe(catalog, "appsettings.json", SettingValues.Parse("{ \"Sample\": { \"Mode\": \"Quiet\" } }"));

        var json = System.Text.Json.JsonSerializer.Serialize(sent, AtomicJsonFile.JsonOptions);
        var received = System.Text.Json.JsonSerializer.Deserialize<SettingsDescription>(json, AtomicJsonFile.JsonOptions)!;

        Assert.Equal(sent.Sections.Select(s => s.Path), received.Sections.Select(s => s.Path));
        var sentFields = sent.Sections.SelectMany(s => s.Fields).ToArray();
        var receivedFields = received.Sections.SelectMany(s => s.Fields).ToArray();
        Assert.Equal(sentFields.Select(f => (f.Path, f.Kind, f.Nullable, f.Locked, f.Default?.ToJsonString())),
            receivedFields.Select(f => (f.Path, f.Kind, f.Nullable, f.Locked, f.Default?.ToJsonString())));
        Assert.Equal(new[] { "Quiet", "Loud" }, receivedFields.Single(f => f.Path == "Sample:Mode").Choices);
        Assert.True(SettingsValidator.Check(received.Sections, received.Values, received.Values).IsValid);
    }
}

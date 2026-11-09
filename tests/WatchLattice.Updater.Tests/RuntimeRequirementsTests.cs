using Xunit;

namespace WatchLattice.Updater.Tests;

public class RuntimeRequirementsTests
{
    private const string FrameworkDependentTray = """
        { "runtimeOptions": { "tfm": "net10.0", "frameworks": [
            { "name": "Microsoft.NETCore.App", "version": "10.0.0" },
            { "name": "Microsoft.WindowsDesktop.App", "version": "10.0.0" } ] } }
        """;
    private const string FrameworkDependentHub = """
        { "runtimeOptions": { "tfm": "net10.0", "framework": { "name": "Microsoft.NETCore.App", "version": "10.0.0" } } }
        """;
    private const string SelfContained = """
        { "runtimeOptions": { "tfm": "net10.0", "includedFrameworks": [
            { "name": "Microsoft.NETCore.App", "version": "10.0.1" } ] } }
        """;

    private static readonly ReleaseVersion Current = ReleaseVersion.Parse("0.1.0");
    private const string PackageName = "WatchLattice-0.2.0-win-x64.zip";

    [Fact]
    public void Read_ListsEveryFrameworkOfAFrameworkDependentApp()
    {
        using var temp = new TempDirectory();
        temp.Write("tray.runtimeconfig.json", FrameworkDependentTray);
        temp.Write("hub.runtimeconfig.json", FrameworkDependentHub);

        var tray = RuntimeRequirements.Read(temp.Combine("tray.runtimeconfig.json"));
        var hub = RuntimeRequirements.Read(temp.Combine("hub.runtimeconfig.json"));

        Assert.Equal(new[] { "Microsoft.NETCore.App", "Microsoft.WindowsDesktop.App" }, tray.Select(r => r.Name));
        Assert.All(tray, r => Assert.Equal(new Version(10, 0, 0), r.Version));
        Assert.Equal("Microsoft.NETCore.App", Assert.Single(hub).Name);
    }

    [Fact]
    public void Read_NeedsNothing_ForASelfContainedAppOrAMissingFile()
    {
        using var temp = new TempDirectory();
        temp.Write("app.runtimeconfig.json", SelfContained);

        Assert.Empty(RuntimeRequirements.Read(temp.Combine("app.runtimeconfig.json")));
        Assert.Empty(RuntimeRequirements.Read(temp.Combine("missing.runtimeconfig.json")));
    }

    [Fact]
    public void Read_RejectsAnUnreadableFile()
    {
        using var temp = new TempDirectory();
        temp.Write("bad.runtimeconfig.json", "{ not json");
        temp.Write("empty.runtimeconfig.json", "{ }");

        Assert.Throws<InvalidDataException>(() => RuntimeRequirements.Read(temp.Combine("bad.runtimeconfig.json")));
        Assert.Throws<InvalidDataException>(() => RuntimeRequirements.Read(temp.Combine("empty.runtimeconfig.json")));
    }

    [Theory]
    [InlineData("Minor", "10.0.0", "10.0.5", true)]
    [InlineData("Minor", "10.0.0", "10.2.0", true)]
    [InlineData("Minor", "10.0.0", "11.0.0", false)]
    [InlineData("Minor", "10.0.0", "8.0.21", false)]
    [InlineData("LatestPatch", "10.0.0", "10.1.0", false)]
    [InlineData("Major", "8.0.0", "10.0.0", true)]
    [InlineData("Disable", "10.0.1", "10.0.2", false)]
    public void IsSatisfiedBy_FollowsTheRollForwardPolicy(string rollForward, string required, string installed, bool expected)
    {
        var requirement = new FrameworkRequirement("Microsoft.NETCore.App", Version.Parse(required), rollForward);

        Assert.Equal(expected, requirement.IsSatisfiedBy(Version.Parse(installed)));
    }

    [Fact]
    public void FindMissing_NamesEachMissingFrameworkOnce()
    {
        var needs = new[]
        {
            new FrameworkRequirement("Microsoft.NETCore.App", new Version(10, 0, 0), "Minor"),
            new FrameworkRequirement("Microsoft.WindowsDesktop.App", new Version(10, 0, 0), "Minor"),
            new FrameworkRequirement("Microsoft.NETCore.App", new Version(10, 0, 0), "Minor"),
        };

        var missing = RuntimeRequirements.FindMissing(needs, _ => new[] { new Version(8, 0, 21) });

        Assert.Equal(2, missing.Count);
        var text = RuntimeRequirements.Describe(missing);
        Assert.Contains("winget install Microsoft.DotNet.DesktopRuntime.10", text);
        Assert.Contains("dotnet/10.0", text);
    }

    [Fact]
    public async Task Apply_ChangesNothing_WhenTheReleaseNeedsARuntimeThatIsNotInstalled()
    {
        using var setup = new ApplySetup(new Dictionary<string, string>
        {
            ["Hub/ScanAlways.Protection.Service.runtimeconfig.json"] = FrameworkDependentHub,
            ["Tray/ScanAlways.Tray.runtimeconfig.json"] = FrameworkDependentTray,
        });

        var outcome = await setup.RunAsync(_ => new[] { new Version(8, 0, 21) });

        Assert.Equal(UpdateOutcome.NotAvailable, outcome);
        Assert.Equal("hub old", setup.Read("Hub", "ScanAlways.Protection.Service.exe"));
        Assert.Equal("tray old", setup.Read("Tray", "ScanAlways.Tray.exe"));
        Assert.Empty(setup.Service.Calls);
        Assert.Contains(setup.Log, line => line.Contains("Microsoft.WindowsDesktop.App 10.0") && line.Contains("Nothing was changed"));
        Assert.Empty(Directory.GetDirectories(setup.HubDir, UpdateApplier.StagingPrefix + "*"));
    }

    [Fact]
    public async Task Apply_Installs_WhenTheRuntimeIsInstalled()
    {
        using var setup = new ApplySetup(new Dictionary<string, string>
        {
            ["Hub/ScanAlways.Protection.Service.runtimeconfig.json"] = FrameworkDependentHub,
            ["Tray/ScanAlways.Tray.runtimeconfig.json"] = FrameworkDependentTray,
        });

        Assert.Equal(UpdateOutcome.Installed, await setup.RunAsync(_ => new[] { new Version(10, 0, 3) }));
        Assert.Equal("hub v0.2.0", setup.Read("Hub", "ScanAlways.Protection.Service.exe"));
    }

    [Fact]
    public async Task Apply_Installs_ASelfContainedReleaseWithNoRuntimeInstalled()
    {
        using var setup = new ApplySetup(new Dictionary<string, string>
        {
            ["Hub/ScanAlways.Protection.Service.runtimeconfig.json"] = SelfContained,
            ["Tray/ScanAlways.Tray.runtimeconfig.json"] = SelfContained,
        });

        Assert.Equal(UpdateOutcome.Installed, await setup.RunAsync(_ => Array.Empty<Version>()));
        Assert.Equal("tray v0.2.0", setup.Read("Tray", "ScanAlways.Tray.exe"));
    }

    private sealed class ApplySetup : IDisposable
    {
        public TempDirectory Temp { get; } = new();
        public FakeHttpHandler Http { get; } = new();
        public FakeReleaseSource Source { get; } = new();
        public FakeServiceControl Service { get; } = new() { Running = true };
        public List<string> Log { get; } = new();

        public ApplySetup(IDictionary<string, string> extra)
        {
            var package = Releases.Package("v0.2.0", extra);
            Source.Next = () => Releases.Make("0.2.0");
            Http.Add(Releases.DownloadUrl("0.2.0", PackageName), package);
            Http.Add(Releases.DownloadUrl("0.2.0", "SHA256SUMS.txt"), $"{Releases.Sha256(package)}  {PackageName}\n");
            Temp.Write("Hub/ScanAlways.Protection.Service.exe", "hub old");
            Temp.Write("Hub/appsettings.json", "my settings");
            Temp.Write("Tray/ScanAlways.Tray.exe", "tray old");
        }

        public string HubDir => Temp.Combine("Hub");

        public Task<UpdateOutcome> RunAsync(Func<string, IReadOnlyList<Version>> installed) =>
            new UpdateApplier(Source, new HttpClient(Http), new UpdaterOptions(), Service, Log.Add, installedFrameworks: installed)
                .ApplyAsync(Current, HubDir, Temp.Combine("Tray"), default);

        public string Read(params string[] parts) => File.ReadAllText(Temp.Combine(parts));

        public void Dispose() => Temp.Dispose();
    }
}

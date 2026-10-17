using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using WatchLattice.Common.Alerts;
using WatchLattice.Common.Modules;
using Xunit;

namespace WatchLattice.Updater.Tests;

public class UpdateMonitorTests
{
    private sealed class Recorder : IAlertPublisher, IUpdateStatusPublisher
    {
        public List<(string Code, AlertSeverity Severity, string Title)> Alerts { get; } = new();
        public List<UpdateNotice?> Notices { get; } = new();

        public void Publish(string module, string code, AlertSeverity severity, string title, string message, string? resource = null) =>
            Alerts.Add((code, severity, title));

        public void SetUpdate(UpdateNotice? notice) => Notices.Add(notice);
    }

    private static UpdateMonitor Create(FakeReleaseSource source, Recorder recorder, string current = "0.1.0", UpdaterOptions? options = null) =>
        new(source, Options.Create(options ?? new UpdaterOptions()), NullLogger<UpdateMonitor>.Instance,
            ReleaseVersion.Parse(current), recorder, recorder);

    [Fact]
    public async Task Check_PublishesTheNotice_AndOneInformationalAlertPerVersion()
    {
        var source = new FakeReleaseSource { Next = () => Releases.Make("0.2.0") };
        var recorder = new Recorder();
        var monitor = Create(source, recorder);

        await monitor.CheckOnceAsync(default);
        await monitor.CheckOnceAsync(default);

        var alert = Assert.Single(recorder.Alerts);
        Assert.Equal(UpdateMonitor.UpdateAvailableCode, alert.Code);
        Assert.Equal(AlertSeverity.Info, alert.Severity);
        Assert.Contains("0.2.0", alert.Title);
        var notice = recorder.Notices[^1]!;
        Assert.Equal("0.1.0", notice.CurrentVersion);
        Assert.Equal("0.2.0", notice.LatestVersion);
        Assert.True(notice.Installable);
        Assert.True(notice.TryGetReleasePage(out _));

        source.Next = () => Releases.Make("0.3.0");
        await monitor.CheckOnceAsync(default);
        Assert.Equal(2, recorder.Alerts.Count);
    }

    [Fact]
    public async Task Check_ClearsTheNotice_WhenUpToDate()
    {
        var source = new FakeReleaseSource { Next = () => Releases.Make("0.1.0") };
        var recorder = new Recorder();

        Assert.Null(await Create(source, recorder).CheckOnceAsync(default));

        Assert.Null(Assert.Single(recorder.Notices));
        Assert.Empty(recorder.Alerts);
    }

    [Fact]
    public async Task Check_KeepsTheLastResult_WhenOffline()
    {
        var calls = 0;
        var source = new FakeReleaseSource
        {
            Next = () => ++calls == 1 ? Releases.Make("0.2.0") : throw new HttpRequestException("offline"),
        };
        var recorder = new Recorder();
        var monitor = Create(source, recorder);

        await monitor.CheckOnceAsync(default);
        var kept = await monitor.CheckOnceAsync(default);

        Assert.Equal(ReleaseVersion.Parse("0.2.0"), kept!.Version);
        Assert.Single(recorder.Notices);
        Assert.Single(recorder.Alerts);
    }

    [Fact]
    public async Task Check_MarksUnverifiableReleasesAsNotInstallable()
    {
        var source = new FakeReleaseSource { Next = () => Releases.Make("0.2.0", checksums: false) };
        var recorder = new Recorder();

        await Create(source, recorder).CheckOnceAsync(default);

        Assert.False(recorder.Notices[^1]!.Installable);
        Assert.NotNull(recorder.Notices[^1]!.Problem);
    }

    [Fact]
    public async Task Run_MakesNoRequests_ForDevelopmentBuilds()
    {
        var source = new FakeReleaseSource { Next = () => Releases.Make("0.2.0") };
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));

        await Create(source, new Recorder(), "0.0.0-dev").RunAsync(cancel.Token);

        Assert.Equal(0, source.Calls);
    }

    [Fact]
    public async Task Run_ChecksOnStart_AndStopsCleanly()
    {
        var source = new FakeReleaseSource { Next = () => Releases.Make("0.2.0") };
        var recorder = new Recorder();
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));

        await Create(source, recorder, options: new UpdaterOptions { InitialDelaySeconds = 0 }).RunAsync(cancel.Token);

        Assert.Equal(1, source.Calls);
        Assert.Single(recorder.Alerts);
    }

    [Fact]
    public async Task Run_RetriesSoonAfterAFailedCheck_ThenReturnsToTheInterval()
    {
        // Offline for the first four checks (a hub that starts before the network), then online.
        var calls = 0;
        var source = new FakeReleaseSource
        {
            Next = () => ++calls <= 4 ? throw new HttpRequestException("offline") : Releases.Make("0.2.0"),
        };
        var recorder = new Recorder();
        var waits = new List<TimeSpan>();
        using var cancel = new CancellationTokenSource();
        var monitor = new UpdateMonitor(source, Options.Create(new UpdaterOptions { InitialDelaySeconds = 30, CheckIntervalHours = 1 }),
            NullLogger<UpdateMonitor>.Instance, ReleaseVersion.Parse("0.1.0"), recorder, recorder,
            delay: (wait, _) =>
            {
                waits.Add(wait);
                if (waits.Count == 8) cancel.Cancel();
                return cancel.IsCancellationRequested ? Task.FromCanceled(cancel.Token) : Task.CompletedTask;
            });

        await monitor.RunAsync(cancel.Token);

        Assert.Equal(new[] { 30.0, 60, 120, 240, 480, 3600, 3600, 3600 }, waits.Select(w => w.TotalSeconds));
        Assert.Single(recorder.Alerts);
        Assert.False(monitor.LastCheckFailed);
    }

    [Fact]
    public async Task Run_CapsTheRetryDelayAtTheCheckInterval()
    {
        var source = new FakeReleaseSource { Next = () => throw new HttpRequestException("offline") };
        var waits = new List<TimeSpan>();
        using var cancel = new CancellationTokenSource();
        var monitor = new UpdateMonitor(source, Options.Create(new UpdaterOptions { InitialDelaySeconds = 0, CheckIntervalHours = 1 }),
            NullLogger<UpdateMonitor>.Instance, ReleaseVersion.Parse("0.1.0"),
            delay: (wait, _) =>
            {
                waits.Add(wait);
                if (waits.Count == 10) cancel.Cancel();
                return cancel.IsCancellationRequested ? Task.FromCanceled(cancel.Token) : Task.CompletedTask;
            });

        await monitor.RunAsync(cancel.Token);

        Assert.Equal(new[] { 0.0, 1, 2, 4, 8, 16, 32, 60, 60, 60 }, waits.Select(w => w.TotalMinutes));
        Assert.True(monitor.LastCheckFailed);
    }

    [Fact]
    public void Module_IsDiscovered_AndBindsItsOptions()
    {
        var module = Assert.Single(ModuleCatalog.Discover(typeof(UpdaterModule).Assembly).Modules);
        Assert.Equal("Updater", module.Id);
        Assert.True(module.EnabledByDefault);

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Updater:CheckIntervalHours"] = "24" })
            .Build();
        var services = new ServiceCollection().AddLogging();
        module.ConfigureServices(services, configuration);
        using var provider = services.BuildServiceProvider();

        Assert.Equal(ReleaseVersion.FromAssembly(typeof(UpdaterModule).Assembly),
            provider.GetRequiredService<UpdateMonitor>().Current);
        Assert.Equal(24, provider.GetRequiredService<IOptions<UpdaterOptions>>().Value.CheckIntervalHours);
    }
}

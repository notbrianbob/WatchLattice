using System.Text.RegularExpressions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using WatchLattice.Common.Alerts;
using WatchLattice.Common.Modules;
using Xunit;

namespace WatchLattice.Common.Tests;

public sealed class EventLogAlertTests
{
    private sealed class FakeWriter : IEventLogWriter
    {
        public bool IsSupported { get; set; } = true;
        public string? Problem { get; set; }
        public bool Fail { get; set; }
        public ManualResetEventSlim Open { get; } = new(true);
        public List<(int Id, EventLogLevel Level, IReadOnlyList<string> Data)> Entries { get; } = new();

        public string? Prepare() => Problem;

        public void Write(int eventId, EventLogLevel level, IReadOnlyList<string> data)
        {
            Open.Wait();
            if (Fail) throw new InvalidOperationException("log is full");
            lock (Entries) Entries.Add((eventId, level, data));
        }

        public int Count { get { lock (Entries) return Entries.Count; } }

        public (int Id, EventLogLevel Level, IReadOnlyList<string> Data)[] Snapshot() { lock (Entries) return Entries.ToArray(); }
    }

    private sealed class Rig
    {
        public required AlertHub Hub { get; init; }
        public required EventLogAlertService Service { get; init; }
        public required FakeWriter Writer { get; init; }
    }

    private static Rig Build(FakeWriter writer, EventLogAlertOptions? options = null)
    {
        var services = new ServiceCollection();
        services.AddSingleton<IOptions<AlertDeliveryOptions>>(Options.Create(new AlertDeliveryOptions()));
        services.AddSingleton<IEventLogWriter>(writer);
        services.AddSingleton<IOptions<EventLogAlertOptions>>(Options.Create(options ?? new EventLogAlertOptions()));
        services.AddSingleton(typeof(Microsoft.Extensions.Logging.ILogger<>), typeof(NullLogger<>));
        services.AddSingleton<EventLogAlertService>();
        services.AddSingleton<IAlertSink>(sp => sp.GetRequiredService<EventLogAlertService>());
        services.AddSingleton<AlertHub>();
        services.AddSingleton<IAlertPublisher>(sp => sp.GetRequiredService<AlertHub>());
        var provider = services.BuildServiceProvider();
        return new Rig
        {
            Hub = provider.GetRequiredService<AlertHub>(),
            Service = provider.GetRequiredService<EventLogAlertService>(),
            Writer = writer,
        };
    }

    private static async Task WaitFor(Func<bool> condition)
    {
        for (var i = 0; i < 200 && !condition(); i++) await Task.Delay(25);
        Assert.True(condition());
    }

    [Theory]
    [InlineData("Canary", "CANARY_MODIFIED", 2001)]
    [InlineData("DefenderWatchdog", "REALTIME_OFF", 3006)]
    [InlineData("DefenderWatchdog", "REALTIME_OFF_CLEARED", 3506)]
    [InlineData("defenderwatchdog", "REALTIME_OFF", 3006)]
    [InlineData("DefenderWatchdog", @"BROAD_EXCLUSION:Path:C:\", 3024)]
    [InlineData("DefenderWatchdog", @"BROAD_EXCLUSION:Path:C:\_CLEARED", 3524)]
    [InlineData("FirewallWatchdog", "PROFILE_DISABLED_PUBLIC", 4004)]
    [InlineData("FirewallWatchdog", "PROFILE_DISABLED_PUBLIC_CLEARED", 4504)]
    [InlineData("Persistence", "ENTRY_ADDED", 5002)]
    [InlineData("Updater", "UPDATE_AVAILABLE", 6001)]
    [InlineData("Canary", "MODULE_FAILED", 1001)]
    [InlineData("Persistence", "MODULE_FINISHED", 1002)]
    public void KnownCodes_HaveTheirDocumentedIds(string module, string code, int expected)
    {
        Assert.Equal(expected, AlertEventIds.For(module, code, AlertSeverity.Warning));
        Assert.True(AlertEventIds.IsClassified(module, code));
    }

    [Theory]
    [InlineData("Canary", "SOMETHING_NEW", AlertSeverity.Info, 2900)]
    [InlineData("Canary", "SOMETHING_NEW", AlertSeverity.Warning, 2901)]
    [InlineData("Canary", "SOMETHING_NEW", AlertSeverity.Critical, 2902)]
    [InlineData("Canary", "SOMETHING_NEW_CLEARED", AlertSeverity.Info, 2900)]
    [InlineData("DefenderWatchdog", "BROAD_EXCLUSION:", AlertSeverity.Warning, 3901)]
    [InlineData("SomeFutureModule", "ANYTHING", AlertSeverity.Critical, 9902)]
    [InlineData("", "", AlertSeverity.Info, 9900)]
    public void UnknownCodes_FallBackToAnUnclassifiedIdBySeverity(string module, string code, AlertSeverity severity, int expected)
    {
        Assert.Equal(expected, AlertEventIds.For(module, code, severity));
        Assert.False(AlertEventIds.IsClassified(module, code));
    }

    [Fact]
    public void ClassifiedIds_AreUnique_AndLeaveRoomForRecoveryAndFallbackIds()
    {
        var ids = AlertEventIds.Classified.Select(c => c.Id).Append(AlertEventIds.AlertsDropped).ToArray();
        Assert.Equal(ids.Length, ids.Distinct().Count());
        Assert.All(ids, id => Assert.InRange(id % 1000, 1, AlertEventIds.ClearedOffset - 1));
        Assert.All(ids, id => Assert.Contains(id / 1000 * 1000, AlertEventIds.Bases.Values));
    }

    [Fact]
    public void EveryClassifiedId_IsDocumented()
    {
        var doc = File.ReadAllText(Path.Join(RepoRoot(), "docs", "event-log.md"));
        foreach (var (module, code, id) in AlertEventIds.Classified)
        {
            Assert.Matches(new Regex($@"^\| {id} \| `{Regex.Escape(code)}` \|", RegexOptions.Multiline), doc);
        }
        Assert.Matches(new Regex($@"^\| {AlertEventIds.AlertsDropped} \|", RegexOptions.Multiline), doc);
        Assert.Contains($"`{EventLogAlertService.SourceName}`", doc);
    }

    [Theory]
    [InlineData(AlertSeverity.Info, EventLogLevel.Information)]
    [InlineData(AlertSeverity.Warning, EventLogLevel.Warning)]
    [InlineData(AlertSeverity.Critical, EventLogLevel.Error)]
    public void Severity_MapsToEntryType(AlertSeverity severity, EventLogLevel level) =>
        Assert.Equal(level, EventLogAlertService.LevelOf(severity));

    [Fact]
    public void Data_HasReadableTextFirst_ThenFieldsInFixedOrder_AndStripsControlCharacters()
    {
        var alert = new ProtectionAlert(Guid.NewGuid(), new DateTimeOffset(2026, 10, 17, 1, 2, 3, TimeSpan.Zero), "Canary",
            "CANARY_RENAMED", AlertSeverity.Critical, "Canary tripped", "Renamed\u0007 to x.locked", @"C:\Users\me\Documents\a.docx");
        var data = EventLogAlertService.DataOf(alert);

        Assert.Equal(10, data.Count);
        Assert.StartsWith("Canary tripped\r\n\r\nRenamed  to x.locked", data[0]);
        Assert.Contains(@"Resource: C:\Users\me\Documents\a.docx", data[0]);
        Assert.Contains("Alert code: CANARY_RENAMED", data[0]);
        Assert.Contains("MITRE ATT&CK: T1486 Data Encrypted for Impact (related)", data[0]);
        Assert.Equal(new[] { "Canary", "CANARY_RENAMED", "Critical", "Canary tripped", "Renamed  to x.locked",
            @"C:\Users\me\Documents\a.docx", alert.Id.ToString(), "2026-10-17T01:02:03.0000000Z", "T1486" }, data.Skip(1));
        Assert.DoesNotContain("Resource:", EventLogAlertService.DataOf(alert with { Resource = null })[0]);
    }

    [Fact]
    public void Data_LeavesTheAttackFieldsOut_ForAnUnmappedAlert()
    {
        var alert = new ProtectionAlert(Guid.NewGuid(), DateTimeOffset.UnixEpoch, "Hub", "DAILY_SUMMARY", AlertSeverity.Info, "Daily summary", "All quiet");
        var data = EventLogAlertService.DataOf(alert);

        Assert.Equal(10, data.Count);
        Assert.DoesNotContain("MITRE ATT&CK", data[0]);
        Assert.Equal("", data[9]);
    }

    [Fact]
    public async Task PublishedAlerts_AreWrittenOnce_WithTheirIdAndLevel_AndRestoredHistoryIsNotReplayed()
    {
        var rig = Build(new FakeWriter());
        rig.Hub.RestoreHistory(new[] { new ProtectionAlert(Guid.NewGuid(), DateTimeOffset.UtcNow.AddDays(-1), "Canary",
            "CANARY_DELETED", AlertSeverity.Critical, "old", "old") });
        await rig.Service.StartAsync(CancellationToken.None);

        rig.Hub.Publish("DefenderWatchdog", "REALTIME_OFF", AlertSeverity.Critical, "Defender needs attention", "Real-time protection is OFF.");
        rig.Hub.Publish("DefenderWatchdog", "REALTIME_OFF", AlertSeverity.Critical, "Defender needs attention", "Real-time protection is OFF.");
        rig.Hub.Publish("DefenderWatchdog", "REALTIME_OFF_CLEARED", AlertSeverity.Info, "Defender recovered", "back on");
        await WaitFor(() => rig.Writer.Count == 2);
        await rig.Service.StopAsync(CancellationToken.None);

        Assert.Equal(new[] { (3006, EventLogLevel.Error), (3506, EventLogLevel.Information) },
            rig.Writer.Entries.Select(e => (e.Id, e.Level)));
        Assert.Equal("Real-time protection is OFF.", rig.Writer.Entries[0].Data[5]);
    }

    [Fact]
    public async Task MinimumSeverity_AndDisabled_KeepAlertsOutOfTheLog()
    {
        var filtered = Build(new FakeWriter(), new EventLogAlertOptions { MinimumSeverity = AlertSeverity.Warning });
        await filtered.Service.StartAsync(CancellationToken.None);
        filtered.Hub.Publish("Persistence", "BASELINE_CREATED", AlertSeverity.Info, "t", "m");
        filtered.Hub.Publish("Persistence", "ENTRY_ADDED", AlertSeverity.Warning, "t", "m");
        await WaitFor(() => filtered.Writer.Count == 1);
        await filtered.Service.StopAsync(CancellationToken.None);
        Assert.Equal(5002, Assert.Single(filtered.Writer.Entries).Id);

        var disabled = Build(new FakeWriter(), new EventLogAlertOptions { Enabled = false });
        await disabled.Service.StartAsync(CancellationToken.None);
        disabled.Hub.Publish("Persistence", "ENTRY_ADDED", AlertSeverity.Warning, "t", "m");
        await disabled.Service.StopAsync(CancellationToken.None);
        Assert.Empty(disabled.Writer.Entries);
        Assert.DoesNotContain(disabled.Hub.Snapshot().Alerts, a => a.Module == "Hub");
    }

    [Fact]
    public async Task UnregisteredSource_IsReportedOnceToTheTray_AndNothingIsWritten()
    {
        var rig = Build(new FakeWriter { Problem = "registering it needs administrator rights" });
        await rig.Service.StartAsync(CancellationToken.None);
        await WaitFor(() => rig.Hub.Snapshot().Alerts.Any(a => a.Code == "EVENTLOG_UNAVAILABLE"));
        rig.Hub.Publish("Canary", "CANARY_MODIFIED", AlertSeverity.Critical, "t", "m");
        await rig.Service.StopAsync(CancellationToken.None);

        Assert.Empty(rig.Writer.Entries);
        var notice = Assert.Single(rig.Hub.Snapshot().Alerts, a => a.Module == "Hub");
        Assert.Equal(AlertSeverity.Warning, notice.Severity);
        Assert.Contains("administrator", notice.Message);
    }

    [Fact]
    public async Task UnsupportedPlatform_IsQuiet()
    {
        var rig = Build(new FakeWriter { IsSupported = false });
        await rig.Service.StartAsync(CancellationToken.None);
        rig.Hub.Publish("Canary", "CANARY_MODIFIED", AlertSeverity.Critical, "t", "m");
        await rig.Service.StopAsync(CancellationToken.None);
        Assert.Empty(rig.Writer.Entries);
        Assert.DoesNotContain(rig.Hub.Snapshot().Alerts, a => a.Module == "Hub");
    }

    [Fact]
    public async Task WriteFailures_AreReportedOnce_AndWritingResumesAfterwards()
    {
        var rig = Build(new FakeWriter { Fail = true });
        await rig.Service.StartAsync(CancellationToken.None);
        rig.Hub.Publish("Canary", "CANARY_MODIFIED", AlertSeverity.Critical, "t", "one");
        rig.Hub.Publish("Canary", "CANARY_MODIFIED", AlertSeverity.Critical, "t", "two");
        await WaitFor(() => rig.Hub.Snapshot().Alerts.Count(a => a.Code == "EVENTLOG_WRITE_FAILED") == 1);

        rig.Writer.Fail = false;
        rig.Hub.Publish("Canary", "CANARY_DELETED", AlertSeverity.Critical, "t", "three");
        await WaitFor(() => rig.Writer.Snapshot().Any(e => e.Id == 2002));
        await rig.Service.StopAsync(CancellationToken.None);
        Assert.Single(rig.Hub.Snapshot().Alerts, a => a.Code == "EVENTLOG_WRITE_FAILED");
    }

    [Fact]
    public async Task Flood_KeepsTheEarliestAlerts_AndRecordsHowManyWereSkipped()
    {
        var writer = new FakeWriter();
        var rig = Build(writer);
        writer.Open.Reset(); // hold the writer so the queue fills
        await rig.Service.StartAsync(CancellationToken.None);

        var total = EventLogAlertService.QueueCapacity + 50;
        for (var i = 0; i < total; i++)
            rig.Hub.Publish("Canary", "CANARY_MODIFIED", AlertSeverity.Critical, "t", "file " + i);
        writer.Open.Set();

        await WaitFor(() => writer.Snapshot().Any(e => e.Id == AlertEventIds.AlertsDropped));
        await rig.Service.StopAsync(CancellationToken.None);
        var written = writer.Entries.Where(e => e.Id == 2001).ToArray();
        Assert.Equal("file 0", written[0].Data[5]);
        var dropped = writer.Entries.Where(e => e.Id == AlertEventIds.AlertsDropped).Sum(e => int.Parse(e.Data[1]));
        Assert.Equal(total, written.Length + dropped);
        Assert.Equal(EventLogLevel.Warning, writer.Entries.First(e => e.Id == AlertEventIds.AlertsDropped).Level);
    }

    [Fact]
    public void Hub_WiresTheSinkIntoTheSharedAlerts_WithoutADependencyCycle()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection().Build();
        var services = new ServiceCollection();
        services.AddSingleton(typeof(Microsoft.Extensions.Logging.ILogger<>), typeof(NullLogger<>));
        services.AddWatchLatticeHub(configuration, ModuleCatalog.Discover(Array.Empty<System.Reflection.Assembly>()));
        using var provider = services.BuildServiceProvider();

        var sink = Assert.Single(provider.GetServices<IAlertSink>());
        Assert.Same(provider.GetRequiredService<EventLogAlertService>(), sink);
        Assert.Contains(provider.GetServices<IHostedService>(), s => ReferenceEquals(s, sink));
        provider.GetRequiredService<IAlertPublisher>().Publish("Hub", "TEST", AlertSeverity.Info, "t", "m");
        Assert.True(provider.GetRequiredService<IOptions<EventLogAlertOptions>>().Value.Enabled);
        Assert.Equal(OperatingSystem.IsWindows(), provider.GetRequiredService<IEventLogWriter>().IsSupported);
    }

    private static string RepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Join(dir.FullName, "WatchLattice.sln"))) return dir.FullName;
        }
        throw new DirectoryNotFoundException("Could not find WatchLattice.sln above the test output folder.");
    }
}

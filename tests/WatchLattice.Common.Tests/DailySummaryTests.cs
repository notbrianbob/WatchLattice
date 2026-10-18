using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using WatchLattice.Common.Alerts;
using Xunit;

namespace WatchLattice.Common.Tests;

public sealed class DailySummaryTests
{
    // UTC+1 with daylight saving (UTC+2) from 29 March 02:00 to 25 October 03:00 local, every year.
    private static readonly TimeZoneInfo Zone = TimeZoneInfo.CreateCustomTimeZone("WatchLattice Test", TimeSpan.FromHours(1), "Test", "Test",
        "Test summer", new[]
        {
            TimeZoneInfo.AdjustmentRule.CreateAdjustmentRule(DateTime.MinValue.Date, DateTime.MaxValue.Date, TimeSpan.FromHours(1),
                TimeZoneInfo.TransitionTime.CreateFixedDateRule(new DateTime(1, 1, 1, 2, 0, 0), 3, 29),
                TimeZoneInfo.TransitionTime.CreateFixedDateRule(new DateTime(1, 1, 1, 3, 0, 0), 10, 25)),
        });

    private static readonly DateTimeOffset Now = new(2026, 10, 18, 7, 0, 0, TimeSpan.Zero); // 09:00 local, summer time

    private static ProtectionAlert Alert(double hoursAgo, string module = "Persistence", string code = "ENTRY_CHANGED",
        AlertSeverity severity = AlertSeverity.Warning, string title = "Autostart entry changed", string? resource = @"Run\Updater") =>
        new(Guid.NewGuid(), Now.AddHours(-hoursAgo), module, code, severity, title, "details", resource);

    [Fact]
    public void Summary_CountsTheLastDay_ByModuleAndSeverity_AndNamesRepeats()
    {
        var history = new[]
        {
            Alert(30), // older than a day
            Alert(20), Alert(10), Alert(1, severity: AlertSeverity.Critical),
            Alert(2, module: "DefenderWatchdog", code: "SIGNATURES_STALE", title: "Signatures are stale", resource: null),
            Alert(3, module: "Hub", code: DailySummary.Code, severity: AlertSeverity.Info, title: DailySummary.Title, resource: null),
            Alert(4, module: "Canary", code: "CANARY_DELETED", severity: AlertSeverity.Critical, title: "Canary deleted", resource: @"C:\x"),
        };

        var text = DailySummary.Build(history, Now, Zone, historyLimit: 200, topRepeated: 5);

        Assert.Equal(
            "5 alerts in the 24 hours since 2026-10-17 09:00 +02:00: 2 critical, 3 warning.\n\n"
            + "By module:\n"
            + "  Persistence: 3 (1 critical, 2 warning)\n"
            + "  Canary: 1 (1 critical)\n"
            + "  DefenderWatchdog: 1 (1 warning)\n\n"
            + "Most repeated:\n"
            + @"  3 × Persistence: Autostart entry changed (Run\Updater)",
            text);
    }

    [Fact]
    public void Summary_SaysWhenNothingHappened_AndWhenTheHistoryIsTooShortForTheDay()
    {
        Assert.Equal("No alerts in the 24 hours since 2026-10-17 09:00 +02:00.",
            DailySummary.Build(Array.Empty<ProtectionAlert>(), Now, Zone, 200, 5));

        var full = new[] { Alert(5), Alert(2, severity: AlertSeverity.Info) };
        var text = DailySummary.Build(full, Now, Zone, historyLimit: 2, topRepeated: 0);
        Assert.DoesNotContain("Most repeated", text);
        Assert.EndsWith("The hub keeps only its newest 2 alerts, and the oldest is from 2026-10-18 04:00 +02:00, "
            + "so earlier alerts in this period are not counted here. The Windows Event Log has all of them.", text);
    }

    [Fact]
    public void Slots_FollowLocalTime_AcrossDaylightSaving()
    {
        // 09:00 local: today's 08:00 has passed.
        Assert.Equal(new DateTimeOffset(2026, 10, 18, 8, 0, 0, TimeSpan.FromHours(2)), DailySummary.PreviousSlot(Now, Zone, 8));
        Assert.Equal(new DateTimeOffset(2026, 10, 19, 8, 0, 0, TimeSpan.FromHours(2)), DailySummary.NextSlot(Now, Zone, 8));
        // Exactly at the slot: it counts as the previous one, and the next is tomorrow.
        var atSlot = new DateTimeOffset(2026, 10, 18, 8, 0, 0, TimeSpan.FromHours(2));
        Assert.Equal(atSlot, DailySummary.PreviousSlot(atSlot, Zone, 8));
        Assert.Equal(atSlot.AddDays(1), DailySummary.NextSlot(atSlot, Zone, 8));
        // Clocks go back on 25 October: the slot after it is at UTC+1.
        Assert.Equal(new DateTimeOffset(2026, 10, 26, 8, 0, 0, TimeSpan.FromHours(1)),
            DailySummary.NextSlot(new DateTimeOffset(2026, 10, 25, 12, 0, 0, TimeSpan.FromHours(1)), Zone, 8));
        // 02:00 does not exist on 29 March, so that day's summary is at 03:00.
        Assert.Equal(new DateTimeOffset(2026, 3, 29, 3, 0, 0, TimeSpan.FromHours(2)),
            DailySummary.NextSlot(new DateTimeOffset(2026, 3, 28, 12, 0, 0, TimeSpan.FromHours(1)), Zone, 2));
        // Hours past 23 mean 23.
        Assert.Equal(23, DailySummary.NextSlot(Now, Zone, 99).ToOffset(TimeSpan.FromHours(2)).Hour);
    }

    [Fact]
    public async Task Service_CatchesUpAMissedSummary_ThenWritesOneEachDay()
    {
        var time = new JumpingTime(Now, Zone);
        var rig = new Rig(time, summariesWanted: 3);
        rig.Hub.RestoreHistory(new[]
        {
            Alert(49, module: "Hub", code: DailySummary.Code, severity: AlertSeverity.Info, title: DailySummary.Title, resource: null),
        });

        var written = await rig.RunAsync();

        Assert.Equal(new[]
        {
            Now + DailySummaryService.StartupDelay,
            new DateTimeOffset(2026, 10, 19, 8, 0, 0, TimeSpan.FromHours(2)),
            new DateTimeOffset(2026, 10, 20, 8, 0, 0, TimeSpan.FromHours(2)),
        }, written);
        Assert.All(time.Waits, w => Assert.True(w <= TimeSpan.FromHours(1)));
        var latest = DailySummary.Latest(rig.Hub.Snapshot().Alerts)!;
        Assert.Equal(AlertSeverity.Info, latest.Severity);
        Assert.Equal(1007, AlertEventIds.For(latest.Module, latest.Code, latest.Severity));
    }

    [Fact]
    public async Task Service_WaitsForTheFirstSlot_OnAFreshInstall()
    {
        var rig = new Rig(new JumpingTime(Now, Zone), summariesWanted: 1);

        var written = await rig.RunAsync();

        Assert.Equal(new DateTimeOffset(2026, 10, 19, 8, 0, 0, TimeSpan.FromHours(2)), Assert.Single(written));
    }

    [Fact]
    public async Task Service_DoesNothing_WhenTurnedOff()
    {
        var time = new JumpingTime(Now, Zone);
        var rig = new Rig(time, summariesWanted: 1, enabled: false);

        await rig.Service.StartAsync(CancellationToken.None);
        await rig.Service.ExecuteTask!.WaitAsync(TimeSpan.FromSeconds(30));

        Assert.Empty(rig.Hub.Snapshot().Alerts);
        Assert.Empty(time.Waits);
    }

    private sealed class Rig : IAlertSink
    {
        private readonly JumpingTime _time;
        private readonly int _wanted;
        private readonly List<DateTimeOffset> _written = new();
        private readonly TaskCompletionSource _done = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Rig(JumpingTime time, int summariesWanted, bool enabled = true)
        {
            _time = time;
            _wanted = summariesWanted;
            var delivery = Options.Create(new AlertDeliveryOptions());
            Hub = new AlertHub(delivery, new IAlertSink[] { this });
            Service = new DailySummaryService(Hub, Options.Create(new DailySummaryOptions { Enabled = enabled, Hour = 8 }), delivery,
                NullLogger<DailySummaryService>.Instance, time);
        }

        public AlertHub Hub { get; }
        public DailySummaryService Service { get; }

        public void Accept(ProtectionAlert alert)
        {
            if (!DailySummary.IsSummary(alert)) return;
            lock (_written)
            {
                _written.Add(_time.GetUtcNow());
                if (_written.Count == _wanted) _done.TrySetResult();
            }
        }

        public async Task<DateTimeOffset[]> RunAsync()
        {
            await Service.StartAsync(CancellationToken.None);
            try { await _done.Task.WaitAsync(TimeSpan.FromSeconds(30)); }
            finally { await Service.StopAsync(CancellationToken.None); }
            lock (_written) return _written.Take(_wanted).ToArray();
        }
    }

    /// <summary>A clock that jumps forward by each timer's due time and fires it at once, so a day passes instantly.</summary>
    private sealed class JumpingTime : TimeProvider
    {
        private readonly object _gate = new();
        private readonly TimeZoneInfo _zone;
        private DateTimeOffset _now;

        public JumpingTime(DateTimeOffset now, TimeZoneInfo zone)
        {
            _now = now;
            _zone = zone;
        }

        public List<TimeSpan> Waits { get; } = new();

        public override TimeZoneInfo LocalTimeZone => _zone;

        public override DateTimeOffset GetUtcNow()
        {
            lock (_gate) return _now;
        }

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            lock (_gate)
            {
                _now += dueTime;
                Waits.Add(dueTime);
            }
            ThreadPool.QueueUserWorkItem(_ => callback(state));
            return new FiredTimer();
        }

        private sealed class FiredTimer : ITimer
        {
            public bool Change(TimeSpan dueTime, TimeSpan period) => true;
            public void Dispose() { }
            public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        }
    }
}

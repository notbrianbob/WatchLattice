using System.Globalization;
using System.Text;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace WatchLattice.Common.Alerts;

public sealed class DailySummaryOptions
{
    public const string SectionName = "Alerts:DailySummary";

    /// <summary>Raise one Info alert a day summarizing the last 24 hours.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Hour of the day, 0 to 23 in the PC's local time, when the summary is written. Larger values mean 23.</summary>
    public int Hour { get; set; } = 8;

    /// <summary>How many of the most repeated alerts the summary names (at most 20).</summary>
    public int TopRepeatedAlerts { get; set; } = 5;
}

/// <summary>
/// Builds the daily summary from the hub's alert history: how many alerts
/// each module raised in the last 24 hours, at which severity, and which
/// alerts repeated most. Counts come from the bounded history, and the text
/// says so when older alerts in the period have already rolled out of it.
/// </summary>
public static class DailySummary
{
    public const string Module = "Hub";
    public const string Code = "DAILY_SUMMARY";
    public const string Title = "Daily summary";
    public static readonly TimeSpan Window = TimeSpan.FromHours(24);

    public static bool IsSummary(ProtectionAlert alert) =>
        string.Equals(alert.Module, Module, StringComparison.OrdinalIgnoreCase) && alert.Code == Code;

    /// <summary>The newest summary in the history, or null.</summary>
    public static ProtectionAlert? Latest(IEnumerable<ProtectionAlert> alerts) =>
        alerts.Where(IsSummary).MaxBy(a => a.At);

    /// <summary>The summary's message for the 24 hours up to <paramref name="now"/>. Earlier summaries are not counted.</summary>
    public static string Build(IReadOnlyList<ProtectionAlert> history, DateTimeOffset now, TimeZoneInfo zone,
        int historyLimit, int topRepeated)
    {
        var since = now - Window;
        var alerts = history.Where(a => !IsSummary(a) && a.At > since && a.At <= now).ToArray();
        var text = new StringBuilder();
        var from = LocalText(since, zone);
        if (alerts.Length == 0)
        {
            text.Append("No alerts in the 24 hours since ").Append(from).Append('.');
        }
        else
        {
            text.Append(Count(alerts.Length, "alert")).Append(" in the 24 hours since ").Append(from).Append(": ")
                .Append(Severities(alerts)).Append(".\n\nBy module:\n");
            foreach (var module in alerts.GroupBy(a => a.Module, StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(g => g.Max(a => a.Severity)).ThenByDescending(g => g.Count()).ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase))
            {
                var items = module.ToArray();
                text.Append("  ").Append(module.Key).Append(": ").Append(items.Length.ToString(CultureInfo.InvariantCulture))
                    .Append(" (").Append(Severities(items)).Append(")\n");
            }
            var repeated = alerts.GroupBy(AlertGrouping.KeyFor, StringComparer.Ordinal)
                .Where(g => g.Count() > 1)
                .OrderByDescending(g => g.Count()).ThenByDescending(g => g.Max(a => a.At))
                .Take(Math.Clamp(topRepeated, 0, 20))
                .ToArray();
            if (repeated.Length > 0)
            {
                text.Append("\nMost repeated:\n");
                foreach (var group in repeated)
                {
                    var latest = group.MaxBy(a => a.At)!;
                    text.Append("  ").Append(group.Count().ToString(CultureInfo.InvariantCulture)).Append(" × ")
                        .Append(latest.Module).Append(": ").Append(latest.Title);
                    if (!string.IsNullOrEmpty(latest.Resource)) text.Append(" (").Append(Clip(latest.Resource, 120)).Append(')');
                    text.Append('\n');
                }
            }
        }

        // The hub keeps only the newest alerts; say so rather than under-count quietly.
        var oldest = history.MinBy(a => a.At);
        if (history.Count >= historyLimit && oldest is not null && oldest.At > since)
        {
            text.Append(alerts.Length == 0 ? "\n\n" : "\n").Append("The hub keeps only its newest ")
                .Append(historyLimit.ToString(CultureInfo.InvariantCulture)).Append(" alerts, and the oldest is from ")
                .Append(LocalText(oldest.At, zone)).Append(", so earlier alerts in this period are not counted here. ")
                .Append("The Windows Event Log has all of them.");
        }
        return text.ToString().TrimEnd('\n');
    }

    /// <summary>The latest summary time at or before <paramref name="now"/>.</summary>
    public static DateTimeOffset PreviousSlot(DateTimeOffset now, TimeZoneInfo zone, int hour)
    {
        var slot = SlotOn(TimeZoneInfo.ConvertTime(now, zone).Date, zone, hour);
        return slot <= now ? slot : SlotOn(TimeZoneInfo.ConvertTime(now, zone).Date.AddDays(-1), zone, hour);
    }

    /// <summary>The first summary time after <paramref name="now"/>.</summary>
    public static DateTimeOffset NextSlot(DateTimeOffset now, TimeZoneInfo zone, int hour)
    {
        var slot = SlotOn(TimeZoneInfo.ConvertTime(now, zone).Date, zone, hour);
        return slot > now ? slot : SlotOn(TimeZoneInfo.ConvertTime(now, zone).Date.AddDays(1), zone, hour);
    }

    private static DateTimeOffset SlotOn(DateTime day, TimeZoneInfo zone, int hour)
    {
        var local = DateTime.SpecifyKind(day.Date.AddHours(Math.Clamp(hour, 0, 23)), DateTimeKind.Unspecified);
        // The hour a daylight-saving change skips happens an hour later that day.
        if (zone.IsInvalidTime(local)) local = local.AddHours(1);
        return new DateTimeOffset(local, zone.GetUtcOffset(local));
    }

    private static string Severities(IReadOnlyCollection<ProtectionAlert> alerts)
    {
        var parts = new List<string>();
        void Add(AlertSeverity severity, string name)
        {
            var count = alerts.Count(a => a.Severity == severity);
            if (count > 0) parts.Add($"{count.ToString(CultureInfo.InvariantCulture)} {name}");
        }
        Add(AlertSeverity.Critical, "critical");
        Add(AlertSeverity.Warning, "warning");
        Add(AlertSeverity.Info, "info");
        return string.Join(", ", parts);
    }

    private static string Count(int count, string noun) =>
        count.ToString(CultureInfo.InvariantCulture) + " " + noun + (count == 1 ? "" : "s");

    private static string LocalText(DateTimeOffset at, TimeZoneInfo zone) =>
        TimeZoneInfo.ConvertTime(at, zone).ToString("yyyy-MM-dd HH:mm zzz", CultureInfo.InvariantCulture);

    private static string Clip(string value, int length) => value.Length <= length ? value : value[..length] + "…";
}

/// <summary>
/// Raises the daily summary as an Info alert from the hub, so it reaches the
/// dashboard's Overview and the Event Log like any other alert. Nothing leaves
/// the PC. If the PC was off or asleep at the usual time, the missed summary
/// is written once soon after the hub starts.
/// </summary>
public sealed class DailySummaryService : BackgroundService
{
    /// <summary>Lets the restored alert history and the modules' first checks land before the first look.</summary>
    public static readonly TimeSpan StartupDelay = TimeSpan.FromMinutes(1);

    // Waits are re-checked against the clock at least this often, so a clock change or sleep can't skew the schedule much.
    private static readonly TimeSpan MaxWait = TimeSpan.FromHours(1);

    private readonly AlertHub _alerts;
    private readonly DailySummaryOptions _options;
    private readonly int _historyLimit;
    private readonly ILogger<DailySummaryService> _logger;
    private readonly TimeProvider _time;

    public DailySummaryService(AlertHub alerts, IOptions<DailySummaryOptions> options, IOptions<AlertDeliveryOptions> delivery,
        ILogger<DailySummaryService> logger, TimeProvider? time = null)
    {
        _alerts = alerts;
        _options = options.Value;
        _historyLimit = Math.Clamp(delivery.Value.HistoryLimit, 1, 1000);
        _logger = logger;
        _time = time ?? TimeProvider.System;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Enabled) return;
        var hour = Math.Clamp(_options.Hour, 0, 23);
        try
        {
            await Task.Delay(StartupDelay, _time, stoppingToken);

            // Catch up once when the last summary is older than the latest scheduled time.
            // A first install has no summary yet and simply waits for the next one.
            var now = _time.GetUtcNow();
            var last = DailySummary.Latest(_alerts.Snapshot().Alerts);
            if (last is not null && last.At < DailySummary.PreviousSlot(now, _time.LocalTimeZone, hour)) Publish();

            while (!stoppingToken.IsCancellationRequested)
            {
                var due = DailySummary.NextSlot(_time.GetUtcNow(), _time.LocalTimeZone, hour);
                for (var wait = due - _time.GetUtcNow(); wait > TimeSpan.Zero; wait = due - _time.GetUtcNow())
                    await Task.Delay(wait < MaxWait ? wait : MaxWait, _time, stoppingToken);
                Publish();
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            _logger.LogDebug("Daily summary stopped with the hub.");
        }
    }

    private void Publish()
    {
        var now = _time.GetUtcNow();
        var message = DailySummary.Build(_alerts.Snapshot().Alerts, now, _time.LocalTimeZone, _historyLimit, _options.TopRepeatedAlerts);
        _alerts.Publish(DailySummary.Module, DailySummary.Code, AlertSeverity.Info, DailySummary.Title, message);
        _logger.LogInformation("Wrote the daily alert summary.");
    }
}

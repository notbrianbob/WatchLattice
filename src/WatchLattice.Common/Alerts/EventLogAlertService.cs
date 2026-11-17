using System.Text;
using System.Threading.Channels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace WatchLattice.Common.Alerts;

public sealed class EventLogAlertOptions
{
    public const string SectionName = "Alerts:EventLog";

    public bool Enabled { get; set; } = true;

    /// <summary>Alerts below this severity stay out of the Event Log (they still reach the tray feed).</summary>
    public AlertSeverity MinimumSeverity { get; set; } = AlertSeverity.Info;
}

public enum EventLogLevel { Information, Warning, Error }

/// <summary>Where Event Log entries go. Split out so the sink is tested without Windows.</summary>
public interface IEventLogWriter
{
    bool IsSupported { get; }

    /// <summary>Makes sure the event source exists. Returns null when entries can be written, else why not. Does not throw.</summary>
    string? Prepare();

    void Write(int eventId, EventLogLevel level, IReadOnlyList<string> data);
}

/// <summary>
/// Copies every shared alert into the Windows Application log under the
/// <see cref="SourceName"/> source, so Event Viewer, Windows Event Forwarding
/// and SIEM agents see them. Publishers only enqueue; a slow or broken Event
/// Log never delays monitoring. See docs/event-log.md.
/// </summary>
public sealed class EventLogAlertService : BackgroundService, IAlertSink
{
    /// <summary>Part of the contract with SIEM rules: never rename. See docs/releasing.md.</summary>
    public const string SourceName = "WatchLattice";
    public const string LogName = "Application";
    public const int QueueCapacity = 256;

    private readonly EventLogAlertOptions _options;
    private readonly IEventLogWriter _writer;
    private readonly ILogger<EventLogAlertService> _logger;
    private readonly IServiceProvider _services;
    private readonly Channel<ProtectionAlert> _queue;
    private volatile bool _off;
    private long _dropped;
    private bool _writeFailed;

    public EventLogAlertService(IOptions<EventLogAlertOptions> options, IEventLogWriter writer,
        ILogger<EventLogAlertService> logger, IServiceProvider services)
    {
        _options = options.Value;
        _writer = writer;
        _logger = logger;
        _services = services;
        _off = !_options.Enabled || !_writer.IsSupported;
        // Keep the earliest alerts when flooded: a burst after a real alert must not push it out.
        _queue = Channel.CreateBounded<ProtectionAlert>(new BoundedChannelOptions(QueueCapacity)
        {
            FullMode = BoundedChannelFullMode.DropWrite,
            SingleReader = true,
        }, _ => Interlocked.Increment(ref _dropped));
    }

    public void Accept(ProtectionAlert alert)
    {
        if (_off || alert.Severity < _options.MinimumSeverity) return;
        _queue.Writer.TryWrite(alert);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Enabled) return;
        if (!_writer.IsSupported)
        {
            _logger.LogDebug("The Windows Event Log is not available on this platform; alerts go to the shared feed only.");
            return;
        }

        // Registering the source can be slow; don't hold up the hub's other services while it happens.
        await Task.Yield();
        var problem = _writer.Prepare();
        if (problem is not null)
        {
            Stop();
            _logger.LogWarning("Alerts will not be written to the Windows Event Log: {Problem}", problem);
            Publisher()?.Publish("Hub", "EVENTLOG_UNAVAILABLE", AlertSeverity.Warning,
                "Event Log alerts unavailable", problem);
            return;
        }

        _logger.LogInformation("Writing alerts to the Windows {Log} log as source {Source}.", LogName, SourceName);
        try
        {
            await foreach (var alert in _queue.Reader.ReadAllAsync(stoppingToken)) Write(alert);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        finally
        {
            Stop();
            // Flush what was already queued at shutdown; the queue is bounded, so this is quick.
            while (_queue.Reader.TryRead(out var alert)) Write(alert);
        }
    }

    private void Stop()
    {
        _off = true;
        _queue.Writer.TryComplete();
    }

    private void Write(ProtectionAlert alert)
    {
        try
        {
            _writer.Write(AlertEventIds.For(alert.Module, alert.Code, alert.Severity), LevelOf(alert.Severity), DataOf(alert));
            var dropped = Interlocked.Exchange(ref _dropped, 0);
            if (dropped > 0)
            {
                _writer.Write(AlertEventIds.AlertsDropped, EventLogLevel.Warning, new[]
                {
                    $"WatchLattice skipped {dropped} alert(s) because they arrived faster than the Event Log accepted them. "
                        + "They are still in the tray's alert history and the module logs.",
                    dropped.ToString(System.Globalization.CultureInfo.InvariantCulture),
                });
            }
            if (_writeFailed) _logger.LogInformation("Writing alerts to the Windows Event Log recovered.");
            _writeFailed = false;
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException or IOException
            or UnauthorizedAccessException or System.ComponentModel.Win32Exception or System.Security.SecurityException)
        {
            if (_writeFailed) return;
            _writeFailed = true;
            _logger.LogWarning("Could not write an alert to the Windows Event Log: {Error}", ex.Message);
            Publisher()?.Publish("Hub", "EVENTLOG_WRITE_FAILED", AlertSeverity.Warning,
                "Event Log alerts failing", "Could not write to the Windows Event Log: " + ex.Message);
        }
    }

    private IAlertPublisher? Publisher() => _services.GetService<IAlertPublisher>();

    public static EventLogLevel LevelOf(AlertSeverity severity) => severity switch
    {
        AlertSeverity.Critical => EventLogLevel.Error,
        AlertSeverity.Warning => EventLogLevel.Warning,
        _ => EventLogLevel.Information,
    };

    /// <summary>
    /// The entry's insertion strings, in a fixed order SIEM parsers rely on
    /// (they appear as EventData Data elements): the readable text Event Viewer
    /// shows, then each field on its own. Append new fields; never reorder.
    /// </summary>
    public static IReadOnlyList<string> DataOf(ProtectionAlert alert)
    {
        var at = alert.At.UtcDateTime.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        var text = new StringBuilder()
            .Append(alert.Title).Append("\r\n\r\n")
            .Append(alert.Message).Append("\r\n\r\n")
            .Append("Module: ").Append(alert.Module).Append("\r\n")
            .Append("Alert code: ").Append(alert.Code).Append("\r\n")
            .Append("Severity: ").Append(alert.Severity).Append("\r\n");
        if (!string.IsNullOrEmpty(alert.Resource)) text.Append("Resource: ").Append(alert.Resource).Append("\r\n");
        var attack = AttackMapping.For(alert.Module, alert.Code, alert.Resource);
        if (attack.Count > 0) text.Append("MITRE ATT&CK: ").Append(AttackMapping.Describe(attack)).Append("\r\n");
        text.Append("Alert ID: ").Append(alert.Id).Append("\r\n")
            .Append("Time (UTC): ").Append(at);
        // Last, so a long message trims the advice rather than the fields above.
        text.Append("\r\n\r\nWhat to do: ").Append(AlertGuidanceCatalog.For(alert).WhatToDo);

        return new[]
        {
            Clean(text.ToString()), Clean(alert.Module), Clean(alert.Code), alert.Severity.ToString(),
            Clean(alert.Title), Clean(alert.Message), Clean(alert.Resource ?? ""), alert.Id.ToString(), at,
            AttackMapping.Ids(attack),
        };
    }

    // Alert text can carry attacker-chosen file names: keep it to printable text and line breaks.
    private static string Clean(string value)
    {
        var builder = new StringBuilder(value.Length);
        foreach (var c in value)
        {
            builder.Append(c is '\r' or '\n' or '\t' || !char.IsControl(c) ? c : ' ');
        }
        return builder.ToString();
    }
}

/// <summary>Stands in on platforms without a Windows Event Log.</summary>
public sealed class UnsupportedEventLogWriter : IEventLogWriter
{
    public bool IsSupported => false;
    public string? Prepare() => "The Windows Event Log is not available on this platform.";
    public void Write(int eventId, EventLogLevel level, IReadOnlyList<string> data) =>
        throw new PlatformNotSupportedException(Prepare());
}

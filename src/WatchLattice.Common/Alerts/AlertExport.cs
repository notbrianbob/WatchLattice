using System.Globalization;
using System.Text;
using System.Text.Json;

namespace WatchLattice.Common.Alerts;

public enum AlertExportFormat { Csv, Json }

/// <summary>
/// Writes alert rows (grouped or one per alert, as <see cref="AlertGrouping"/>
/// built them) to CSV or JSON for spreadsheets, tickets and scripts. Alert text
/// can carry attacker-chosen file names, so CSV cells that a spreadsheet would
/// read as a formula are prefixed with an apostrophe. Times are UTC, ISO 8601.
/// </summary>
public static class AlertExport
{
    public const int CurrentVersion = 1;

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public static readonly string[] CsvColumns =
    {
        "LastSeenUtc", "FirstSeenUtc", "Count", "Severity", "Module", "Code", "Title", "Message", "Resource",
        "Status", "NewCount", "AlertId", "EventId",
    };

    /// <summary>The format a file name asks for: .json is JSON, anything else CSV.</summary>
    public static AlertExportFormat FormatFor(string path) =>
        string.Equals(Path.GetExtension(path), ".json", StringComparison.OrdinalIgnoreCase) ? AlertExportFormat.Json : AlertExportFormat.Csv;

    /// <summary>"csv" or "json", in any case; null for anything else.</summary>
    public static AlertExportFormat? ParseFormat(string? text) => text?.Trim().ToLowerInvariant() switch
    {
        "csv" => AlertExportFormat.Csv,
        "json" => AlertExportFormat.Json,
        _ => null,
    };

    /// <summary>Writes the rows to a file, replacing it. CSV gets a UTF-8 byte order mark so Excel reads it as UTF-8.</summary>
    public static void WriteFile(string path, IReadOnlyList<AlertGroup> rows, AlertExportFormat format, bool grouped, DateTimeOffset exportedAt)
    {
        using var stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None);
        using var writer = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: format == AlertExportFormat.Csv));
        Write(writer, rows, format, grouped, exportedAt);
    }

    public static void Write(TextWriter writer, IReadOnlyList<AlertGroup> rows, AlertExportFormat format, bool grouped, DateTimeOffset exportedAt)
    {
        if (format == AlertExportFormat.Json) WriteJson(writer, rows, grouped, exportedAt);
        else WriteCsv(writer, rows);
    }

    /// <summary>What a row's Status column says: New, "2 new", Acknowledged or Dismissed.</summary>
    public static string StatusText(AlertGroup row) => row.State switch
    {
        AlertReviewState.New when row.NewCount < row.Count => $"{row.NewCount} new",
        AlertReviewState.New => "New",
        AlertReviewState.Acknowledged => "Acknowledged",
        _ => "Dismissed",
    };

    private static void WriteCsv(TextWriter writer, IReadOnlyList<AlertGroup> rows)
    {
        // RFC 4180 line endings, whatever the platform.
        writer.Write(string.Join(',', CsvColumns));
        writer.Write("\r\n");
        foreach (var row in rows)
        {
            var alert = row.Latest;
            var cells = new[]
            {
                Time(row.LastSeen), Time(row.FirstSeen), Number(row.Count), row.Severity.ToString(), alert.Module, alert.Code,
                alert.Title, alert.Message, alert.Resource ?? "", StatusText(row), Number(row.NewCount), alert.Id.ToString(),
                Number(AlertEventIds.For(alert.Module, alert.Code, alert.Severity)),
            };
            writer.Write(string.Join(',', cells.Select(CsvCell)));
            writer.Write("\r\n");
        }
    }

    /// <summary>
    /// One CSV cell: quoted when it holds a comma, quote or line break, and
    /// prefixed with an apostrophe when a spreadsheet would otherwise run it as
    /// a formula (it starts with =, +, -, @, a tab or a carriage return, after
    /// any leading spaces).
    /// </summary>
    public static string CsvCell(string value)
    {
        var first = value.TrimStart(' ');
        if (first.Length > 0 && first[0] is '=' or '+' or '-' or '@' or '\t' or '\r' or '\n') value = "'" + value;
        return value.IndexOfAny(new[] { ',', '"', '\r', '\n' }) < 0 ? value : "\"" + value.Replace("\"", "\"\"") + "\"";
    }

    private static void WriteJson(TextWriter writer, IReadOnlyList<AlertGroup> rows, bool grouped, DateTimeOffset exportedAt)
    {
        var document = new ExportFile(CurrentVersion, exportedAt.ToUniversalTime(), grouped, rows.Count, rows.Sum(r => r.Count),
            rows.Select(r => new ExportRow(r.LastSeen.ToUniversalTime(), r.FirstSeen.ToUniversalTime(), r.Count, r.Severity.ToString(),
                r.Latest.Module, r.Latest.Code, r.Latest.Title, r.Latest.Message, r.Latest.Resource, StatusText(r), r.NewCount,
                r.Latest.Id, AlertEventIds.For(r.Latest.Module, r.Latest.Code, r.Latest.Severity),
                r.Alerts.Select(a => new ExportOccurrence(a.Id, a.At.ToUniversalTime(), a.Severity.ToString(), a.Title)).ToArray()))
            .ToArray());
        writer.Write(JsonSerializer.Serialize(document, JsonOptions));
        writer.Write('\n');
    }

    private static string Time(DateTimeOffset at) => at.UtcDateTime.ToString("o", CultureInfo.InvariantCulture);

    private static string Number(int value) => value.ToString(CultureInfo.InvariantCulture);

    private sealed record ExportFile(int Version, DateTimeOffset ExportedAt, bool Grouped, int RowCount, int AlertCount,
        IReadOnlyList<ExportRow> Rows);

    private sealed record ExportRow(DateTimeOffset LastSeen, DateTimeOffset FirstSeen, int Count, string Severity, string Module,
        string Code, string Title, string Message, string? Resource, string Status, int NewCount, Guid AlertId, int EventId,
        IReadOnlyList<ExportOccurrence> Occurrences);

    private sealed record ExportOccurrence(Guid Id, DateTimeOffset At, string Severity, string Title);
}

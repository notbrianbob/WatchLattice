using System.Text;
using System.Text.Json;
using WatchLattice.Common.Alerts;
using Xunit;

namespace WatchLattice.Common.Tests;

public sealed class AlertExportTests : IDisposable
{
    private static readonly DateTimeOffset Start = new(2026, 10, 17, 16, 0, 0, TimeSpan.Zero);
    private readonly string _folder = Path.Join(Path.GetTempPath(), "watchlattice-export-" + Guid.NewGuid().ToString("N"));

    private static ProtectionAlert Alert(int minute, string title = "Autostart entry changed", string message = "details",
        string? resource = @"Run\Updater", AlertSeverity severity = AlertSeverity.Warning) =>
        new(Guid.NewGuid(), Start.AddMinutes(minute), "Persistence", "ENTRY_CHANGED", severity, title, message, resource);

    [Theory]
    [InlineData("=HYPERLINK(\"http://x\")", "\"'=HYPERLINK(\"\"http://x\"\")\"")]
    [InlineData("+cmd|' /C calc'!A0", "'+cmd|' /C calc'!A0")]
    [InlineData("-2+3", "'-2+3")]
    [InlineData("@SUM(A1)", "'@SUM(A1)")]
    [InlineData("  =1+1", "'  =1+1")]
    [InlineData("\t=1", "'\t=1")]
    [InlineData("\r=1", "\"'\r=1\"")]
    [InlineData("plain text", "plain text")]
    [InlineData("a, b", "\"a, b\"")]
    [InlineData("line\nbreak", "\"line\nbreak\"")]
    [InlineData("say \"hi\"", "\"say \"\"hi\"\"\"")]
    [InlineData("", "")]
    [InlineData(@"C:\Users\a=b.exe", @"C:\Users\a=b.exe")]
    public void CsvCells_AreQuoted_AndNeverStartAsAFormula(string value, string expected)
    {
        Assert.Equal(expected, AlertExport.CsvCell(value));
    }

    [Fact]
    public void Csv_HasAHeader_AndOneRowPerGroup_WithFormulaTextDefused()
    {
        var alerts = new[]
        {
            Alert(0), Alert(5, message: "=cmd|'/C calc'!A0, then more"),
            Alert(9, title: "Firewall", resource: null, severity: AlertSeverity.Critical),
        };
        var rows = AlertGrouping.Build(alerts, AlertReviewSet.Empty);

        using var text = new StringWriter();
        AlertExport.Write(text, rows, AlertExportFormat.Csv, grouped: true, Start);
        var lines = text.ToString().Split("\r\n");

        Assert.Equal(string.Join(',', AlertExport.CsvColumns), lines[0]);
        Assert.Equal(4, lines.Length); // header, two rows, and the empty string after the last line break
        Assert.Equal("", lines[^1]);
        Assert.StartsWith("2026-10-17T16:09:00.0000000Z,2026-10-17T16:09:00.0000000Z,1,Critical,Persistence,ENTRY_CHANGED,Firewall,", lines[1]);
        Assert.Contains(",\"'=cmd|'/C calc'!A0, then more\",", lines[2]);
        Assert.Contains(",2,Warning,", lines[2]);
        Assert.EndsWith($",New,2,{alerts[1].Id},5003", lines[2]);
    }

    [Fact]
    public void Json_KeepsEveryOccurrence_AndTheReviewState()
    {
        var alerts = new[] { Alert(0), Alert(5) };
        var key = AlertGrouping.KeyFor(alerts[0]);
        var review = AlertReviewSet.Empty.Mark(new[] { (key, alerts[0].At) }, dismiss: false, Start);
        var rows = AlertGrouping.Build(alerts, review);

        using var text = new StringWriter();
        AlertExport.Write(text, rows, AlertExportFormat.Json, grouped: true, Start.AddHours(1));
        using var json = JsonDocument.Parse(text.ToString());
        var root = json.RootElement;

        Assert.Equal(1, root.GetProperty("version").GetInt32());
        Assert.True(root.GetProperty("grouped").GetBoolean());
        Assert.Equal(2, root.GetProperty("alertCount").GetInt32());
        var row = Assert.Single(root.GetProperty("rows").EnumerateArray());
        Assert.Equal("1 new", row.GetProperty("status").GetString());
        Assert.Equal(5003, row.GetProperty("eventId").GetInt32());
        Assert.Equal(alerts[1].Id, row.GetProperty("alertId").GetGuid());
        Assert.Equal(new[] { alerts[1].Id, alerts[0].Id },
            row.GetProperty("occurrences").EnumerateArray().Select(o => o.GetProperty("id").GetGuid()));
    }

    [Fact]
    public void Files_GetTheirFormat_AndCsvHasAByteOrderMark()
    {
        Directory.CreateDirectory(_folder);
        var rows = AlertGrouping.Build(new[] { Alert(0, title: "Élan") }, AlertReviewSet.Empty, group: false);
        var csv = Path.Join(_folder, "a.csv");
        var json = Path.Join(_folder, "a.JSON");

        AlertExport.WriteFile(csv, rows, AlertExport.FormatFor(csv), grouped: false, Start);
        AlertExport.WriteFile(json, rows, AlertExport.FormatFor(json), grouped: false, Start);

        Assert.Equal(AlertExportFormat.Csv, AlertExport.FormatFor("alerts.txt"));
        var csvBytes = File.ReadAllBytes(csv);
        Assert.Equal(new byte[] { 0xEF, 0xBB, 0xBF }, csvBytes[..3]);
        Assert.Contains("Élan", Encoding.UTF8.GetString(csvBytes));
        var jsonBytes = File.ReadAllBytes(json);
        Assert.Equal((byte)'{', jsonBytes[0]);
        using var parsed = JsonDocument.Parse(jsonBytes);
        Assert.False(parsed.RootElement.GetProperty("grouped").GetBoolean());
    }

    [Theory]
    [InlineData("csv", AlertExportFormat.Csv)]
    [InlineData(" JSON ", AlertExportFormat.Json)]
    [InlineData("xml", null)]
    [InlineData(null, null)]
    public void Formats_AreParsed(string? text, AlertExportFormat? expected)
    {
        Assert.Equal(expected, AlertExport.ParseFormat(text));
    }

    public void Dispose()
    {
        if (Directory.Exists(_folder)) Directory.Delete(_folder, recursive: true);
    }
}

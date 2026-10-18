using System.Text.Json;
using Microsoft.Extensions.Configuration;
using WatchLattice.Common.Alerts;

namespace WatchLattice.Hub;

/// <summary>
/// <c>--export-alerts &lt;path&gt; [--format csv|json] [--group]</c> writes the
/// alert history from the shared feed to a file, or to standard output when the
/// path is <c>-</c>. One row per alert unless <c>--group</c> is given; the
/// Status column is the running account's own acknowledged and dismissed
/// state from the dashboard. Read-only, and needs no administrator rights, but
/// only the account the installer gave the feed to (and SYSTEM) can read it.
/// Exit codes: 0 written, 1 the feed could not be read, 2 bad arguments or the
/// file could not be written.
/// </summary>
internal static class ExportCommand
{
    public const string Switch = "--export-alerts";
    private const string FormatSwitch = "--format";
    private const string GroupSwitch = "--group";

    public sealed record Request(string? Path, string? Format, bool Group);

    /// <summary>
    /// Finds the export switch and its values, and returns the other arguments
    /// for the host, so a path such as /tmp/a.csv is never read as a setting.
    /// </summary>
    public static Request? Parse(string[] args, out string[] remaining)
    {
        var index = Array.FindIndex(args, a => string.Equals(a, Switch, StringComparison.OrdinalIgnoreCase));
        if (index < 0)
        {
            remaining = args;
            return null;
        }
        var rest = new List<string>();
        string? path = null, format = null;
        var group = false;
        for (var i = 0; i < args.Length; i++)
        {
            if (i == index)
            {
                if (i + 1 < args.Length && !IsSwitch(args[i + 1])) path = args[++i];
            }
            else if (string.Equals(args[i], FormatSwitch, StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 < args.Length) format = args[++i];
                else format = "";
            }
            else if (string.Equals(args[i], GroupSwitch, StringComparison.OrdinalIgnoreCase)) group = true;
            else rest.Add(args[i]);
        }
        remaining = rest.ToArray();
        return new Request(path, format, group);
    }

    public static int Run(Request request, IConfiguration configuration)
    {
        if (string.IsNullOrWhiteSpace(request.Path))
        {
            Console.Error.WriteLine($"Usage: {Switch} <path or -> [{FormatSwitch} csv|json] [{GroupSwitch}]");
            return 2;
        }
        var toConsole = request.Path == "-";
        AlertExportFormat format;
        if (request.Format is not null)
        {
            if (AlertExport.ParseFormat(request.Format) is not { } parsed)
            {
                Console.Error.WriteLine($"{FormatSwitch} must be csv or json.");
                return 2;
            }
            format = parsed;
        }
        else format = toConsole ? AlertExportFormat.Csv : AlertExport.FormatFor(request.Path);

        var options = new AlertDeliveryOptions();
        configuration.GetSection("Alerts").Bind(options);
        AlertSnapshot snapshot;
        string feed;
        try
        {
            feed = options.ResolveFeedPath();
            snapshot = AlertSnapshot.Read(feed, includeHeartbeat: false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or JsonException
            or ArgumentException or NotSupportedException)
        {
            Console.Error.WriteLine("The alert feed could not be read: " + ex.Message);
            return 1;
        }

        var review = new AlertReviewStore();
        var rows = AlertGrouping.Build(snapshot.Alerts, review.Refresh(), request.Group);
        if (review.Problem is not null) Console.Error.WriteLine(review.Problem);
        try
        {
            if (toConsole)
            {
                AlertExport.Write(Console.Out, rows, format, request.Group, DateTimeOffset.UtcNow);
                return 0;
            }
            var path = Path.GetFullPath(request.Path);
            AlertExport.WriteFile(path, rows, format, request.Group, DateTimeOffset.UtcNow);
            Console.WriteLine($"Wrote {rows.Count} row(s) for {snapshot.Alerts.Count} alert(s) from {feed} to {path}.");
            return 0;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            Console.Error.WriteLine("The export could not be written: " + ex.Message);
            return 2;
        }
    }

    private static bool IsSwitch(string arg) => arg.StartsWith("--", StringComparison.Ordinal);
}

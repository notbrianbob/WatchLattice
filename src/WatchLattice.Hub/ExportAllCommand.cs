using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using WatchLattice.Common;
using WatchLattice.Common.Activity;
using WatchLattice.Common.Alerts;
using WatchLattice.Common.Checkup;
using WatchLattice.Common.Export;
using WatchLattice.Common.Modules;
using WatchLattice.Common.Settings;
using WatchLattice.DefenderWatchdog;
using WatchLattice.Updater;

namespace WatchLattice.Hub;

/// <summary>
/// <c>--export-all &lt;path or -&gt; [--keep-names]</c> writes one Markdown file
/// with everything worth showing an AI assistant for a health review: version,
/// module health, settings, the security checkup, Defender's state, install
/// integrity, alerts with their guidance, and recent activity (see
/// <see cref="FullExport"/>). User and computer names are hidden unless
/// <c>--keep-names</c> is given. Read-only, and needs no administrator rights;
/// the alert feed is readable only by the account the installer gave it to.
/// Each part that can't be read is noted in the file instead of failing the
/// export. Exit codes: 0 written, 2 bad arguments or the file could not be written.
/// </summary>
internal static class ExportAllCommand
{
    public const string Switch = "--export-all";
    public const string KeepNamesSwitch = "--keep-names";

    public sealed record Request(string? Path, bool KeepNames);

    /// <summary>Finds the switch and its path, and returns the other arguments for the host.</summary>
    public static Request? Parse(string[] args, out string[] remaining)
    {
        var index = Array.FindIndex(args, a => string.Equals(a, Switch, StringComparison.OrdinalIgnoreCase));
        if (index < 0)
        {
            remaining = args;
            return null;
        }
        var rest = new List<string>();
        string? path = null;
        var keepNames = false;
        for (var i = 0; i < args.Length; i++)
        {
            if (i == index)
            {
                if (i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal)) path = args[++i];
            }
            else if (string.Equals(args[i], KeepNamesSwitch, StringComparison.OrdinalIgnoreCase)) keepNames = true;
            else rest.Add(args[i]);
        }
        remaining = rest.ToArray();
        return new Request(path, keepNames);
    }

    public static async Task<int> RunAsync(Request request, IConfiguration configuration, ModuleCatalog catalog)
    {
        if (string.IsNullOrWhiteSpace(request.Path))
        {
            Console.Error.WriteLine($"Usage: {Switch} <path or -> [{KeepNamesSwitch}]");
            return 2;
        }
        var data = await GatherAsync(configuration, catalog);
        var options = new FullExportOptions { HideNames = !request.KeepNames };
        var redactor = NameRedactor.ForCurrentUser();
        try
        {
            if (request.Path == "-")
            {
                Console.Out.Write(FullExport.Build(data, options, redactor));
                return 0;
            }
            var path = Path.GetFullPath(request.Path);
            FullExport.WriteFile(path, data, options, redactor);
            Console.WriteLine($"Wrote the WatchLattice data export to {path}.");
            foreach (var problem in data.Problems) Console.Error.WriteLine("Left out: " + problem);
            return 0;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            Console.Error.WriteLine("The export could not be written: " + ex.Message);
            return 2;
        }
    }

    private static async Task<FullExportData> GatherAsync(IConfiguration configuration, ModuleCatalog catalog)
    {
        var now = DateTimeOffset.UtcNow;
        var problems = new List<string>();

        var alertOptions = new AlertDeliveryOptions();
        configuration.GetSection("Alerts").Bind(alertOptions);
        AlertSnapshot? feed = null;
        ActivitySnapshot? activity = null;
        string? feedPath = null;
        try
        {
            feedPath = alertOptions.ResolveFeedPath();
            feed = AlertSnapshot.Read(feedPath);
        }
        catch (Exception ex) when (IsReadProblem(ex))
        {
            problems.Add("the alert feed (" + ex.Message + ")");
        }
        if (feedPath is not null)
        {
            try { activity = ActivitySnapshot.Read(ActivitySnapshot.PathFor(feedPath)); }
            catch (Exception ex) when (IsReadProblem(ex)) { problems.Add("the activity log (" + ex.Message + ")"); }
        }

        var review = new AlertReviewStore();
        var reviewed = review.Refresh();
        if (review.Problem is not null) problems.Add("the dashboard's review marks (" + review.Problem + ")");

        JsonObject? settings = null;
        var settingsPath = Path.Combine(AppContext.BaseDirectory, SettingsApplier.SettingsFileName);
        try { settings = SettingValues.Parse(await File.ReadAllTextAsync(settingsPath)); }
        catch (Exception ex) when (IsReadProblem(ex)) { problems.Add("the settings file (" + ex.Message + ")"); }

        var modules = catalog.Modules.Select(m => new ExportModule(m.Id, m.DisplayName, ModuleCatalog.IsEnabled(m, configuration))).ToList();

        DefenderFacts defender;
        try
        {
            using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var status = await new PowerShellDefenderStatusProvider().GetStatusAsync(limit.Token);
            defender = new DefenderFacts(status.Available, status.RealTimeProtectionEnabled, status.IsTamperProtected, status.SignatureLastUpdated, status.Error);
        }
        catch (OperationCanceledException)
        {
            defender = new DefenderFacts(false, null, null, null, "Defender did not answer in time");
        }

        IMachineRegistry registry = OperatingSystem.IsWindows() ? new WindowsMachineRegistry() : new NoMachineRegistry();
        var checkup = SecurityCheckup.Run(registry, defender, feed, now);

        var version = ReleaseVersion.FromAssembly(typeof(ExportAllCommand).Assembly);
        ExportIntegrity integrity;
        if (version.IsDevelopmentBuild)
        {
            integrity = new ExportIntegrity("Not checked (development build)", Array.Empty<string>());
        }
        else
        {
            var integrityOptions = new InstallIntegrityOptions();
            configuration.GetSection(InstallIntegrityOptions.SectionName).Bind(integrityOptions);
            var report = InstallIntegrityChecker.Check(AppContext.BaseDirectory, version, integrityOptions);
            integrity = new ExportIntegrity(report.State switch
            {
                IntegrityState.Verified => $"Verified: all {report.FilesChecked} checked files match the release",
                IntegrityState.Modified => "MODIFIED: some installed files differ from the release",
                IntegrityState.ManifestMissing => "Not checked: the release file list is missing",
                IntegrityState.ManifestInvalid => "Not checked: the release file list could not be read",
                _ => "Not checked: the installed files belong to another release (an update may be waiting for a restart)",
            }, report.Findings.Concat(report.Unreadable.Select(f => f + " (could not be read)")).ToList(), report.Problem);
        }

        return new FullExportData(now, version.ToString(), RuntimeInformation.OSDescription, modules, feed, reviewed, activity,
            settings, defender, checkup, integrity, problems);
    }

    private static bool IsReadProblem(Exception ex) => ex is IOException or UnauthorizedAccessException or InvalidDataException
        or JsonException or ArgumentException or NotSupportedException;
}

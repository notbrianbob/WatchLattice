using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using WatchLattice.Common;
using WatchLattice.Common.Alerts;
using WatchLattice.Common.Settings;
using WatchLattice.Updater;

namespace WatchLattice.Tray;

/// <summary>
/// Talks to the hub installed next to this tray (…\Hub and …\Tray) through its
/// command line, never through a path from the alert feed. Reading settings
/// needs no rights; saving them runs only inside the elevated settings editor.
/// </summary>
internal static class HubSettings
{
    private const int MaxOutputChars = 4 * 1024 * 1024;
    private const int ErrorCancelled = 1223;

    public static string? HubExecutable => ReleaseLayout.FindHubExecutable(AppContext.BaseDirectory);

    public static string NotInstalledMessage =>
        "This tray is not installed next to the hub (…\\Hub and …\\Tray), so it cannot show or change the hub's settings. "
        + "Install WatchLattice with Install.cmd, or edit appsettings.json next to the hub by hand.";

    /// <summary>Runs <c>--describe-settings</c> as the current user.</summary>
    public static async Task<SettingsDescription> DescribeAsync(CancellationToken cancellationToken = default)
    {
        var (exitCode, output) = await RunHubAsync("--describe-settings", TimeSpan.FromSeconds(30), cancellationToken);
        if (exitCode != 0) throw new InvalidOperationException(output.Trim().Length > 0 ? output.Trim() : $"The hub exited with code {exitCode}.");
        var description = JsonSerializer.Deserialize<SettingsDescription>(output, AtomicJsonFile.JsonOptions);
        if (description is null || description.Version != SettingsDescription.CurrentVersion || description.Sections is null
            || description.Modules is null || description.Values is null)
            throw new InvalidDataException("The hub described its settings in a format this tray does not understand.");
        return description;
    }

    /// <summary>
    /// Stages the new settings in the hub's own folder and runs
    /// <c>--apply-settings</c>. Only works from the elevated settings editor,
    /// since that folder is writable only by administrators.
    /// </summary>
    public static async Task<(SettingsOutcome Outcome, string Output)> ApplyAsync(JsonObject proposed, CancellationToken cancellationToken = default)
    {
        var hub = HubExecutable ?? throw new InvalidOperationException(NotInstalledMessage);
        var pending = Path.Combine(Path.GetDirectoryName(hub)!, SettingsApplier.PendingFileName);
        await File.WriteAllTextAsync(pending, SettingValues.Serialize(proposed), new UTF8Encoding(false), cancellationToken);
        var (exitCode, output) = await RunHubAsync("--apply-settings", TimeSpan.FromMinutes(4), cancellationToken);
        return (Enum.IsDefined(typeof(SettingsOutcome), exitCode) ? (SettingsOutcome)exitCode : SettingsOutcome.Failed, output);
    }

    /// <summary>
    /// Opens the settings editor with administrator rights through Windows'
    /// consent prompt. Returns false when the user declined the prompt.
    /// </summary>
    public static async Task<bool> OpenEditorElevatedAsync(IWin32Window? owner, string? section, string? toggleModule,
        IReadOnlyList<BaselineApproval>? approvals = null)
    {
        if (Environment.ProcessPath is not { } tray) return false;
        var arguments = new StringBuilder("--edit-settings");
        if (section is not null) arguments.Append(" --section ").Append(Quote(section));
        if (toggleModule is not null) arguments.Append(" --toggle-module ").Append(Quote(toggleModule));
        // Encoded as base64url, which needs no quoting, whatever the entry's name contains.
        foreach (var approval in approvals ?? Array.Empty<BaselineApproval>())
            arguments.Append(" --approve ").Append(BaselineApprovals.Encode(approval));
        try
        {
            using var process = Process.Start(new ProcessStartInfo(tray)
            {
                UseShellExecute = true,
                Verb = "runas",
                Arguments = arguments.ToString(),
                WorkingDirectory = Path.GetDirectoryName(tray)!,
            });
            if (process is not null) await process.WaitForExitAsync();
            return true;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == ErrorCancelled)
        {
            return false;
        }
        catch (Win32Exception ex)
        {
            MessageBox.Show(owner, "The settings editor could not start: " + ex.Message, "WatchLattice settings",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            return false;
        }
    }

    // Section and module ids are letters, digits, ':', '-' and '_' (see ModuleCatalog), so quoting is enough.
    private static string Quote(string value) => "\"" + value.Replace("\"", "") + "\"";

    private static async Task<(int ExitCode, string Output)> RunHubAsync(string argument, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var hub = HubExecutable ?? throw new InvalidOperationException(NotInstalledMessage);
        var start = new ProcessStartInfo(hub)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            WorkingDirectory = Path.GetDirectoryName(hub)!,
        };
        start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("The hub did not start.");
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        limit.CancelAfter(timeout);
        var output = ReadBoundedAsync(process.StandardOutput, limit.Token);
        var error = ReadBoundedAsync(process.StandardError, limit.Token);
        try { await process.WaitForExitAsync(limit.Token); }
        catch (OperationCanceledException)
        {
            try { process.Kill(); }
            catch (InvalidOperationException) { }
            throw new TimeoutException("The hub did not answer in time.");
        }
        var text = await output;
        var problems = await error;
        return (process.ExitCode, problems.Length == 0 ? text : text + Environment.NewLine + problems);
    }

    private static async Task<string> ReadBoundedAsync(StreamReader reader, CancellationToken cancellationToken)
    {
        var text = new StringBuilder();
        var buffer = new char[8192];
        int count;
        while ((count = await reader.ReadAsync(buffer, cancellationToken)) > 0)
        {
            if (text.Length + count > MaxOutputChars) throw new InvalidDataException("The hub's answer was unexpectedly large.");
            text.Append(buffer, 0, count);
        }
        return text.ToString();
    }
}

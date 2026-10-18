using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Microsoft.Win32;
using WatchLattice.Persistence.Verification;
using WatchLattice.Persistence.Verification.Windows;

namespace WatchLattice.Persistence;

/// <summary>Reads documented Windows autostart locations; never launches the discovered commands.</summary>
public sealed class WindowsPersistenceProvider : IPersistenceProvider
{
    private readonly PersistenceOptions _options;
    public WindowsPersistenceProvider(IOptions<PersistenceOptions> options) => _options = options.Value;

    public async Task<IReadOnlyList<PersistenceSource>> ReadAsync(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
            return new[] { new PersistenceSource("Windows", Array.Empty<PersistenceEntry>(), "Autostart inventory is only available on Windows.") };

        var sources = new List<PersistenceSource>();
        if (_options.WatchRegistry) sources.AddRange(ReadRegistry(cancellationToken));
        if (_options.WatchStartupFolders)
        {
            var folders = _options.ResolveStartupFolders();
            if (folders.Count == 0) sources.Add(new("Startup", Array.Empty<PersistenceEntry>(), "No Startup folders resolved for this account."));
            foreach (var folder in folders)
            {
                cancellationToken.ThrowIfCancellationRequested();
                sources.Add(ReadStartupFolder(folder, cancellationToken));
            }
        }
        if (_options.WatchScheduledTasks) sources.Add(await ReadScheduledTasksAsync(cancellationToken));
        if (_options.WatchServices) sources.Add(ReadServices(cancellationToken));
        if (_options.WatchWmiSubscriptions) sources.Add(await ReadWmiSubscriptionsAsync(cancellationToken));
        return sources;
    }

    [SupportedOSPlatform("windows")]
    private static IEnumerable<PersistenceSource> ReadRegistry(CancellationToken cancellationToken)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var account = identity.User?.Value ?? Environment.UserName;
        var views = Environment.Is64BitOperatingSystem ? new[] { RegistryView.Registry64, RegistryView.Registry32 } : new[] { RegistryView.Registry32 };
        foreach (var hive in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
        // HKCU\Software Run keys are shared between views; avoid duplicate alerts for the same user entry.
        foreach (var view in hive == RegistryHive.CurrentUser ? new[] { RegistryView.Default } : views)
        foreach (var name in new[] { "Run", "RunOnce" })
        {
            cancellationToken.ThrowIfCancellationRequested();
            var keyPath = @"Software\Microsoft\Windows\CurrentVersion\" + name;
            var id = $"Registry/{(hive == RegistryHive.CurrentUser ? "HKCU-" + account : "HKLM")}/{view}/{name}";
            PersistenceSource source;
            try
            {
                using var root = RegistryKey.OpenBaseKey(hive, view);
                using var key = root.OpenSubKey(keyPath, writable: false);
                var entries = new List<PersistenceEntry>();
                if (key is not null)
                {
                    foreach (var valueName in key.GetValueNames())
                    {
                        var value = key.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                        if (value is null) throw new IOException("A registry entry changed during inventory; retrying on the next check.");
                        var text = value switch
                        {
                            string[] strings => JsonSerializer.Serialize(strings),
                            byte[] bytes => Convert.ToHexString(bytes),
                            _ => Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? "",
                        };
                        if (text.Length > 65536) throw new IOException("Registry value exceeds the inventory size limit.");
                        entries.Add(new(string.IsNullOrEmpty(valueName) ? "(Default)" : valueName, $"{key.GetValueKind(valueName)}: {text}"));
                    }
                }
                source = new(id, entries);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException)
            {
                source = new(id, Array.Empty<PersistenceEntry>(), ex.Message);
            }
            yield return source;
        }
    }

    private PersistenceSource ReadStartupFolder(string folder, CancellationToken cancellationToken)
    {
        var id = "Startup/" + folder;
        try
        {
            var entries = new List<PersistenceEntry>();
            foreach (var path in Directory.GetFiles(folder))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (string.Equals(Path.GetFileName(path), "desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                // Hash shortcut/script contents without resolving or executing them. A bounded read avoids large startup binaries.
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                var limit = Math.Clamp(_options.MaxStartupFileBytes, 4096, 16 * 1024 * 1024);
                if (stream.Length > limit) throw new IOException($"Startup file exceeds {limit} bytes: {path}");
                using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                var buffer = new byte[8192];
                var total = 0;
                int read;
                while ((read = stream.Read(buffer)) > 0)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    total += read;
                    if (total > limit) throw new IOException($"Startup file grew beyond {limit} bytes: {path}");
                    hash.AppendData(buffer, 0, read);
                }
                entries.Add(new(Path.GetFileName(path), $"File: {path}; SHA256: {Convert.ToHexString(hash.GetHashAndReset())}"));
            }
            return new(id, entries);
        }
        catch (DirectoryNotFoundException) { return new(id, Array.Empty<PersistenceEntry>()); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException)
        {
            return new(id, Array.Empty<PersistenceEntry>(), ex.Message);
        }
    }

    /// <summary>Projects stable task fields, excluding transient runtime state. Queries only; no registration or execution.</summary>
    public const string ScheduledTaskScript = """
        $ErrorActionPreference = 'Stop'
        [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
        $entries = @(Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
            $task = $_
            $definition = [ordered]@{
                Enabled = $task.Settings.Enabled
                UserId = $task.Principal.UserId
                GroupId = $task.Principal.GroupId
                RunLevel = [string]$task.Principal.RunLevel
                LogonType = [string]$task.Principal.LogonType
                Actions = @($task.Actions | ForEach-Object {
                    [ordered]@{ Execute = $_.Execute; Arguments = $_.Arguments; WorkingDirectory = $_.WorkingDirectory; ClassId = $_.ClassId; Data = $_.Data }
                })
                Triggers = @($task.Triggers | ForEach-Object {
                    [ordered]@{
                        Type = $_.CimClass.CimClassName; Enabled = $_.Enabled
                        StartBoundary = $_.StartBoundary; EndBoundary = $_.EndBoundary
                        UserId = $_.UserId; DaysInterval = $_.DaysInterval; WeeksInterval = $_.WeeksInterval
                        DaysOfWeek = $_.DaysOfWeek; DaysOfMonth = $_.DaysOfMonth; MonthsOfYear = $_.MonthsOfYear
                        Subscription = $_.Subscription; Delay = $_.Delay
                        Interval = $_.Repetition.Interval; Duration = $_.Repetition.Duration
                    }
                })
            }
            [pscustomobject]@{ Id = $task.TaskPath + $task.TaskName; Command = ($definition | ConvertTo-Json -Depth 8 -Compress) }
        })
        ConvertTo-Json -InputObject $entries -Depth 4 -Compress
        """;

    /// <summary>
    /// Projects every permanent WMI event subscription in root\subscription:
    /// filters, consumers (every consumer class, with all its own properties)
    /// and the bindings that connect them. CreatorSID is shown as a SID.
    /// Queries only; nothing is registered, removed or triggered.
    /// </summary>
    public const string WmiSubscriptionScript = """
        $ErrorActionPreference = 'Stop'
        [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
        $ns = 'root\subscription'
        function Ref($instance) { [string]$instance.CimSystemProperties.ClassName + '/' + [string]$instance.Name }
        function Props($instance) {
            $values = [ordered]@{}
            foreach ($p in @($instance.CimInstanceProperties | Sort-Object Name)) {
                if ($p.Name -like '__*' -or $p.Name -eq 'Name') { continue }
                $v = $p.Value
                if ($p.Name -eq 'CreatorSID' -and $v -is [byte[]]) {
                    try { $v = ([System.Security.Principal.SecurityIdentifier]::new([byte[]]$v, 0)).Value } catch { $v = [Convert]::ToBase64String([byte[]]$v) }
                } elseif ($v -is [Microsoft.Management.Infrastructure.CimInstance]) { $v = Ref $v }
                $values[$p.Name] = $v
            }
            $values
        }
        $entries = @()
        $entries += @(Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ Id = 'Filter/' + $_.Name; Command = (ConvertTo-Json -InputObject (Props $_) -Depth 6 -Compress) }
        })
        $entries += @(Get-CimInstance -Namespace $ns -ClassName __EventConsumer -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ Id = 'Consumer/' + (Ref $_); Command = (ConvertTo-Json -InputObject (Props $_) -Depth 6 -Compress) }
        })
        $entries += @(Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ Id = 'Binding/' + (Ref $_.Filter) + ' -> ' + (Ref $_.Consumer); Command = (ConvertTo-Json -InputObject (Props $_) -Depth 6 -Compress) }
        })
        ConvertTo-Json -InputObject @($entries) -Depth 4 -Compress
        """;

    /// <summary>Source ID prefix for WMI subscriptions; the namespace follows it.</summary>
    public const string WmiSourcePrefix = "WmiSubscriptions/";

    [SupportedOSPlatform("windows")]
    private static async Task<PersistenceSource> ReadScheduledTasksAsync(CancellationToken cancellationToken)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var id = "ScheduledTasks/" + (identity.User?.Value ?? Environment.UserName);
        return await RunInventoryScriptAsync(id, "Scheduled task", ScheduledTaskScript, ParseScheduledTasks, cancellationToken);
    }

    [SupportedOSPlatform("windows")]
    private static Task<PersistenceSource> ReadWmiSubscriptionsAsync(CancellationToken cancellationToken) =>
        RunInventoryScriptAsync(WmiSourcePrefix + "root/subscription", "WMI subscription", WmiSubscriptionScript, ParseWmiSubscriptions, cancellationToken);

    [SupportedOSPlatform("windows")]
    private static PersistenceSource ReadServices(CancellationToken cancellationToken)
    {
        try { return new(ServiceVerifier.SourceId, WindowsServiceRegistry.ReadAutoStartServices(cancellationToken)); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException)
        {
            return new(ServiceVerifier.SourceId, Array.Empty<PersistenceEntry>(), ex.Message);
        }
    }

    /// <summary>Runs a read-only inventory script in the in-box Windows PowerShell with a time limit and bounded output.</summary>
    [SupportedOSPlatform("windows")]
    private static async Task<PersistenceSource> RunInventoryScriptAsync(string id, string what, string script,
        Func<string, IReadOnlyList<PersistenceEntry>> parse, CancellationToken cancellationToken)
    {
        var start = new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
            "WindowsPowerShell", "v1.0", "powershell.exe"))
        {
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var argument in new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(script)) })
            start.ArgumentList.Add(argument);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(60));
        try
        {
            using var process = Process.Start(start) ?? throw new IOException("Windows PowerShell did not start.");
            try
            {
                var output = ReadBoundedAsync(process.StandardOutput, 4 * 1024 * 1024, timeout.Token);
                var error = ReadBoundedAsync(process.StandardError, 65536, timeout.Token);
                var exited = process.WaitForExitAsync(timeout.Token);
                // A reader hitting its bound must terminate the producer rather than leaving it blocked on a full pipe.
                var first = await Task.WhenAny(output, error, exited);
                await first;
                var second = first == output ? error : output;
                await await Task.WhenAny(second, exited);
                await exited;
                var text = await output;
                var errorText = await error;
                if (process.ExitCode != 0) return new(id, Array.Empty<PersistenceEntry>(),
                    $"{what} inventory failed ({process.ExitCode}): {errorText.Trim()}");
                return new(id, parse(text));
            }
            finally
            {
                if (!process.HasExited)
                {
                    try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
                }
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new(id, Array.Empty<PersistenceEntry>(), $"{what} inventory timed out.");
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or JsonException)
        {
            return new(id, Array.Empty<PersistenceEntry>(), ex.Message);
        }
    }

    public static IReadOnlyList<PersistenceEntry> ParseScheduledTasks(string json) => ParseEntries(json, "Scheduled task");

    public static IReadOnlyList<PersistenceEntry> ParseWmiSubscriptions(string json) => ParseEntries(json, "WMI subscription");

    private static IReadOnlyList<PersistenceEntry> ParseEntries(string json, string what)
    {
        var entries = JsonSerializer.Deserialize<PersistenceEntry[]>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        if (entries is null || entries.Any(e => e is null || string.IsNullOrWhiteSpace(e.Id) || e.Command is null)
            || entries.Select(e => e.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count() != entries.Length)
            throw new InvalidDataException($"{what} inventory was incomplete or invalid.");
        return entries;
    }

    private static async Task<string> ReadBoundedAsync(StreamReader reader, int limit, CancellationToken cancellationToken)
    {
        var result = new StringBuilder();
        var buffer = new char[4096];
        int count;
        while ((count = await reader.ReadAsync(buffer.AsMemory(), cancellationToken)) > 0)
        {
            if (result.Length + count > limit) throw new InvalidDataException("Inventory output exceeds the size limit.");
            result.Append(buffer, 0, count);
        }
        return result.ToString();
    }
}

using Microsoft.Win32;
using WatchLattice.ScriptHostAudit;

namespace WatchLattice.DetectionChecks;

/// <summary>
/// The checks. Each change is chosen so that it does nothing even if it were
/// left behind: autostart entries point at a file that does not exist, the
/// scheduled task is disabled with a trigger in the year 2000, the WMI filter
/// has no consumer, the firewall rule allows a program that does not exist,
/// hosts lines use the reserved .invalid domain, the proxy server is written
/// with the proxy left off, and the extension policy names an extension ID
/// and update URL that do not exist. The Defender exclusion (opt-in) is for a
/// folder that does not exist.
/// </summary>
public static class Scenarios
{
    public const string Marker = "WatchLatticeDetectionTest";

    /// <summary>A path that does not exist, in a folder only administrators can write to, so nothing can be planted there.</summary>
    public static readonly string MissingProgram = @"C:\Windows\System32\" + Marker + "-does-not-exist.exe";

    public const string TestDomain = "watchlattice-detection-test.invalid";
    public const string ProtectedTestDomain = "watchlattice-protected-test.invalid";
    public const string ExtensionId = "pppppppppppppppppppppppppppppppp";
    public const string ExtensionUpdateUrl = "https://watchlattice-detection-test.invalid/update.xml";

    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string InternetSettingsKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    private const string EdgePolicyKey = @"Software\Policies\Microsoft\Edge";
    private const string ForcelistKey = EdgePolicyKey + @"\ExtensionInstallForcelist";
    private const string ProcessCreationGuid = "{0CCE922B-69AE-11D9-BED3-505054503030}";

    public static string StartupFile => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Startup), Marker + ".txt");
    public static string MissingExclusionFolder => @"C:\" + Marker + "-does-not-exist";
    public static string HostsPath => Path.Combine(Environment.SystemDirectory, @"drivers\etc\hosts");

    public static IReadOnlyList<Scenario> All(CheckArgs args) => new List<Scenario>
    {
        new()
        {
            Name = "Run key value (current user)",
            Probe = ProbeKind.Persistence, Module = "Persistence",
            Change = $"Adds the value `{Marker}` to `HKCU\\{RunKey}`, pointing at a program that does not exist.",
            Undo = "Deletes the value.",
            ExpectedCode = "ENTRY_ADDED", ExpectedRevertCode = "ENTRY_REMOVED",
            SampleResource = $"Registry/HKCU-<your SID>/Default/Run/{Marker}",
            ResourceMatches = r => r is not null && r.StartsWith("Registry/HKCU-", StringComparison.OrdinalIgnoreCase) && r.EndsWith("/Run/" + Marker, StringComparison.OrdinalIgnoreCase),
            Apply = () => Task.Run(() => SetValue(Registry.CurrentUser, RunKey, Marker, $"\"{MissingProgram}\"")),
            Revert = () => Task.Run(() => DeleteValue(Registry.CurrentUser, RunKey, Marker)),
            Cleanup = () => Task.Run(() => DeleteValue(Registry.CurrentUser, RunKey, Marker)),
        },
        new()
        {
            Name = "Run key value (all users)",
            Probe = ProbeKind.Persistence, Module = "Persistence", NeedsAdministrator = true,
            Change = $"Adds the value `{Marker}` to `HKLM\\{RunKey}` (64-bit view), pointing at a program that does not exist.",
            Undo = "Deletes the value.",
            ExpectedCode = "ENTRY_ADDED", ExpectedRevertCode = "ENTRY_REMOVED",
            SampleResource = $"Registry/HKLM/Registry64/Run/{Marker}",
            ResourceMatches = r => string.Equals(r, $"Registry/HKLM/Registry64/Run/{Marker}", StringComparison.OrdinalIgnoreCase),
            Apply = () => Task.Run(() => SetValue(Machine64(), RunKey, Marker, $"\"{MissingProgram}\"")),
            Revert = () => Task.Run(() => DeleteValue(Machine64(), RunKey, Marker)),
            Cleanup = () => Task.Run(() => DeleteValue(Machine64(), RunKey, Marker)),
        },
        new()
        {
            Name = "Startup folder file (current user)",
            Probe = ProbeKind.Persistence, Module = "Persistence",
            Change = $"Creates an empty `{Marker}.txt` in your Startup folder.",
            Undo = "Deletes the file.",
            ExpectedCode = "ENTRY_ADDED", ExpectedRevertCode = "ENTRY_REMOVED",
            SampleResource = $@"Startup/C:\Users\<you>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup/{Marker}.txt",
            ResourceMatches = r => r is not null && r.StartsWith("Startup/", StringComparison.OrdinalIgnoreCase) && r.EndsWith("/" + Marker + ".txt", StringComparison.OrdinalIgnoreCase),
            Apply = () => File.WriteAllTextAsync(StartupFile, ""),
            Revert = () => Task.Run(() => File.Delete(StartupFile)),
            Cleanup = () => Task.Run(() => File.Delete(StartupFile)),
        },
        new()
        {
            Name = "Scheduled task (disabled, never runs)",
            Probe = ProbeKind.Persistence, Module = "Persistence",
            Change = $"Registers `\\{Marker}\\{Marker}` for your account: disabled, a one-time trigger on 1 January 2000, action `cmd.exe /c exit`.",
            Undo = "Unregisters the task and its folder.",
            ExpectedCode = "ENTRY_ADDED", ExpectedRevertCode = "ENTRY_REMOVED",
            SampleResource = $@"ScheduledTasks/<your SID>/\{Marker}\{Marker}",
            ResourceMatches = r => r is not null && r.StartsWith("ScheduledTasks/", StringComparison.OrdinalIgnoreCase) && r.EndsWith($@"\{Marker}\{Marker}", StringComparison.OrdinalIgnoreCase),
            Apply = () => Shell.PowerShellAsync($$"""
                $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c exit'
                $trigger = New-ScheduledTaskTrigger -Once -At ([datetime]'2000-01-01T00:00:00')
                $settings = New-ScheduledTaskSettingsSet -Disable
                Register-ScheduledTask -TaskPath '\{{Marker}}\' -TaskName '{{Marker}}' -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
                """),
            Revert = () => RemoveTaskAsync(),
            Cleanup = () => RemoveTaskAsync(),
        },
        new()
        {
            Name = "Auto-start service (program does not exist)",
            Probe = ProbeKind.Persistence, Module = "Persistence", NeedsAdministrator = true,
            Change = $"Creates the service `{Marker}` (start type automatic) whose program does not exist. It is never started.",
            Undo = "Deletes the service.",
            ExpectedCode = "ENTRY_ADDED", ExpectedRevertCode = "ENTRY_REMOVED",
            SampleResource = $"Services/{Marker}",
            ResourceMatches = r => string.Equals(r, $"Services/{Marker}", StringComparison.OrdinalIgnoreCase),
            Apply = () => Shell.RunAsync("sc.exe", "create", Marker, "binPath=", MissingProgram, "start=", "auto"),
            Revert = () => Shell.RunAsync("sc.exe", "delete", Marker),
            Cleanup = () => Shell.RunAsync(okExitCodes: new[] { 0, 1060 }, "sc.exe", "delete", Marker),
        },
        new()
        {
            Name = "WMI event filter (no consumer, never runs anything)",
            Probe = ProbeKind.Persistence, Module = "Persistence", NeedsAdministrator = true,
            Change = $"Creates the `__EventFilter` `{Marker}` in `root\\subscription`, for a time that never comes (the year 1999). No consumer or binding is created, so it can never run anything.",
            Undo = "Deletes the filter.",
            ExpectedCode = "ENTRY_ADDED", ExpectedRevertCode = "ENTRY_REMOVED",
            SampleResource = $"WmiSubscriptions/root/subscription/Filter/{Marker}",
            ResourceMatches = r => r is not null && r.StartsWith("WmiSubscriptions/", StringComparison.OrdinalIgnoreCase) && r.EndsWith("/Filter/" + Marker, StringComparison.OrdinalIgnoreCase),
            Apply = () => Shell.PowerShellAsync($$"""
                New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property @{
                    Name = '{{Marker}}'; EventNamespace = 'root/cimv2'; QueryLanguage = 'WQL'
                    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 3600 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Year = 1999"
                } | Out-Null
                """),
            Revert = () => RemoveWmiFilterAsync(),
            Cleanup = () => RemoveWmiFilterAsync(),
        },
        new()
        {
            Name = "Hosts file line for a test domain",
            Probe = ProbeKind.HostsProxy, Module = "HostsProxyWatchdog", NeedsAdministrator = true,
            Change = $"Appends `127.0.0.1 {TestDomain}` to the hosts file (`.invalid` is reserved and never resolves on the internet).",
            Undo = "Writes the hosts file back exactly as it was.",
            ExpectedCode = "HOSTS_CHANGED", ExpectedRevertCode = "HOSTS_CHANGED",
            SampleResource = @"C:\Windows\System32\drivers\etc\hosts",
            ResourceMatches = r => r is not null && r.EndsWith(@"\hosts", StringComparison.OrdinalIgnoreCase),
            Apply = () => Hosts.AppendAsync($"127.0.0.1 {TestDomain}"),
            Revert = () => Hosts.RestoreAsync(),
            Cleanup = () => Hosts.RemoveMarkedLinesAsync(),
        },
        new()
        {
            Name = "Hosts file override of a protected domain",
            Probe = ProbeKind.HostsProxy, Module = "HostsProxyWatchdog", NeedsAdministrator = true,
            Change = $"Appends `127.0.0.1 {ProtectedTestDomain}` to the hosts file. The check adds that test domain to the module's protected list, so no real update or security domain is touched.",
            Undo = "Writes the hosts file back exactly as it was.",
            ExpectedCode = "PROTECTED_HOST_OVERRIDDEN", ExpectedRevertCode = "PROTECTED_HOST_OVERRIDDEN_CLEARED",
            SampleResource = @"C:\Windows\System32\drivers\etc\hosts",
            ResourceMatches = _ => true,
            Apply = () => Hosts.AppendAsync($"127.0.0.1 {ProtectedTestDomain}"),
            Revert = () => Hosts.RestoreAsync(),
            Cleanup = () => Hosts.RemoveMarkedLinesAsync(),
        },
        new()
        {
            Name = "Proxy server set (current user, proxy left off)",
            Probe = ProbeKind.HostsProxy, Module = "HostsProxyWatchdog",
            Change = "Writes `ProxyServer = 127.0.0.1:9` under your Internet Settings without turning the proxy on, so browsing is not affected.",
            Undo = "Puts `ProxyServer` back as it was (or deletes it).",
            ExpectedCode = "PROXY_CHANGED", ExpectedRevertCode = "PROXY_CHANGED",
            SampleResource = "User:<your SID>",
            ResourceMatches = r => r is not null && r.StartsWith("User:", StringComparison.OrdinalIgnoreCase),
            Precondition = () => Registry.CurrentUser.OpenSubKey(InternetSettingsKey)?.GetValue("ProxyEnable") is int enabled && enabled != 0
                ? "a proxy is turned on for this account, and the check must not change a proxy in use"
                : null,
            Apply = () => Task.Run(() => Proxy.Set("127.0.0.1:9")),
            Revert = () => Task.Run(Proxy.Restore),
            Cleanup = () => Task.Run(Proxy.RemoveIfOurs),
        },
        new()
        {
            Name = "Inbound allow firewall rule for a program that does not exist",
            Probe = ProbeKind.Firewall, Module = "FirewallWatchdog", NeedsAdministrator = true,
            Change = $"Adds the inbound rule `{Marker}` allowing TCP port 49999 for a program that does not exist, so nothing can listen behind it.",
            Undo = "Removes the rule.",
            ExpectedCode = "INBOUND_ALLOW_RULE_ADDED",
            SampleResource = Marker,
            ResourceMatches = r => r is not null && r.Contains(Marker, StringComparison.OrdinalIgnoreCase),
            Apply = () => Shell.PowerShellAsync($"New-NetFirewallRule -Name '{Marker}' -DisplayName '{Marker}' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 49999 -Program '{MissingProgram}' -Profile Any -Enabled True | Out-Null"),
            Revert = () => RemoveFirewallRuleAsync(),
            Cleanup = () => RemoveFirewallRuleAsync(),
        },
        new()
        {
            Name = "Microsoft Defender exclusion for a folder that does not exist",
            Probe = ProbeKind.Defender, Module = "DefenderWatchdog", NeedsAdministrator = true,
            Change = $"Adds `{MissingExclusionFolder}` (a folder that does not exist) to Defender's path exclusions with `Add-MpPreference`.",
            Undo = "Removes the exclusion with `Remove-MpPreference`.",
            ExpectedCode = "EXCLUSION_ADDED", ExpectedRevertCode = "EXCLUSION_REMOVED",
            SampleResource = MissingExclusionFolder,
            ResourceMatches = _ => true,
            Precondition = () => args.IncludeDefender ? null : "opt-in: pass --include-defender",
            Apply = () => Shell.PowerShellAsync($"Add-MpPreference -ExclusionPath '{MissingExclusionFolder}'"),
            Revert = () => Shell.PowerShellAsync($"Remove-MpPreference -ExclusionPath '{MissingExclusionFolder}'"),
            Cleanup = () => Shell.PowerShellAsync($"if (Get-Command Remove-MpPreference -ErrorAction SilentlyContinue) {{ Remove-MpPreference -ExclusionPath '{MissingExclusionFolder}' -ErrorAction SilentlyContinue }}"),
        },
        new()
        {
            Name = "Edge force-install policy for an extension that does not exist",
            Probe = ProbeKind.BrowserExtensions, Module = "BrowserExtensionWatchdog", NeedsAdministrator = true,
            Change = $"Adds the value `{Marker}` = `{ExtensionId};{ExtensionUpdateUrl}` to `HKLM\\{ForcelistKey}`. Neither the extension nor its update host exists.",
            Undo = "Deletes the value, and the policy keys if the check created them.",
            ExpectedCode = "POLICY_EXTENSION_ADDED", ExpectedRevertCode = "POLICY_EXTENSION_REMOVED",
            SampleResource = "Edge policy (this computer)",
            ResourceMatches = _ => true,
            Apply = () => Task.Run(EdgePolicy.Add),
            Revert = () => Task.Run(EdgePolicy.Remove),
            Cleanup = () => Task.Run(EdgePolicy.Remove),
        },
        new()
        {
            Name = "PowerShell started with an encoded command",
            Probe = ProbeKind.ScriptHosts, Module = "ScriptHostAudit", NeedsAdministrator = true,
            Change = "Runs `powershell.exe -NoProfile -EncodedCommand` with `Get-Date` encoded. With --include-audit-policy, first turns on process creation auditing (and command lines in it) if it is off.",
            Undo = "Nothing to undo for the launch. Audit settings the check turned on are set back.",
            ExpectedCode = "SCRIPT_HOST_LAUNCHED",
            SampleResource = @"<this program>|C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            ResourceMatches = r => r is not null && r.EndsWith(@"\powershell.exe", StringComparison.OrdinalIgnoreCase),
            RetrySeconds = 30,
            Precondition = () => Audit.IsOn() || args.IncludeAuditPolicy
                ? null
                : "process creation auditing is off: pass --include-audit-policy to turn it on for the check",
            Apply = async () =>
            {
                Audit.TurnOnIfOff();
                await Shell.RunAsync("powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand",
                    Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes("Get-Date | Out-Null")));
            },
            Revert = () => Task.Run(Audit.Restore),
            Cleanup = () => Task.Run(Audit.Restore),
        },
        new()
        {
            Name = "Canary file overwritten",
            Probe = ProbeKind.Canary, Module = "Canary",
            Change = "Plants canaries in a throwaway folder and overwrites the first 4 KiB of one, as in-place encryption would.",
            Undo = "Deletes the throwaway folder.",
            ExpectedCode = "CANARY_MODIFIED",
            SampleResource = @"<temp>\canary\Documents\<canary>",
            ResourceMatches = _ => true,
            RetrySeconds = 20,
            Apply = () => Task.Run(CanaryProbe.OverwriteOne),
            Revert = () => Task.CompletedTask,
            Cleanup = () => Task.CompletedTask,
        },
    };

    private static RegistryKey Machine64() => RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);

    private static void SetValue(RegistryKey root, string path, string name, string value)
    {
        using var key = root.CreateSubKey(path, writable: true);
        key.SetValue(name, value, RegistryValueKind.String);
    }

    private static void DeleteValue(RegistryKey root, string path, string name)
    {
        using var key = root.OpenSubKey(path, writable: true);
        key?.DeleteValue(name, throwOnMissingValue: false);
    }

    private static Task RemoveTaskAsync() => Shell.PowerShellAsync($$"""
        Get-ScheduledTask -TaskPath '\{{Marker}}\' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
        $service = New-Object -ComObject Schedule.Service
        $service.Connect()
        try { $service.GetFolder('\').DeleteFolder('{{Marker}}', 0) } catch { }
        """);

    private static Task RemoveWmiFilterAsync() => Shell.PowerShellAsync(
        $"Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -Filter \"Name='{Marker}'\" | Remove-CimInstance");

    private static Task RemoveFirewallRuleAsync() => Shell.PowerShellAsync(
        $"Get-NetFirewallRule -Name '{Marker}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule");

    /// <summary>Hosts file edits that put the file back byte for byte.</summary>
    private static class Hosts
    {
        private static byte[]? _original;

        public static async Task AppendAsync(string line)
        {
            _original ??= await File.ReadAllBytesAsync(HostsPath);
            var text = System.Text.Encoding.UTF8.GetString(_original);
            var separator = text.Length == 0 || text.EndsWith('\n') ? "" : "\r\n";
            await File.WriteAllTextAsync(HostsPath, text + separator + line + "   # " + Marker + "\r\n");
        }

        public static async Task RestoreAsync()
        {
            if (_original is null) return;
            await File.WriteAllBytesAsync(HostsPath, _original);
            _original = null;
        }

        public static async Task RemoveMarkedLinesAsync()
        {
            var lines = await File.ReadAllLinesAsync(HostsPath);
            if (!lines.Any(l => l.Contains(Marker, StringComparison.Ordinal))) return;
            await File.WriteAllLinesAsync(HostsPath, lines.Where(l => !l.Contains(Marker, StringComparison.Ordinal)));
        }
    }

    /// <summary>The current user's WinINet ProxyServer value, put back as it was.</summary>
    private static class Proxy
    {
        private static bool _saved;
        private static object? _original;

        public static void Set(string server)
        {
            using var key = Registry.CurrentUser.CreateSubKey(InternetSettingsKey, writable: true);
            if (!_saved)
            {
                _original = key.GetValue("ProxyServer");
                _saved = true;
            }
            key.SetValue("ProxyServer", server, RegistryValueKind.String);
        }

        public static void Restore()
        {
            if (!_saved) return;
            using var key = Registry.CurrentUser.CreateSubKey(InternetSettingsKey, writable: true);
            if (_original is null) key.DeleteValue("ProxyServer", throwOnMissingValue: false);
            else key.SetValue("ProxyServer", _original);
            _saved = false;
        }

        /// <summary>After an interrupted run: only the value this check writes is removed.</summary>
        public static void RemoveIfOurs()
        {
            using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, writable: true);
            if (key?.GetValue("ProxyServer") is "127.0.0.1:9") key.DeleteValue("ProxyServer", throwOnMissingValue: false);
        }
    }

    /// <summary>The Edge force-install value, and the policy keys when they did not exist before.</summary>
    private static class EdgePolicy
    {
        private static bool _createdEdgeKey;
        private static bool _createdForcelistKey;

        public static void Add()
        {
            using var machine = Machine64();
            using (var edge = machine.OpenSubKey(EdgePolicyKey)) _createdEdgeKey = edge is null;
            using (var list = machine.OpenSubKey(ForcelistKey)) _createdForcelistKey = list is null;
            using var key = machine.CreateSubKey(ForcelistKey, writable: true);
            key.SetValue(Marker, $"{ExtensionId};{ExtensionUpdateUrl}", RegistryValueKind.String);
        }

        public static void Remove()
        {
            using var machine = Machine64();
            using (var key = machine.OpenSubKey(ForcelistKey, writable: true)) key?.DeleteValue(Marker, throwOnMissingValue: false);
            DeleteIfEmpty(machine, ForcelistKey, _createdForcelistKey);
            DeleteIfEmpty(machine, EdgePolicyKey, _createdEdgeKey);
            _createdEdgeKey = _createdForcelistKey = false;
        }

        private static void DeleteIfEmpty(RegistryKey machine, string path, bool createdByUs)
        {
            if (!createdByUs) return;
            using (var key = machine.OpenSubKey(path))
            {
                if (key is null || key.ValueCount > 0 || key.SubKeyCount > 0) return;
            }
            machine.DeleteSubKey(path, throwOnMissingSubKey: false);
        }
    }

    /// <summary>Process creation auditing: turned on only when the run was told it may, and put back afterwards.</summary>
    private static class Audit
    {
        private static bool _turnedOnSuccess;
        private static bool _savedCommandLine;
        private static object? _originalCommandLine;

        public static bool IsOn() => new WindowsProcessCreationSource().ReadAuditStatus().ProcessCreationAudited == true;

        public static void TurnOnIfOff()
        {
            if (!IsOn())
            {
                Shell.RunAsync("auditpol.exe", "/set", $"/subcategory:{ProcessCreationGuid}", "/success:enable").GetAwaiter().GetResult();
                _turnedOnSuccess = true;
            }
            using var key = Machine64().CreateSubKey(WindowsProcessCreationSource.CommandLinePolicyKey, writable: true);
            if (key.GetValue(WindowsProcessCreationSource.CommandLinePolicyValue) is not 1)
            {
                _originalCommandLine = key.GetValue(WindowsProcessCreationSource.CommandLinePolicyValue);
                _savedCommandLine = true;
                key.SetValue(WindowsProcessCreationSource.CommandLinePolicyValue, 1, RegistryValueKind.DWord);
            }
        }

        public static void Restore()
        {
            if (_turnedOnSuccess)
            {
                Shell.RunAsync("auditpol.exe", "/set", $"/subcategory:{ProcessCreationGuid}", "/success:disable").GetAwaiter().GetResult();
                _turnedOnSuccess = false;
            }
            if (_savedCommandLine)
            {
                using var key = Machine64().CreateSubKey(WindowsProcessCreationSource.CommandLinePolicyKey, writable: true);
                if (_originalCommandLine is null) key.DeleteValue(WindowsProcessCreationSource.CommandLinePolicyValue, throwOnMissingValue: false);
                else key.SetValue(WindowsProcessCreationSource.CommandLinePolicyValue, _originalCommandLine);
                _savedCommandLine = false;
            }
        }
    }
}

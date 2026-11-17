namespace WatchLattice.Common.Alerts;

/// <summary>How closely an alert matches a technique.</summary>
public enum AttackFit
{
    /// <summary>The alert reports the technique's own artifact (a new Run key value is T1547.001).</summary>
    Direct,

    /// <summary>The alert reports a change the technique is one common cause of; other causes exist.</summary>
    Related,
}

/// <summary>A MITRE ATT&amp;CK Enterprise technique, as published in <see cref="AttackMapping.AttackVersion"/>.</summary>
public sealed record AttackTechnique(string Id, string Name, string Tactics)
{
    /// <summary>The technique's page on attack.mitre.org; sub-techniques use a slash (T1547/001).</summary>
    public string Url => "https://attack.mitre.org/techniques/" + Id.Replace('.', '/') + "/";

    public override string ToString() => $"{Id} {Name}";
}

/// <summary>One technique an alert maps to, and how closely.</summary>
public sealed record AttackTag(AttackTechnique Technique, AttackFit Fit)
{
    public override string ToString() => Fit == AttackFit.Direct ? Technique.ToString() : Technique + " (related)";
}

/// <summary>
/// Maps WatchLattice alerts to MITRE ATT&amp;CK Enterprise techniques, so a SIEM
/// rule or an analyst can see which adversary behavior an alert is evidence
/// of. A mapping says what the alert is evidence of, never that WatchLattice
/// blocks or reliably catches the technique: every module reports a change
/// after it happened, on a polling interval, and an attacker with
/// administrator rights can stop the hub first.
///
/// IDs follow <see cref="AttackVersion"/>. ATT&amp;CK v18 moved the Impair
/// Defenses techniques: T1562.001 became T1685 and T1562.004 became
/// T1686.003. docs/attack-coverage.md lists every mapping;
/// AttackMappingTests keeps the two in step.
/// </summary>
public static class AttackMapping
{
    public const string AttackVersion = "Enterprise ATT&CK v20.1";

    private const string Persistence = "Persistence, Privilege Escalation";

    public static readonly AttackTechnique RunKeysStartupFolder = new("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", Persistence);
    public static readonly AttackTechnique ScheduledTask = new("T1053.005", "Scheduled Task/Job: Scheduled Task", "Execution, Persistence, Privilege Escalation");
    public static readonly AttackTechnique WindowsService = new("T1543.003", "Create or Modify System Process: Windows Service", Persistence);
    public static readonly AttackTechnique WmiEventSubscription = new("T1546.003", "Event Triggered Execution: Windows Management Instrumentation Event Subscription", Persistence);
    public static readonly AttackTechnique DisableOrModifyTools = new("T1685", "Disable or Modify Tools", "Defense Impairment");
    public static readonly AttackTechnique WindowsHostFirewall = new("T1686.003", "Disable or Modify System Firewall: Windows Host Firewall", "Defense Impairment");
    public static readonly AttackTechnique ModifyRegistry = new("T1112", "Modify Registry", "Defense Impairment, Persistence");
    public static readonly AttackTechnique AdversaryInTheMiddle = new("T1557", "Adversary-in-the-Middle", "Credential Access, Collection");
    public static readonly AttackTechnique BrowserExtensions = new("T1176.001", "Software Extensions: Browser Extensions", "Persistence");
    public static readonly AttackTechnique CommandAndScriptingInterpreter = new("T1059", "Command and Scripting Interpreter", "Execution");
    public static readonly AttackTechnique PowerShell = new("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution");
    public static readonly AttackTechnique VisualBasic = new("T1059.005", "Command and Scripting Interpreter: Visual Basic", "Execution");
    public static readonly AttackTechnique JavaScript = new("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution");
    public static readonly AttackTechnique CompiledHtmlFile = new("T1218.001", "System Binary Proxy Execution: Compiled HTML File", "Stealth");
    public static readonly AttackTechnique Cmstp = new("T1218.003", "System Binary Proxy Execution: CMSTP", "Stealth");
    public static readonly AttackTechnique InstallUtil = new("T1218.004", "System Binary Proxy Execution: InstallUtil", "Stealth");
    public static readonly AttackTechnique Mshta = new("T1218.005", "System Binary Proxy Execution: Mshta", "Stealth");
    public static readonly AttackTechnique RegsvcsRegasm = new("T1218.009", "System Binary Proxy Execution: Regsvcs/Regasm", "Stealth");
    public static readonly AttackTechnique Regsvr32 = new("T1218.010", "System Binary Proxy Execution: Regsvr32", "Stealth");
    public static readonly AttackTechnique Rundll32 = new("T1218.011", "System Binary Proxy Execution: Rundll32", "Stealth");
    public static readonly AttackTechnique IngressToolTransfer = new("T1105", "Ingress Tool Transfer", "Command and Control");
    public static readonly AttackTechnique Deobfuscate = new("T1140", "Deobfuscate/Decode Files or Information", "Stealth");
    public static readonly AttackTechnique BitsJobs = new("T1197", "BITS Jobs", "Stealth, Persistence, Execution");
    public static readonly AttackTechnique Wmi = new("T1047", "Windows Management Instrumentation", "Execution");
    public static readonly AttackTechnique IndirectCommandExecution = new("T1202", "Indirect Command Execution", "Stealth");
    public static readonly AttackTechnique DataEncryptedForImpact = new("T1486", "Data Encrypted for Impact", "Impact");
    public static readonly AttackTechnique DataDestruction = new("T1485", "Data Destruction", "Impact");
    public static readonly AttackTechnique HijackDll = new("T1574.001", "Hijack Execution Flow: DLL", "Stealth, Execution");

    /// <summary>Every technique any alert can map to, for documentation and tests.</summary>
    public static IReadOnlyList<AttackTechnique> All { get; } = new[]
    {
        RunKeysStartupFolder, ScheduledTask, WindowsService, WmiEventSubscription, DisableOrModifyTools, WindowsHostFirewall,
        ModifyRegistry, AdversaryInTheMiddle, BrowserExtensions, CommandAndScriptingInterpreter, PowerShell, VisualBasic, JavaScript,
        CompiledHtmlFile, Cmstp, InstallUtil, Mshta, RegsvcsRegasm, Regsvr32, Rundll32, IngressToolTransfer, Deobfuscate, BitsJobs,
        Wmi, IndirectCommandExecution, DataEncryptedForImpact, DataDestruction, HijackDll,
    };

    private static AttackTag D(AttackTechnique t) => new(t, AttackFit.Direct);
    private static AttackTag R(AttackTechnique t) => new(t, AttackFit.Related);

    private static readonly AttackTag[] None = Array.Empty<AttackTag>();

    private static readonly Dictionary<(string Module, string Code), AttackTag[]> Exact = new(ModuleCodeComparer.Instance)
    {
        [("Canary", "CANARY_MODIFIED")] = new[] { R(DataEncryptedForImpact) },
        [("Canary", "CANARY_RENAMED")] = new[] { R(DataEncryptedForImpact) },
        [("Canary", "CANARY_DELETED")] = new[] { R(DataEncryptedForImpact), R(DataDestruction) },

        [("DefenderWatchdog", "NOT_RUNNING")] = new[] { D(DisableOrModifyTools) },
        [("DefenderWatchdog", "PASSIVE_MODE")] = new[] { R(DisableOrModifyTools) },
        [("DefenderWatchdog", "SERVICE_DISABLED")] = new[] { D(DisableOrModifyTools) },
        [("DefenderWatchdog", "ANTIVIRUS_DISABLED")] = new[] { D(DisableOrModifyTools) },
        [("DefenderWatchdog", "REALTIME_OFF")] = new[] { D(DisableOrModifyTools) },
        [("DefenderWatchdog", "BEHAVIOR_MONITOR_OFF")] = new[] { D(DisableOrModifyTools) },
        [("DefenderWatchdog", "IOAV_OFF")] = new[] { D(DisableOrModifyTools) },
        [("DefenderWatchdog", "ON_ACCESS_OFF")] = new[] { D(DisableOrModifyTools) },
        [("DefenderWatchdog", "TAMPER_PROTECTION_OFF")] = new[] { D(DisableOrModifyTools) },
        [("DefenderWatchdog", "SIGNATURES_STALE")] = new[] { R(DisableOrModifyTools) },
        [("DefenderWatchdog", "SIGNATURES_VERY_STALE")] = new[] { R(DisableOrModifyTools) },
        [("DefenderWatchdog", "EXCLUSIONS_HIDDEN")] = new[] { R(DisableOrModifyTools) },
        [("DefenderWatchdog", "CLOUD_PROTECTION_OFF")] = new[] { D(DisableOrModifyTools) },
        [("DefenderWatchdog", "BLOCK_AT_FIRST_SEEN_OFF")] = new[] { D(DisableOrModifyTools) },
        [("DefenderWatchdog", "EXCLUSION_ADDED")] = new[] { D(DisableOrModifyTools) },
        [("DefenderWatchdog", "EXCLUSIONS_ADDED")] = new[] { D(DisableOrModifyTools) },
        [("DefenderWatchdog", "ASR_RULE_WEAKENED")] = new[] { D(DisableOrModifyTools) },
        [("DefenderWatchdog", "ASR_RULES_WEAKENED")] = new[] { D(DisableOrModifyTools) },
        [("DefenderWatchdog", "CLOUD_BLOCK_LEVEL_LOWERED")] = new[] { D(DisableOrModifyTools) },

        [("FirewallWatchdog", "PROFILE_DISABLED_DOMAIN")] = new[] { D(WindowsHostFirewall) },
        [("FirewallWatchdog", "PROFILE_DISABLED_PRIVATE")] = new[] { D(WindowsHostFirewall) },
        [("FirewallWatchdog", "PROFILE_DISABLED_PUBLIC")] = new[] { D(WindowsHostFirewall) },
        [("FirewallWatchdog", "INBOUND_DEFAULT_ALLOW_DOMAIN")] = new[] { D(WindowsHostFirewall) },
        [("FirewallWatchdog", "INBOUND_DEFAULT_ALLOW_PRIVATE")] = new[] { D(WindowsHostFirewall) },
        [("FirewallWatchdog", "INBOUND_DEFAULT_ALLOW_PUBLIC")] = new[] { D(WindowsHostFirewall) },
        [("FirewallWatchdog", "INBOUND_DEFAULT_CHANGED_DOMAIN")] = new[] { D(WindowsHostFirewall) },
        [("FirewallWatchdog", "INBOUND_DEFAULT_CHANGED_PRIVATE")] = new[] { D(WindowsHostFirewall) },
        [("FirewallWatchdog", "INBOUND_DEFAULT_CHANGED_PUBLIC")] = new[] { D(WindowsHostFirewall) },
        [("FirewallWatchdog", "INBOUND_ALLOW_RULE_ADDED")] = new[] { D(WindowsHostFirewall) },
        [("FirewallWatchdog", "INBOUND_ALLOW_RULES_ADDED")] = new[] { D(WindowsHostFirewall) },

        [("InstallIntegrity", "INSTALL_MODIFIED")] = new[] { R(HijackDll), R(DisableOrModifyTools) },

        [("HostsProxyWatchdog", "PROTECTED_HOST_OVERRIDDEN")] = new[] { D(DisableOrModifyTools), R(AdversaryInTheMiddle) },
        [("HostsProxyWatchdog", "HOSTS_PATH_MOVED")] = new[] { D(ModifyRegistry), R(AdversaryInTheMiddle) },
        [("HostsProxyWatchdog", "HOSTS_CHANGED")] = new[] { R(AdversaryInTheMiddle) },
        [("HostsProxyWatchdog", "PROXY_CHANGED")] = new[] { R(AdversaryInTheMiddle) },

        [("BrowserExtensionWatchdog", "EXTENSION_ADDED")] = new[] { D(BrowserExtensions) },
        [("BrowserExtensionWatchdog", "EXTENSIONS_ADDED")] = new[] { D(BrowserExtensions) },
        [("BrowserExtensionWatchdog", "POLICY_EXTENSION_ADDED")] = new[] { D(BrowserExtensions) },
        [("BrowserExtensionWatchdog", "POLICY_EXTENSIONS_ADDED")] = new[] { D(BrowserExtensions) },

        [("ScriptHostAudit", "SCRIPT_HOST_LAUNCHES")] = new[] { R(CommandAndScriptingInterpreter) },
    };

    // Persistence alerts name the source they came from at the start of their resource.
    private static readonly (string Prefix, AttackTechnique Technique)[] PersistenceSources =
    {
        ("Registry/", RunKeysStartupFolder),
        ("Startup/", RunKeysStartupFolder),
        ("ScheduledTasks/", ScheduledTask),
        ("Services/", WindowsService),
        ("WmiSubscriptions/", WmiEventSubscription),
    };

    private static readonly HashSet<string> PersistenceChangeCodes = new(StringComparer.Ordinal)
    {
        "ENTRY_ADDED", "ENTRY_CHANGED", "VERIFY_PASSED", "VERIFY_NEEDS_REVIEW", "VERIFY_SUSPICIOUS",
    };

    // Script hosts by file name. A host the table doesn't know still maps to T1059 as related.
    private static readonly Dictionary<string, AttackTag[]> ScriptHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        ["powershell.exe"] = new[] { D(PowerShell) },
        ["pwsh.exe"] = new[] { D(PowerShell) },
        ["powershell_ise.exe"] = new[] { D(PowerShell) },
        ["wscript.exe"] = new[] { D(VisualBasic), D(JavaScript) },
        ["cscript.exe"] = new[] { D(VisualBasic), D(JavaScript) },
        ["mshta.exe"] = new[] { D(Mshta) },
        ["rundll32.exe"] = new[] { D(Rundll32) },
        ["regsvr32.exe"] = new[] { D(Regsvr32) },
        ["certutil.exe"] = new[] { D(IngressToolTransfer), D(Deobfuscate) },
        ["bitsadmin.exe"] = new[] { D(BitsJobs) },
        ["installutil.exe"] = new[] { D(InstallUtil) },
        ["regasm.exe"] = new[] { D(RegsvcsRegasm) },
        ["regsvcs.exe"] = new[] { D(RegsvcsRegasm) },
        ["cmstp.exe"] = new[] { D(Cmstp) },
        ["wmic.exe"] = new[] { D(Wmi) },
        ["hh.exe"] = new[] { D(CompiledHtmlFile) },
        ["forfiles.exe"] = new[] { D(IndirectCommandExecution) },
        ["scriptrunner.exe"] = new[] { D(IndirectCommandExecution) },
    };

    /// <summary>
    /// The techniques an alert is evidence of; empty for health, baseline,
    /// removal and recovery alerts. Persistence alerts are mapped by the source
    /// in their resource, script host launches by the host's file name.
    /// </summary>
    public static IReadOnlyList<AttackTag> For(string module, string code, string? resource = null)
    {
        if (code.EndsWith(AlertEventIds.ClearedSuffix, StringComparison.Ordinal)) return None;
        if (string.Equals(module, "Persistence", StringComparison.OrdinalIgnoreCase))
        {
            if (!PersistenceChangeCodes.Contains(code) || resource is null) return None;
            foreach (var (prefix, technique) in PersistenceSources)
            {
                if (resource.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return new[] { D(technique) };
            }
            return None;
        }
        if (string.Equals(module, "ScriptHostAudit", StringComparison.OrdinalIgnoreCase)
            && string.Equals(code, "SCRIPT_HOST_LAUNCHED", StringComparison.Ordinal))
        {
            return ScriptHosts.TryGetValue(HostFileName(resource), out var tags) ? tags : new[] { R(CommandAndScriptingInterpreter) };
        }
        if (string.Equals(module, "DefenderWatchdog", StringComparison.OrdinalIgnoreCase)
            && code.StartsWith("BROAD_EXCLUSION:", StringComparison.Ordinal))
        {
            return new[] { D(DisableOrModifyTools) };
        }
        return Exact.TryGetValue((module, code), out var exact) ? exact : None;
    }

    /// <summary>One line for alert text and the Event Log, e.g. "T1547.001 Boot or Logon ..."; empty when unmapped.</summary>
    public static string Describe(IReadOnlyList<AttackTag> tags) => string.Join("; ", tags);

    /// <summary>The technique IDs alone, comma-separated, for machine-readable fields; empty when unmapped.</summary>
    public static string Ids(IReadOnlyList<AttackTag> tags) => string.Join(",", tags.Select(t => t.Technique.Id));

    /// <summary>Every mapped (module, code) and its tags, for documentation and tests. Persistence and script host rows are per source or host.</summary>
    public static IEnumerable<(string Module, string Code, string Condition, IReadOnlyList<AttackTag> Tags)> Rows
    {
        get
        {
            foreach (var code in PersistenceChangeCodes.Order(StringComparer.Ordinal))
            {
                foreach (var (prefix, technique) in PersistenceSources)
                    yield return ("Persistence", code, $"source `{prefix}…`", new[] { D(technique) });
            }
            foreach (var (host, tags) in ScriptHosts)
                yield return ("ScriptHostAudit", "SCRIPT_HOST_LAUNCHED", $"host `{host}`", tags);
            yield return ("ScriptHostAudit", "SCRIPT_HOST_LAUNCHED", "any other host", new[] { R(CommandAndScriptingInterpreter) });
            yield return ("DefenderWatchdog", "BROAD_EXCLUSION:*", "", new[] { D(DisableOrModifyTools) });
            foreach (var pair in Exact) yield return (pair.Key.Module, pair.Key.Code, "", pair.Value);
        }
    }

    private static string HostFileName(string? resource)
    {
        if (string.IsNullOrEmpty(resource)) return "";
        var host = resource[(resource.LastIndexOf('|') + 1)..];
        var slash = host.LastIndexOfAny(new[] { '\\', '/' });
        return slash < 0 ? host : host[(slash + 1)..];
    }

    private sealed class ModuleCodeComparer : IEqualityComparer<(string Module, string Code)>
    {
        public static readonly ModuleCodeComparer Instance = new();

        public bool Equals((string Module, string Code) x, (string Module, string Code) y) =>
            string.Equals(x.Module, y.Module, StringComparison.OrdinalIgnoreCase) && string.Equals(x.Code, y.Code, StringComparison.Ordinal);

        public int GetHashCode((string Module, string Code) obj) =>
            HashCode.Combine(StringComparer.OrdinalIgnoreCase.GetHashCode(obj.Module), StringComparer.Ordinal.GetHashCode(obj.Code));
    }
}

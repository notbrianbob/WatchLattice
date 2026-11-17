namespace WatchLattice.Common.Alerts;

/// <summary>
/// A built-in Windows screen or tool the dashboard can open for an alert.
/// Every kind starts a fixed program with fixed arguments; the only thing
/// taken from an alert is a file path for <see cref="OpenFileLocation"/>,
/// which Explorer shows selected and never runs. See <see cref="SafeActionLauncher"/>.
/// </summary>
public enum SafeActionKind
{
    OpenWindowsSecurity,
    OpenVirusProtectionSettings,
    DefenderQuickScan,
    OpenFirewallSettings,
    OpenFileLocation,
    OpenApplicationLog,
    OpenSecurityLog,
    OpenStartupApps,
    OpenTaskScheduler,
    OpenServices,
    OpenProxySettings,
}

/// <summary>One button: what it says and what it opens. Path is set only for <see cref="SafeActionKind.OpenFileLocation"/>.</summary>
public sealed record SafeAction(SafeActionKind Kind, string Label, string? Path = null);

/// <summary>What an alert means and what to do about it, in plain words, with the safe actions that help.</summary>
public sealed record AlertGuidance(string Meaning, string WhatToDo, IReadOnlyList<SafeAction> Actions);

/// <summary>
/// Plain-language guidance for every alert type. Guidance never tells
/// someone an alert is malware: most changes WatchLattice reports are made
/// by the person or by software they installed, so each entry starts from
/// "did you or an installer do this?" and points at the built-in Windows
/// screen where the change can be checked or undone.
/// </summary>
public static class AlertGuidanceCatalog
{
    // The supervisor raises MODULE_FAILED / MODULE_FINISHED under the failing module's own name.
    private const string AnyModule = "(any)";

    private const string IfYouDidIt = "If you or software you just installed or updated made this change, it is expected: acknowledge the alert.";
    private const string IfNot = "If nobody did, treat it as suspicious:";

    private static readonly SafeAction WindowsSecurity = new(SafeActionKind.OpenWindowsSecurity, "Open Windows Security");
    private static readonly SafeAction VirusSettings = new(SafeActionKind.OpenVirusProtectionSettings, "Open virus protection settings");
    private static readonly SafeAction QuickScan = new(SafeActionKind.DefenderQuickScan, "Run a Defender quick scan");
    private static readonly SafeAction Firewall = new(SafeActionKind.OpenFirewallSettings, "Open firewall settings");
    private static readonly SafeAction ApplicationLog = new(SafeActionKind.OpenApplicationLog, "Open Event Viewer");
    private static readonly SafeAction SecurityLog = new(SafeActionKind.OpenSecurityLog, "Open the Security log");
    private static readonly SafeAction StartupApps = new(SafeActionKind.OpenStartupApps, "Open startup apps");
    private static readonly SafeAction TaskScheduler = new(SafeActionKind.OpenTaskScheduler, "Open Task Scheduler");
    private static readonly SafeAction Services = new(SafeActionKind.OpenServices, "Open Services");
    private static readonly SafeAction ProxySettings = new(SafeActionKind.OpenProxySettings, "Open proxy settings");

    private static SafeAction FileLocation(string path) => new(SafeActionKind.OpenFileLocation, "Open file location", path);

    private static AlertGuidance G(string meaning, string todo, params SafeAction[] actions) => new(meaning, todo, actions);

    private static readonly AlertGuidance WatchdogState = G(
        "The module could not save or read its own record of how things looked last time, so it may report existing items as new, or miss a change made while it couldn't save.",
        "Usually a disk or permissions problem in the WatchLattice data folder, and it clears by itself once the file can be written. If it keeps coming back, check Event Viewer for errors from WatchLattice.",
        ApplicationLog);

    private static readonly Dictionary<(string Module, string Code), Func<ProtectionAlert, AlertGuidance>> Entries = new(new ModuleCodeComparer())
    {
        [(AnyModule, "MODULE_FAILED")] = _ => G(
            "One WatchLattice module stopped with an error. The hub restarts it automatically after a short wait; the other modules keep running.",
            "Nothing to do if it does not repeat. If it keeps failing, export the alerts and open an issue on GitHub with the module's log (in the WatchLattice data folder).",
            ApplicationLog),
        [(AnyModule, "MODULE_FINISHED")] = _ => G(
            "A module stopped on its own without being asked to, so it is not watching anything until the hub restarts it.",
            "Restarting the WatchLattice service, or the PC, starts it again. If it keeps happening, report it with the module's log.",
            ApplicationLog),
        [("Hub", "ALERT_HISTORY_UNAVAILABLE")] = _ => G(
            "Earlier alerts could not be loaded when the hub started, so the list starts empty. Monitoring itself is not affected.",
            "Nothing needs doing. The Windows Event Log still has the earlier alerts under the source WatchLattice.",
            ApplicationLog),
        [("Hub", "EVENTLOG_UNAVAILABLE")] = _ => G(
            "Alerts are not being written to the Windows Event Log, because the WatchLattice event source is not registered. The dashboard still gets every alert.",
            "Run the hub once as its service (or from an elevated prompt) to register the source, or see docs/event-log.md for the one-line command.",
            ApplicationLog),
        [("Hub", "EVENTLOG_WRITE_FAILED")] = _ => G(
            "An alert could not be written to the Windows Event Log. It is still in the dashboard.",
            "Usually temporary (a full or locked log). If it repeats, check the Application log's size settings in Event Viewer.",
            ApplicationLog),
        [("Hub", "DAILY_SUMMARY")] = _ => G(
            "A once-a-day count of the alerts each module raised. It is a summary, not a new problem.",
            "Nothing to do. A module that suddenly raises many more alerts than usual is worth a look."),

        [("Canary", "CANARY_MODIFIED")] = a => Canary(a, "written to or replaced"),
        [("Canary", "CANARY_RENAMED")] = a => Canary(a, "renamed"),
        [("Canary", "CANARY_DELETED")] = a => Canary(a, "deleted"),

        [("DefenderWatchdog", "STATUS_UNAVAILABLE")] = _ => G(
            "WatchLattice could not ask Microsoft Defender for its status, so it cannot tell you whether Defender is healthy right now.",
            "Open Windows Security and check that Virus & threat protection shows no warnings. If another antivirus is installed, Defender may be turned off on purpose.",
            WindowsSecurity),
        [("DefenderWatchdog", "NOT_RUNNING")] = _ => DefenderOff("Defender antivirus is not running."),
        [("DefenderWatchdog", "SERVICE_DISABLED")] = _ => DefenderOff("The Defender antimalware service is disabled, so Defender cannot start."),
        [("DefenderWatchdog", "ANTIVIRUS_DISABLED")] = _ => DefenderOff("Defender antivirus is turned off."),
        [("DefenderWatchdog", "PASSIVE_MODE")] = _ => G(
            "Defender is in passive mode: it is installed but another antivirus is doing the real-time protection.",
            "Expected if you installed another antivirus. If you didn't, open Windows Security and check which antivirus it lists as active.",
            WindowsSecurity),
        [("DefenderWatchdog", "REALTIME_OFF")] = _ => DefenderSetting("Real-time protection is off, so Defender is not scanning files as they are opened or downloaded."),
        [("DefenderWatchdog", "BEHAVIOR_MONITOR_OFF")] = _ => DefenderSetting("Behavior monitoring is off, so Defender is not watching what running programs do."),
        [("DefenderWatchdog", "IOAV_OFF")] = _ => DefenderSetting("Scanning of downloaded files and attachments is off."),
        [("DefenderWatchdog", "ON_ACCESS_OFF")] = _ => DefenderSetting("On-access protection is off, so files are not scanned when they are opened."),
        [("DefenderWatchdog", "TAMPER_PROTECTION_OFF")] = _ => DefenderSetting("Tamper protection is off, so other programs can change Defender's settings."),
        [("DefenderWatchdog", "CLOUD_PROTECTION_OFF")] = _ => DefenderSetting("Cloud-delivered protection is off, so Defender cannot ask Microsoft about new threats."),
        [("DefenderWatchdog", "BLOCK_AT_FIRST_SEEN_OFF")] = _ => DefenderSetting("Block at first sight is off, so brand-new files are not held back while the cloud checks them."),
        [("DefenderWatchdog", "SIGNATURES_STALE")] = _ => Signatures("Defender's threat definitions are more than two days old."),
        [("DefenderWatchdog", "SIGNATURES_VERY_STALE")] = _ => Signatures("Defender's threat definitions are more than a week old, so it may miss recent threats."),
        [("DefenderWatchdog", "SIGNATURE_DATE_UNKNOWN")] = _ => Signatures("Defender did not say when its threat definitions were last updated."),
        [("DefenderWatchdog", "SETTINGS_UNAVAILABLE")] = _ => G(
            "Defender's exclusions, attack surface reduction rules and cloud settings could not be read, so changes to them are not being watched right now.",
            "Usually temporary. If it repeats, check that the WatchLattice service runs as Local System (the default).",
            ApplicationLog),
        [("DefenderWatchdog", "EXCLUSIONS_HIDDEN")] = _ => G(
            "Defender hides its exclusion list from this account, so WatchLattice cannot see whether exclusions were added.",
            "Expected when the hub is not running as its service. Install it as the WatchLattice service (the default) to watch exclusions."),
        [("DefenderWatchdog", "EXCLUSION_ADDED")] = _ => Exclusion(),
        [("DefenderWatchdog", "EXCLUSIONS_ADDED")] = _ => Exclusion(),
        [("DefenderWatchdog", "EXCLUSION_REMOVED")] = _ => Undone("A Defender exclusion was removed, so Defender scans that item again."),
        [("DefenderWatchdog", "EXCLUSIONS_REMOVED")] = _ => Undone("Several Defender exclusions were removed, so Defender scans those items again."),
        [("DefenderWatchdog", "ASR_RULE_WEAKENED")] = _ => DefenderSetting("An attack surface reduction rule was turned off or set to audit only, so Defender no longer blocks that behavior."),
        [("DefenderWatchdog", "ASR_RULES_WEAKENED")] = _ => DefenderSetting("Several attack surface reduction rules were turned off or set to audit only."),
        [("DefenderWatchdog", "ASR_RULE_STRENGTHENED")] = _ => Undone("An attack surface reduction rule was made stricter. That makes the PC safer."),
        [("DefenderWatchdog", "CLOUD_BLOCK_LEVEL_LOWERED")] = _ => DefenderSetting("Defender's cloud block level was lowered, so it blocks fewer suspicious files."),
        [("DefenderWatchdog", "CLOUD_BLOCK_LEVEL_RAISED")] = _ => Undone("Defender's cloud block level was raised. That makes the PC safer, though it may block more harmless files."),
        [("DefenderWatchdog", "SETTINGS_BASELINE_CREATED")] = _ => Baseline("Defender's exclusions, attack surface reduction rules and cloud settings"),
        [("DefenderWatchdog", "STATE_SAVE_FAILED")] = _ => WatchdogState,
        [("DefenderWatchdog", "STATE_UNREADABLE")] = _ => WatchdogState,

        [("FirewallWatchdog", "STATUS_UNAVAILABLE")] = _ => G(
            "Windows Firewall's status could not be read, so WatchLattice cannot tell whether it is on.",
            "Open the firewall settings and check that each network profile shows the firewall as on.",
            Firewall),
        [("FirewallWatchdog", "PROFILE_DISABLED_DOMAIN")] = _ => FirewallOff("Domain"),
        [("FirewallWatchdog", "PROFILE_DISABLED_PRIVATE")] = _ => FirewallOff("Private"),
        [("FirewallWatchdog", "PROFILE_DISABLED_PUBLIC")] = _ => FirewallOff("Public"),
        [("FirewallWatchdog", "INBOUND_DEFAULT_ALLOW_DOMAIN")] = _ => InboundAllow("Domain"),
        [("FirewallWatchdog", "INBOUND_DEFAULT_ALLOW_PRIVATE")] = _ => InboundAllow("Private"),
        [("FirewallWatchdog", "INBOUND_DEFAULT_ALLOW_PUBLIC")] = _ => InboundAllow("Public"),
        [("FirewallWatchdog", "INBOUND_DEFAULT_CHANGED_DOMAIN")] = _ => InboundChanged("Domain"),
        [("FirewallWatchdog", "INBOUND_DEFAULT_CHANGED_PRIVATE")] = _ => InboundChanged("Private"),
        [("FirewallWatchdog", "INBOUND_DEFAULT_CHANGED_PUBLIC")] = _ => InboundChanged("Public"),
        [("FirewallWatchdog", "RULES_UNAVAILABLE")] = _ => G(
            "The list of inbound firewall rules could not be read, so new allow rules are not being watched right now.",
            "Usually temporary. If it repeats, check that the WatchLattice service runs as Local System.",
            ApplicationLog),
        [("FirewallWatchdog", "INBOUND_ALLOW_RULE_ADDED")] = _ => NewRule(),
        [("FirewallWatchdog", "INBOUND_ALLOW_RULES_ADDED")] = _ => NewRule(),
        [("FirewallWatchdog", "RULE_BASELINE_CREATED")] = _ => Baseline("the inbound firewall allow rules"),
        [("FirewallWatchdog", "STATE_SAVE_FAILED")] = _ => WatchdogState,
        [("FirewallWatchdog", "STATE_UNREADABLE")] = _ => WatchdogState,

        [("Persistence", "BASELINE_CREATED")] = _ => Baseline("the programs set to start automatically from this place"),
        [("Persistence", "ENTRY_ADDED")] = a => Autostart(a, "Something new was set to start automatically"),
        [("Persistence", "ENTRY_CHANGED")] = a => Autostart(a, "Something already set to start automatically was changed"),
        [("Persistence", "ENTRY_REMOVED")] = a => G(
            "Something that used to start automatically no longer does, usually because a program was uninstalled or a setting was turned off.",
            "Nothing to do unless you expected it to still be there.",
            AutostartActions(a.Resource).ToArray()),
        [("Persistence", "SOURCE_UNAVAILABLE")] = _ => G(
            "One place programs can start from could not be read, so changes there are not being watched right now.",
            "Usually temporary. If it repeats, check that the WatchLattice service runs as Local System.",
            ApplicationLog),
        [("Persistence", "SOURCE_RECOVERED")] = _ => Undone("That place can be read again and is watched as before."),
        [("Persistence", "VERIFY_PASSED")] = a => G(
            "WatchLattice checked the changed task or service: its program exists, is signed by a publisher it knows, and runs with ordinary rights. That is evidence, not proof that it is harmless.",
            "If you recognize it, approve it as baseline so it doesn't alert again.",
            AutostartActions(a.Resource).ToArray()),
        [("Persistence", "VERIFY_NEEDS_REVIEW")] = a => G(
            "WatchLattice checked the changed task or service and something needs a human look: an unsigned or unfamiliar program, a missing file, or a check it could not finish.",
            "Look at the program named in the details. If you know what it is, approve it as baseline. If you don't, search the file name, and run a Defender quick scan.",
            AutostartActions(a.Resource).Append(QuickScan).ToArray()),
        [("Persistence", "VERIFY_SUSPICIOUS")] = a => G(
            "WatchLattice checked the changed task or service and found a pattern common in malware: its program was swapped, it now runs with the highest rights or as SYSTEM, or it runs from a folder any user can write to.",
            "Don't approve it unless you are sure. " + IfNot + " run a Defender quick scan, then disable the task or service and look up its program.",
            AutostartActions(a.Resource).Append(QuickScan).ToArray()),
        [("Persistence", "VERIFICATION_STORE_FAILED")] = _ => WatchdogState,

        [("Updater", "UPDATE_AVAILABLE")] = _ => G(
            "A newer WatchLattice release is available on GitHub.",
            "Choose Install update in the tray or the dashboard. It is checked against the release's SHA-256 hashes before anything is replaced, and your settings are kept."),

        [("InstallIntegrity", "INSTALL_MODIFIED")] = a => G(
            "WatchLattice's own installed files no longer match the release: a file changed or is missing, or an unexpected program file appeared next to the hub.",
            "If you just updated or repaired WatchLattice, check again after it finishes. Otherwise reinstall the latest release from GitHub and run a Defender quick scan: a program planted next to a security tool is a common way to tamper with it.",
            PathActions(a.Resource).Append(QuickScan).ToArray()),
        [("InstallIntegrity", "MANIFEST_UNAVAILABLE")] = _ => G(
            "The list of release files next to the hub is missing or unreadable, so WatchLattice cannot check its own files.",
            "Reinstalling the latest release puts the list back."),

        [("HostsProxyWatchdog", "HOSTS_UNAVAILABLE")] = _ => G(
            "The hosts file could not be read, so changes to it are not being watched right now.",
            "Usually temporary (another program has it locked). If it repeats, check that the hosts file is not unusually large.",
            ApplicationLog),
        [("HostsProxyWatchdog", "PROTECTED_HOST_OVERRIDDEN")] = a => G(
            "The hosts file now blocks or redirects a Windows Update, Defender, SmartScreen or WatchLattice update address. Malware does this to stop security updates.",
            "Some ad blockers and 'privacy' tools do it too. " + IfNot + " open the hosts file location, remove the lines the alert lists (editing needs an administrator), and run a Defender quick scan.",
            PathActions(a.Resource).Append(QuickScan).ToArray()),
        [("HostsProxyWatchdog", "HOSTS_PATH_MOVED")] = _ => G(
            "Windows has been told to read its hosts file from a different folder than usual. That is rare, and it hides hosts entries from anyone checking the normal file.",
            IfYouDidIt + " " + IfNot + " ask whoever manages the PC, or set the Tcpip DataBasePath registry value back to %SystemRoot%\\System32\\drivers\\etc, then run a Defender quick scan.",
            QuickScan),
        [("HostsProxyWatchdog", "HOSTS_CHANGED")] = a => G(
            "Lines in the hosts file were added, changed or removed. The hosts file decides where some web addresses go, so a change can send you to a different site.",
            IfYouDidIt + " Development tools and ad blockers often add lines. " + IfNot + " open the file location, review the lines the alert lists, and run a Defender quick scan.",
            PathActions(a.Resource).Append(QuickScan).ToArray()),
        [("HostsProxyWatchdog", "PROXY_UNAVAILABLE")] = _ => G(
            "Proxy settings could not be read, so changes to them are not being watched right now.",
            "Usually temporary. If it repeats, check that the WatchLattice service runs as Local System.",
            ApplicationLog),
        [("HostsProxyWatchdog", "PROXY_CHANGED")] = _ => G(
            "Proxy settings changed. A proxy can see and change your web traffic, so malware sometimes sets one.",
            IfYouDidIt + " Work VPNs and some security tools set proxies too. " + IfNot + " open the proxy settings and turn off any proxy or setup script you don't recognize, then run a Defender quick scan.",
            ProxySettings, QuickScan),
        [("HostsProxyWatchdog", "BASELINE_CREATED")] = _ => Baseline("the hosts file and proxy settings"),
        [("HostsProxyWatchdog", "STATE_SAVE_FAILED")] = _ => WatchdogState,
        [("HostsProxyWatchdog", "STATE_UNREADABLE")] = _ => WatchdogState,

        [("BrowserExtensionWatchdog", "BASELINE_CREATED")] = _ => Baseline("the browser extensions in each profile"),
        [("BrowserExtensionWatchdog", "EXTENSION_ADDED")] = _ => Extension(),
        [("BrowserExtensionWatchdog", "EXTENSIONS_ADDED")] = _ => Extension(),
        [("BrowserExtensionWatchdog", "EXTENSION_REMOVED")] = _ => Undone("A browser extension was removed."),
        [("BrowserExtensionWatchdog", "EXTENSIONS_REMOVED")] = _ => Undone("Several browser extensions were removed."),
        [("BrowserExtensionWatchdog", "POLICY_EXTENSION_ADDED")] = _ => ExtensionPolicy(),
        [("BrowserExtensionWatchdog", "POLICY_EXTENSIONS_ADDED")] = _ => ExtensionPolicy(),
        [("BrowserExtensionWatchdog", "POLICY_EXTENSION_REMOVED")] = _ => Undone("A policy that installs a browser extension was removed."),
        [("BrowserExtensionWatchdog", "POLICY_EXTENSIONS_REMOVED")] = _ => Undone("Several policies that install browser extensions were removed."),
        [("BrowserExtensionWatchdog", "PROFILE_ADDED")] = _ => G(
            "A browser profile was seen for the first time (a new profile, a new user, or a newly installed browser). Its existing extensions are recorded, not reported one by one.",
            "Nothing to do unless you don't recognize the profile."),
        [("BrowserExtensionWatchdog", "PROFILE_REMOVED")] = _ => Undone("A browser profile was deleted."),
        [("BrowserExtensionWatchdog", "PROFILE_UNREADABLE")] = _ => G(
            "A browser profile could not be read, often because the browser had its files locked. Its last inventory is kept.",
            "Usually clears at the next check. If it repeats, close and reopen the browser."),
        [("BrowserExtensionWatchdog", "POLICY_UNAVAILABLE")] = _ => G(
            "Browser extension policies could not be read, so policy-installed extensions are not being watched right now.",
            "Usually temporary. If it repeats, check that the WatchLattice service runs as Local System.",
            ApplicationLog),
        [("BrowserExtensionWatchdog", "STATE_SAVE_FAILED")] = _ => WatchdogState,
        [("BrowserExtensionWatchdog", "STATE_UNREADABLE")] = _ => WatchdogState,

        [("ScriptHostAudit", "PROCESS_AUDITING_OFF")] = _ => G(
            "Windows is not recording when programs start, so script host launches can't be reported. WatchLattice never changes audit policy itself.",
            "To turn it on, follow 'Turning on process creation auditing' in the Script Host Audit README (two commands from an elevated prompt), or turn the module off if you don't want it."),
        [("ScriptHostAudit", "COMMAND_LINE_NOT_RECORDED")] = _ => G(
            "Windows records program starts but without their command lines, so launches are judged only by what started them and from where.",
            "Turn on 'Include command line in process creation events' as the Script Host Audit README shows."),
        [("ScriptHostAudit", "AUDIT_POLICY_UNAVAILABLE")] = _ => G(
            "The audit policy could not be read. Launches are still reported whenever the Security log has them.",
            "Nothing needs doing unless no launches are ever reported."),
        [("ScriptHostAudit", "SECURITY_LOG_UNAVAILABLE")] = _ => G(
            "The Security event log could not be read, so script host launches are not being reported right now.",
            "Check that the WatchLattice service runs as Local System: reading the Security log needs it.",
            SecurityLog),
        [("ScriptHostAudit", "SCRIPT_HOST_LAUNCHED")] = _ => ScriptHost(),
        [("ScriptHostAudit", "SCRIPT_HOST_LAUNCHES")] = _ => ScriptHost(),
        [("ScriptHostAudit", "EVENTS_MISSED")] = _ => G(
            "Some program starts were not read: the Security log was cleared, it wrapped before WatchLattice read it, or very many programs started at once. Clearing the Security log is also something attackers do to hide.",
            "If nobody cleared the log, look in the Security log for event 1102 (log cleared), and consider making the log larger (see the Script Host Audit README).",
            SecurityLog),
        [("ScriptHostAudit", "STATE_SAVE_FAILED")] = _ => WatchdogState,
        [("ScriptHostAudit", "STATE_UNREADABLE")] = _ => WatchdogState,
    };

    /// <summary>Guidance for an alert. Every alert gets some; an alert this version does not know gets a general entry.</summary>
    public static AlertGuidance For(ProtectionAlert alert)
    {
        var code = alert.Code;
        if (code.EndsWith(AlertEventIds.ClearedSuffix, StringComparison.Ordinal))
            return Undone("The problem this alert was about has cleared. Nothing to do.");
        if (string.Equals(alert.Module, "DefenderWatchdog", StringComparison.OrdinalIgnoreCase)
            && code.StartsWith("BROAD_EXCLUSION:", StringComparison.Ordinal))
        {
            return G(
                "Defender has an exclusion so broad that malware can hide behind it: a whole drive, a common file type, or a common program.",
                "Broad exclusions are rarely needed. Open the virus protection settings, go to Exclusions, and remove it unless a program you trust documents that it needs it.",
                VirusSettings);
        }
        if (Entries.TryGetValue((alert.Module, code), out var entry) || Entries.TryGetValue((AnyModule, code), out entry))
            return entry(alert);
        return G("WatchLattice reported something this version has no explanation for yet.",
                "Read the details below. If it isn't clear, export the alert and ask in the project's GitHub issues.",
                ApplicationLog);
    }

    /// <summary>True when the catalog has its own entry for this (module, code), for tests.</summary>
    public static bool HasEntry(string module, string code) => Entries.ContainsKey((module, code)) || Entries.ContainsKey((AnyModule, code))
        || (string.Equals(module, "DefenderWatchdog", StringComparison.OrdinalIgnoreCase) && code.StartsWith("BROAD_EXCLUSION:", StringComparison.Ordinal));

    private static AlertGuidance Canary(ProtectionAlert alert, string what) => G(
        $"A canary file was {what}. Canaries are decoy documents nothing should touch; ransomware encrypts, renames or deletes files like these first.",
        "If you opened, moved or deleted the file yourself, acknowledge it. If not, act now: disconnect the PC from the network, run a Defender quick scan, and check whether your other documents still open.",
        PathActions(alert.Resource).Append(QuickScan).Append(WindowsSecurity).ToArray());

    private static AlertGuidance DefenderOff(string what) => G(
        what + " Without it, Windows has no antivirus protection unless another antivirus is installed.",
        "Expected only if you installed another antivirus. Otherwise open Windows Security and turn it back on; if it won't turn on, run a scan with another trusted tool, because some malware switches Defender off.",
        WindowsSecurity);

    private static AlertGuidance DefenderSetting(string what) => G(
        what + " Malware often weakens Defender before doing anything else.",
        IfYouDidIt + " " + IfNot + " open the virus protection settings, switch it back, and run a Defender quick scan.",
        VirusSettings, QuickScan);

    private static AlertGuidance Signatures(string what) => G(
        what + " Out-of-date definitions are often just a PC that has been off or offline, but malware sometimes blocks updates.",
        "Open Windows Security and choose Protection updates > Check for updates. If updates fail, check the hosts file and proxy alerts too.",
        WindowsSecurity);

    private static AlertGuidance Exclusion() => G(
        "A new Defender exclusion tells Defender not to scan a file, folder, file type or program. Malware adds exclusions to hide from it.",
        "Some games, developer tools and backup programs ask for exclusions. " + IfNot + " open the virus protection settings, go to Exclusions, remove it, and run a Defender quick scan.",
        VirusSettings, QuickScan);

    private static AlertGuidance FirewallOff(string profile) => G(
        $"Windows Firewall is off for the {profile} network profile, so other devices on that kind of network can reach programs on this PC.",
        IfYouDidIt + " " + IfNot + " open the firewall settings and turn it back on.",
        Firewall);

    private static AlertGuidance InboundAllow(string profile) => G(
        $"The {profile} network profile now lets other devices connect to this PC by default, instead of only through allowed rules.",
        "This is rarely what anyone wants. Open the firewall settings and set incoming connections back to blocked unless your administrator chose this.",
        Firewall);

    private static AlertGuidance InboundChanged(string profile) => G(
        $"The default for incoming connections on the {profile} network profile changed.",
        IfYouDidIt + " If it now allows connections and nobody chose that, open the firewall settings and set it back to blocked.",
        Firewall);

    private static AlertGuidance NewRule() => G(
        "A new firewall rule lets other devices connect to a program on this PC. Installers add these for games, chat and file sharing; malware adds them to accept remote commands.",
        IfYouDidIt + " " + IfNot + " open the firewall settings, find the rule named in the details, and remove it.",
        Firewall);

    private static AlertGuidance Extension() => G(
        "A browser extension appeared. Extensions can read and change the pages you visit, so a bad one can steal passwords or inject ads.",
        "If you installed it, acknowledge or approve it. If you didn't, open the browser's extensions page (for example edge://extensions), remove it, and run a Defender quick scan, because programs can install extensions behind your back.",
        QuickScan);

    private static AlertGuidance ExtensionPolicy() => G(
        "A policy now forces a browser extension onto this PC, so it can't be removed from the browser itself. Organizations use this; adware and malware use it too.",
        "On a work PC, ask whoever manages it. On a personal PC with no administrator, this is suspicious: run a Defender quick scan, then remove the policy entry named in the details (in the registry, as an administrator) or use a trusted removal tool.",
        QuickScan);

    private static AlertGuidance ScriptHost() => G(
        "A scripting or system tool (PowerShell, mshta, wscript, rundll32, certutil or similar) was started in a way malware often uses: by an Office app or browser, from a temporary folder, or with a hidden or encoded command.",
        "Many admin tools and installers do this harmlessly. Check what started it and the command line in the details. If you don't recognize it, run a Defender quick scan; if it is a known tool, approve it as baseline.",
        QuickScan, SecurityLog);

    private static AlertGuidance Autostart(ProtectionAlert alert, string what) => G(
        what + ". That is how most software starts with Windows, and also how malware survives a restart.",
        IfYouDidIt + " Approve it as baseline if you want WatchLattice to stop reporting it. If you don't recognize it, look up the program named in the details, disable it, and run a Defender quick scan.",
        AutostartActions(alert.Resource).Append(QuickScan).ToArray());

    private static AlertGuidance Baseline(string what) => G(
        $"WatchLattice recorded how {what} look right now, to compare later checks against. This is an inventory, not a verdict that everything in it is safe.",
        "Nothing to do. From now on only changes are reported.");

    private static AlertGuidance Undone(string what) => G(what, "Nothing to do.");

    /// <summary>The built-in screens that show a persistence source, from the alert's resource.</summary>
    private static IEnumerable<SafeAction> AutostartActions(string? resource)
    {
        if (resource is null) yield break;
        if (resource.StartsWith("Registry/", StringComparison.OrdinalIgnoreCase)) yield return StartupApps;
        else if (resource.StartsWith("Startup/", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var action in PathActions(resource["Startup/".Length..].Replace('/', '\\'))) yield return action;
            yield return StartupApps;
        }
        else if (resource.StartsWith("ScheduledTasks/", StringComparison.OrdinalIgnoreCase)) yield return TaskScheduler;
        else if (resource.StartsWith("Services/", StringComparison.OrdinalIgnoreCase)) yield return Services;
    }

    /// <summary>Open file location, only when the resource is a plain local absolute path.</summary>
    private static IEnumerable<SafeAction> PathActions(string? resource)
    {
        if (SafeActionLauncher.IsLocalPath(resource)) yield return FileLocation(resource!);
    }

    private sealed class ModuleCodeComparer : IEqualityComparer<(string Module, string Code)>
    {
        public bool Equals((string Module, string Code) x, (string Module, string Code) y) =>
            string.Equals(x.Module, y.Module, StringComparison.OrdinalIgnoreCase) && string.Equals(x.Code, y.Code, StringComparison.Ordinal);

        public int GetHashCode((string Module, string Code) obj) =>
            HashCode.Combine(StringComparer.OrdinalIgnoreCase.GetHashCode(obj.Module), StringComparer.Ordinal.GetHashCode(obj.Code));
    }
}

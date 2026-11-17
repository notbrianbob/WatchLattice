using WatchLattice.Common.Alerts;

namespace WatchLattice.Common.Checkup;

/// <summary>How one checkup item came out, from best to worst. Unknown means it couldn't be read.</summary>
public enum CheckupStatus
{
    Good,
    Advice,
    Risk,
    Unknown,
}

/// <summary>One line of the checkup: what was found, why it matters, and how to change it.</summary>
public sealed record CheckupItem(
    string Id,
    string Title,
    CheckupStatus Status,
    string Finding,
    string WhyItMatters,
    string HowToChange,
    SafeAction? Action = null);

/// <summary>What Microsoft Defender reports about itself, as far as a standard user can read it.</summary>
public sealed record DefenderFacts(
    bool Available,
    bool? RealTimeProtection,
    bool? TamperProtection,
    DateTimeOffset? SignaturesUpdated,
    string? Problem = null);

/// <summary>Reads values under HKEY_LOCAL_MACHINE. Abstracted so the checks are testable anywhere.</summary>
public interface IMachineRegistry
{
    /// <summary>The value, or null when the key or value is missing.</summary>
    object? Read(string key, string name);

    /// <summary>True when the key exists.</summary>
    bool KeyExists(string key);
}

/// <summary>
/// A read-only look at Windows settings that make attacks harder. Every
/// check reads a value a standard user can read; nothing is changed, and no
/// administrator rights are needed. Each item says what it found, why it
/// matters, and where in Windows to change it, so the person decides.
/// Settings that a device's organisation manages can differ for good reasons,
/// so nothing here is called a vulnerability.
/// </summary>
public static class SecurityCheckup
{
    private const string Policies = @"SOFTWARE\Policies\Microsoft";
    private const string FirewallPolicy = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";
    private const string SystemPolicies = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    private const string TerminalServer = @"SYSTEM\CurrentControlSet\Control\Terminal Server";
    private const string RdpTcp = TerminalServer + @"\WinStations\RDP-Tcp";

    private static readonly SafeAction WindowsSecurity = new(SafeActionKind.OpenWindowsSecurity, "Open Windows Security");
    private static readonly SafeAction VirusSettings = new(SafeActionKind.OpenVirusProtectionSettings, "Open virus protection settings");
    private static readonly SafeAction Firewall = new(SafeActionKind.OpenFirewallSettings, "Open firewall settings");
    private static readonly SafeAction DeviceSecurity = new(SafeActionKind.OpenDeviceSecurity, "Open device security");
    private static readonly SafeAction AppBrowser = new(SafeActionKind.OpenAppAndBrowserControl, "Open app & browser control");
    private static readonly SafeAction WindowsUpdate = new(SafeActionKind.OpenWindowsUpdate, "Open Windows Update");
    private static readonly SafeAction RemoteDesktop = new(SafeActionKind.OpenRemoteDesktopSettings, "Open Remote Desktop settings");

    /// <summary>Security intelligence older than this is worth a look; three times as old is a risk.</summary>
    public static readonly TimeSpan SignatureAgeLimit = TimeSpan.FromDays(3);

    public static IReadOnlyList<CheckupItem> Run(IMachineRegistry registry, DefenderFacts? defender, AlertSnapshot? hub, DateTimeOffset now) => new[]
    {
        Safely("watchlattice", "WatchLattice is running", () => WatchLattice(hub, now)),
        Safely("defender-realtime", "Defender real-time protection", () => RealTime(defender)),
        Safely("defender-tamper", "Defender tamper protection", () => Tamper(defender)),
        Safely("defender-signatures", "Defender security intelligence", () => Signatures(defender, now)),
        Safely("firewall", "Windows Firewall", () => FirewallProfiles(registry)),
        Safely("uac", "User Account Control", () => Uac(registry)),
        Safely("smartscreen", "SmartScreen for apps and files", () => SmartScreen(registry)),
        Safely("remote-desktop", "Remote Desktop", () => Rdp(registry)),
        Safely("smb1", "SMBv1 file sharing", () => Smb1(registry)),
        Safely("secure-boot", "Secure Boot", () => SecureBoot(registry)),
        Safely("memory-integrity", "Memory integrity", () => MemoryIntegrity(registry)),
        Safely("lsa-protection", "Local Security Authority protection", () => LsaProtection(registry)),
    };

    /// <summary>A short summary line, such as "9 good • 2 to consider • 1 to fix".</summary>
    public static string Summary(IReadOnlyList<CheckupItem> items)
    {
        var parts = new List<string> { $"{items.Count(i => i.Status == CheckupStatus.Good)} good" };
        var advice = items.Count(i => i.Status == CheckupStatus.Advice);
        var risk = items.Count(i => i.Status == CheckupStatus.Risk);
        var unknown = items.Count(i => i.Status == CheckupStatus.Unknown);
        if (risk > 0) parts.Add($"{risk} to fix");
        if (advice > 0) parts.Add($"{advice} to consider");
        if (unknown > 0) parts.Add($"{unknown} couldn't be checked");
        return string.Join(" • ", parts);
    }

    private static CheckupItem Safely(string id, string title, Func<(CheckupStatus, string, string, string, SafeAction?)> check)
    {
        try
        {
            var (status, finding, why, how, action) = check();
            return new CheckupItem(id, title, status, finding, why, how, action);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException or PlatformNotSupportedException)
        {
            return new CheckupItem(id, title, CheckupStatus.Unknown, "Couldn't be read: " + ex.Message,
                "", "Nothing to do: this item is left out of the result.");
        }
    }

    private static (CheckupStatus, string, string, string, SafeAction?) WatchLattice(AlertSnapshot? hub, DateTimeOffset now)
    {
        const string Why = "WatchLattice only watches while its service runs.";
        const string How = "Start the \"ScanAlways Protection\" service in Services, or reinstall from the latest release. The dashboard's Overview tab shows each module.";
        if (hub is null) return (CheckupStatus.Unknown, "The service's alert feed hasn't been read yet.", Why, How, null);
        if (!hub.IsFresh(now)) return (CheckupStatus.Risk, $"The service hasn't reported since {hub.HeartbeatAt.ToLocalTime():g}.", Why, How, null);
        var troubled = hub.Modules.Where(m => m.State is ModuleRunState.Failed or ModuleRunState.Restarting or ModuleRunState.Finished).Select(m => m.Id).ToArray();
        return troubled.Length > 0
            ? (CheckupStatus.Advice, $"Running, but {string.Join(", ", troubled)} {(troubled.Length == 1 ? "has" : "have")} stopped.", Why, How, null)
            : (CheckupStatus.Good, $"Running, with {hub.Modules.Count(m => m.State == ModuleRunState.Running)} modules watching.", Why, How, null);
    }

    private static (CheckupStatus, string, string, string, SafeAction?) RealTime(DefenderFacts? defender)
    {
        const string Why = "Real-time protection scans files as they are opened or downloaded. Without it, Defender only finds malware when a scan runs.";
        const string How = "Windows Security > Virus & threat protection > Manage settings > Real-time protection. If another antivirus is installed, it may have turned Defender's off on purpose.";
        return defender switch
        {
            null or { Available: false } => (CheckupStatus.Unknown, Unreadable(defender), Why, How, WindowsSecurity),
            { RealTimeProtection: true } => (CheckupStatus.Good, "On.", Why, How, VirusSettings),
            { RealTimeProtection: false } => (CheckupStatus.Risk, "Off.", Why, How, VirusSettings),
            _ => (CheckupStatus.Unknown, "Defender didn't say.", Why, How, VirusSettings),
        };
    }

    private static (CheckupStatus, string, string, string, SafeAction?) Tamper(DefenderFacts? defender)
    {
        const string Why = "Tamper protection stops other programs, including malware running as administrator, from turning Defender's protection off.";
        const string How = "Windows Security > Virus & threat protection > Manage settings > Tamper protection.";
        return defender switch
        {
            null or { Available: false } => (CheckupStatus.Unknown, Unreadable(defender), Why, How, WindowsSecurity),
            { TamperProtection: true } => (CheckupStatus.Good, "On.", Why, How, VirusSettings),
            { TamperProtection: false } => (CheckupStatus.Risk, "Off.", Why, How, VirusSettings),
            _ => (CheckupStatus.Unknown, "Defender didn't say.", Why, How, VirusSettings),
        };
    }

    private static (CheckupStatus, string, string, string, SafeAction?) Signatures(DefenderFacts? defender, DateTimeOffset now)
    {
        const string Why = "Defender recognises new malware from its security intelligence, which normally updates several times a day.";
        const string How = "Windows Update > Check for updates, or Windows Security > Virus & threat protection > Protection updates.";
        if (defender is null or { Available: false }) return (CheckupStatus.Unknown, Unreadable(defender), Why, How, WindowsSecurity);
        if (defender.SignaturesUpdated is not { } updated) return (CheckupStatus.Unknown, "Defender didn't say when it last updated.", Why, How, WindowsUpdate);
        var age = now - updated;
        var finding = $"Last updated {updated.ToLocalTime():g} ({Days(age)}).";
        if (age <= SignatureAgeLimit) return (CheckupStatus.Good, finding, Why, How, WindowsUpdate);
        return (age <= SignatureAgeLimit * 3 ? CheckupStatus.Advice : CheckupStatus.Risk, finding, Why, How, WindowsUpdate);
    }

    private static (CheckupStatus, string, string, string, SafeAction?) FirewallProfiles(IMachineRegistry registry)
    {
        const string Why = "The firewall blocks unrequested connections from the network, which is how worms and many remote attacks get in.";
        const string How = "Windows Security > Firewall & network protection. Turn it on for each network type.";
        var off = new List<string>();
        var unknown = new List<string>();
        foreach (var (profile, policy, name) in new[] { ("DomainProfile", "DomainProfile", "domain"), ("StandardProfile", "PrivateProfile", "private"), ("PublicProfile", "PublicProfile", "public") })
        {
            // Group Policy wins over the local setting.
            var value = Dword(registry, $@"{Policies}\WindowsFirewall\{policy}", "EnableFirewall")
                ?? Dword(registry, $@"{FirewallPolicy}\{profile}", "EnableFirewall");
            if (value is null) unknown.Add(name);
            else if (value == 0) off.Add(name);
        }
        if (off.Count > 0)
            return (off.Contains("public") ? CheckupStatus.Risk : CheckupStatus.Advice, $"Off for {Join(off)} networks.", Why, How, Firewall);
        if (unknown.Count == 3) return (CheckupStatus.Unknown, "The firewall settings couldn't be found.", Why, How, Firewall);
        return (CheckupStatus.Good, unknown.Count == 0 ? "On for every network type." : $"On ({Join(unknown)} not reported).", Why, How, Firewall);
    }

    private static (CheckupStatus, string, string, string, SafeAction?) Uac(IMachineRegistry registry)
    {
        const string Why = "User Account Control asks before a program gets administrator rights, so malware can't quietly take over the whole PC.";
        const string How = "Search the Start menu for \"Change User Account Control settings\" and keep the slider on one of the top two levels. Changing it needs an administrator.";
        var lua = Dword(registry, SystemPolicies, "EnableLUA");
        var consent = Dword(registry, SystemPolicies, "ConsentPromptBehaviorAdmin");
        var secureDesktop = Dword(registry, SystemPolicies, "PromptOnSecureDesktop");
        if (lua == 0) return (CheckupStatus.Risk, "Turned off: every administrator program runs with full rights without asking.", Why, How, null);
        if (consent == 0) return (CheckupStatus.Risk, "On, but administrators are never asked: programs are elevated silently.", Why, How, null);
        if (secureDesktop == 0) return (CheckupStatus.Advice, "On, but the prompt isn't shown on the secure desktop, so other programs could click it.", Why, How, null);
        if (lua is null) return (CheckupStatus.Unknown, "The setting couldn't be found.", Why, How, null);
        return (CheckupStatus.Good, "On, and asks before elevating.", Why, How, null);
    }

    private static (CheckupStatus, string, string, string, SafeAction?) SmartScreen(IMachineRegistry registry)
    {
        const string Why = "SmartScreen warns before running downloaded programs that are unknown or reported as malicious.";
        const string How = "Windows Security > App & browser control > Reputation-based protection > Check apps and files.";
        var policy = Dword(registry, $@"{Policies}\Windows\System", "EnableSmartScreen");
        var local = registry.Read(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled") as string;
        if (policy == 0) return (CheckupStatus.Risk, "Turned off by policy.", Why, How, AppBrowser);
        if (string.Equals(local, "Off", StringComparison.OrdinalIgnoreCase)) return (CheckupStatus.Risk, "Off.", Why, How, AppBrowser);
        return (CheckupStatus.Good, "No sign that it has been turned off.", Why, How, AppBrowser);
    }

    private static (CheckupStatus, string, string, string, SafeAction?) Rdp(IMachineRegistry registry)
    {
        const string Why = "Remote Desktop lets anyone who can reach this PC try to sign in. It is a common way in for ransomware gangs, especially without Network Level Authentication.";
        const string How = "Settings > System > Remote Desktop. Turn it off if you don't use it; if you do, keep \"Require devices to use Network Level Authentication\" on.";
        var denied = Dword(registry, $@"{Policies}\Windows NT\Terminal Services", "fDenyTSConnections")
            ?? Dword(registry, TerminalServer, "fDenyTSConnections");
        if (denied is null) return (CheckupStatus.Unknown, "The setting couldn't be found.", Why, How, RemoteDesktop);
        if (denied != 0) return (CheckupStatus.Good, "Off.", Why, How, RemoteDesktop);
        var nla = Dword(registry, $@"{Policies}\Windows NT\Terminal Services", "UserAuthentication") ?? Dword(registry, RdpTcp, "UserAuthentication");
        return nla == 0
            ? (CheckupStatus.Risk, "On, without Network Level Authentication: anyone who can reach the PC sees the sign-in screen.", Why, How, RemoteDesktop)
            : (CheckupStatus.Advice, "On, with Network Level Authentication. Fine if you use it; turn it off if you don't.", Why, How, RemoteDesktop);
    }

    private static (CheckupStatus, string, string, string, SafeAction?) Smb1(IMachineRegistry registry)
    {
        const string Why = "SMBv1 is the 30-year-old file sharing protocol that WannaCry and NotPetya spread through. Windows 11 doesn't install it unless something asks for it.";
        const string How = "Control Panel > Programs > Turn Windows features on or off > clear \"SMB 1.0/CIFS File Sharing Support\". Changing it needs an administrator and a restart.";
        var server = Dword(registry, @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1");
        var clientInstalled = registry.KeyExists(@"SYSTEM\CurrentControlSet\Services\mrxsmb10");
        var clientStart = clientInstalled ? Dword(registry, @"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start") : null;
        var clientOn = clientInstalled && clientStart != 4;
        if (server == 1 || clientOn)
            return (CheckupStatus.Risk, server == 1 ? "Installed and enabled for sharing." : "The SMBv1 client is installed and enabled.", Why, How, null);
        return (CheckupStatus.Good, "Not installed or turned off.", Why, How, null);
    }

    private static (CheckupStatus, string, string, string, SafeAction?) SecureBoot(IMachineRegistry registry)
    {
        const string Why = "Secure Boot only starts a signed Windows boot loader, which stops bootkits that load before Windows and Defender.";
        const string How = "It is turned on in the PC's UEFI firmware settings, not in Windows. Check the PC maker's instructions before changing firmware settings.";
        var value = Dword(registry, @"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled");
        return value switch
        {
            1 => (CheckupStatus.Good, "On.", Why, How, DeviceSecurity),
            0 => (CheckupStatus.Advice, "Off.", Why, How, DeviceSecurity),
            _ => (CheckupStatus.Advice, "Not supported or not reported: this PC may start in legacy BIOS mode.", Why, How, DeviceSecurity),
        };
    }

    private static (CheckupStatus, string, string, string, SafeAction?) MemoryIntegrity(IMachineRegistry registry)
    {
        const string Why = "Memory integrity uses virtualization to stop untrusted drivers and kernel code from loading, a common way to disable security software.";
        const string How = "Windows Security > Device security > Core isolation details > Memory integrity. A few old drivers aren't compatible; Windows lists them if so.";
        var value = Dword(registry, @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled");
        return value == 1
            ? (CheckupStatus.Good, "On.", Why, How, DeviceSecurity)
            : (CheckupStatus.Advice, "Off.", Why, How, DeviceSecurity);
    }

    private static (CheckupStatus, string, string, string, SafeAction?) LsaProtection(IMachineRegistry registry)
    {
        const string Why = "LSA protection keeps other programs from reading sign-in secrets out of memory, which credential-stealing tools try to do.";
        const string How = "Windows Security > Device security > Core isolation details > Local Security Authority protection. It needs a restart.";
        var value = Dword(registry, @"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL");
        return value is 1 or 2
            ? (CheckupStatus.Good, "On.", Why, How, DeviceSecurity)
            : (CheckupStatus.Advice, "Off.", Why, How, DeviceSecurity);
    }

    private static int? Dword(IMachineRegistry registry, string key, string name) => registry.Read(key, name) switch
    {
        int i => i,
        long l => (int)l,
        _ => null,
    };

    private static string Unreadable(DefenderFacts? defender) =>
        defender?.Problem is { } problem ? "Defender's status couldn't be read: " + problem : "Defender's status couldn't be read.";

    private static string Days(TimeSpan age) => age.TotalHours < 24 ? "today" : age.TotalDays < 2 ? "1 day ago" : $"{(int)age.TotalDays} days ago";

    private static string Join(IReadOnlyList<string> names) =>
        names.Count == 1 ? names[0] : string.Join(", ", names.Take(names.Count - 1)) + " and " + names[^1];
}

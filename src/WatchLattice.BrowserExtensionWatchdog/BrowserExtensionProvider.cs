using System.Runtime.Versioning;
using System.Security;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Microsoft.Win32;

namespace WatchLattice.BrowserExtensionWatchdog;

/// <summary>Reads installed extensions and extension policies. Abstracted so the watchdog is testable without Windows.</summary>
public interface IBrowserExtensionProvider
{
    Task<BrowserExtensionSnapshot> ReadAsync(CancellationToken cancellationToken);
}

/// <summary>
/// Finds every Windows user profile (from the ProfileList, or the folders in
/// <see cref="BrowserExtensionWatchdogOptions.UserProfileFolders"/>) and reads
/// each one's Edge, Chrome and Firefox profiles from disk, then the extension
/// policies from the registry. The hub runs as LocalSystem, so it can read
/// every user's folders; run without administrator rights, it reads only the
/// current user's. Strictly read-only: nothing is written, deleted or launched,
/// and browsers are never started.
/// </summary>
public sealed class BrowserExtensionProvider : IBrowserExtensionProvider
{
    public const string ProfileListKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

    private readonly BrowserExtensionWatchdogOptions _options;
    private readonly IExtensionPolicyReader _policies;

    public BrowserExtensionProvider(IOptions<BrowserExtensionWatchdogOptions> options, IExtensionPolicyReader? policies = null)
    {
        _options = options.Value;
        _policies = policies ?? new WindowsExtensionPolicyReader();
    }

    public Task<BrowserExtensionSnapshot> ReadAsync(CancellationToken cancellationToken) =>
        Task.Run(() => Read(cancellationToken), cancellationToken);

    private BrowserExtensionSnapshot Read(CancellationToken cancellationToken)
    {
        var browsers = _options.EnabledBrowsers();
        var maxBytes = Math.Max(64 * 1024, _options.MaxFileBytes);
        var users = new List<UserScan>();
        var accounts = Accounts();

        foreach (var account in accounts)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!CanRead(account))
            {
                continue;
            }

            var profiles = new List<BrowserProfile>();
            var errors = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var browser in browsers)
            {
                try
                {
                    profiles.AddRange(browser == Browsers.Firefox
                        ? FirefoxProfileReader.Read(account.Id, account.Name, Path.Join(account.Roaming, "Mozilla", "Firefox"), maxBytes, cancellationToken)
                        : ChromiumProfileReader.Read(browser, account.Id, account.Name, ChromiumUserData(browser, account.Local), maxBytes, cancellationToken));
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException or JsonException or InvalidDataException)
                {
                    errors[browser] = ex.Message;
                }
            }
            users.Add(new UserScan(account.Id, account.Name, profiles) { BrowserErrors = errors });
        }

        var snapshot = new BrowserExtensionSnapshot { Users = users };
        if (!_options.WatchPolicies)
        {
            return snapshot;
        }
        try
        {
            var sids = accounts.Where(a => a.Sid is not null).Select(a => (a.Sid!, a.Name)).ToList();
            var (entries, scopes) = _policies.Read(browsers, sids, cancellationToken);
            return snapshot with { Policies = entries, PolicyScopes = scopes };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException or PlatformNotSupportedException)
        {
            return snapshot with { PolicyError = ex.Message };
        }
    }

    public static string ChromiumUserData(string browser, string localAppData) => browser == Browsers.Edge
        ? Path.Join(localAppData, "Microsoft", "Edge", "User Data")
        : Path.Join(localAppData, "Google", "Chrome", "User Data");

    private sealed record Account(string Id, string? Sid, string Name, string Home, string Local, string Roaming, bool IsSelf);

    private static bool CanRead(Account account)
    {
        try
        {
            if (!Directory.Exists(account.Home))
            {
                return false;
            }
            // Without administrator rights other users' folders are off limits; that's expected, not a finding.
            _ = Directory.EnumerateFileSystemEntries(account.Home).Take(1).Count();
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException)
        {
            return account.IsSelf;
        }
    }

    private List<Account> Accounts()
    {
        var configured = (_options.UserProfileFolders ?? Array.Empty<string>()).Where(f => !string.IsNullOrWhiteSpace(f)).ToList();
        if (configured.Count > 0)
        {
            return configured
                .Select(f => Path.GetFullPath(Environment.ExpandEnvironmentVariables(f.Trim())))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Select(home => FromHome("Folder:" + home, null, Path.GetFileName(Path.TrimEndingDirectorySeparator(home)), home, isSelf: false))
                .ToList();
        }

        var accounts = OperatingSystem.IsWindows() ? WindowsAccounts() : new List<Account>();
        if (accounts.All(a => !a.IsSelf))
        {
            // The account the hub runs as, when it has no ProfileList entry of
            // its own (LocalSystem) or this is not Windows.
            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (!string.IsNullOrEmpty(home))
            {
                var sid = OperatingSystem.IsWindows() ? CurrentSid() : null;
                accounts.Add(new Account(sid is null ? "Self:" + Environment.UserName : "User:" + sid, sid, Environment.UserName, home,
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), IsSelf: true));
            }
        }
        return accounts;
    }

    private static Account FromHome(string id, string? sid, string name, string home, bool isSelf) =>
        new(id, sid, name, home, Path.Join(home, "AppData", "Local"), Path.Join(home, "AppData", "Roaming"), isSelf);

    [SupportedOSPlatform("windows")]
    private static string? CurrentSid()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.User?.Value;
    }

    /// <summary>Local, domain and Entra ID user profiles from the ProfileList.</summary>
    [SupportedOSPlatform("windows")]
    private static List<Account> WindowsAccounts()
    {
        var self = CurrentSid();
        var accounts = new List<Account>();
        try
        {
            using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var list = root.OpenSubKey(ProfileListKey, writable: false);
            foreach (var sid in list?.GetSubKeyNames() ?? Array.Empty<string>())
            {
                if (!sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) && !sid.StartsWith("S-1-12-1-", StringComparison.OrdinalIgnoreCase)
                    || sid.EndsWith(".bak", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
                using var key = list!.OpenSubKey(sid, writable: false);
                if (key?.GetValue("ProfileImagePath") is not string { Length: > 0 } home)
                {
                    continue;
                }
                var isSelf = string.Equals(sid, self, StringComparison.OrdinalIgnoreCase);
                var account = FromHome("User:" + sid, sid, AccountName(sid), Environment.ExpandEnvironmentVariables(home).Trim(), isSelf);
                if (isSelf)
                {
                    // The current account's own folders also follow folder redirection.
                    account = account with
                    {
                        Local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                        Roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    };
                }
                accounts.Add(account);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException)
        {
            // Fall back to the current account below.
        }
        return accounts.OrderBy(a => a.Id, StringComparer.OrdinalIgnoreCase).ToList();
    }

    [SupportedOSPlatform("windows")]
    private static string AccountName(string sid)
    {
        try
        {
            return new SecurityIdentifier(sid).Translate(typeof(NTAccount)).Value;
        }
        catch (SystemException)
        {
            // Unknown or deleted account: the SID is still a stable name.
            return sid;
        }
    }
}

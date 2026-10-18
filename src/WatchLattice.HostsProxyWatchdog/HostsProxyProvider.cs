using System.Runtime.Versioning;
using System.Security;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.Win32;

namespace WatchLattice.HostsProxyWatchdog;

/// <summary>Reads the hosts file and proxy settings. Abstracted so the watchdog is testable without Windows.</summary>
public interface IHostsProxyProvider
{
    Task<HostsProxySnapshot> ReadAsync(bool hosts, bool proxy, CancellationToken cancellationToken);
}

/// <summary>
/// Reads the hosts file Windows actually uses (following Tcpip's
/// <c>DataBasePath</c>) and the documented proxy settings in the registry:
/// WinINET per user and per machine (values, policies and the binary
/// <c>DefaultConnectionSettings</c>), WinHTTP's <c>WinHttpSettings</c>, and
/// the <c>HTTP_PROXY</c>-style environment variables many tools honor.
/// Strictly read-only: every file and registry key is opened for reading,
/// and nothing is ever written, deleted or launched.
/// </summary>
public sealed class WindowsHostsProxyProvider : IHostsProxyProvider
{
    public const string TcpipParametersKey = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";
    public const string InternetSettingsKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    public const string InternetSettingsPolicyKey = @"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings";
    public const string MachineEnvironmentKey = @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";

    private static readonly string[] WinInetValues = { "ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL" };
    private static readonly string[] PolicyValues = { "ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL", "ProxySettingsPerUser" };
    private static readonly string[] EnvironmentValues = { "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY" };
    private const int MaxValueLength = 4096;

    private readonly HostsProxyWatchdogOptions _options;

    public WindowsHostsProxyProvider(IOptions<HostsProxyWatchdogOptions> options) => _options = options.Value;

    public Task<HostsProxySnapshot> ReadAsync(bool hosts, bool proxy, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var snapshot = new HostsProxySnapshot { Hosts = hosts ? ReadHosts() : null };
        if (proxy)
        {
            snapshot = OperatingSystem.IsWindows()
                ? snapshot with { Proxy = ReadProxyScopes(cancellationToken) }
                : snapshot with { ProxyError = "Proxy settings are only available on Windows." };
        }
        return Task.FromResult(snapshot);
    }

    private HostsFileSnapshot ReadHosts()
    {
        string path;
        string? databasePath = null;
        var moved = false;
        if (!string.IsNullOrWhiteSpace(_options.HostsFilePath))
        {
            path = Path.GetFullPath(Environment.ExpandEnvironmentVariables(_options.HostsFilePath));
        }
        else if (OperatingSystem.IsWindows())
        {
            var defaultFolder = Path.Join(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "drivers", "etc");
            try
            {
                databasePath = ReadDatabasePath() ?? defaultFolder;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException)
            {
                return HostsFileSnapshot.Unavailable(Path.Join(defaultFolder, "hosts"), $"Could not read where Windows keeps the hosts file: {ex.Message}");
            }
            moved = !string.Equals(Path.TrimEndingDirectorySeparator(databasePath),
                Path.TrimEndingDirectorySeparator(defaultFolder), StringComparison.OrdinalIgnoreCase);
            path = Path.Join(databasePath, "hosts");
        }
        else
        {
            return HostsFileSnapshot.Unavailable("hosts", "The Windows hosts file is only available on Windows; set HostsFilePath to watch another file.");
        }

        var snapshot = new HostsFileSnapshot { Path = path, DatabasePath = databasePath, DatabasePathMoved = moved };
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (stream.Length > _options.MaxHostsFileBytes)
            {
                return snapshot with { Error = $"The file is {stream.Length:N0} bytes, over the {_options.MaxHostsFileBytes:N0}-byte MaxHostsFileBytes limit." };
            }
            using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            return snapshot with { Entries = HostsFileParser.Parse(reader.ReadToEnd()) };
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            // Windows resolves names normally without a hosts file, so no file means no entries.
            return snapshot with { Entries = new Dictionary<string, IReadOnlyList<string>>() };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException)
        {
            return snapshot with { Error = ex.Message };
        }
    }

    [SupportedOSPlatform("windows")]
    private static string? ReadDatabasePath()
    {
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
        using var key = root.OpenSubKey(TcpipParametersKey, writable: false);
        return key?.GetValue("DataBasePath") is string { Length: > 0 } value
            ? Environment.ExpandEnvironmentVariables(value).Trim()
            : null;
    }

    [SupportedOSPlatform("windows")]
    private static IReadOnlyList<ProxyScope> ReadProxyScopes(CancellationToken cancellationToken)
    {
        var scopes = new List<ProxyScope>();
        using var identity = WindowsIdentity.GetCurrent();
        var self = identity.User?.Value;

        foreach (var sid in UserHives(self))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var scope = ReadScope($"User:{sid}", $"user {AccountName(sid)}", RegistryHive.Users, sid + @"\", @"Environment");
            // Without administrator rights other users' hives are off limits; that's expected, not a finding.
            if (scope.Error is null || sid == self)
            {
                scopes.Add(scope);
            }
        }

        cancellationToken.ThrowIfCancellationRequested();
        scopes.Add(ReadScope("Machine", "this computer (all users)", RegistryHive.LocalMachine, "", MachineEnvironmentKey));
        scopes.Add(ReadWinHttp());
        return scopes;
    }

    /// <summary>Loaded user hives: signed-in local, domain and Entra ID accounts, LocalSystem, and the current account.</summary>
    [SupportedOSPlatform("windows")]
    private static IEnumerable<string> UserHives(string? self)
    {
        string[] names;
        try
        {
            using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default);
            names = users.GetSubKeyNames();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException)
        {
            names = Array.Empty<string>();
        }

        return names
            .Where(n => !n.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)
                        && (n.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)
                            || n.StartsWith("S-1-12-1-", StringComparison.OrdinalIgnoreCase)
                            || n.Equals("S-1-5-18", StringComparison.OrdinalIgnoreCase)))
            .Concat(self is null ? Array.Empty<string>() : new[] { self })
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(n => n, StringComparer.OrdinalIgnoreCase);
    }

    [SupportedOSPlatform("windows")]
    private static ProxyScope ReadScope(string id, string displayName, RegistryHive hive, string prefix, string environmentKey)
    {
        var values = new SortedDictionary<string, string>(StringComparer.Ordinal);
        try
        {
            using var root = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
            using (var key = root.OpenSubKey(prefix + InternetSettingsKey, writable: false))
            {
                AddValues(values, key, "", WinInetValues);
            }
            using (var key = root.OpenSubKey(prefix + InternetSettingsKey + @"\Connections", writable: false))
            {
                if (key?.GetValue("DefaultConnectionSettings") is byte[] blob)
                {
                    ConnectionSettingsBlob.AddTo(values, "Connection.", blob, winInet: true);
                }
            }
            using (var key = root.OpenSubKey(prefix + InternetSettingsPolicyKey, writable: false))
            {
                AddValues(values, key, "Policy.", PolicyValues);
            }
            using (var key = root.OpenSubKey(prefix + environmentKey, writable: false))
            {
                AddValues(values, key, "Env.", EnvironmentValues);
            }
            return new ProxyScope(id, displayName, values);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException)
        {
            return new ProxyScope(id, displayName, new Dictionary<string, string>(), ex.Message);
        }
    }

    [SupportedOSPlatform("windows")]
    private static ProxyScope ReadWinHttp()
    {
        const string id = "WinHTTP";
        const string displayName = "WinHTTP (Windows services and updates)";
        var values = new SortedDictionary<string, string>(StringComparer.Ordinal);
        try
        {
            using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,
                Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Default);
            using var key = root.OpenSubKey(InternetSettingsKey + @"\Connections", writable: false);
            if (key?.GetValue("WinHttpSettings") is byte[] blob)
            {
                ConnectionSettingsBlob.AddTo(values, "WinHTTP.", blob, winInet: false);
            }
            return new ProxyScope(id, displayName, values);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException)
        {
            return new ProxyScope(id, displayName, new Dictionary<string, string>(), ex.Message);
        }
    }

    [SupportedOSPlatform("windows")]
    private static void AddValues(IDictionary<string, string> values, RegistryKey? key, string prefix, IEnumerable<string> names)
    {
        if (key is null)
        {
            return;
        }
        var present = new HashSet<string>(key.GetValueNames(), StringComparer.OrdinalIgnoreCase);
        foreach (var name in names.Where(present.Contains))
        {
            var text = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) switch
            {
                null => null,
                byte[] bytes => "hex:" + Convert.ToHexString(bytes),
                string[] strings => string.Join("|", strings),
                var other => Convert.ToString(other, System.Globalization.CultureInfo.InvariantCulture),
            };
            if (text is null)
            {
                continue;
            }
            values[prefix + name] = text.Length <= MaxValueLength
                ? text
                : text[..256] + "… sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
        }
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

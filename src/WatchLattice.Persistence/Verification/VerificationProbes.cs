namespace WatchLattice.Persistence.Verification;

// The read-only Windows lookups verification needs. Each is an interface so
// every scenario can be tested with fakes off Windows; the Windows
// implementations live in Verification/Windows and are exercised by the
// Windows CI job. None of them may write, register, load or execute anything.

public enum TaskReadStatus { Found, NotFound, AccessDenied, Error }

public sealed record TaskReadResult(TaskReadStatus Status, string? Xml = null, string? Error = null);

/// <summary>Reads one registered task's definition by its full path.</summary>
public interface IScheduledTaskSource
{
    /// <param name="taskPath">A path already checked by <see cref="WindowsPath.IsValidTaskPath"/>.</param>
    TaskReadResult Read(string taskPath);
}

public enum ServiceReadStatus { Found, NotFound, AccessDenied, Error }

public sealed record ServiceReadResult(ServiceReadStatus Status, ServiceDefinition? Definition = null, string? Error = null);

/// <summary>Reads one service's configuration from the registry. Never opens the Service Control Manager for changes or starts anything.</summary>
public interface IServiceSource
{
    /// <param name="serviceName">A name already checked by <see cref="ServiceAnalysis.IsValidServiceName"/>.</param>
    ServiceReadResult Read(string serviceName);
}

public enum ComScope { Machine64, Machine32, User }

/// <summary>One CLSID key as read from one registry location.</summary>
/// <param name="Location">The key that was read, for display, e.g. <c>HKLM\SOFTWARE\Classes\CLSID\{…} (64-bit)</c>.</param>
/// <param name="HiveUnavailable">For per-user lookups: the account's registry hive is not loaded, so it could not be checked.</param>
public sealed record ComRegistration(string Location, bool Exists, string? InprocServer32 = null,
    string? LocalServer32 = null, string? TreatAs = null, bool AccessDenied = false, bool HiveUnavailable = false,
    string? Error = null)
{
    public bool Readable => !AccessDenied && !HiveUnavailable && Error is null;
}

/// <summary>Reads COM class registrations without activating anything.</summary>
public interface IComRegistry
{
    /// <param name="clsid">A canonical <c>{XXXXXXXX-…}</c> CLSID from <see cref="WindowsPath.TryNormalizeClsid"/>.</param>
    /// <param name="userSid">For <see cref="ComScope.User"/>: a SID checked by <see cref="Accounts.IsSid"/>.</param>
    ComRegistration Read(ComScope scope, string clsid, string? userSid = null);

    /// <summary>SIDs of user profiles whose registry hives are loaded now (signed-in users).</summary>
    IReadOnlyList<string> LoadedUserSids();
}

/// <summary>Translates task principals into SIDs and profile folders.</summary>
public interface IAccountResolver
{
    /// <summary>The SID for an account or group name or SID string, or null when it cannot be resolved.</summary>
    string? ToSid(string account);

    /// <summary>The profile folder of a user SID, or null.</summary>
    string? ProfilePath(string sid);

    /// <summary>Who runs the verification, recorded with each run.</summary>
    string CurrentAccount { get; }
}

/// <summary>Reads a file's Authenticode signature, embedded or from a system catalog.</summary>
public interface IAuthenticodeInspector
{
    SignatureEvidence Inspect(string path);
}

/// <summary>Collects hash, version and signature evidence for one file. Never runs or loads it.</summary>
public interface IFileInspector
{
    /// <summary>Whether a regular file exists at the path, for search-order resolution.</summary>
    bool Exists(string path);

    Task<FileEvidence> InspectAsync(string path, CancellationToken cancellationToken);
}

/// <summary>Windows folders that %VARIABLES% in task actions and COM registrations may refer to.</summary>
/// <param name="Variables">Machine-wide variables only, such as SystemRoot and ProgramFiles. Keys are case-insensitive.</param>
public sealed record SystemPaths(IReadOnlyDictionary<string, string> Variables, bool Is64BitOperatingSystem)
{
    public string SystemRoot => Variables.TryGetValue("SystemRoot", out var root) ? root : @"C:\Windows";

    public string System32 => SystemRoot.TrimEnd('\\') + @"\System32";

    /// <summary>The machine-wide variables a task or COM registration may use, read from this process.</summary>
    public static SystemPaths FromEnvironment()
    {
        var variables = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in MachineVariables)
        {
            var value = Environment.GetEnvironmentVariable(name);
            if (!string.IsNullOrWhiteSpace(value)) variables[name] = value.TrimEnd('\\');
        }
        if (!variables.ContainsKey("SystemRoot"))
        {
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (!string.IsNullOrEmpty(windows)) variables["SystemRoot"] = windows.TrimEnd('\\');
        }
        if (variables.TryGetValue("SystemRoot", out var root)) variables.TryAdd("windir", root);
        return new(variables, Environment.Is64BitOperatingSystem);
    }

    /// <summary>
    /// Variables that mean the same thing for every account. Anything else
    /// (TEMP, PATH, a made-up name) depends on who runs the task, so a path
    /// using it is reported as unresolved rather than guessed.
    /// </summary>
    public static IReadOnlyList<string> MachineVariables { get; } = new[]
    {
        "SystemRoot", "windir", "SystemDrive", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432",
        "CommonProgramFiles", "CommonProgramFiles(x86)", "CommonProgramW6432", "ProgramData", "ALLUSERSPROFILE", "PUBLIC",
    };
}

/// <summary>Well-known accounts, so principals compare and resolve the same way on every machine and language.</summary>
public static class Accounts
{
    public const string LocalSystem = "S-1-5-18";
    public const string LocalService = "S-1-5-19";
    public const string NetworkService = "S-1-5-20";
    public const string Administrators = "S-1-5-32-544";

    private static readonly Dictionary<string, string> WellKnown = new(StringComparer.OrdinalIgnoreCase)
    {
        ["SYSTEM"] = LocalSystem, [@"NT AUTHORITY\SYSTEM"] = LocalSystem, ["LocalSystem"] = LocalSystem,
        ["LOCAL SERVICE"] = LocalService, [@"NT AUTHORITY\LOCAL SERVICE"] = LocalService, ["LocalService"] = LocalService,
        ["NETWORK SERVICE"] = NetworkService, [@"NT AUTHORITY\NETWORK SERVICE"] = NetworkService, ["NetworkService"] = NetworkService,
        ["INTERACTIVE"] = "S-1-5-4", [@"NT AUTHORITY\INTERACTIVE"] = "S-1-5-4",
        ["Authenticated Users"] = "S-1-5-11", [@"NT AUTHORITY\Authenticated Users"] = "S-1-5-11",
        ["Users"] = "S-1-5-32-545", [@"BUILTIN\Users"] = "S-1-5-32-545",
        ["Administrators"] = Administrators, [@"BUILTIN\Administrators"] = Administrators,
        ["Everyone"] = "S-1-1-0",
    };

    /// <summary>A syntactically valid SID string such as S-1-5-21-1-2-3-1001.</summary>
    public static bool IsSid(string? value) =>
        value is { Length: > 4 and <= 184 } && System.Text.RegularExpressions.Regex.IsMatch(value, @"\AS-1-\d{1,13}(-\d{1,10}){1,15}\z");

    /// <summary>Accounts that run as a real user profile, whose per-user registrations apply.</summary>
    public static bool IsUserSid(string sid) => sid.StartsWith("S-1-5-21-", StringComparison.Ordinal)
        || sid.StartsWith("S-1-12-1-", StringComparison.Ordinal) || sid is LocalSystem or LocalService or NetworkService;

    /// <summary>The SID of an account, using well-known names first, then the resolver; null when unknown.</summary>
    public static string? Normalize(string? account, IAccountResolver resolver)
    {
        if (string.IsNullOrWhiteSpace(account)) return null;
        account = account.Trim();
        if (IsSid(account)) return account.ToUpperInvariant();
        if (WellKnown.TryGetValue(account, out var sid)) return sid;
        var resolved = resolver.ToSid(account);
        return IsSid(resolved) ? resolved!.ToUpperInvariant() : null;
    }

    public static string Describe(string sid) => sid switch
    {
        LocalSystem => "SYSTEM",
        LocalService => "LOCAL SERVICE",
        NetworkService => "NETWORK SERVICE",
        _ => sid,
    };
}

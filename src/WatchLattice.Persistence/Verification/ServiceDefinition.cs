using System.Text.Json;
using System.Text.Json.Serialization;

namespace WatchLattice.Persistence.Verification;

/// <summary>
/// The fields of a Windows service that decide what runs and as whom, read
/// from <c>HKLM\SYSTEM\CurrentControlSet\Services\&lt;name&gt;</c> without
/// expanding variables. Display text and evidence only, never executed.
/// </summary>
public sealed record ServiceDefinition(int Type, int Start, string? ImagePath, string? ServiceDll, string? ObjectName,
    string? FailureCommand)
{
    public const int AutoStart = 2;
    private const int Win32Types = 0x10 | 0x20;
    private const int UserServiceInstance = 0x80;

    private static readonly JsonSerializerOptions Json = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    /// <summary>
    /// A Win32 service (own or shared process, including per-user service
    /// templates) that Windows starts automatically. Per-user instances,
    /// which Windows creates with a random suffix at every sign-in, are left
    /// out: their template is inventoried instead.
    /// </summary>
    [JsonIgnore]
    public bool IsAutoStartWin32Service => (Type & Win32Types) != 0 && (Type & UserServiceInstance) == 0 && Start == AutoStart;

    /// <summary>The stable text the baseline stores and compares.</summary>
    public string ToProjection() => JsonSerializer.Serialize(this, Json);

    /// <summary>The definition from a stored projection, or null when the text is not one (for example an unreadable key).</summary>
    public static ServiceDefinition? TryParse(string? projection)
    {
        if (string.IsNullOrWhiteSpace(projection) || !projection.TrimStart().StartsWith('{')) return null;
        try { return JsonSerializer.Deserialize<ServiceDefinition>(projection, Json); }
        catch (JsonException) { return null; }
    }
}

public enum ServiceLocation
{
    /// <summary>The Windows folder or a Program Files folder, which standard users cannot write to.</summary>
    Protected,
    /// <summary>A user profile, ProgramData, Public or a Windows temp folder, where standard users or any process can place files.</summary>
    UserWritable,
    /// <summary>Somewhere else, such as another drive. Neither expected nor clearly writable.</summary>
    Other,
    /// <summary>The path could not be resolved without guessing.</summary>
    Unresolved,
}

/// <summary>The file a service runs: its ServiceDll for shared-process services, otherwise the program in its ImagePath.</summary>
public sealed record ServiceTarget(string Raw, bool IsServiceDll, ResolvedPath Resolved, string Arguments);

/// <summary>
/// Pure comparisons over service definitions, shared by the auditor (to
/// grade alerts) and the service verifier. Behaves the same on every platform.
/// </summary>
public static class ServiceAnalysis
{
    /// <summary>A service key name: no separators, no control characters, at most 256 characters.</summary>
    public static bool IsValidServiceName(string? name) =>
        name is { Length: > 0 and <= 256 } && name.IndexOfAny(new[] { '\\', '/' }) < 0 && !name.Any(char.IsControl) && name.Trim().Length > 0;

    /// <summary>Accounts that mean LocalSystem, including an empty ObjectName, which Windows treats as LocalSystem.</summary>
    public static bool IsLocalSystem(string? account) => string.IsNullOrWhiteSpace(account) || account.Trim().ToUpperInvariant()
        is "LOCALSYSTEM" or @".\LOCALSYSTEM" or "SYSTEM" or @"NT AUTHORITY\SYSTEM" or Accounts.LocalSystem;

    public static string DescribeAccount(string? account) => IsLocalSystem(account) ? "LocalSystem" : account!.Trim();

    /// <summary>Rewrites the kernel-style prefixes Windows accepts in ImagePath into forms <see cref="WindowsPath.Resolve"/> understands.</summary>
    public static string NormalizeImagePath(string imagePath)
    {
        var text = imagePath.Trim();
        if (text.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) return "%SystemRoot%" + text[11..];
        if (text.StartsWith(@"System32\", StringComparison.OrdinalIgnoreCase)) return @"%SystemRoot%\" + text;
        return text;
    }

    /// <summary>Splits an ImagePath into its program and the remaining arguments, as Windows parses it.</summary>
    public static (string Program, string Arguments) SplitCommand(string? imagePath)
    {
        if (string.IsNullOrWhiteSpace(imagePath)) return ("", "");
        var text = NormalizeImagePath(imagePath);
        if (text.StartsWith('"'))
        {
            var end = text.IndexOf('"', 1);
            return end < 0 ? (text[1..], "") : (text[1..end], text[(end + 1)..].Trim());
        }
        var program = WindowsPath.ExtractCommandPath(text);
        return (program, text[program.Length..].Trim());
    }

    public static ServiceTarget? Target(ServiceDefinition service, SystemPaths paths, Func<string, bool> exists)
    {
        var (program, arguments) = SplitCommand(service.ImagePath);
        if (!string.IsNullOrWhiteSpace(service.ServiceDll))
            return new(service.ServiceDll, true, WindowsPath.Resolve(service.ServiceDll, paths, null, exists, defaultExtension: ".dll"), arguments);
        if (program.Length == 0) return null;
        return new(program, false, WindowsPath.Resolve(program, paths, null, exists), arguments);
    }

    /// <summary>Where a resolved path is, judged by folder alone. Folder permissions are not read.</summary>
    public static ServiceLocation Classify(ResolvedPath resolved, SystemPaths paths)
    {
        if (resolved.Kind is not (PathResolution.Resolved or PathResolution.SearchOrder) || resolved.Path is null) return ServiceLocation.Unresolved;
        var path = resolved.Path;
        var drive = paths.Variables.TryGetValue("SystemDrive", out var d) ? d.TrimEnd('\\') : paths.SystemRoot[..2];
        string Folder(string name, string fallback) => paths.Variables.TryGetValue(name, out var value) ? value : fallback;
        var programData = Folder("ProgramData", drive + @"\ProgramData");

        if (WindowsPath.IsUnder(path, programData + @"\Microsoft\Windows Defender\Platform")) return ServiceLocation.Protected;
        var writable = new[]
        {
            drive + @"\Users", Folder("PUBLIC", drive + @"\Users\Public"), programData,
            paths.SystemRoot + @"\Temp", paths.SystemRoot + @"\Tasks", paths.SystemRoot + @"\Tracing",
            paths.System32 + @"\Tasks", paths.System32 + @"\spool\drivers\color",
        };
        if (writable.Any(root => WindowsPath.IsUnder(path, root))) return ServiceLocation.UserWritable;
        var protectedRoots = new[]
        {
            paths.SystemRoot, Folder("ProgramFiles", drive + @"\Program Files"), Folder("ProgramFiles(x86)", drive + @"\Program Files (x86)"),
            Folder("ProgramW6432", drive + @"\Program Files"),
        };
        return protectedRoots.Any(root => WindowsPath.IsUnder(path, root)) ? ServiceLocation.Protected : ServiceLocation.Other;
    }

    /// <summary>Location of what a logged projection runs, for grading alerts; Unresolved when it cannot be told.</summary>
    public static ServiceLocation LocationOf(string? projection, SystemPaths paths)
    {
        var service = ServiceDefinition.TryParse(projection);
        var target = service is null ? null : Target(service, paths, _ => false);
        return target is null ? ServiceLocation.Unresolved : Classify(target.Resolved, paths);
    }

    /// <summary>The fields that differ, grouped like task changes so verification records read the same way.</summary>
    public static IReadOnlyList<FieldChange> Differences(ServiceDefinition before, ServiceDefinition after)
    {
        var changes = new List<FieldChange>();
        void Add(string field, ChangeArea area, string? a, string? b)
        {
            if (!string.Equals(a, b, StringComparison.Ordinal)) changes.Add(new(field, area, a, b));
        }
        Add("ImagePath", ChangeArea.Action, before.ImagePath, after.ImagePath);
        Add("ServiceDll", ChangeArea.Action, before.ServiceDll, after.ServiceDll);
        Add("FailureCommand", ChangeArea.Action, before.FailureCommand, after.FailureCommand);
        if (!string.Equals(DescribeAccount(before.ObjectName), DescribeAccount(after.ObjectName), StringComparison.OrdinalIgnoreCase))
            changes.Add(new("ObjectName", ChangeArea.Principal, before.ObjectName, after.ObjectName));
        Add("Start", ChangeArea.Enabled, before.Start.ToString(), after.Start.ToString());
        Add("Type", ChangeArea.Other, $"0x{before.Type:X}", $"0x{after.Type:X}");
        return changes;
    }

    /// <summary>
    /// The program or service DLL changed, other than a routine update in
    /// place (see <see cref="IsRoutineUpdate"/>).
    /// </summary>
    public static bool ChangesTarget(ServiceDefinition before, ServiceDefinition after, SystemPaths paths) =>
        !IsRoutineUpdate(before, after, paths) && (!SamePath(SplitCommand(before.ImagePath).Program, SplitCommand(after.ImagePath).Program)
            || !SamePath(before.ServiceDll, after.ServiceDll));

    /// <summary>
    /// Only the folder of the same-named program or DLL changed, both folders
    /// are protected (Windows, Program Files, Defender's platform folder), and
    /// nothing else differs: what Defender, Edge and other updaters do when
    /// they install a new version into a versioned folder.
    /// </summary>
    public static bool IsRoutineUpdate(ServiceDefinition before, ServiceDefinition after, SystemPaths paths)
    {
        if (before == after || before.Type != after.Type || before.Start != after.Start
            || !string.Equals(DescribeAccount(before.ObjectName), DescribeAccount(after.ObjectName), StringComparison.OrdinalIgnoreCase)
            || !string.Equals(before.FailureCommand, after.FailureCommand, StringComparison.Ordinal)) return false;
        var (beforeProgram, beforeArguments) = SplitCommand(before.ImagePath);
        var (afterProgram, afterArguments) = SplitCommand(after.ImagePath);
        return string.Equals(beforeArguments, afterArguments, StringComparison.Ordinal)
            && SameFileInProtectedFolder(beforeProgram, afterProgram, paths, ".exe")
            && SameFileInProtectedFolder(before.ServiceDll, after.ServiceDll, paths, ".dll");
    }

    public static bool IsPrivilegeGain(ServiceDefinition before, ServiceDefinition after) =>
        !IsLocalSystem(before.ObjectName) && IsLocalSystem(after.ObjectName);

    private static bool SamePath(string? a, string? b) =>
        string.Equals(string.IsNullOrWhiteSpace(a) ? null : a.Trim(), string.IsNullOrWhiteSpace(b) ? null : b.Trim(), StringComparison.OrdinalIgnoreCase);

    private static bool SameFileInProtectedFolder(string? a, string? b, SystemPaths paths, string extension)
    {
        if (SamePath(a, b)) return true;
        if (string.IsNullOrWhiteSpace(a) || string.IsNullOrWhiteSpace(b)) return false;
        var first = WindowsPath.Resolve(a, paths, null, _ => false, defaultExtension: extension);
        var second = WindowsPath.Resolve(b, paths, null, _ => false, defaultExtension: extension);
        return first.Kind == PathResolution.Resolved && second.Kind == PathResolution.Resolved
            && string.Equals(WindowsPath.FileName(first.Path!), WindowsPath.FileName(second.Path!), StringComparison.OrdinalIgnoreCase)
            && Classify(first, paths) == ServiceLocation.Protected && Classify(second, paths) == ServiceLocation.Protected;
    }
}

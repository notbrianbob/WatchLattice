using System.Text;

namespace WatchLattice.Persistence.Verification;

public enum PathResolution
{
    /// <summary>An absolute local path.</summary>
    Resolved,
    /// <summary>Found by a search (bare file name or relative path), so which file runs depends on search order.</summary>
    SearchOrder,
    /// <summary>Could not be resolved without guessing, e.g. a per-account variable or a file not on the search path.</summary>
    Unresolved,
    /// <summary>A UNC or other network path. Never opened: reading it as the hub's account would contact that host.</summary>
    Network,
    /// <summary>Malformed or deliberately unusual: device paths, alternate data streams, wildcard characters.</summary>
    Invalid,
}

public sealed record ResolvedPath(PathResolution Kind, string? Path, string Note);

/// <summary>
/// Validation and resolution of the Windows paths, task paths and CLSIDs that
/// come from task definitions and the registry. Pure string handling, so it
/// behaves the same on every platform and never touches the file system
/// except through the <c>exists</c> callback. Everything here treats its
/// input as untrusted: nothing is passed to a shell or expanded with the
/// process's own environment.
/// </summary>
public static class WindowsPath
{
    private const int MaxPathLength = 32767;
    private static readonly char[] TaskNameInvalid = { '/', ':', '*', '?', '"', '<', '>', '|' };
    private static readonly char[] PathInvalid = { '*', '?', '"', '<', '>', '|' };

    /// <summary>A task path such as <c>\Microsoft\Windows\Defrag\ScheduledDefrag</c>.</summary>
    public static bool IsValidTaskPath(string? path)
    {
        if (path is null || path.Length < 2 || path.Length > 1024 || path[0] != '\\' || path[^1] == '\\') return false;
        if (path.Any(c => char.IsControl(c)) || path.IndexOfAny(TaskNameInvalid) >= 0) return false;
        var segments = path[1..].Split('\\');
        return segments.All(s => s.Length > 0 && s != "." && s != ".." && s.Trim().Length > 0);
    }

    /// <summary>Splits a valid task path into its folder (<c>\</c> for the root) and name.</summary>
    public static (string Folder, string Name) SplitTaskPath(string path)
    {
        var last = path.LastIndexOf('\\');
        return (last == 0 ? "\\" : path[..last], path[(last + 1)..]);
    }

    /// <summary>Accepts <c>{xxxxxxxx-xxxx-…}</c> or the same without braces; returns the braced upper-case form.</summary>
    public static bool TryNormalizeClsid(string? value, out string clsid)
    {
        clsid = "";
        if (value is null) return false;
        var text = value.Trim();
        if (!Guid.TryParseExact(text, "B", out var guid) && !Guid.TryParseExact(text, "D", out guid)) return false;
        clsid = "{" + guid.ToString("D").ToUpperInvariant() + "}";
        return true;
    }

    /// <summary>
    /// The program path from a command line such as a LocalServer32 value:
    /// the quoted part if it starts with a quote, otherwise up to the first
    /// <c>.exe</c>, otherwise up to the first space.
    /// </summary>
    public static string ExtractCommandPath(string commandLine)
    {
        var text = commandLine.Trim();
        if (text.StartsWith('"'))
        {
            var end = text.IndexOf('"', 1);
            return end < 0 ? text[1..] : text[1..end];
        }
        var exe = text.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exe >= 0)
        {
            // Windows ignores dots after a name, so "a.exe. -k" still runs a.exe.
            var end = exe + 4;
            while (end < text.Length && text[end] == '.') end++;
            if (end == text.Length || text[end] == ' ') return text[..end];
        }
        var space = text.IndexOf(' ');
        return space < 0 ? text : text[..space];
    }

    /// <summary>Removes one pair of surrounding quotes.</summary>
    public static string Unquote(string value)
    {
        var text = value.Trim();
        return text.Length >= 2 && text[0] == '"' && text[^1] == '"' ? text[1..^1].Trim() : text;
    }

    /// <summary>
    /// Expands %NAME% using only the given lookup. Returns null and the first
    /// unknown name when a variable cannot be expanded.
    /// </summary>
    public static string? ExpandVariables(string text, Func<string, string?> lookup, out string? unknown)
    {
        unknown = null;
        var result = new StringBuilder(text.Length + 32);
        var index = 0;
        while (index < text.Length)
        {
            var start = text.IndexOf('%', index);
            if (start < 0) { result.Append(text, index, text.Length - index); break; }
            var end = text.IndexOf('%', start + 1);
            if (end < 0) { result.Append(text, index, text.Length - index); break; }
            result.Append(text, index, start - index);
            var name = text[(start + 1)..end];
            var value = name.Length == 0 ? null : lookup(name);
            if (value is null)
            {
                unknown = name.Length == 0 ? "%%" : name;
                return null;
            }
            result.Append(value);
            index = end + 1;
        }
        return result.ToString();
    }

    /// <summary>
    /// Resolves a program or DLL path the way Windows would find it, without
    /// guessing. <paramref name="accountVariables"/> supplies per-account
    /// variables (such as LOCALAPPDATA) when the account is known.
    /// </summary>
    public static ResolvedPath Resolve(string raw, SystemPaths paths, Func<string, string?>? accountVariables,
        Func<string, bool> exists, string? workingDirectory = null, string defaultExtension = ".exe")
    {
        var text = Unquote(raw);
        if (text.Length == 0) return new(PathResolution.Invalid, null, "The path is empty.");
        if (text.Length > MaxPathLength || text.Any(char.IsControl)) return new(PathResolution.Invalid, null, "The path contains control characters or is too long.");

        string? Lookup(string name) => paths.Variables.TryGetValue(name, out var value) ? value : accountVariables?.Invoke(name);
        var expanded = ExpandVariables(text, Lookup, out var unknown);
        if (expanded is null)
            return new(PathResolution.Unresolved, null, $"Uses %{unknown}%, which depends on the account or environment that runs it, so it was not guessed.");

        var path = expanded.Replace('/', '\\');
        if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
            return new(PathResolution.Network, path, "A network path. It was not opened, so no network host was contacted.");
        if (path.StartsWith(@"\\?\", StringComparison.Ordinal) || path.StartsWith(@"\??\", StringComparison.Ordinal))
            path = path[4..];
        else if (path.StartsWith(@"\\.\", StringComparison.Ordinal))
            return new(PathResolution.Invalid, path, "A device path, which a task or COM server does not normally use.");
        else if (path.StartsWith(@"\\", StringComparison.Ordinal))
            return new(PathResolution.Network, path, "A network path. It was not opened, so no network host was contacted.");

        if (path.IndexOfAny(PathInvalid) >= 0) return new(PathResolution.Invalid, path, "The path contains wildcard or quote characters.");
        // The only colon a path may hold is the one after a drive letter.
        var colon = path.IndexOf(':');
        if (colon == 1 && IsDriveLetter(path[0])) colon = path.IndexOf(':', 2);
        if (colon >= 0) return new(PathResolution.Invalid, path, "The path names an alternate data stream or is malformed.");

        if (IsDriveRooted(path))
        {
            var canonical = Canonicalize(path, out var trimmed);
            return new(PathResolution.Resolved, canonical, trimmed ? "Windows ignores trailing dots and spaces in names; they were removed." : "");
        }
        if (path.Length >= 2 && path[1] == ':') return new(PathResolution.Unresolved, null, "A drive-relative path depends on the current folder.");
        if (path.StartsWith('\\')) return new(PathResolution.Unresolved, null, "A path relative to the current drive depends on the current folder.");

        if (path.Contains('\\'))
        {
            var folder = workingDirectory is null ? null : Resolve(workingDirectory, paths, accountVariables, _ => true, null, "");
            if (folder is { Kind: PathResolution.Resolved, Path: not null })
            {
                var combined = Canonicalize(folder.Path.TrimEnd('\\') + "\\" + path, out _);
                return new(PathResolution.SearchOrder, combined, "A relative path, taken from the task's working directory.");
            }
            return new(PathResolution.Unresolved, null, "A relative path with no usable working directory.");
        }

        var name = Path.HasExtension(path) || defaultExtension.Length == 0 ? path : path + defaultExtension;
        var candidates = new List<string>();
        if (workingDirectory is not null)
        {
            var folder = Resolve(workingDirectory, paths, accountVariables, _ => true, null, "");
            if (folder is { Kind: PathResolution.Resolved, Path: not null }) candidates.Add(folder.Path);
        }
        candidates.Add(paths.System32);
        candidates.Add(paths.SystemRoot);
        candidates.Add(paths.System32 + @"\Wbem");
        candidates.Add(paths.System32 + @"\WindowsPowerShell\v1.0");
        foreach (var candidate in candidates.Select(c => Canonicalize(c.TrimEnd('\\') + "\\" + name, out _)))
        {
            if (exists(candidate))
                return new(PathResolution.SearchOrder, candidate, $"A bare file name; Windows finds it by search order. Found at {candidate}.");
        }
        return new(PathResolution.Unresolved, null, $"A bare file name ({name}) that is not in the working directory or the Windows system folders.");
    }

    /// <summary>Case-insensitive comparison of two canonical paths.</summary>
    public static bool SamePath(string? a, string? b) =>
        a is not null && b is not null && string.Equals(a.TrimEnd('\\'), b.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);

    /// <summary>True when <paramref name="path"/> is <paramref name="folder"/> or inside it.</summary>
    public static bool IsUnder(string path, string folder)
    {
        var root = folder.TrimEnd('\\') + "\\";
        return path.StartsWith(root, StringComparison.OrdinalIgnoreCase) || SamePath(path, folder);
    }

    public static string FileName(string path)
    {
        var slash = path.LastIndexOf('\\');
        return slash < 0 ? path : path[(slash + 1)..];
    }

    private static bool IsDriveLetter(char c) => c is >= 'A' and <= 'Z' or >= 'a' and <= 'z';

    private static bool IsDriveRooted(string path) => path.Length >= 3 && IsDriveLetter(path[0]) && path[1] == ':' && path[2] == '\\';

    /// <summary>Collapses <c>.</c>, <c>..</c> and repeated separators, and upper-cases the drive letter.</summary>
    private static string Canonicalize(string path, out bool trimmed)
    {
        trimmed = false;
        var parts = new List<string>();
        foreach (var raw in path[3..].Split('\\'))
        {
            if (raw.Length == 0 || raw == ".") continue;
            if (raw == "..")
            {
                if (parts.Count > 0) parts.RemoveAt(parts.Count - 1);
                continue;
            }
            var part = raw.TrimEnd('.', ' ');
            if (part.Length != raw.Length) trimmed = true;
            if (part.Length > 0) parts.Add(part);
        }
        return char.ToUpperInvariant(path[0]) + @":\" + string.Join('\\', parts);
    }
}

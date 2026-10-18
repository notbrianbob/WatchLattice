namespace WatchLattice.Updater;

/// <summary>
/// The SHA-256 of every file a release installs under Hub/ and Tray/, shipped
/// inside the package as <see cref="ReleaseLayout.FileManifestName"/> next to
/// the hub. The release workflow writes it after signing, so the hashes are of
/// the exact bytes that get installed. Format: a <c># WatchLattice &lt;version&gt;</c>
/// header line, then <c>sha256sum</c>-style lines with forward-slash paths
/// relative to the install folder, for example <c>Hub/WatchLattice.Common.dll</c>.
/// The hub's appsettings.json is never listed, because users edit it.
/// </summary>
public sealed record InstallManifest(ReleaseVersion Version, IReadOnlyDictionary<string, string> Files)
{
    public const string HeaderPrefix = "# WatchLattice ";
    private const long MaxBytes = 1024 * 1024;

    public static InstallManifest Read(string path)
    {
        var info = new FileInfo(path);
        if (info.Length > MaxBytes) throw new InvalidDataException($"{info.Name} is larger than any release writes.");
        return Parse(File.ReadAllText(path));
    }

    public static InstallManifest Parse(string text)
    {
        var header = text.Split('\n').Select(l => l.TrimEnd('\r')).FirstOrDefault(l => l.Trim().Length > 0);
        if (header is null || !header.StartsWith(HeaderPrefix, StringComparison.Ordinal)
            || !ReleaseVersion.TryParse(header[HeaderPrefix.Length..], out var version))
            throw new InvalidDataException("The install manifest does not start with a '# WatchLattice <version>' line.");

        var files = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, hash) in Sha256Sums.Parse(text))
        {
            if (!IsInstallPath(name)) throw new InvalidDataException($"The install manifest lists an unexpected path: {name}");
            if (files.TryGetValue(name, out var existing) && existing != hash)
                throw new InvalidDataException($"The install manifest lists {name} twice with different hashes.");
            files[name] = hash;
        }
        if (files.Count == 0) throw new InvalidDataException("The install manifest lists no files.");
        return new InstallManifest(version, files);
    }

    /// <summary>Writes a manifest for an install folder; the release workflow does the same in PowerShell.</summary>
    public static string Create(ReleaseVersion version, string installRoot)
    {
        var lines = new List<string> { HeaderPrefix + version };
        foreach (var folder in new[] { ReleaseLayout.HubFolder, ReleaseLayout.TrayFolder })
        {
            var directory = Path.Join(installRoot, folder);
            if (!Directory.Exists(directory)) continue;
            lines.AddRange(Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal)
                .Select(file => (Path: file, Relative: Normalize(Path.GetRelativePath(installRoot, file))))
                .Where(file => !IsExcluded(file.Relative))
                .Select(file => $"{HashFile(file.Path)}  {file.Relative}"));
        }
        return string.Join("\n", lines) + "\n";
    }

    private static string HashFile(string path)
    {
        using var stream = File.OpenRead(path);
        return Sha256Sums.Compute(stream);
    }

    /// <summary>Files a release never lists: the user's settings and the manifest itself.</summary>
    public static bool IsExcluded(string relativePath) =>
        string.Equals(relativePath, ReleaseLayout.HubFolder + "/" + ReleaseLayout.HubSettingsFile, StringComparison.OrdinalIgnoreCase)
        || string.Equals(relativePath, ReleaseLayout.HubFolder + "/" + ReleaseLayout.FileManifestName, StringComparison.OrdinalIgnoreCase);

    public static string Normalize(string relativePath) => relativePath.Replace('\\', '/').Trim();

    private static bool IsInstallPath(string name) =>
        (name.StartsWith(ReleaseLayout.HubFolder + "/", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith(ReleaseLayout.TrayFolder + "/", StringComparison.OrdinalIgnoreCase))
        && !name.Contains('\\') && !name.Contains(':')
        && name.Split('/').All(part => part.Length > 0 && part != "." && part != "..");
}

using WatchLattice.Common.Settings;

namespace WatchLattice.Updater;

public enum IntegrityState
{
    /// <summary>Every listed file is present and unchanged.</summary>
    Verified,
    /// <summary>A listed file changed or is missing, or an unexpected binary was found.</summary>
    Modified,
    /// <summary>There is no manifest next to the hub.</summary>
    ManifestMissing,
    /// <summary>The manifest could not be read or is malformed.</summary>
    ManifestInvalid,
    /// <summary>The manifest belongs to another release than the running hub: an update is in progress or awaits a restart.</summary>
    VersionMismatch,
}

public sealed record IntegrityReport(IntegrityState State, string InstallRoot, ReleaseVersion? ManifestVersion,
    IReadOnlyList<string> Changed, IReadOnlyList<string> Missing, IReadOnlyList<string> Unexpected,
    IReadOnlyList<string> Unreadable, int FilesChecked, string? Problem = null)
{
    /// <summary>Every finding as "path (kind)", sorted, so two reports with the same findings compare equal.</summary>
    public IReadOnlyList<string> Findings => Changed.Select(p => p + " (changed)")
        .Concat(Missing.Select(p => p + " (missing)"))
        .Concat(Unexpected.Select(p => p + " (not part of the release)"))
        .Order(StringComparer.OrdinalIgnoreCase).ToList();

    /// <summary>True when a changed or unexpected file is a program file rather than data.</summary>
    public bool AffectsBinaries => Changed.Concat(Unexpected).Any(InstallIntegrityChecker.IsBinary);
}

/// <summary>
/// Compares the installed Hub\ and Tray\ folders with the manifest the release
/// shipped. Read-only: it never repairs, moves or deletes anything.
/// </summary>
public static class InstallIntegrityChecker
{
    private static readonly string[] BinaryExtensions = { ".exe", ".dll" };

    public static IntegrityReport Check(string hubDirectory, ReleaseVersion running, InstallIntegrityOptions options)
    {
        hubDirectory = Path.GetFullPath(hubDirectory);
        var root = Path.GetDirectoryName(hubDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar))
            ?? hubDirectory;
        var none = Array.Empty<string>();
        var manifestPath = Path.Join(hubDirectory, ReleaseLayout.FileManifestName);
        if (!File.Exists(manifestPath))
            return new(IntegrityState.ManifestMissing, root, null, none, none, none, none, 0,
                $"{ReleaseLayout.FileManifestName} is missing from {hubDirectory}.");

        InstallManifest manifest;
        try
        {
            manifest = InstallManifest.Read(manifestPath);
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or UnauthorizedAccessException)
        {
            return new(IntegrityState.ManifestInvalid, root, null, none, none, none, none, 0,
                $"{ReleaseLayout.FileManifestName} could not be read: {ex.Message}");
        }
        if (manifest.Version != running)
            return new(IntegrityState.VersionMismatch, root, manifest.Version, none, none, none, none, 0,
                $"The installed files are WatchLattice {manifest.Version} but the running hub is {running}.");

        var ignored = new HashSet<string>(options.IgnoredFiles.Where(f => !string.IsNullOrWhiteSpace(f))
            .Select(InstallManifest.Normalize), StringComparer.OrdinalIgnoreCase);
        var trayInstalled = Directory.Exists(Path.Join(root, ReleaseLayout.TrayFolder));
        var changed = new List<string>();
        var missing = new List<string>();
        var unreadable = new List<string>();
        var checkedCount = 0;

        foreach (var (relative, expected) in manifest.Files.OrderBy(f => f.Key, StringComparer.OrdinalIgnoreCase))
        {
            if (InstallManifest.IsExcluded(relative) || ignored.Contains(relative)) continue;
            // Hub-only layouts (a tray installed elsewhere, or none) only check the hub.
            if (!trayInstalled && relative.StartsWith(ReleaseLayout.TrayFolder + "/", StringComparison.OrdinalIgnoreCase)) continue;

            var path = Path.Join(root, relative.Replace('/', Path.DirectorySeparatorChar));
            if (!File.Exists(path))
            {
                missing.Add(relative);
                continue;
            }
            try
            {
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete, 81920, FileOptions.SequentialScan);
                checkedCount++;
                if (!Sha256Sums.Matches(Sha256Sums.Compute(stream), expected)) changed.Add(relative);
            }
            catch (FileNotFoundException)
            {
                missing.Add(relative);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                unreadable.Add(relative);
            }
        }

        var unexpected = options.ReportUnexpectedBinaries
            ? FindUnexpectedBinaries(root, trayInstalled, manifest, ignored, unreadable)
            : new List<string>();
        var state = changed.Count + missing.Count + unexpected.Count > 0 ? IntegrityState.Modified : IntegrityState.Verified;
        return new(state, root, manifest.Version, changed, missing, unexpected, unreadable, checkedCount);
    }

    public static bool IsBinary(string path) =>
        BinaryExtensions.Contains(Path.GetExtension(path), StringComparer.OrdinalIgnoreCase);

    private static List<string> FindUnexpectedBinaries(string root, bool trayInstalled, InstallManifest manifest,
        HashSet<string> ignored, List<string> unreadable)
    {
        var found = new List<string>();
        var folders = trayInstalled ? new[] { ReleaseLayout.HubFolder, ReleaseLayout.TrayFolder } : new[] { ReleaseLayout.HubFolder };
        foreach (var folder in folders)
        {
            var pending = new Stack<string>();
            pending.Push(Path.Join(root, folder));
            while (pending.Count > 0)
            {
                var directory = pending.Pop();
                try
                {
                    found.AddRange(Directory.EnumerateFiles(directory).Where(IsBinary)
                        .Select(file => InstallManifest.Normalize(Path.GetRelativePath(root, file)))
                        .Where(relative => !manifest.Files.ContainsKey(relative) && !ignored.Contains(relative)));
                    foreach (var child in Directory.EnumerateDirectories(directory).Where(c => !IsWorkingFolder(Path.GetFileName(c))))
                        pending.Push(child);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    // A folder that can't be listed can't be cleared either; report it with the unreadable files.
                    unreadable.Add(InstallManifest.Normalize(Path.GetRelativePath(root, directory)) + "/");
                }
            }
        }
        found.Sort(StringComparer.OrdinalIgnoreCase);
        return found;
    }

    /// <summary>
    /// Folders the updater and the settings editor create next to the hub. An
    /// update's backup keeps the previous release's files (a running program
    /// can be moved aside but not deleted), so they are not part of the install.
    /// </summary>
    private static bool IsWorkingFolder(string name) =>
        name.StartsWith(UpdateInstaller.BackupPrefix, StringComparison.OrdinalIgnoreCase)
        || name.StartsWith(UpdateApplier.StagingPrefix, StringComparison.OrdinalIgnoreCase)
        || string.Equals(name, SettingsApplier.BackupFolderName, StringComparison.OrdinalIgnoreCase);
}

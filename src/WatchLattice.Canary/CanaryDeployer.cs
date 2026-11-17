using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;

namespace WatchLattice.Canary;

/// <summary>State of one canary when it is checked against the manifest.</summary>
public enum CanaryState
{
    Intact,
    Missing,
    Changed,

    /// <summary>
    /// Briefly locked by another process (an antivirus or indexer scanning it).
    /// Not an alert on its own: the next check, or the file watcher, decides.
    /// </summary>
    Unreadable,
}

/// <summary>The outcome of planting canaries at startup.</summary>
public sealed record CanaryDeployment(
    IReadOnlyList<string> Active,
    IReadOnlyList<CanaryAlert> TamperedWhileOffline,
    IReadOnlyList<string> SkippedForeignFiles);

/// <summary>
/// Plants, verifies, and removes canary files. It only ever writes or deletes
/// files it planted itself (tracked in <see cref="CanaryManifest"/>); a real
/// user file that happens to share a canary's name is left untouched.
/// </summary>
public sealed class CanaryDeployer
{
    private readonly CanaryOptions _options;
    private readonly ILogger _logger;
    private readonly string _manifestPath;
    private CanaryManifest _manifest;

    public CanaryDeployer(CanaryOptions options, ILogger logger)
    {
        _options = options;
        _logger = logger;
        _manifestPath = options.ResolveManifestPath();
        _manifest = CanaryManifest.Load(_manifestPath);
    }

    /// <summary>
    /// Plants every configured canary. A canary from a previous run that was
    /// changed or deleted while the watcher was not running is reported, then
    /// re-planted. Canaries in folders that are no longer configured are
    /// removed if they are still intact.
    /// </summary>
    public CanaryDeployment Deploy()
    {
        var active = new List<string>();
        var tampered = new List<CanaryAlert>();
        var skipped = new List<string>();
        var wanted = new HashSet<string>(CanaryPaths.Comparer);

        foreach (var folder in _options.ResolveFolders())
        {
            foreach (var name in _options.ResolveFileNames())
            {
                var path = CanaryPaths.Normalize(Path.Combine(folder, name));
                wanted.Add(path);

                if (_manifest.Files.TryGetValue(path, out var expected))
                {
                    var state = Verify(path, expected);
                    if (state is CanaryState.Intact or CanaryState.Unreadable)
                    {
                        active.Add(path);
                        continue;
                    }

                    tampered.Add(new CanaryAlert(
                        DateTimeOffset.UtcNow,
                        path,
                        state == CanaryState.Missing ? CanaryChange.Deleted : CanaryChange.Modified,
                        "while the watcher was not running"));
                }
                else if (File.Exists(path) || Directory.Exists(path))
                {
                    // Not ours: never overwrite something we didn't create.
                    skipped.Add(path);
                    _logger.LogWarning("Skipping canary {Path}: a file we did not create already exists there.", path);
                    continue;
                }

                if (TryPlant(path))
                {
                    active.Add(path);
                }
            }
        }

        RemoveOrphans(wanted);
        SaveManifest();
        return new CanaryDeployment(active, tampered, skipped);
    }

    /// <summary>Checks one planted canary against its recorded hash.</summary>
    public CanaryState Verify(string path) =>
        _manifest.Files.TryGetValue(CanaryPaths.Normalize(path), out var expected)
            ? Verify(path, expected)
            : CanaryState.Missing;

    /// <summary>Canaries the manifest still records as planted by this watcher.</summary>
    public IReadOnlyList<string> PlantedFiles => _manifest.Files.Keys.Order(CanaryPaths.Comparer).ToList();

    /// <summary>
    /// Deletes every planted canary that is still intact. Changed ones stay in
    /// place as evidence and remain in <see cref="PlantedFiles"/>.
    /// </summary>
    public int RemoveAll()
    {
        var removed = 0;
        foreach (var (path, hash) in _manifest.Files.ToList())
        {
            if (TryDelete(path, hash))
            {
                _manifest.Files.Remove(path);
                removed++;
            }
            else if (!File.Exists(path))
            {
                _manifest.Files.Remove(path);
            }
        }
        SaveManifest();
        return removed;
    }

    private bool TryPlant(string path)
    {
        try
        {
            var content = CanaryContent.Create(Path.GetFileName(path), _options.CanarySizeBytes);

            // The hub runs as LocalSystem and this folder belongs to the user, so
            // the write must not follow a junction or link the user put there.
            if (RedirectionSafeFile.Write(path, content, _options.MarkHidden) is { } refusal)
            {
                _logger.LogWarning("Did not plant canary {Path}: {Reason}.", path, refusal.Reason);
                _manifest.Files.Remove(path);
                return false;
            }

            _manifest.Files[path] = Hash(content);
            _logger.LogInformation("Canary planted: {Path}", path);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning("Could not plant canary {Path}: {Error}", path, ex.Message);
            _manifest.Files.Remove(path);
            return false;
        }
    }

    private void RemoveOrphans(HashSet<string> wanted)
    {
        foreach (var (path, hash) in _manifest.Files.ToList())
        {
            if (wanted.Contains(path))
            {
                continue;
            }

            TryDelete(path, hash);
            _manifest.Files.Remove(path);
        }
    }

    private static CanaryState Verify(string path, string expectedHash)
    {
        try
        {
            if (!File.Exists(path))
            {
                return CanaryState.Missing;
            }

            using var stream = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var actual = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
            return actual == expectedHash ? CanaryState.Intact : CanaryState.Changed;
        }
        catch (FileNotFoundException)
        {
            return CanaryState.Missing;
        }
        catch (UnauthorizedAccessException)
        {
            // Our own file's permissions were changed: nothing legitimate does that.
            return CanaryState.Changed;
        }
        catch (IOException)
        {
            // Usually a sharing violation while something scans the file.
            return CanaryState.Unreadable;
        }
    }

    /// <summary>Deletes a canary only if it is still exactly what was planted, checked and deleted through one handle.</summary>
    private bool TryDelete(string path, string expectedHash)
    {
        try
        {
            if (!File.Exists(path)) return false;
            if (RedirectionSafeFile.DeleteIf(path, content => Hash(content) == expectedHash, MaxCanaryBytes) is { } refusal)
            {
                _logger.LogInformation("Left canary {Path} in place: {Reason}.", path, refusal.Reason);
                return false;
            }
            _logger.LogInformation("Canary removed: {Path}", path);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning("Could not remove canary {Path}: {Error}", path, ex.Message);
            return false;
        }
    }

    private void SaveManifest()
    {
        try
        {
            _manifest.Save(_manifestPath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning("Could not save canary manifest {Path}: {Error}", _manifestPath, ex.Message);
        }
    }

    // A canary is CanarySizeBytes, or a header plus 64 bytes if that is larger.
    private int MaxCanaryBytes => Math.Max(_options.CanarySizeBytes, 0) + 1024;

    private static string Hash(byte[] content) => Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
}

/// <summary>
/// Builds canary content: a header that matches the file's extension (so a
/// quick magic-byte check sees the expected type) followed by random bytes.
/// Random content is fresh on every plant, so a canary cannot be fingerprinted
/// by a fixed hash.
/// </summary>
public static class CanaryContent
{
    public static byte[] Create(string fileName, int size)
    {
        var header = HeaderFor(Path.GetExtension(fileName));
        var total = Math.Max(size, header.Length + 64);
        var content = new byte[total];
        RandomNumberGenerator.Fill(content);
        header.CopyTo(content, 0);
        return content;
    }

    private static byte[] HeaderFor(string extension) => extension.ToLowerInvariant() switch
    {
        ".docx" or ".xlsx" or ".pptx" or ".zip" => new byte[] { 0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00 },
        ".pdf" => Encoding.ASCII.GetBytes("%PDF-1.7\n"),
        ".jpg" or ".jpeg" => new byte[] { 0xFF, 0xD8, 0xFF, 0xE0 },
        ".png" => new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A },
        _ => Array.Empty<byte>(),
    };
}

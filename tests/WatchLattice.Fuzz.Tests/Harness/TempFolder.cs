namespace WatchLattice.Fuzz.Tests.Harness;

/// <summary>A scratch folder for readers that only take a path. Emptied between cases and deleted at the end.</summary>
public sealed class TempFolder : IDisposable
{
    public TempFolder()
    {
        Path = System.IO.Path.Join(System.IO.Path.GetTempPath(), "watchlattice-fuzz-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    /// <summary>Writes a file below the folder, creating its folders. The name always uses forward slashes.</summary>
    public string Write(string relativePath, byte[] content)
    {
        var path = System.IO.Path.Join(Path, relativePath.Replace('/', System.IO.Path.DirectorySeparatorChar));
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, content);
        return path;
    }

    public void Clear()
    {
        foreach (var entry in Directory.EnumerateFileSystemEntries(Path))
        {
            if (Directory.Exists(entry)) Directory.Delete(entry, recursive: true);
            else File.Delete(entry);
        }
    }

    public void Dispose()
    {
        try { Directory.Delete(Path, recursive: true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // A scanner can hold a file for a moment on Windows; the system's temp cleanup takes it later.
        }
    }
}

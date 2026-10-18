using System.Text.Json;

namespace WatchLattice.Common;

/// <summary>Bounded JSON reads and same-directory atomic replacement for local state files.</summary>
public static class AtomicJsonFile
{
    public const int MaxBytes = 8 * 1024 * 1024;
    public static JsonSerializerOptions JsonOptions { get; } = new(JsonSerializerDefaults.Web);

    public static T Read<T>(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        if (stream.Length > MaxBytes) throw new InvalidDataException("State file exceeds the size limit.");
        // Bound the actual read too, in case another process grows the file after opening it.
        using var buffer = new MemoryStream();
        var bytes = new byte[8192];
        int count;
        while ((count = stream.Read(bytes)) > 0)
        {
            if (buffer.Length + count > MaxBytes) throw new InvalidDataException("State file exceeds the size limit.");
            buffer.Write(bytes, 0, count);
        }
        return JsonSerializer.Deserialize<T>(buffer.ToArray(), JsonOptions)
            ?? throw new InvalidDataException("State file contains null.");
    }

    public static void Write<T>(string path, T value)
    {
        path = Path.GetFullPath(path);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions);
        if (bytes.Length > MaxBytes) throw new InvalidDataException("State exceeds the size limit.");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            Replace(temporary, path);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    /// <summary>
    /// Windows can refuse a replace for a moment while another process (a reader, or an
    /// antivirus scan of the new file) has one of the two files open, so a few quick retries
    /// keep a busy moment from counting as a failed write.
    /// </summary>
    private static void Replace(string temporary, string path)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                File.Move(temporary, path, overwrite: true);
                return;
            }
            catch (Exception ex) when (attempt < 5 && ex is UnauthorizedAccessException or IOException)
            {
                Thread.Sleep(10 * attempt);
            }
        }
    }
}

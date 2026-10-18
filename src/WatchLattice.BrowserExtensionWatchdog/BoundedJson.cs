using System.Text.Json;

namespace WatchLattice.BrowserExtensionWatchdog;

/// <summary>Size-limited, share-friendly JSON reads of files a running browser may hold open, and small lookup helpers.</summary>
internal static class BoundedJson
{
    private static readonly JsonDocumentOptions Options = new()
    {
        AllowTrailingCommas = true,
        CommentHandling = JsonCommentHandling.Skip,
        MaxDepth = 256,
    };

    /// <summary>The parsed file, or null when it does not exist. Throws when it can't be read or is over <paramref name="maxBytes"/>.</summary>
    public static JsonDocument? TryRead(string path, int maxBytes)
    {
        byte[] bytes;
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (stream.Length > maxBytes)
            {
                throw new InvalidDataException($"{path} is {stream.Length:N0} bytes, over the {maxBytes:N0}-byte MaxFileBytes limit.");
            }
            bytes = new byte[stream.Length];
            stream.ReadExactly(bytes);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return null;
        }
        catch (EndOfStreamException)
        {
            throw new IOException($"{path} shrank while it was being read.");
        }
        var start = bytes.AsSpan().StartsWith("﻿"u8) ? 3 : 0;
        return JsonDocument.Parse(bytes.AsMemory(start), Options);
    }

    /// <summary>True for a single folder or file name with no path parts, such as an extension ID or a locale.</summary>
    public static bool IsSafeName(string name) =>
        name.Length is > 0 and <= 128 && name != "." && name != ".."
        && name.IndexOfAny(Path.GetInvalidFileNameChars()) < 0 && name.IndexOfAny(new[] { '/', '\\', ':' }) < 0;

    public static bool TryGetPath(this JsonElement element, out JsonElement value, params string[] names)
    {
        value = element;
        foreach (var name in names)
        {
            if (value.ValueKind != JsonValueKind.Object || !value.TryGetProperty(name, out value))
            {
                return false;
            }
        }
        return true;
    }

    public static string? GetStringOrNull(this JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    public static int? GetIntOrNull(this JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value)
        && value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number)
            ? number
            : null;

    public static bool? GetBoolOrNull(this JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value)
            ? value.ValueKind switch { JsonValueKind.True => true, JsonValueKind.False => false, _ => null }
            : null;
}

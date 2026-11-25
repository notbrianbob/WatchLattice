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

    /// <summary>
    /// True for a path that names another computer or a device
    /// (<c>\\server\share</c>, <c>//server/share</c>, <c>\\?\…</c>, <c>\\.\…</c>)
    /// rather than a folder on a local drive. Browser profiles are written by
    /// the user, and the hub reads them as LocalSystem: opening such a path
    /// would make the computer sign in to whatever host the file names.
    /// </summary>
    public static bool IsRemoteOrDevicePath(string path)
    {
        var text = path.TrimStart();
        return text.Length >= 2 && text[0] is '\\' or '/' && text[1] is '\\' or '/';
    }

    public static bool TryGetPath(this JsonElement element, out JsonElement value, params string[] names)
    {
        value = element;
        foreach (var name in names)
        {
            if (!value.TryGet(name, out value))
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>
    /// The named property of an object; false for anything else. Unlike
    /// <see cref="JsonElement.TryGetProperty(string, out JsonElement)"/> this
    /// never throws: that method reads the other names in the object while it
    /// looks, and throws when one of them is spelled with a broken \u escape,
    /// which would let one entry in a file hide every entry beside it.
    /// </summary>
    public static bool TryGet(this JsonElement element, string name, out JsonElement value)
    {
        value = default;
        if (element.ValueKind != JsonValueKind.Object) return false;
        try
        {
            return element.TryGetProperty(name, out value);
        }
        catch (InvalidOperationException)
        {
            // Look again, stepping over the names that cannot be read. The last match wins, as it does above.
            var found = false;
            foreach (var property in element.EnumerateObject().Where(p => p.NameOrNull() == name))
            {
                value = property.Value;
                found = true;
            }
            return found;
        }
    }

    public static string? GetStringOrNull(this JsonElement element, string name) =>
        element.TryGet(name, out var value) ? value.StringOrNull() : null;

    /// <summary>
    /// The element's text, or null when it is not a string or is not valid
    /// text. JSON may spell half of a surrogate pair or carry bytes that are
    /// not UTF-8; reading such a string throws, and a file a browser extension
    /// wrote must not be able to stop the scan that way.
    /// </summary>
    public static string? StringOrNull(this JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.String) return null;
        try { return element.GetString(); }
        catch (InvalidOperationException) { return null; }
    }

    /// <summary>The property's name, or null when it is not valid text (see <see cref="StringOrNull"/>).</summary>
    public static string? NameOrNull(this JsonProperty property)
    {
        try { return property.Name; }
        catch (InvalidOperationException) { return null; }
    }

    /// <summary>What to call an extension: its name, else its ID, else a placeholder, so an alert never names nothing.</summary>
    public static string DisplayName(string? name, string id) =>
        !string.IsNullOrWhiteSpace(name) ? name.Trim() : !string.IsNullOrWhiteSpace(id) ? id.Trim() : "(no name)";

    public static int? GetIntOrNull(this JsonElement element, string name) =>
        element.TryGet(name, out var value) && value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number)
            ? number
            : null;

    public static bool? GetBoolOrNull(this JsonElement element, string name) =>
        element.TryGet(name, out var value)
            ? value.ValueKind switch { JsonValueKind.True => true, JsonValueKind.False => false, _ => null }
            : null;
}

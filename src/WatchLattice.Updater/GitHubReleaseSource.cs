using System.Net;
using System.Text.Json;

namespace WatchLattice.Updater;

/// <summary>Reads the latest release from the GitHub REST API (unauthenticated, read-only).</summary>
public sealed class GitHubReleaseSource : IReleaseSource
{
    internal const int MaxMetadataBytes = 1024 * 1024;
    private const int MaxAssets = 200;
    private readonly HttpClient _http;
    private readonly string _repository;

    public GitHubReleaseSource(HttpClient http, string repository)
    {
        _http = http;
        _repository = repository;
    }

    public async Task<ReleaseInfo?> GetLatestAsync(CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"https://api.github.com/repos/{_repository}/releases/latest");
        request.Headers.Accept.ParseAdd("application/vnd.github+json");
        request.Headers.Add("X-GitHub-Api-Version", "2022-11-28");
        using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        // GitHub answers 404 when the repository has no published release yet.
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        response.EnsureSuccessStatusCode();
        var bytes = await UpdateHttp.ReadBoundedAsync(response.Content, MaxMetadataBytes, cancellationToken);
        return Parse(bytes);
    }

    /// <summary>
    /// Parses one release object from the GitHub REST API. Anything else is
    /// refused with <see cref="JsonException"/> or <see cref="InvalidDataException"/>.
    /// </summary>
    public static ReleaseInfo Parse(ReadOnlySpan<byte> json)
    {
        try
        {
            return Read(json);
        }
        catch (InvalidOperationException ex)
        {
            // A value of the wrong kind where a string or number belongs, or text spelled with a broken \u escape.
            throw new InvalidDataException("Release metadata is not in the expected form: " + ex.Message, ex);
        }
    }

    private static ReleaseInfo Read(ReadOnlySpan<byte> json)
    {
        var reader = new Utf8JsonReader(json);
        using var document = JsonDocument.ParseValue(ref reader);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Release metadata is not an object.");

        var tag = RequiredString(root, "tag_name");
        var name = OptionalString(root, "name");
        var page = RequiredUri(root, "html_url");
        DateTimeOffset? published = root.TryGetProperty("published_at", out var publishedAt)
            && publishedAt.ValueKind == JsonValueKind.String && publishedAt.TryGetDateTimeOffset(out var at) ? at : null;

        var assets = new List<ReleaseAsset>();
        if (root.TryGetProperty("assets", out var list) && list.ValueKind == JsonValueKind.Array)
        {
            foreach (var asset in list.EnumerateArray())
            {
                if (assets.Count == MaxAssets) throw new InvalidDataException("Release lists too many assets.");
                if (asset.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Release metadata lists an asset that is not an object.");
                assets.Add(new ReleaseAsset(RequiredString(asset, "name"), RequiredUri(asset, "browser_download_url"),
                    asset.TryGetProperty("size", out var size) && size.ValueKind == JsonValueKind.Number && size.TryGetInt64(out var bytes) ? bytes : -1));
            }
        }

        return new ReleaseInfo(tag, string.IsNullOrWhiteSpace(name) ? tag : name!, page, published, assets,
            Bool(root, "prerelease"), Bool(root, "draft"));
    }

    private static string RequiredString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            && !string.IsNullOrWhiteSpace(value.GetString()) && value.GetString()!.Length <= 512
            ? value.GetString()!
            : throw new InvalidDataException($"Release metadata has no valid '{property}'.");

    private static string? OptionalString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? Clip(value.GetString()!, 200) : null;

    private static Uri RequiredUri(JsonElement element, string property)
    {
        // Only text that says it is https is handed to the URL parser at all: other text takes the parser down
        // its file-path branches, which this never needs.
        var text = RequiredString(element, property);
        return text.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
            && Uri.TryCreate(text, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps
            ? uri : throw new InvalidDataException($"Release metadata '{property}' is not an https URL.");
    }

    private static bool Bool(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.True;

    private static string Clip(string value, int length) => value.Length <= length ? value : value[..length];
}

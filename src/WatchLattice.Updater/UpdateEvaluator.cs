namespace WatchLattice.Updater;

/// <summary>A release newer than the running build, and whether it can be installed safely.</summary>
public sealed record UpdateCandidate(ReleaseInfo Release, ReleaseVersion Version, ReleaseAsset? Package,
    ReleaseAsset? Checksums, string? Problem)
{
    public bool Installable => Problem is null && Package is not null && Checksums is not null;
}

public static class UpdateEvaluator
{
    /// <summary>
    /// Returns the release when it is newer than <paramref name="current"/>,
    /// otherwise null. A newer release that lacks its package, lacks a checksum
    /// file, or points downloads anywhere but this repository's release
    /// downloads is still reported, but marked not installable.
    /// </summary>
    public static UpdateCandidate? FindNewer(ReleaseVersion current, ReleaseInfo? release, string repository)
    {
        if (release is null || release.Draft) return null;
        if (!ReleaseVersion.TryParse(release.TagName, out var version))
            throw new InvalidDataException($"The latest release tag '{release.TagName}' is not a version.");
        if (version <= current) return null;
        // /releases/latest never returns prereleases, but a custom source might.
        if ((release.Prerelease || version.Prerelease is not null) && current.Prerelease is null) return null;

        var packageName = ReleaseLayout.PackageFileName(version);
        var package = release.Assets.FirstOrDefault(a => a.Name == packageName);
        var checksums = release.Assets.FirstOrDefault(a => a.Name == ReleaseLayout.ChecksumFileName);
        string? problem = null;
        if (package is null)
            problem = $"The release has no {packageName} package, so it has to be installed by hand.";
        else if (checksums is null)
            problem = $"The release publishes no {ReleaseLayout.ChecksumFileName}, so it cannot be verified and will not be installed.";
        else if (!IsReleaseDownload(package.DownloadUrl, repository) || !IsReleaseDownload(checksums.DownloadUrl, repository))
            problem = "The release's downloads are not hosted on this repository's GitHub release page, so they will not be installed.";
        return new UpdateCandidate(release, version, package, checksums, problem);
    }

    /// <summary>
    /// An HTTPS address under this repository's release downloads on
    /// github.com, with nothing in its path that could lead back out of them.
    /// </summary>
    public static bool IsReleaseDownload(Uri url, string repository) =>
        url.Scheme == Uri.UriSchemeHttps && url.IsDefaultPort && string.IsNullOrEmpty(url.UserInfo)
        && string.Equals(url.Host, "github.com", StringComparison.OrdinalIgnoreCase)
        && url.AbsolutePath.StartsWith($"/{repository}/releases/download/", StringComparison.OrdinalIgnoreCase)
        && !ClimbsOut(url.AbsolutePath);

    /// <summary>
    /// A "." or ".." step in the path once escapes are undone and backslashes
    /// read as slashes. <see cref="Uri"/> resolves the plain spellings itself
    /// but keeps one written as <c>..%5C</c>, which a server could still
    /// read as a step up.
    /// </summary>
    private static bool ClimbsOut(string path) =>
        Uri.UnescapeDataString(path).Replace('\\', '/').Split('/').Any(step => step is "." or "..");
}

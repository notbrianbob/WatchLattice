using System.IO.Compression;
using System.Text;
using System.Text.Json;
using WatchLattice.Fuzz.Tests.Harness;
using WatchLattice.Updater;
using Xunit;

namespace WatchLattice.Fuzz.Tests;

/// <summary>
/// The updater reads what a download gave it: release metadata, a checksum
/// file, a zip, and the files inside the zip. All of it is checked before
/// anything is installed, so the checks themselves must hold up against input
/// that was made to break them: refuse it the documented way, and never write
/// outside the staging folder.
/// </summary>
public class UpdaterFuzzTests
{
    private const string Repository = "notbrianbob/WatchLattice";

    private static readonly string[] VersionWords =
    {
        "v", "0", "1", "10", "007", "999999999", "1000000000", "2147483648", ".", "-", "+", "rc", "rc.1", "dev", "alpha", "beta.2", "1.2.3", "v0.10.0",
        "1.2.3-rc.1+build.5", " ", "\n", "\u0662", "\uff11", "x", "-5", "01",
    };

    private const string SampleRelease =
        "{\"tag_name\":\"v0.11.0\",\"name\":\"WatchLattice 0.11.0\",\"html_url\":\"https://github.com/notbrianbob/WatchLattice/releases/tag/v0.11.0\","
        + "\"published_at\":\"2026-11-20T10:00:00Z\",\"prerelease\":false,\"draft\":false,\"assets\":["
        + "{\"name\":\"WatchLattice-0.11.0-win-x64.zip\",\"size\":73400320,\"browser_download_url\":\"https://github.com/notbrianbob/WatchLattice/releases/download/v0.11.0/WatchLattice-0.11.0-win-x64.zip\"},"
        + "{\"name\":\"SHA256SUMS.txt\",\"size\":180,\"browser_download_url\":\"https://github.com/notbrianbob/WatchLattice/releases/download/v0.11.0/SHA256SUMS.txt\"}]}";

    private static readonly string[] ReleaseKeys = { "tag_name", "name", "html_url", "published_at", "prerelease", "draft", "assets", "size", "browser_download_url" };

    private static readonly string[] ReleaseStrings =
    {
        "v0.11.0", "v99.0.0", "0.0.1", "WatchLattice-99.0.0-win-x64.zip", "SHA256SUMS.txt", "2026-11-20T10:00:00Z",
        "https://github.com/notbrianbob/WatchLattice/releases/download/v99.0.0/WatchLattice-99.0.0-win-x64.zip",
        "https://github.com/notbrianbob/WatchLattice/releases/download/v99.0.0/SHA256SUMS.txt",
        "https://github.com/notbrianbob/WatchLattice/releases/tag/v99.0.0", "http://github.com/x", "https://evil.example/x.zip", "file:///c:/x", "", " ",
    };

    private static readonly string[] UrlWords =
    {
        "https://", "http://", "HTTPS://", "ftp://", "file:///", "//", "github.com", "GitHub.com", "api.github.com", "objects.githubusercontent.com",
        "githubusercontent.com", "evilgithubusercontent.com", ".githubusercontent.com", "github.com.evil.example", "evil.example", "github.com@evil.example",
        "evil.example@github.com", "user:pass@", "@", ":443", ":444", ":80", ":", "/", "\\", "/notbrianbob/WatchLattice/releases/download/", "/NotBrianBob/watchlattice/releases/download/",
        "/notbrianbob/WatchLattice-evil/releases/download/", "/notbrianbob/WatchLattice/releases/download/../../../../evil/repo/releases/download/", "..", "/../", "%2e%2e", "%2f", "%5c",
        "%00", "?", "#", "x.zip", "g\u0131thub.com", "github\u3002com", "github.com\u3002", "xn--github-9za.com", "[::1]", "127.0.0.1", "\t", " ",
    };

    private static readonly string[] EntryNames =
    {
        "Hub/ScanAlways.Protection.Service.exe", "Hub/WatchLattice.Common.dll", "Hub/appsettings.json", "Tray/ScanAlways.Tray.exe", "Hub/", "Tray/", "Hub/sub/", "Hub/sub/file.txt",
        "../evil.txt", "..\\evil.txt", "Hub/../../evil.txt", "Hub\\..\\..\\evil.txt", "/etc/evil", "\\evil", "C:/evil.txt", "C:\\evil.txt", "Hub/C:evil", "//server/share/evil", "\\\\server\\share\\evil",
        "Hub//double", "Hub/./dot", "Hub/.../three", "Hub/..x", "Hub/x..", "Hub/trail. ", " Hub/space", "Hub/\u202etxt.exe", "Hub/CON", "Hub/NUL.txt", "Hub/stream.txt:evil",
        "..", ".", "", "a", "~", "Hub/\u00e9\u00e8", "Hub/" + "long/long/long/long/long/long/long/long/long/long/long/long/long/long/long/long/long/name",
    };

    [Fact]
    public void ReleaseVersion_AnyText_ParsesOrIsRefused_AndReadsBackTheSame()
    {
        Fuzzer.RunText(6000, r => r.Chance(0.5) ? r.Text(VersionWords, 5, 12) : r.Mutate(r.Pick("1.2.3", "v0.10.0", "1.2.3-rc.1+build.5", "10.20.30-dev"), VersionWords), text =>
        {
            if (!ReleaseVersion.TryParse(text, out var version))
            {
                Assert.Throws<FormatException>(() => ReleaseVersion.Parse(text));
                return;
            }
            Assert.True(version.Major >= 0 && version.Minor >= 0 && version.Patch >= 0);
            // The text a version prints is the text that parses back to it, so the file name built from it names one release.
            Assert.Equal(version, ReleaseVersion.Parse(version.ToString()));
            Assert.Matches(@"\A[0-9A-Za-z.-]+\z", version.ToString());
            Assert.Equal(0, version.CompareTo(version));
            _ = version.IsDevelopmentBuild;
            _ = ReleaseLayout.PackageFileName(version);
        });
    }

    [Fact]
    public void ReleaseVersion_Ordering_IsConsistent()
    {
        ReleaseVersion Version(FuzzRandom r) => new(r.Pick(0, 1, 2, 10), r.Pick(0, 1, 9, 10), r.Pick(0, 1, 2),
            r.Chance(0.5) ? null : string.Join('.', Enumerable.Range(0, r.Next(1, 4)).Select(_ => r.Pick("rc", "RC", "alpha", "beta", "dev", "1", "2", "10", "01", "-5", "x-1", "99999999999999999999"))));

        Fuzzer.Run(6000, r => (A: Version(r), B: Version(r), C: Version(r)), input =>
        {
            var (a, b, c) = input;
            // Which release is newer must not depend on the order they are compared in.
            Assert.Equal(Math.Sign(a.CompareTo(b)), -Math.Sign(b.CompareTo(a)));
            if (a.CompareTo(b) <= 0 && b.CompareTo(c) <= 0) Assert.True(a.CompareTo(c) <= 0, "a <= b and b <= c, but a > c");
            if (a == b) Assert.Equal(0, a.CompareTo(b));
            // A prerelease comes before its release.
            if (a.Prerelease is not null) Assert.True(a < a with { Prerelease = null });
            Assert.Equal(a > b, b < a);
            Assert.Equal(a >= b, !(a < b));
        }, input => $"{input.A} / {input.B} / {input.C}");
    }

    [Fact]
    public void Checksums_AnyText_ParseOrAreRefused_AndHashesAreAlwaysHashes()
    {
        var hash = new string('a', 64);
        var words = new[] { hash, new string('A', 64), new string('0', 63), new string('g', 64), new string('\u0661', 64), "  ", " *", " ", "\t", "\r\n", "\n", "#", "./", "Hub/", "x.zip", "WatchLattice-0.11.0-win-x64.zip" };
        var sample = $"# comment\r\n{hash}  WatchLattice-0.11.0-win-x64.zip\r\n{new string('b', 64)} *./other.zip\n\n";
        Fuzzer.RunText(5000, r => r.Chance(0.4) ? r.Text(words, 6, 30) : r.Mutate(sample, words), text =>
        {
            IReadOnlyDictionary<string, string> sums;
            try
            {
                sums = Sha256Sums.Parse(text);
            }
            catch (InvalidDataException)
            {
                return;
            }
            foreach (var (name, value) in sums)
            {
                Assert.Matches(@"\A[0-9a-f]{64}\z", value);
                Assert.NotEqual("", name);
                Assert.True(Sha256Sums.Matches(value, value.ToUpperInvariant()));
            }
        });
    }

    [Fact]
    public void Checksums_Matches_AnyTwoTexts_NeverThrows_AndOnlyEqualHashesMatch()
    {
        var words = new[] { new string('a', 64), new string('A', 64), new string('a', 63) + "b", new string('a', 63), new string('g', 64), new string('\u0661', 64), new string('\uff41', 64), "", " " };
        Fuzzer.Run(4000, r => (A: r.Chance(0.6) ? r.Pick(words) : r.Mutate(r.Pick(words), maxChanges: 2), B: r.Chance(0.6) ? r.Pick(words) : r.Mutate(r.Pick(words), maxChanges: 2)), input =>
        {
            var matches = Sha256Sums.Matches(input.A, input.B);
            var bothHashes = IsHash(input.A) && IsHash(input.B);
            Assert.Equal(bothHashes && string.Equals(input.A, input.B, StringComparison.OrdinalIgnoreCase), matches);
        }, input => $"{Fuzzer.Literal(input.A)} and {Fuzzer.Literal(input.B)}");
    }

    [Fact]
    public void Checksums_WrittenTheUsualWays_ReadBackExactly()
    {
        Fuzzer.Run(2000, r =>
        {
            var expected = new Dictionary<string, string>(StringComparer.Ordinal);
            var file = new StringBuilder();
            for (var i = r.Count(5, 40); i > 0; i--)
            {
                switch (r.Next(5))
                {
                    case 0: file.Append("# ").Append(r.Ascii().Replace('\n', ' ').Replace('\r', ' ')); break;
                    case 1: file.Append(r.Pick("", "  ", "\t")); break;
                    default:
                        var name = r.Pick("WatchLattice-0.11.0-win-x64.zip", "Hub/" + r.Identifier() + ".dll", r.Identifier() + " with spaces.txt", r.Identifier());
                        var hash = string.Concat(Enumerable.Range(0, 64).Select(_ => "0123456789abcdef"[r.Next(16)]));
                        // The same file listed twice with the same hash is fine; with two hashes the whole file is refused, which is tested above.
                        if (expected.TryGetValue(name, out var existing)) hash = existing;
                        expected[name] = hash;
                        file.Append(r.Chance(0.3) ? hash.ToUpperInvariant() : hash).Append(r.Pick("  ", " *")).Append(r.Chance(0.2) ? "./" : "").Append(name);
                        break;
                }
                file.Append(r.Pick("\n", "\r\n"));
            }
            return (Text: file.ToString(), Expected: expected);
        }, input => Assert.Equal(input.Expected.OrderBy(p => p.Key, StringComparer.Ordinal), Sha256Sums.Parse(input.Text).OrderBy(p => p.Key, StringComparer.Ordinal)),
        input => Fuzzer.Literal(input.Text));
    }

    [Fact]
    public void InstallManifest_AnyText_ParsesOrIsRefused_AndOnlyListsFilesInsideTheInstall()
    {
        var hash = new string('a', 64);
        var words = new[]
        {
            InstallManifest.HeaderPrefix, "# WatchLattice 0.11.0", "0.11.0", hash, new string('b', 64), "  ", " *", "\n", "\r\n", "Hub/", "Tray/", "hub/", "Hub\\", "../", "..", "./", "/", ":", "C:",
            "Hub/../evil.dll", "Hub/sub/../../evil.dll", "Hub//x", "Hub/x.dll", "Tray/y.exe", "Other/z.dll", "appsettings.json",
        };
        var sample = $"# WatchLattice 0.11.0\n{hash}  Hub/WatchLattice.Common.dll\n{new string('b', 64)}  Tray/ScanAlways.Tray.exe\n";
        var root = OperatingSystem.IsWindows() ? @"C:\Program Files\WatchLattice\" : "/opt/watchlattice/";
        Fuzzer.RunText(5000, r => r.Chance(0.4) ? r.Text(words, 6, 30) : r.Mutate(sample, words), text =>
        {
            InstallManifest manifest;
            try
            {
                manifest = InstallManifest.Parse(text);
            }
            catch (InvalidDataException)
            {
                return;
            }
            Assert.NotEmpty(manifest.Files);
            foreach (var (name, value) in manifest.Files)
            {
                Assert.Matches(@"\A[0-9a-f]{64}\z", value);
                // The integrity check hashes whatever these paths name, so none may lead out of the install folder.
                Assert.StartsWith(root, Path.GetFullPath(Path.Join(root, name)), StringComparison.Ordinal);
                Assert.True(name.StartsWith("Hub/", StringComparison.OrdinalIgnoreCase) || name.StartsWith("Tray/", StringComparison.OrdinalIgnoreCase), name);
            }
        });
    }

    [Fact]
    public void ReleaseMetadata_AnyBytes_ParseOrAreRefused_AndOnlyThisRepositorysDownloadsAreInstallable()
    {
        var sample = Encoding.UTF8.GetBytes(SampleRelease);
        var current = new ReleaseVersion(0, 10, 0);
        Fuzzer.RunBytes(6000, r => r.Next(4) switch
        {
            0 => Encoding.UTF8.GetBytes(r.Json(ReleaseKeys, ReleaseStrings)),
            1 => Encoding.UTF8.GetBytes(Release(r)),
            2 => r.Mutate(sample),
            _ => Encoding.UTF8.GetBytes(r.Mutate(SampleRelease, ReleaseKeys.Concat(ReleaseStrings).ToArray())),
        }, bytes =>
        {
            ReleaseInfo release;
            UpdateCandidate? candidate;
            try
            {
                release = GitHubReleaseSource.Parse(bytes);
                candidate = UpdateEvaluator.FindNewer(current, release, Repository);
            }
            catch (Exception ex) when (ex is JsonException or InvalidDataException)
            {
                // The documented ways to refuse metadata; the update check reports them and tries again later.
                return;
            }
            Assert.False(string.IsNullOrWhiteSpace(release.TagName));
            Assert.False(string.IsNullOrWhiteSpace(release.Name));
            Assert.Equal(Uri.UriSchemeHttps, release.HtmlUrl.Scheme);
            Assert.All(release.Assets, asset => Assert.Equal(Uri.UriSchemeHttps, asset.DownloadUrl.Scheme));
            if (candidate is null) return;
            Assert.True(candidate.Version > current);
            Assert.False(release.Draft);
            if (!candidate.Installable) return;
            foreach (var asset in new[] { candidate.Package!, candidate.Checksums! })
            {
                AssertThisRepositorysDownload(asset.DownloadUrl);
                Assert.True(UpdateHttp.IsGitHubHost(asset.DownloadUrl));
            }
            Assert.Equal(ReleaseLayout.PackageFileName(candidate.Version), candidate.Package!.Name);
        });
    }

    [Fact]
    public void DownloadAddresses_HoweverSpelled_OnlyPassWhenTheyReallyAreGitHub()
    {
        Fuzzer.RunText(8000, r => r.Chance(0.3)
            ? "https://" + r.Pick("github.com", "api.github.com", "objects.githubusercontent.com") + r.Text(UrlWords, 3, 8)
            : r.Pick("https://", "https://", "HTTPS://", "") + r.Text(UrlWords, 5, 12), text =>
        {
            // As the product does, only text that says it is https reaches the URL parser.
            if (!text.StartsWith("https://", StringComparison.OrdinalIgnoreCase) || !Uri.TryCreate(text, UriKind.Absolute, out var url) || !CanBeSent(url)) return;
            if (UpdateEvaluator.IsReleaseDownload(url, Repository)) AssertThisRepositorysDownload(url);
            if (UpdateHttp.IsGitHubHost(url))
            {
                var host = HostOf(url);
                Assert.True(host is "github.com" or "api.github.com" || host.EndsWith(".githubusercontent.com", StringComparison.Ordinal), host);
                Assert.Equal("https", url.Scheme);
                Assert.Equal(443, url.Port);
            }
        });
    }

    [Fact]
    public void Package_AnyEntryNames_NeverWriteOutsideTheStagingFolder()
    {
        using var temp = new TempFolder();
        var staging = Path.Join(temp.Path, "staging");
        var marker = temp.Write("outside/marker.txt", "untouched"u8.ToArray());
        Fuzzer.Run(400, r =>
        {
            var names = Enumerable.Range(0, r.Count(4, 12)).Select(_ => r.Next(6) switch
            {
                0 => r.Mutate(r.Pick(EntryNames), EntryNames, 2),
                1 => r.Pick(EntryNames) + r.Pick(EntryNames),
                _ => r.Pick(EntryNames),
            }).Where(n => n.Length > 0 && !n.Contains('\0')).ToArray();
            var zip = Zip(names);
            return (Names: names, Zip: r.Chance(0.2) ? r.Mutate(zip, 3) : zip);
        }, input =>
        {
            if (Directory.Exists(staging)) Directory.Delete(staging, recursive: true);
            var extracted = false;
            try
            {
                using var stream = new MemoryStream(input.Zip);
                PackageExtractor.Extract(stream, staging, new[] { "Hub/ScanAlways.Protection.Service.exe" });
                extracted = true;
            }
            catch (Exception ex) when (ex is InvalidDataException or IOException or UnauthorizedAccessException)
            {
                // The documented ways to refuse a package; the installer deletes the staging folder and stops.
            }
            // Whatever the package said, the only things beside the staging folder are the ones that were already there.
            Assert.Equal(new[] { "outside", "staging" }, Directory.EnumerateFileSystemEntries(temp.Path).Select(Path.GetFileName).Order(StringComparer.Ordinal));
            Assert.Equal(new[] { marker }, Directory.EnumerateFileSystemEntries(Path.Join(temp.Path, "outside"), "*", SearchOption.AllDirectories));
            Assert.Equal("untouched", File.ReadAllText(marker));
            if (extracted) Assert.True(File.Exists(Path.Join(staging, "Hub", "ScanAlways.Protection.Service.exe")));
        }, input => $"entries [{string.Join(", ", input.Names.Select(Fuzzer.Literal))}], zip {Fuzzer.Hex(input.Zip)}");
    }

    [Fact]
    public void RuntimeConfig_AnyFile_IsReadOrRefused_WithoutThrowing()
    {
        using var temp = new TempFolder();
        const string sample = "{\"runtimeOptions\":{\"tfm\":\"net10.0\",\"rollForward\":\"LatestPatch\",\"frameworks\":[{\"name\":\"Microsoft.NETCore.App\",\"version\":\"10.0.0\"},"
            + "{\"name\":\"Microsoft.WindowsDesktop.App\",\"version\":\"10.0.0-rc.1\"}],\"framework\":{\"name\":\"Microsoft.NETCore.App\",\"version\":\"10.0.1\"}}}";
        var keys = new[] { "runtimeOptions", "includedFrameworks", "rollForward", "frameworks", "framework", "name", "version", "tfm" };
        var strings = new[] { "Microsoft.NETCore.App", "Microsoft.WindowsDesktop.App", "..\\..\\evil", "../x", "10.0.0", "10.0", "10", "1.2.3.4.5", "-1.0", "99999999999.0", "Minor", "Disable", "LatestMajor", "" };
        Fuzzer.RunBytes(3000, r => r.Next(3) switch
        {
            0 => Encoding.UTF8.GetBytes(r.Json(keys, strings)),
            1 => r.Mutate(Encoding.UTF8.GetBytes(sample)),
            _ => Encoding.UTF8.GetBytes(r.Mutate(sample, keys.Concat(strings).ToArray())),
        }, bytes =>
        {
            var path = temp.Write("app.runtimeconfig.json", bytes);
            IReadOnlyList<FrameworkRequirement> requirements;
            try
            {
                requirements = RuntimeRequirements.Read(path);
            }
            catch (InvalidDataException)
            {
                return;
            }
            foreach (var requirement in requirements)
            {
                // The name becomes a folder under the .NET install, so it must never be a path.
                Assert.Matches(@"\A[A-Za-z0-9]+(\.[A-Za-z0-9]+)*\z", requirement.Name);
                Assert.True(requirement.IsSatisfiedBy(new Version(requirement.Version.Major, requirement.Version.Minor, requirement.Version.Build)));
                Assert.Empty(RuntimeRequirements.InstalledVersions(requirement.Name + "-not-installed"));
            }
            var missing = RuntimeRequirements.FindMissing(requirements, _ => Array.Empty<Version>());
            if (missing.Count > 0) Assert.NotEqual("", RuntimeRequirements.Describe(missing));
            Assert.Empty(RuntimeRequirements.FindMissing(requirements, name => requirements.Where(q => q.Name == name).Select(q => q.Version).ToArray()));
        });
    }

    private static bool IsHash(string text) => text.Length == 64 && text.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F');

    /// <summary>False for the few addresses .NET accepts but cannot turn into a host name to connect to.</summary>
    private static bool CanBeSent(Uri url)
    {
        try
        {
            return url.IdnHost.Length > 0;
        }
        catch (UriFormatException)
        {
            return false;
        }
    }

    /// <summary>The host as it goes on the wire: lower case, internationalized names in their ASCII form.</summary>
    private static string HostOf(Uri url) => url.IdnHost.ToLowerInvariant();

    /// <summary>Checked from the address as it would be sent, not from the properties the product reads.</summary>
    private static void AssertThisRepositorysDownload(Uri url)
    {
        Assert.Equal("github.com", HostOf(url));
        Assert.Equal("https", url.Scheme);
        Assert.Equal(443, url.Port);
        Assert.Equal("", url.UserInfo);
        var sent = url.GetComponents(UriComponents.Path, UriFormat.UriEscaped);
        Assert.StartsWith("notbrianbob/watchlattice/releases/download/", sent.ToLowerInvariant(), StringComparison.Ordinal);
        // Nothing later in the path may climb back out of this repository's downloads, in any spelling a server might undo.
        var decoded = Uri.UnescapeDataString(sent).Replace('\\', '/');
        Assert.DoesNotContain("/../", "/" + decoded + "/", StringComparison.Ordinal);
    }

    private static string Release(FuzzRandom r)
    {
        var version = r.Pick("99.0.0", "0.10.1", "0.9.0", "1.0.0-rc.1", "v2");
        string Url(string file) => r.Next(8) switch
        {
            0 => "https://" + r.Text(UrlWords, 3, 8),
            1 => r.Text(UrlWords, 4, 10),
            2 => $"https://github.com/someone-else/WatchLattice/releases/download/v{version}/{file}",
            _ => $"https://github.com/{Repository}/releases/download/v{version}/{file}",
        };
        var package = r.Chance(0.9) ? $"WatchLattice-{version}-win-x64.zip" : r.Pick(ReleaseStrings);
        var assets = new List<string>
        {
            $"{{\"name\":{FuzzRandom.JsonString(package)},\"size\":{r.Pick("1", "-1", "\"1\"", "1e99", "null")},\"browser_download_url\":{FuzzRandom.JsonString(Url(package))}}}",
        };
        if (r.Chance(0.9)) assets.Add($"{{\"name\":\"SHA256SUMS.txt\",\"browser_download_url\":{FuzzRandom.JsonString(Url("SHA256SUMS.txt"))}}}");
        if (r.Chance(0.1)) assets.Add(r.Pick("null", "1", "\"x\"", "[]", "{}"));
        return $"{{\"tag_name\":{FuzzRandom.JsonString(r.Chance(0.9) ? "v" + version : r.Token(VersionWords))},\"name\":{r.Pick("null", "\"\"", "\"WatchLattice\"", "5")},"
            + $"\"html_url\":\"https://github.com/{Repository}/releases/tag/v{version}\",\"prerelease\":{r.Pick("false", "false", "true", "\"no\"")},\"draft\":{r.Pick("false", "false", "true")},"
            + $"\"published_at\":{r.Pick("\"2026-11-20T10:00:00Z\"", "\"soon\"", "null", "7")},\"assets\":[{string.Join(",", assets)}]}}";
    }

    private static byte[] Zip(IEnumerable<string> names)
    {
        using var buffer = new MemoryStream();
        using (var archive = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var name in names)
            {
                var entry = archive.CreateEntry(name, CompressionLevel.NoCompression);
                if (name.EndsWith('/')) continue;
                using var content = entry.Open();
                content.Write("x"u8);
            }
        }
        return buffer.ToArray();
    }
}

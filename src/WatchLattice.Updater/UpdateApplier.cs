namespace WatchLattice.Updater;

/// <summary>Process exit codes for <c>--apply-update</c>; the tray reads them.</summary>
public enum UpdateOutcome
{
    Installed = 0,
    Failed = 1,
    VerificationFailed = 2,
    NotAvailable = 3,
    RollbackFailed = 4,
    UpToDate = 10,
    NotSupported = 11,
}

/// <summary>Stops and restarts the hub's Windows service around an install.</summary>
public interface IHubServiceControl : WatchLattice.Common.IServiceControl
{
}

/// <summary>
/// Installs the latest release when the user asks for it: re-reads the release
/// from GitHub (never from the alert feed), downloads the package and its
/// SHA256SUMS.txt, verifies the hash, extracts it, checks code signatures
/// against the installed copy, stops the hub service, swaps files with
/// rollback, and starts the service again. Any verification problem stops
/// before a single installed file is touched.
/// </summary>
public sealed class UpdateApplier
{
    public const string StagingPrefix = ".update-staging-";
    private const long MaxChecksumBytes = 64 * 1024;
    private static readonly TimeSpan ServiceTimeout = TimeSpan.FromSeconds(60);

    private readonly IReleaseSource _source;
    private readonly HttpClient _http;
    private readonly UpdaterOptions _options;
    private readonly IHubServiceControl? _service;
    private readonly Action<string> _log;
    private readonly ISignatureVerifier? _signatures;
    private readonly Func<string, IReadOnlyList<Version>> _installedFrameworks;

    /// <param name="signatures">Checks Authenticode signatures; null skips the check (non-Windows hosts).</param>
    /// <param name="installedFrameworks">
    /// The installed versions of a shared .NET framework, by name; defaults to this PC's
    /// .NET installs. A release that needs a runtime this PC lacks is refused before any file changes.
    /// </param>
    public UpdateApplier(IReleaseSource source, HttpClient http, UpdaterOptions options, IHubServiceControl? service,
        Action<string> log, ISignatureVerifier? signatures = null,
        Func<string, IReadOnlyList<Version>>? installedFrameworks = null)
    {
        _source = source;
        _http = http;
        _options = options;
        _service = service;
        _log = log;
        _signatures = signatures;
        _installedFrameworks = installedFrameworks ?? RuntimeRequirements.InstalledVersions;
    }

    public async Task<UpdateOutcome> ApplyAsync(ReleaseVersion current, string hubDirectory, string? trayDirectory,
        CancellationToken cancellationToken)
    {
        if (current.IsDevelopmentBuild)
        {
            _log($"This is a development build ({current}). Update it from source; only release builds update themselves.");
            return UpdateOutcome.NotSupported;
        }

        string repository;
        UpdateCandidate? candidate;
        try
        {
            repository = _options.ResolveRepository();
            _log($"Checking https://github.com/{repository}/releases for a version newer than {current}…");
            candidate = UpdateEvaluator.FindNewer(current, await _source.GetLatestAsync(cancellationToken), repository);
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidDataException or System.Text.Json.JsonException
            or TaskCanceledException && !cancellationToken.IsCancellationRequested)
        {
            _log("Could not check for updates: " + ex.Message);
            return UpdateOutcome.Failed;
        }
        if (candidate is null)
        {
            _log($"WatchLattice {current} is up to date.");
            return UpdateOutcome.UpToDate;
        }
        if (!candidate.Installable)
        {
            _log($"Version {candidate.Version} is available but cannot be installed automatically: {candidate.Problem}");
            _log("Release page: " + candidate.Release.HtmlUrl);
            return UpdateOutcome.NotAvailable;
        }

        hubDirectory = Path.GetFullPath(hubDirectory);
        RemoveOldStaging(hubDirectory);
        // Stage inside the install directory: it inherits the install folder's
        // permissions, so a process that cannot write the install cannot swap
        // the package between verification and install either.
        var work = Path.Combine(hubDirectory, StagingPrefix + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(work);
            _log($"Downloading {candidate.Package!.Name} and {ReleaseLayout.ChecksumFileName}…");
            var sums = Sha256Sums.Parse(await UpdateHttp.DownloadTextAsync(_http, candidate.Checksums!.DownloadUrl,
                MaxChecksumBytes, cancellationToken));
            if (!sums.TryGetValue(candidate.Package.Name, out var expected))
            {
                _log($"{ReleaseLayout.ChecksumFileName} has no entry for {candidate.Package.Name}. Nothing was changed.");
                return UpdateOutcome.VerificationFailed;
            }

            var staging = Path.Combine(work, "package");
            // The same exclusive handle is hashed and then extracted, so the
            // verified bytes are the installed bytes.
            await using (var zip = new FileStream(Path.Combine(work, candidate.Package.Name), FileMode.CreateNew,
                FileAccess.ReadWrite, FileShare.None, 81920, FileOptions.DeleteOnClose))
            {
                var actual = await UpdateHttp.DownloadToAsync(_http, candidate.Package.DownloadUrl, zip,
                    Math.Max(1, _options.MaxPackageBytes), cancellationToken);
                if (!Sha256Sums.Matches(actual, expected))
                {
                    _log($"SHA-256 mismatch for {candidate.Package.Name}: expected {expected}, downloaded {actual}. Nothing was changed.");
                    return UpdateOutcome.VerificationFailed;
                }
                _log($"SHA-256 verified: {actual}");
                zip.Position = 0;
                PackageExtractor.Extract(zip, staging, new[]
                {
                    Path.Combine(ReleaseLayout.HubFolder, ReleaseLayout.HubExecutable),
                    Path.Combine(ReleaseLayout.TrayFolder, ReleaseLayout.TrayExecutable),
                });
            }

            var components = new List<InstallComponent>
            {
                new(ReleaseLayout.HubFolder, Path.Combine(staging, ReleaseLayout.HubFolder), hubDirectory,
                    new[] { ReleaseLayout.HubSettingsFile }),
            };
            if (trayDirectory is not null)
                components.Add(new(ReleaseLayout.TrayFolder, Path.Combine(staging, ReleaseLayout.TrayFolder), trayDirectory));

            var missing = RuntimeRequirements.FindMissing(components.SelectMany(c => RuntimeRequirements.Read(
                Path.Join(c.SourceDirectory, RuntimeConfigName(c.Name)))), _installedFrameworks);
            if (missing.Count > 0)
            {
                _log($"WatchLattice {candidate.Version} cannot be installed yet: " + RuntimeRequirements.Describe(missing)
                    + " Nothing was changed.");
                return UpdateOutcome.NotAvailable;
            }

            if (_signatures is not null)
            {
                var problem = SignaturePolicy.Check(_signatures, Path.Join(hubDirectory, ReleaseLayout.HubExecutable),
                    components.Select(c => c.SourceDirectory), staging, _log);
                if (problem is not null)
                {
                    _log("Code signature check failed: " + problem + " Nothing was changed.");
                    return UpdateOutcome.VerificationFailed;
                }
            }

            return Install(candidate.Version, components);
        }
        catch (InvalidDataException ex)
        {
            _log("The package failed verification: " + ex.Message + " Nothing was changed.");
            return UpdateOutcome.VerificationFailed;
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or UnauthorizedAccessException
            or TaskCanceledException && !cancellationToken.IsCancellationRequested)
        {
            _log("The download failed: " + ex.Message + " Nothing was changed.");
            return UpdateOutcome.Failed;
        }
        finally
        {
            try { if (Directory.Exists(work)) Directory.Delete(work, recursive: true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }

    private UpdateOutcome Install(ReleaseVersion version, IReadOnlyList<InstallComponent> components)
    {
        var wasRunning = false;
        try
        {
            wasRunning = _service?.IsRunning() == true;
            if (wasRunning)
            {
                _log("Stopping the hub service…");
                _service!.Stop(ServiceTimeout);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log("Could not stop the hub service: " + ex.Message + " Nothing was changed. Run the update as administrator.");
            return UpdateOutcome.Failed;
        }

        var outcome = UpdateOutcome.Failed;
        try
        {
            var result = UpdateInstaller.Install(components);
            _log($"Installed WatchLattice {version}: {result.FilesReplaced} file(s) replaced, {result.FilesAdded} added.");
            foreach (var kept in result.PreservedFiles)
                _log($"Kept your {Path.GetFileName(kept)}; the release's defaults are in {Path.GetFileName(kept)}{UpdateInstaller.DefaultSuffix}.");
            outcome = UpdateOutcome.Installed;
        }
        catch (UpdateRollbackException ex)
        {
            _log(ex.Message);
            _log("The hub service was left stopped. Restore those files, or reinstall from the release page, before starting it.");
            return UpdateOutcome.RollbackFailed;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _log("The install failed and the previous version was restored: " + ex.Message);
        }

        if (wasRunning)
        {
            try
            {
                _log("Starting the hub service…");
                _service!.Start(ServiceTimeout);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _log("The hub service did not start: " + ex.Message);
                if (outcome == UpdateOutcome.Installed) outcome = UpdateOutcome.Failed;
            }
        }
        else if (outcome == UpdateOutcome.Installed)
        {
            _log("The hub service is not running here. Restart any hub you run in a console to use the new version.");
        }
        return outcome;
    }

    private static string RuntimeConfigName(string component) => Path.ChangeExtension(
        component == ReleaseLayout.TrayFolder ? ReleaseLayout.TrayExecutable : ReleaseLayout.HubExecutable, ".runtimeconfig.json");

    private static void RemoveOldStaging(string hubDirectory)
    {
        if (!Directory.Exists(hubDirectory)) return;
        foreach (var old in Directory.EnumerateDirectories(hubDirectory, StagingPrefix + "*"))
        {
            try { Directory.Delete(old, recursive: true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }
}

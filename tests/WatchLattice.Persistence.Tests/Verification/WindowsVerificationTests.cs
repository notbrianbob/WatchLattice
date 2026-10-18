using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Options;
using WatchLattice.Persistence.Verification;
using WatchLattice.Persistence.Verification.Windows;
using Xunit;
using Xunit.Abstractions;

namespace WatchLattice.Persistence.Tests.Verification;

/// <summary>
/// Live checks against the real Windows APIs on the Windows CI runner,
/// including the reference scenario (SvcRestartTask → sppcext.dll). Elsewhere
/// there is nothing to call, so these return early.
/// </summary>
public sealed class WindowsVerificationTests
{
    private readonly ITestOutputHelper _output;

    public WindowsVerificationTests(ITestOutputHelper output) => _output = output;

    private static string Sppcext => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "sppcext.dll");

    [Fact]
    public void Authenticode_EmbeddedSignature_IsValid()
    {
        if (!OperatingSystem.IsWindows()) return;
        var signature = new WindowsAuthenticodeInspector().Inspect(Path.Join(RuntimeEnvironment.GetRuntimeDirectory(), "coreclr.dll"));

        Assert.True(signature.State == SignatureState.Valid, signature.Problem);
        Assert.Equal(SignatureKind.Embedded, signature.Kind);
        Assert.Contains("Microsoft", signature.Subject);
        Assert.NotNull(signature.Thumbprint);
    }

    [Fact]
    public void Authenticode_SystemDll_IsSignedByMicrosoftWindows_EmbeddedOrThroughACatalog()
    {
        if (!OperatingSystem.IsWindows()) return;
        var signature = new WindowsAuthenticodeInspector().Inspect(Sppcext);
        _output.WriteLine($"{signature.Kind}: {signature.Subject} ({signature.Problem})");

        Assert.True(signature.State == SignatureState.Valid, signature.Problem);
        Assert.Equal(TrustedBaseline.MicrosoftWindowsPublisher, CertificateNames.CommonName(signature.Subject));
    }

    [Fact]
    public void Authenticode_UnsignedAndTamperedFiles_AreNotValid()
    {
        if (!OperatingSystem.IsWindows()) return;
        var inspector = new WindowsAuthenticodeInspector();
        Assert.Equal(SignatureState.NotSigned, inspector.Inspect(typeof(WindowsVerificationTests).Assembly.Location).State);

        var directory = Directory.CreateTempSubdirectory("watchlattice-sig-");
        try
        {
            var bytes = File.ReadAllBytes(Path.Join(RuntimeEnvironment.GetRuntimeDirectory(), "coreclr.dll"));
            bytes[bytes.Length / 2] ^= 0xFF;
            var tampered = Path.Combine(directory.FullName, "coreclr.dll");
            File.WriteAllBytes(tampered, bytes);
            Assert.Equal(SignatureState.Invalid, inspector.Inspect(tampered).State);

            // A modified copy of a catalog-signed system file is no longer in any catalog.
            var system = File.ReadAllBytes(Sppcext);
            var original = inspector.Inspect(Sppcext);
            system[system.Length / 2] ^= 0xFF;
            var modified = Path.Combine(directory.FullName, "sppcext.dll");
            File.WriteAllBytes(modified, system);
            Assert.NotEqual(SignatureState.Valid, inspector.Inspect(modified).State);
            _output.WriteLine($"original {original.Kind}/{original.State}, modified {inspector.Inspect(modified).State}");
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public void ComRegistry_ResolvesTheReferenceClsid_ToSppcext()
    {
        if (!OperatingSystem.IsWindows()) return;
        var registration = new WindowsComRegistry().Read(ComScope.Machine64, TaskScenarios.Clsid);
        _output.WriteLine($"{registration.Location}: {registration.InprocServer32}");

        Assert.True(registration.Exists, registration.Error);
        Assert.EndsWith(@"\sppcext.dll", registration.InprocServer32, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(@"%SystemRoot%", registration.InprocServer32, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ComRegistry_UnknownClassAndUnloadedProfile_AreReportedAsSuch()
    {
        if (!OperatingSystem.IsWindows()) return;
        var registry = new WindowsComRegistry();
        var missing = registry.Read(ComScope.Machine64, "{" + Guid.NewGuid().ToString("D").ToUpperInvariant() + "}");
        Assert.False(missing.Exists);
        Assert.True(missing.Readable);

        var nobody = registry.Read(ComScope.User, TaskScenarios.Clsid, "S-1-5-21-1-2-3-999999");
        Assert.False(nobody.Exists);
        Assert.True(nobody.HiveUnavailable);
        Assert.All(registry.LoadedUserSids(), sid => Assert.True(Accounts.IsSid(sid)));
    }

    [Fact]
    public void TaskScheduler_ReadsTheReferenceTask_AndReportsMissingOnes()
    {
        if (!OperatingSystem.IsWindows()) return;
        var source = new WindowsScheduledTaskSource();

        var read = source.Read(TaskScenarios.TaskPath);
        Assert.True(read.Status == TaskReadStatus.Found, read.Error);
        var facts = TaskFacts.FromXml(read.Xml!);
        var action = Assert.Single(facts.Actions);
        Assert.Equal(TaskActionKinds.ComHandler, action.Kind);
        Assert.True(WindowsPath.TryNormalizeClsid(action.ClassId, out var clsid));
        Assert.Equal(TaskScenarios.Clsid, clsid);

        Assert.Equal(TaskReadStatus.NotFound, source.Read(@"\Microsoft\Windows\SoftwareProtectionPlatform\NoSuchTask" + Guid.NewGuid().ToString("N")).Status);
        Assert.Equal(TaskReadStatus.NotFound, source.Read(@"\NoSuchFolder" + Guid.NewGuid().ToString("N") + @"\Task").Status);
    }

    [Fact]
    public void Accounts_ResolveTheCurrentUserAndWellKnownProfiles()
    {
        if (!OperatingSystem.IsWindows()) return;
        var accounts = new WindowsAccountResolver(SystemPaths.FromEnvironment());
        var sid = accounts.ToSid(accounts.CurrentAccount);
        Assert.True(Accounts.IsSid(sid), sid);
        Assert.Equal(Accounts.NetworkService, Accounts.Normalize("NETWORK SERVICE", accounts));
        Assert.NotNull(accounts.ProfilePath(Accounts.LocalSystem));
    }

    /// <summary>
    /// The reference scenario end to end on a real machine: the auditor's own
    /// inventory of SvcRestartTask is the "after" state, a copy with an earlier
    /// trigger time is the "before" state, and every probe is the real one.
    /// </summary>
    [Fact]
    public async Task ReferenceScenario_SvcRestartTask_PassesWithOnlyTheTriggerTimeChanged()
    {
        if (!OperatingSystem.IsWindows()) return;
        var provider = new WindowsPersistenceProvider(Options.Create(new PersistenceOptions { WatchRegistry = false, WatchStartupFolders = false }));
        var source = Assert.Single(await provider.ReadAsync(default));
        Assert.True(source.Error is null, source.Error);
        var entry = source.Entries.Single(e => string.Equals(e.Id, TaskScenarios.TaskPath, StringComparison.OrdinalIgnoreCase));
        _output.WriteLine(entry.Command);

        var before = JsonNode.Parse(entry.Command)!.AsObject();
        var triggers = before["Triggers"]!.AsArray();
        Assert.NotEmpty(triggers);
        triggers[0]!["StartBoundary"] = "2020-01-01T00:00:00Z";
        var observation = new PersistenceObservation(source.Id, entry.Id, PersistenceChangeKind.Changed,
            before.ToJsonString(), entry.Command, DateTimeOffset.UtcNow);

        var run = await VerificationFactory.CreateEngine().VerifyAsync(observation, VerificationTrigger.Manual, default);
        _output.WriteLine(run.Describe());

        var change = Assert.Single(run.LoggedChanges);
        Assert.Equal("Triggers[0].StartBoundary", change.Field);
        var action = Assert.Single(run.Actions);
        Assert.Equal(Sppcext, action.ResolvedPath, ignoreCase: true);
        Assert.Equal(64, action.File!.Sha256!.Length);
        Assert.Equal(CheckStatus.Pass, run.Check("action1.baseline").Status);
        Assert.Equal(CheckStatus.Pass, run.Check("action1.signature").Status);
        Assert.Equal(CheckStatus.Pass, run.Check("action1.publisher").Status);
        Assert.True(run.Outcome == VerificationOutcome.ChecksPassed, run.Describe());
    }

    /// <summary>Every trusted baseline entry present on this machine must match it, or the baseline is wrong.</summary>
    [Fact]
    public async Task TrustedBaseline_MatchesThisMachine()
    {
        if (!OperatingSystem.IsWindows()) return;
        var engine = VerificationFactory.CreateEngine();
        var tasks = new WindowsScheduledTaskSource();
        foreach (var trusted in TrustedBaseline.Tasks)
        {
            var read = tasks.Read(trusted.TaskPath);
            if (read.Status == TaskReadStatus.NotFound)
            {
                _output.WriteLine($"{trusted.TaskPath}: not on this machine");
                continue;
            }
            var observation = new PersistenceObservation(TaskScenarios.Source, trusted.TaskPath, PersistenceChangeKind.Added, null, null, DateTimeOffset.UtcNow);
            var run = await engine.VerifyAsync(observation, VerificationTrigger.Manual, default);
            _output.WriteLine(trusted.TaskPath + "\n" + run.Describe());
            Assert.DoesNotContain(run.Checks, c => c.Status == CheckStatus.Fail);
            Assert.Equal(CheckStatus.Pass, run.Check("known-configuration").Status);
        }
    }

    [Fact]
    public async Task Services_AreInventoried_AndEventLogVerifiesAgainstItsServiceDll()
    {
        if (!OperatingSystem.IsWindows()) return;
        var provider = new WindowsPersistenceProvider(Options.Create(new PersistenceOptions
        {
            WatchRegistry = false, WatchStartupFolders = false, WatchScheduledTasks = false, WatchServices = true, WatchWmiSubscriptions = false,
        }));
        var source = Assert.Single(await provider.ReadAsync(default));
        Assert.True(source.Error is null, source.Error);
        _output.WriteLine($"{source.Entries.Count} auto-start services");
        var eventLog = ServiceDefinition.TryParse(Assert.Single(source.Entries, e => e.Id == "EventLog").Command);
        Assert.NotNull(eventLog);
        Assert.EndsWith("wevtsvc.dll", eventLog!.ServiceDll, StringComparison.OrdinalIgnoreCase);

        var observation = new PersistenceObservation(ServiceVerifier.SourceId, "EventLog", PersistenceChangeKind.Added, null, eventLog.ToProjection(), DateTimeOffset.UtcNow);
        var run = await VerificationFactory.CreateEngine().VerifyAsync(observation, VerificationTrigger.Manual, default);
        _output.WriteLine(run.Describe());
        Assert.DoesNotContain(run.Checks, c => c.Status == CheckStatus.Fail);
        Assert.Equal(CheckStatus.Pass, run.Check("service.location").Status);
        Assert.Equal(CheckStatus.Pass, run.Check("service.signature").Status);
        Assert.Equal(CheckStatus.Pass, run.Check("since-alert").Status);
    }

    [Fact]
    public async Task WmiSubscriptions_AreInventoried()
    {
        if (!OperatingSystem.IsWindows()) return;
        var provider = new WindowsPersistenceProvider(Options.Create(new PersistenceOptions
        {
            WatchRegistry = false, WatchStartupFolders = false, WatchScheduledTasks = false, WatchServices = false, WatchWmiSubscriptions = true,
        }));
        var source = Assert.Single(await provider.ReadAsync(default));
        Assert.True(source.Error is null, source.Error);
        Assert.StartsWith(WindowsPersistenceProvider.WmiSourcePrefix, source.Id);
        foreach (var entry in source.Entries) _output.WriteLine($"{entry.Id}: {entry.Command}");
        Assert.All(source.Entries, e => Assert.Matches("^(Filter|Consumer|Binding)/", e.Id));
    }
}

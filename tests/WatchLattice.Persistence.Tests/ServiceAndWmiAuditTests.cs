using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using WatchLattice.Common.Alerts;
using WatchLattice.Persistence.Tests.Verification;
using WatchLattice.Persistence.Verification;
using Xunit;

namespace WatchLattice.Persistence.Tests;

/// <summary>How the auditor grades service and WMI subscription changes.</summary>
public sealed class ServiceAndWmiAuditTests : IDisposable
{
    private const string Wmi = WindowsPersistenceProvider.WmiSourcePrefix + "root/subscription";
    private const string Platform = @"C:\ProgramData\Microsoft\Windows Defender\Platform";
    private readonly string _directory = Directory.CreateTempSubdirectory("watchlattice-svc-").FullName;
    private readonly Provider _provider = new();
    private readonly Alerts _alerts = new();
    private readonly Evidence _evidence = new();

    private PersistenceAuditor Auditor(bool verified = true)
    {
        _evidence.Verifies = verified;
        return new(_provider, Options.Create(new PersistenceOptions { BaselinePath = Path.Join(_directory, "baseline.json") }),
            NullLogger<PersistenceAuditor>.Instance, _alerts, _evidence, TaskScenarios.Paths);
    }

    private async Task<ProtectionAlert> ChangeAsync(string source, PersistenceEntry? before, PersistenceEntry? after, bool verified = true)
    {
        var auditor = Auditor(verified);
        _provider.Sources = new[] { new PersistenceSource(source, before is null ? Array.Empty<PersistenceEntry>() : new[] { before }) };
        await auditor.CheckOnceAsync(default);
        _alerts.Items.Clear();
        _provider.Sources = new[] { new PersistenceSource(source, after is null ? Array.Empty<PersistenceEntry>() : new[] { after }) };
        await auditor.CheckOnceAsync(default);
        return Assert.Single(_alerts.Items);
    }

    private static PersistenceEntry Service(string imagePath, string? dll = null) =>
        new("Svc", new ServiceDefinition(0x10, 2, imagePath, dll, null, null).ToProjection());

    [Fact]
    public async Task NewWmiSubscription_IsCritical_AndRemovalIsInfo()
    {
        var consumer = new PersistenceEntry("Consumer/CommandLineEventConsumer/Updater", "{\"CommandLineTemplate\":\"powershell -enc AAAA\"}");
        var added = await ChangeAsync(Wmi, null, consumer);
        Assert.Equal("ENTRY_ADDED", added.Code);
        Assert.Equal(AlertSeverity.Critical, added.Severity);
        Assert.Contains("WMI event subscription", added.Title);
        Assert.Contains("filter, consumer and binding", added.Message);

        var removed = await ChangeAsync(Wmi + "2", consumer, null);
        Assert.Equal(AlertSeverity.Info, removed.Severity);
    }

    [Fact]
    public async Task NewServiceFromAUserWritableFolder_IsCritical_WithOrWithoutVerification()
    {
        var alert = await ChangeAsync(ServiceVerifier.SourceId, null, Service(@"""C:\Users\Bob\AppData\Roaming\svc.exe"""), verified: false);
        Assert.Equal(AlertSeverity.Critical, alert.Severity);
        Assert.Contains("user-writable", alert.Title);
    }

    [Fact]
    public async Task NewServiceFromProgramFiles_IsAWarning()
    {
        var alert = await ChangeAsync(ServiceVerifier.SourceId, null, Service(@"""C:\Program Files\Vendor\svc.exe"""));
        Assert.Equal(AlertSeverity.Warning, alert.Severity);
        Assert.Equal("Autostart entry added", alert.Title);
    }

    [Fact]
    public async Task VersionFolderUpdate_IsInfo_OnlyWhenVerificationFollows()
    {
        var before = Service($@"""{Platform}\4.18.1-0\MsMpEng.exe""");
        var after = Service($@"""{Platform}\4.18.2-0\MsMpEng.exe""");

        var verified = await ChangeAsync(ServiceVerifier.SourceId, before, after);
        Assert.Equal(AlertSeverity.Info, verified.Severity);
        Assert.Contains("updated in place", verified.Title);

        Directory.Delete(_directory, recursive: true);
        Directory.CreateDirectory(_directory);
        var unverified = await ChangeAsync(ServiceVerifier.SourceId, before, after, verified: false);
        Assert.Equal(AlertSeverity.Warning, unverified.Severity);
    }

    [Fact]
    public async Task ServiceDllSwap_StaysAWarning()
    {
        var alert = await ChangeAsync(ServiceVerifier.SourceId,
            Service(@"%SystemRoot%\System32\svchost.exe -k netsvcs", @"%SystemRoot%\System32\good.dll"),
            Service(@"%SystemRoot%\System32\svchost.exe -k netsvcs", @"%SystemRoot%\System32\evil.dll"));
        Assert.Equal(AlertSeverity.Warning, alert.Severity);
    }

    [Fact]
    public void WmiInventory_ParsesLikeTasks()
    {
        var entries = WindowsPersistenceProvider.ParseWmiSubscriptions(
            "[{\"Id\":\"Filter/SCM Event Log Filter\",\"Command\":\"{}\"},{\"Id\":\"Binding/__EventFilter/A -> CommandLineEventConsumer/B\",\"Command\":\"{}\"}]");
        Assert.Equal(2, entries.Count);
        Assert.Throws<InvalidDataException>(() => WindowsPersistenceProvider.ParseWmiSubscriptions("[{\"Id\":\"A\",\"Command\":\"x\"},{\"Id\":\"a\",\"Command\":\"y\"}]"));
        Assert.Empty(WindowsPersistenceProvider.ParseWmiSubscriptions("[]"));
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory)) Directory.Delete(_directory, recursive: true);
    }

    private sealed class Provider : IPersistenceProvider
    {
        public IReadOnlyList<PersistenceSource> Sources { get; set; } = Array.Empty<PersistenceSource>();
        public Task<IReadOnlyList<PersistenceSource>> ReadAsync(CancellationToken cancellationToken) => Task.FromResult(Sources);
    }

    private sealed class Evidence : IChangeEvidenceSink
    {
        public bool Verifies { get; set; }
        public bool Stage(string resource, PersistenceObservation observation) => Verifies;
    }

    private sealed class Alerts : IAlertPublisher
    {
        public List<ProtectionAlert> Items { get; } = new();
        public void Publish(string module, string code, AlertSeverity severity, string title, string message, string? resource = null) =>
            Items.Add(new(Guid.NewGuid(), DateTimeOffset.UtcNow, module, code, severity, title, message, resource));
    }
}

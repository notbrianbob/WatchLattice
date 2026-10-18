using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using WatchLattice.Common;
using WatchLattice.Common.Alerts;
using Xunit;

namespace WatchLattice.Persistence.Tests;

public sealed class PersistenceAuditorTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "watchlattice-persistence-" + Guid.NewGuid().ToString("N"));
    private readonly FakeProvider _provider = new();
    private readonly RecordingAlerts _alerts = new();
    private readonly PersistenceOptions _options;

    public PersistenceAuditorTests()
    {
        Directory.CreateDirectory(_directory);
        _options = new() { BaselinePath = Path.Combine(_directory, "baseline.json") };
    }

    private PersistenceAuditor Auditor() => new(_provider, Options.Create(_options), NullLogger<PersistenceAuditor>.Instance, _alerts);
    private void Inventory(params PersistenceEntry[] entries) => _provider.Sources = new[] { new PersistenceSource("Registry/Test/Run", entries) };

    [Fact]
    public async Task FirstInventory_BaselinesExistingEntries_WithoutWarning_AndSurvivesRestart()
    {
        Inventory(new PersistenceEntry("App", "app.exe"));
        await Auditor().CheckOnceAsync(default);
        Assert.DoesNotContain(_alerts.Items, a => a.Severity >= AlertSeverity.Warning);
        Assert.Single(AtomicJsonFile.Read<PersistenceBaseline>(_options.BaselinePath!).Sources["Registry/Test/Run"]);
        _alerts.Items.Clear();
        await Auditor().CheckOnceAsync(default);
        Assert.Empty(_alerts.Items);
    }

    [Fact]
    public async Task ChangesAcrossRestart_ReportBeforeAndAfter_Once()
    {
        Inventory(new PersistenceEntry("App", "old.exe"), new("Gone", "gone.exe"));
        await Auditor().CheckOnceAsync(default);
        _alerts.Items.Clear();
        Inventory(new PersistenceEntry("App", "new.exe --flag"), new("New", "new-app.exe"));
        var auditor = Auditor();
        await auditor.CheckOnceAsync(default);
        await auditor.CheckOnceAsync(default);
        Assert.Equal(3, _alerts.Items.Count);
        var changed = Assert.Single(_alerts.Items, a => a.Code == "ENTRY_CHANGED");
        Assert.Contains("Previous: old.exe", changed.Message);
        Assert.Contains("Current: new.exe --flag", changed.Message);
        Assert.Contains(_alerts.Items, a => a.Code == "ENTRY_ADDED" && a.Severity == AlertSeverity.Warning);
        Assert.Contains(_alerts.Items, a => a.Code == "ENTRY_REMOVED" && a.Severity == AlertSeverity.Info);
    }

    [Fact]
    public async Task LongCommands_KeepBothBeforeAndAfterVisible_InBoundedAlerts()
    {
        Inventory(new PersistenceEntry("App", new string('a', 3000)));
        var auditor = Auditor();
        await auditor.CheckOnceAsync(default);
        _alerts.Items.Clear();
        Inventory(new PersistenceEntry("App", new string('b', 3000)));
        await auditor.CheckOnceAsync(default);
        var alert = Assert.Single(_alerts.Items);
        Assert.Contains("Previous: aaa", alert.Message);
        Assert.Contains("Current: bbb", alert.Message);
        Assert.Contains("(truncated)", alert.Message);
        Assert.True(alert.Message.Length < 2048);
        Assert.Equal(3000, Assert.Single(AtomicJsonFile.Read<PersistenceBaseline>(_options.BaselinePath!).Sources["Registry/Test/Run"]).Command.Length);
    }

    [Fact]
    public async Task InaccessibleSource_PreservesBaseline_DeduplicatesWarning_AndReportsChangesAfterRecovery()
    {
        Inventory(new PersistenceEntry("App", "old.exe"));
        var auditor = Auditor();
        await auditor.CheckOnceAsync(default);
        _alerts.Items.Clear();
        _provider.Sources = new[] { new PersistenceSource("Registry/Test/Run", Array.Empty<PersistenceEntry>(), "Access denied") };
        await auditor.CheckOnceAsync(default);
        await auditor.CheckOnceAsync(default);
        Assert.Equal("SOURCE_UNAVAILABLE", Assert.Single(_alerts.Items).Code);
        Assert.Equal("old.exe", Assert.Single(AtomicJsonFile.Read<PersistenceBaseline>(_options.BaselinePath!).Sources["Registry/Test/Run"]).Command);
        Inventory(new PersistenceEntry("App", "changed.exe"));
        await auditor.CheckOnceAsync(default);
        Assert.Contains(_alerts.Items, a => a.Code == "SOURCE_RECOVERED");
        Assert.Contains(_alerts.Items, a => a.Code == "ENTRY_CHANGED");
        Assert.DoesNotContain(_alerts.Items, a => a.Code == "ENTRY_REMOVED");
    }

    [Theory]
    [InlineData("broken json")]
    [InlineData("{}")]
    [InlineData("{\"version\":2,\"sources\":{}}")]
    [InlineData("{\"version\":1,\"sources\":null}")]
    public async Task InvalidBaseline_IsNotSilentlyOverwritten(string content)
    {
        File.WriteAllText(_options.BaselinePath!, content);
        Inventory(new PersistenceEntry("App", "app.exe"));
        var auditor = Auditor();
        await auditor.CheckOnceAsync(default);
        await auditor.CheckOnceAsync(default);
        Assert.Equal(content, File.ReadAllText(_options.BaselinePath!));
        Assert.Equal(0, _provider.Reads);
        Assert.Equal("SOURCE_UNAVAILABLE", Assert.Single(_alerts.Items).Code);
        // An explicit user reset (removing the invalid baseline) lets auditing resume.
        File.Delete(_options.BaselinePath!);
        await auditor.CheckOnceAsync(default);
        Assert.Equal(1, _provider.Reads);
        Assert.Contains(_alerts.Items, a => a.Code == "SOURCE_RECOVERED");
    }

    [Fact]
    public async Task Exclusions_SuppressOnlyMatchingEntries_AndStillAdvanceBaseline()
    {
        Inventory();
        var auditor = Auditor();
        await auditor.CheckOnceAsync(default);
        _alerts.Items.Clear();
        _options.IgnoredEntries = new[] { "registry/*/Trusted*" };
        Inventory(new PersistenceEntry("TrustedApp", "trusted.exe"), new("Other", "other.exe"));
        await auditor.CheckOnceAsync(default);
        Assert.Equal("Registry/Test/Run/Other", Assert.Single(_alerts.Items).Resource);
        _alerts.Items.Clear();
        _options.IgnoredEntries = Array.Empty<string>();
        await Auditor().CheckOnceAsync(default);
        Assert.Empty(_alerts.Items);
    }

    [Fact]
    public async Task FailedBaselineSave_IsVisible_AndRetriedWithoutNewChanges()
    {
        Inventory(new PersistenceEntry("App", "app.exe"));
        var auditor = Auditor();
        await auditor.CheckOnceAsync(default);
        File.Delete(_options.BaselinePath!);
        Directory.CreateDirectory(_options.BaselinePath!);
        Inventory(new PersistenceEntry("App", "updated.exe"));
        await auditor.CheckOnceAsync(default);
        Assert.Contains(_alerts.Items, a => a.Resource == "baseline-save" && a.Code == "SOURCE_UNAVAILABLE");
        Directory.Delete(_options.BaselinePath!);
        await auditor.CheckOnceAsync(default);
        Assert.Equal("updated.exe", Assert.Single(AtomicJsonFile.Read<PersistenceBaseline>(_options.BaselinePath!).Sources["Registry/Test/Run"]).Command);
        Assert.Contains(_alerts.Items, a => a.Resource == "baseline-save" && a.Code == "SOURCE_RECOVERED");
    }

    [Fact]
    public async Task DuplicateInventory_ReportsIncompleteSource_WithoutDeletingBaseline()
    {
        Inventory(new PersistenceEntry("App", "old.exe"));
        var auditor = Auditor();
        await auditor.CheckOnceAsync(default);
        _alerts.Items.Clear();
        Inventory(new PersistenceEntry("App", "new.exe"), new("APP", "other.exe"));
        await auditor.CheckOnceAsync(default);
        Assert.Equal("SOURCE_UNAVAILABLE", Assert.Single(_alerts.Items).Code);
        Assert.Equal("old.exe", Assert.Single(AtomicJsonFile.Read<PersistenceBaseline>(_options.BaselinePath!).Sources["Registry/Test/Run"]).Command);
    }

    [Fact]
    public async Task Run_StopsCleanlyOnCancellation()
    {
        Inventory();
        using var cts = new CancellationTokenSource();
        var run = Auditor().RunAsync(cts.Token);
        Assert.Equal(1, _provider.Reads);
        cts.Cancel();
        await run.WaitAsync(TimeSpan.FromSeconds(5));
    }

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    [Fact]
    public async Task EntryAlerts_EndWithTheFingerprintOfTheCurrentValue()
    {
        Inventory(new PersistenceEntry("App", "old.exe"));
        var auditor = Auditor();
        await auditor.CheckOnceAsync(default);
        _alerts.Items.Clear();
        Inventory(new PersistenceEntry("App", "new.exe"), new PersistenceEntry("Long", new string('x', 5000)));
        await auditor.CheckOnceAsync(default);
        Assert.Equal(2, _alerts.Items.Count);
        foreach (var alert in _alerts.Items)
        {
            Assert.True(alert.Message.Length <= 2048);
            var approval = BaselineApprovals.For(alert);
            Assert.NotNull(approval);
            Assert.True(ApprovedEntry.TryParse(approval.Value, out var entry));
            Assert.Equal(alert.Resource, entry.Resource);
        }
        Assert.EndsWith(BaselineApprovals.FingerprintLine("new.exe"), Assert.Single(_alerts.Items, a => a.Code == "ENTRY_CHANGED").Message);
    }

    [Fact]
    public async Task ApprovedEntry_RaisesNoAlert_WhenItComesBackExactlyAsApproved()
    {
        Inventory(new PersistenceEntry("Other", "other.exe"));
        await Auditor().CheckOnceAsync(default);
        _alerts.Items.Clear();

        // The entry appears and alerts; the user approves it from that alert.
        Inventory(new PersistenceEntry("Other", "other.exe"), new PersistenceEntry("App", "app.exe --tray"));
        await Auditor().CheckOnceAsync(default);
        var approval = BaselineApprovals.For(Assert.Single(_alerts.Items))!;
        _options.ApprovedEntries = new[] { "  " + approval.Value + "  ", "not an approval" };
        _alerts.Items.Clear();

        // Removed (Info), then added back as it was: no alert for the return.
        Inventory(new PersistenceEntry("Other", "other.exe"));
        var auditor = Auditor();
        await auditor.CheckOnceAsync(default);
        Assert.Equal("ENTRY_REMOVED", Assert.Single(_alerts.Items).Code);
        _alerts.Items.Clear();
        Inventory(new PersistenceEntry("Other", "other.exe"), new PersistenceEntry("app", "app.exe --tray"));
        await auditor.CheckOnceAsync(default);
        Assert.Empty(_alerts.Items);

        // Any other value still alerts, and flipping back to the approved one does not.
        Inventory(new PersistenceEntry("Other", "other.exe"), new PersistenceEntry("App", "evil.exe"));
        await auditor.CheckOnceAsync(default);
        Assert.Equal("ENTRY_CHANGED", Assert.Single(_alerts.Items).Code);
        _alerts.Items.Clear();
        Inventory(new PersistenceEntry("Other", "other.exe"), new PersistenceEntry("App", "app.exe --tray"));
        await auditor.CheckOnceAsync(default);
        Assert.Empty(_alerts.Items);

        // The approval is for that entry only.
        Inventory(new PersistenceEntry("Other", "app.exe --tray"), new PersistenceEntry("App", "app.exe --tray"));
        await auditor.CheckOnceAsync(default);
        Assert.Equal("Registry/Test/Run/Other", Assert.Single(_alerts.Items).Resource);
        Assert.Equal("app.exe --tray", Assert.Single(AtomicJsonFile.Read<PersistenceBaseline>(_options.BaselinePath!).Sources["Registry/Test/Run"],
            e => e.Id == "App").Command);
    }

    private sealed class FakeProvider : IPersistenceProvider
    {
        public IReadOnlyList<PersistenceSource> Sources { get; set; } = Array.Empty<PersistenceSource>();
        public int Reads { get; private set; }
        public Task<IReadOnlyList<PersistenceSource>> ReadAsync(CancellationToken cancellationToken)
        {
            Reads++;
            return Task.FromResult(Sources);
        }
    }

    private sealed class RecordingAlerts : IAlertPublisher
    {
        public List<ProtectionAlert> Items { get; } = new();
        public void Publish(string module, string code, AlertSeverity severity, string title, string message, string? resource = null) =>
            Items.Add(new(Guid.NewGuid(), DateTimeOffset.UtcNow, module, code, severity, title, message, resource));
    }
}

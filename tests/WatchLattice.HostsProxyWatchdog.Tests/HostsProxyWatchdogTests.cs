using Microsoft.Extensions.Logging.Abstractions;
using WatchLattice.Common.Alerts;
using Xunit;
using static WatchLattice.HostsProxyWatchdog.HostsProxyEvaluator;

namespace WatchLattice.HostsProxyWatchdog.Tests;

public class HostsProxyWatchdogTests : IDisposable
{
    private readonly string _folder = Path.Join(Path.GetTempPath(), $"watchlattice-hostsproxy-{Guid.NewGuid():N}");
    private readonly FakeProvider _provider = new();

    private HostsProxyWatchdogOptions Options() => new()
    {
        StatePath = Path.Join(_folder, "state.json"),
        AlertLogPath = Path.Join(_folder, "hosts-proxy.log"),
    };

    private HostsProxyWatchdog Create(HostsProxyWatchdogOptions? options = null, IAlertPublisher? alerts = null) => new(
        _provider,
        Microsoft.Extensions.Options.Options.Create(options ?? Options()),
        NullLogger<HostsProxyWatchdog>.Instance,
        alerts);

    [Fact]
    public async Task FirstCheck_RecordsABaseline_ThenStaysQuiet()
    {
        using var watchdog = Create();
        var changes = new List<HostsProxyChange>();
        var raised = new List<HostsProxyFinding>();
        watchdog.ChangeDetected += changes.Add;
        watchdog.AlertRaised += raised.Add;

        await watchdog.CheckOnceAsync(default);
        await watchdog.CheckOnceAsync(default);

        var baseline = Assert.Single(changes);
        Assert.Equal(BaselineCreated, baseline.Code);
        Assert.Equal(AlertSeverity.Info, baseline.Severity);
        Assert.Contains("1 host name", baseline.Message);
        Assert.Contains("no proxy server or auto-config script is set", baseline.Message);
        Assert.Empty(raised);
    }

    [Fact]
    public async Task HostsChange_IsReported_AndSurvivesARestart()
    {
        using (var first = Create())
        {
            await first.CheckOnceAsync(default);
        }

        // Changed while the hub was stopped.
        _provider.Hosts = TestData.DefaultHosts + "203.0.113.50 login.bank.test\n";
        using var second = Create();
        var changes = new List<HostsProxyChange>();
        second.ChangeDetected += changes.Add;

        await second.CheckOnceAsync(default);
        await second.CheckOnceAsync(default);

        var change = Assert.Single(changes);
        Assert.Equal(HostsChanged, change.Code);
        Assert.Equal(AlertSeverity.Warning, change.Severity);
        Assert.Contains("added login.bank.test → 203.0.113.50", change.Message);
    }

    [Fact]
    public async Task BlockedUpdateHost_IsCritical_StaysOpenWhileUnreadable_AndClears()
    {
        var shared = new AlertHub(Microsoft.Extensions.Options.Options.Create(new AlertDeliveryOptions()));
        using var watchdog = Create(alerts: shared);
        var raised = new List<HostsProxyFinding>();
        var cleared = new List<HostsProxyFinding>();
        watchdog.AlertRaised += raised.Add;
        watchdog.AlertCleared += cleared.Add;

        await watchdog.CheckOnceAsync(default);
        _provider.Hosts = TestData.DefaultHosts + "0.0.0.0 definitionupdates.microsoft.com\n";
        await watchdog.CheckOnceAsync(default);
        await watchdog.CheckOnceAsync(default);

        Assert.Equal(ProtectedHostOverridden, Assert.Single(raised).Code);
        Assert.Contains(shared.Snapshot().Alerts, a => a.Module == "HostsProxyWatchdog" && a.Code == HostsChanged && a.Severity == AlertSeverity.Critical);
        Assert.Contains(shared.Snapshot().Alerts, a => a.Code == ProtectedHostOverridden && a.Severity == AlertSeverity.Critical);

        _provider.HostsError = "The process cannot access the file because it is being used by another process.";
        await watchdog.CheckOnceAsync(default);
        Assert.Empty(cleared);

        _provider.HostsError = null;
        _provider.Hosts = TestData.DefaultHosts;
        await watchdog.CheckOnceAsync(default);

        Assert.Contains(cleared, f => f.Code == ProtectedHostOverridden);
        Assert.Contains(cleared, f => f.Code == HostsUnavailable);
        Assert.Contains(shared.Snapshot().Alerts, a => a.Code == ProtectedHostOverridden + "_CLEARED" && a.Severity == AlertSeverity.Info);
    }

    [Fact]
    public async Task ProxyChange_IsReportedOncePerScope()
    {
        using var watchdog = Create();
        var changes = new List<HostsProxyChange>();
        await watchdog.CheckOnceAsync(default);
        watchdog.ChangeDetected += changes.Add;

        _provider.Scopes = new[]
        {
            TestData.Scope(("ProxyEnable", "1"), ("ProxyServer", "127.0.0.1:8080"), ("Connection.ProxyEnabled", "1")),
            TestData.Scope("WinHTTP"),
        };
        await watchdog.CheckOnceAsync(default);
        await watchdog.CheckOnceAsync(default);

        var change = Assert.Single(changes);
        Assert.Equal(ProxyChanged, change.Code);
        Assert.Equal(AlertSeverity.Warning, change.Severity);
        Assert.Equal("User:S-1-5-21-1", change.Resource);
        Assert.Contains("Connection.ProxyEnabled", change.Message);
    }

    [Fact]
    public async Task SignedOutUser_IsNotAChange_AndNewUsersAreRecordedQuietly()
    {
        _provider.Scopes = new[] { TestData.Scope(("ProxyServer", "proxy.corp:80")), TestData.Scope("WinHTTP") };
        using var watchdog = Create();
        await watchdog.CheckOnceAsync(default);
        var changes = new List<HostsProxyChange>();
        watchdog.ChangeDetected += changes.Add;

        _provider.Scopes = new[] { TestData.Scope("WinHTTP"), TestData.Scope("User:S-1-5-21-2", ("ProxyServer", "x:1")) };
        await watchdog.CheckOnceAsync(default);
        _provider.Scopes = new[] { TestData.Scope(("ProxyServer", "proxy.corp:80")), TestData.Scope("WinHTTP"), TestData.Scope("User:S-1-5-21-2", ("ProxyServer", "x:1")) };
        await watchdog.CheckOnceAsync(default);

        Assert.Empty(changes);
    }

    [Fact]
    public async Task UnreadableScope_KeepsItsBaseline()
    {
        _provider.Scopes = new[] { TestData.Scope("Machine", ("ProxyServer", "proxy.corp:80")) };
        using var watchdog = Create();
        await watchdog.CheckOnceAsync(default);
        var changes = new List<HostsProxyChange>();
        var raised = new List<HostsProxyFinding>();
        watchdog.ChangeDetected += changes.Add;
        watchdog.AlertRaised += raised.Add;

        _provider.Scopes = new[] { new ProxyScope("Machine", "Machine", new Dictionary<string, string>(), "Access is denied.") };
        await watchdog.CheckOnceAsync(default);
        _provider.Scopes = new[] { TestData.Scope("Machine", ("ProxyServer", "proxy.corp:80")) };
        await watchdog.CheckOnceAsync(default);

        Assert.Empty(changes);
        Assert.Equal(ProxyUnavailable, Assert.Single(raised).Code);
    }

    [Fact]
    public async Task TurningAHostsCheckOff_ForgetsItsBaseline()
    {
        using (var first = Create())
        {
            await first.CheckOnceAsync(default);
        }
        var off = Options();
        off.WatchHostsFile = false;
        using (var second = Create(off))
        {
            await second.CheckOnceAsync(default);
        }

        _provider.Hosts = TestData.DefaultHosts + "10.0.0.1 nas.home\n";
        using var third = Create();
        var changes = new List<HostsProxyChange>();
        third.ChangeDetected += changes.Add;
        await third.CheckOnceAsync(default);

        Assert.Equal(BaselineCreated, Assert.Single(changes).Code);
        Assert.Equal(new[] { (false, true) }, _provider.Requests.Skip(1).Take(1));
    }

    [Fact]
    public async Task CorruptState_IsReportedOnce_AndWatchingContinues()
    {
        Directory.CreateDirectory(_folder);
        await File.WriteAllTextAsync(Path.Join(_folder, "state.json"), "{ not json");
        using var watchdog = Create();
        var changes = new List<HostsProxyChange>();
        watchdog.ChangeDetected += changes.Add;

        await watchdog.CheckOnceAsync(default);
        await watchdog.CheckOnceAsync(default);

        Assert.Equal(new[] { HostsProxyWatchdog.StateUnreadable, BaselineCreated }, changes.Select(c => c.Code));
    }

    [Fact]
    public async Task ProviderFailure_IsReported_NotThrown()
    {
        _provider.Throw = new InvalidOperationException("boom");
        using var watchdog = Create();

        var findings = await watchdog.CheckOnceAsync(default);

        Assert.Equal(new[] { HostsUnavailable, ProxyUnavailable }, findings.Select(f => f.Code).Order());
    }

    [Fact]
    public async Task RunAsync_StopsCleanlyWhenCancelled()
    {
        using var watchdog = Create();
        using var cts = new CancellationTokenSource();
        _provider.OnRead = cts.Cancel;

        await watchdog.RunAsync(cts.Token);

        Assert.Single(_provider.Requests);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_folder, recursive: true);
        }
        catch (DirectoryNotFoundException)
        {
        }
    }

    private sealed class FakeProvider : IHostsProxyProvider
    {
        public string Hosts { get; set; } = TestData.DefaultHosts;
        public string? HostsError { get; set; }
        public IReadOnlyList<ProxyScope> Scopes { get; set; } = new[] { TestData.Scope(("ProxyEnable", "0")), TestData.Scope("WinHTTP") };
        public Exception? Throw { get; set; }
        public Action? OnRead { get; set; }
        public List<(bool Hosts, bool Proxy)> Requests { get; } = new();

        public Task<HostsProxySnapshot> ReadAsync(bool hosts, bool proxy, CancellationToken cancellationToken)
        {
            Requests.Add((hosts, proxy));
            OnRead?.Invoke();
            if (Throw is not null)
            {
                return Task.FromException<HostsProxySnapshot>(Throw);
            }
            const string path = @"C:\Windows\System32\drivers\etc\hosts";
            return Task.FromResult(new HostsProxySnapshot
            {
                Hosts = !hosts ? null
                    : HostsError is not null ? HostsFileSnapshot.Unavailable(path, HostsError)
                    : new HostsFileSnapshot { Path = path, DatabasePath = @"C:\Windows\System32\drivers\etc", Entries = HostsFileParser.Parse(Hosts) },
                Proxy = proxy ? Scopes : null,
            });
        }
    }
}

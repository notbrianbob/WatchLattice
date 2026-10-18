using WatchLattice.Common.Alerts;
using Xunit;
using static WatchLattice.HostsProxyWatchdog.HostsProxyEvaluator;

namespace WatchLattice.HostsProxyWatchdog.Tests;

public class HostsProxyEvaluatorTests
{
    private static readonly HostsProxyWatchdogOptions Defaults = new();

    [Fact]
    public void DefaultHostsFile_HasNoFindings()
    {
        var findings = Evaluate(TestData.Snapshot("127.0.0.1 localhost\n::1 localhost"), Defaults);
        Assert.Empty(findings);
    }

    [Fact]
    public void BlockedUpdateHost_IsCritical_AndNamesTheHost()
    {
        var findings = Evaluate(TestData.Snapshot("0.0.0.0 download.windowsupdate.com\n203.0.113.5 wdcp.microsoft.com\n0.0.0.0 ads.test"), Defaults);

        var finding = Assert.Single(findings);
        Assert.Equal(ProtectedHostOverridden, finding.Code);
        Assert.Equal(AlertSeverity.Critical, finding.Severity);
        Assert.Contains("download.windowsupdate.com blocked (0.0.0.0)", finding.Message);
        Assert.Contains("wdcp.microsoft.com → 203.0.113.5", finding.Message);
        Assert.DoesNotContain("ads.test", finding.Message);
    }

    [Fact]
    public void ProtectedDomains_CanBeExtended_ReplacedOrIgnored()
    {
        var hosts = TestData.Snapshot("0.0.0.0 download.windowsupdate.com\n10.1.1.1 intranet.corp.test");

        Assert.Contains("intranet.corp.test", Assert.Single(Evaluate(hosts,
            new HostsProxyWatchdogOptions { ProtectedDomains = new[] { "*.corp.test" } })).Message);
        Assert.Empty(Evaluate(hosts, new HostsProxyWatchdogOptions { IncludeBuiltInProtectedDomains = false }));
        Assert.Empty(Evaluate(hosts, new HostsProxyWatchdogOptions { IgnoredHosts = new[] { "*.WindowsUpdate.com" } }));
    }

    [Fact]
    public void UnreadableAndMovedHostsFiles_AreReported()
    {
        var unreadable = Evaluate(new HostsProxySnapshot { Hosts = HostsFileSnapshot.Unavailable(@"C:\x\hosts", "Access is denied.") }, Defaults);
        Assert.Equal(HostsUnavailable, Assert.Single(unreadable).Code);

        var moved = Evaluate(new HostsProxySnapshot
        {
            Hosts = new HostsFileSnapshot
            {
                Path = @"C:\Users\Public\etc\hosts",
                DatabasePath = @"C:\Users\Public\etc",
                DatabasePathMoved = true,
                Entries = new Dictionary<string, IReadOnlyList<string>>(),
            },
        }, Defaults);
        var finding = Assert.Single(moved);
        Assert.Equal(HostsPathMoved, finding.Code);
        Assert.Equal(@"C:\Users\Public\etc", finding.Resource);
    }

    [Fact]
    public void UnreadableProxyScopes_AreOneFinding()
    {
        var findings = Evaluate(new HostsProxySnapshot
        {
            Proxy = new[]
            {
                new ProxyScope("Machine", "this computer", new Dictionary<string, string>(), "Access is denied."),
                new ProxyScope("WinHTTP", "WinHTTP", new Dictionary<string, string>()),
            },
        }, Defaults);

        var finding = Assert.Single(findings);
        Assert.Equal(ProxyUnavailable, finding.Code);
        Assert.Contains("this computer: Access is denied.", finding.Message);
    }

    [Fact]
    public void CompareHosts_ListsBeforeAndAfter_WithSeverityByWhatChanged()
    {
        var baseline = TestData.Baseline("10.0.0.5 nas.home\n0.0.0.0 ads.test\n10.0.0.9 old.home");

        var change = CompareHosts(baseline, TestData.Entries("10.0.0.6 nas.home\n0.0.0.0 ads.test\n203.0.113.7 bank.test"), "hosts", Defaults);
        Assert.NotNull(change);
        Assert.Equal(HostsChanged, change.Code);
        Assert.Equal(AlertSeverity.Warning, change.Severity);
        Assert.Contains("(1 added, 1 changed, 1 removed)", change.Message);
        Assert.Contains("added bank.test → 203.0.113.7", change.Message);
        Assert.Contains("changed nas.home → 10.0.0.6 (was 10.0.0.5)", change.Message);
        Assert.Contains("removed old.home (was 10.0.0.9)", change.Message);

        var removalOnly = CompareHosts(baseline, TestData.Entries("10.0.0.5 nas.home\n0.0.0.0 ads.test"), "hosts", Defaults);
        Assert.Equal(AlertSeverity.Info, removalOnly?.Severity);

        var updateBlocked = CompareHosts(baseline, TestData.Entries("10.0.0.5 nas.home\n0.0.0.0 ads.test\n10.0.0.9 old.home\n0.0.0.0 go.microsoft.com"), "hosts", Defaults);
        Assert.Equal(AlertSeverity.Critical, updateBlocked?.Severity);

        Assert.Null(CompareHosts(baseline, TestData.Entries("10.0.0.5 nas.home\n0.0.0.0 ads.test\n10.0.0.9 old.home"), "hosts", Defaults));
    }

    [Fact]
    public void CompareHosts_SummarizesLargeChanges()
    {
        var current = TestData.Entries(string.Join("\n", Enumerable.Range(0, 5000).Select(i => $"0.0.0.0 ad{i:D4}.test")));

        var change = CompareHosts(new Dictionary<string, string[]>(), current, "hosts", new HostsProxyWatchdogOptions { MaxChangesPerAlert = 3 });

        Assert.NotNull(change);
        Assert.EndsWith("added ad0002.test blocked (0.0.0.0); and 4997 more.", change.Message);

        var withUpdateHost = CompareHosts(new Dictionary<string, string[]>(),
            TestData.Entries(string.Join("\n", Enumerable.Range(0, 50).Select(i => $"0.0.0.0 ad{i:D4}.test")) + "\n0.0.0.0 zz.windowsupdate.com"),
            "hosts", new HostsProxyWatchdogOptions { MaxChangesPerAlert = 3 });
        Assert.Contains("added zz.windowsupdate.com blocked", withUpdateHost?.Message);
        Assert.Equal(AlertSeverity.Critical, withUpdateHost?.Severity);
    }

    [Fact]
    public void CompareProxy_NewProxyServer_IsAWarning_WithBeforeAndAfter()
    {
        var change = CompareProxy(
            new Dictionary<string, string> { ["ProxyEnable"] = "0" },
            TestData.Scope(("ProxyEnable", "1"), ("ProxyServer", "127.0.0.1:8080")),
            Defaults);

        Assert.NotNull(change);
        Assert.Equal(ProxyChanged, change.Code);
        Assert.Equal(AlertSeverity.Warning, change.Severity);
        Assert.Equal("User:S-1-5-21-1", change.Resource);
        Assert.Contains("ProxyEnable: \"0\" → \"1\"", change.Message);
        Assert.Contains("ProxyServer: (not set) → \"127.0.0.1:8080\"", change.Message);
    }

    [Theory]
    [InlineData("AutoConfigURL", null, "http://evil.test/p.pac", AlertSeverity.Warning)]
    [InlineData("Env.HTTPS_PROXY", null, "http://10.9.9.9:3128", AlertSeverity.Warning)]
    [InlineData("WinHTTP.ProxyServer", "proxy.corp:80", "203.0.113.4:80", AlertSeverity.Warning)]
    [InlineData("Policy.ProxySettingsPerUser", null, "0", AlertSeverity.Warning)]
    [InlineData("ProxyEnable", "1", "0", AlertSeverity.Info)]
    [InlineData("ProxyServer", "proxy.corp:80", null, AlertSeverity.Info)]
    [InlineData("ProxyOverride", "<local>", "*.corp;<local>", AlertSeverity.Info)]
    [InlineData("Connection.AutoDetect", "1", "0", AlertSeverity.Info)]
    [InlineData("Connection.AutoDetect", "0", "1", AlertSeverity.Info)]
    public void CompareProxy_Severity(string name, string? before, string? after, AlertSeverity expected)
    {
        var baseline = before is null ? new Dictionary<string, string>() : new Dictionary<string, string> { [name] = before };
        var scope = after is null ? TestData.Scope() : TestData.Scope((name, after));

        Assert.Equal(expected, CompareProxy(baseline, scope, Defaults)?.Severity);
    }

    [Fact]
    public void CompareProxy_NoDifference_IsNull() =>
        Assert.Null(CompareProxy(new Dictionary<string, string> { ["ProxyEnable"] = "0" }, TestData.Scope(("ProxyEnable", "0")), Defaults));

    [Fact]
    public void DescribeProxyScopes_NamesOnlyWhatIsSet()
    {
        Assert.Equal("no proxy server or auto-config script is set",
            DescribeProxyScopes(new[] { TestData.Scope(("ProxyEnable", "0"), ("Connection.AutoDetect", "1")) }, Defaults));
        Assert.Contains("ProxyServer = proxy.corp:80",
            DescribeProxyScopes(new[] { TestData.Scope(("ProxyEnable", "1"), ("ProxyServer", "proxy.corp:80")) }, Defaults));
    }
}

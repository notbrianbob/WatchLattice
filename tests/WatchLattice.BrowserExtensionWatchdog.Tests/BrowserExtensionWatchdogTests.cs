using Microsoft.Extensions.Logging.Abstractions;
using WatchLattice.Common.Alerts;
using Xunit;
using static WatchLattice.BrowserExtensionWatchdog.BrowserExtensionWatchdog;

namespace WatchLattice.BrowserExtensionWatchdog.Tests;

/// <summary>The watchdog end to end: the real profile readers over fixture folders, with test-controlled policies.</summary>
public sealed class BrowserExtensionWatchdogTests : IDisposable
{
    private readonly Fixture _fixture = new();
    private readonly FakePolicyReader _policies = new();

    private BrowserExtensionWatchdogOptions Options(Action<BrowserExtensionWatchdogOptions>? configure = null)
    {
        var options = new BrowserExtensionWatchdogOptions
        {
            UserProfileFolders = new[] { _fixture.Home("alex") },
            StatePath = Path.Join(_fixture.Root, "state", "state.json"),
            AlertLogPath = Path.Join(_fixture.Root, "state", "browser-extensions.log"),
        };
        configure?.Invoke(options);
        return options;
    }

    private BrowserExtensionWatchdog Create(BrowserExtensionWatchdogOptions? options = null, IAlertPublisher? alerts = null, TimeProvider? time = null)
    {
        var wrapped = Microsoft.Extensions.Options.Options.Create(options ?? Options());
        return new BrowserExtensionWatchdog(new BrowserExtensionProvider(wrapped, _policies), wrapped,
            NullLogger<BrowserExtensionWatchdog>.Instance, alerts, time);
    }

    private static async Task<List<BrowserExtensionChange>> Check(BrowserExtensionWatchdog watchdog)
    {
        var changes = new List<BrowserExtensionChange>();
        watchdog.ChangeDetected += changes.Add;
        try
        {
            await watchdog.CheckOnceAsync(default);
        }
        finally
        {
            watchdog.ChangeDetected -= changes.Add;
        }
        return changes;
    }

    private void TypicalMachine()
    {
        _fixture.ChromiumProfile(Browsers.Chrome, "Default", "Alex");
        _fixture.AddChromiumExtension(Browsers.Chrome, Fixture.StoreExtension, "uBlock Origin Lite");
        _fixture.ChromiumProfile(Browsers.Edge, "Default", "Profile 1");
        _fixture.FirefoxProfiles("alex", ("default-release", "Profiles/abcd.default-release"));
        _fixture.FirefoxAddons("Profiles/abcd.default-release", "alex", Fixture.FirefoxAddon("uBlock0@raymondhill.net", "uBlock Origin"));
    }

    [Fact]
    public async Task FirstCheck_RecordsABaseline_ThenStaysQuiet()
    {
        TypicalMachine();
        _policies.Entries.Add(FakePolicyReader.ForceInstall(Browsers.Edge, Fixture.PolicyExtension));
        using var watchdog = Create();

        var first = await Check(watchdog);
        var second = await Check(watchdog);

        var baseline = Assert.Single(first);
        Assert.Equal(BaselineCreated, baseline.Code);
        Assert.Equal(AlertSeverity.Info, baseline.Severity);
        Assert.Contains("2 extensions in 3 browser profiles", baseline.Message);
        Assert.Contains("Google Chrome: 1 profile, 1 extension", baseline.Message);
        Assert.Contains("1 extension install policy or registration", baseline.Message);
        Assert.Empty(second);
        Assert.Empty(await watchdog.CheckOnceAsync(default));
    }

    [Fact]
    public async Task AddedExtension_IsReportedWithEverythingNeeded_AndSurvivesARestart()
    {
        TypicalMachine();
        _policies.Entries.Add(FakePolicyReader.ForceInstall(Browsers.Chrome, Fixture.PolicyExtension));
        using (var first = Create())
        {
            await Check(first);
        }

        // Installed while the hub was stopped.
        _fixture.AddChromiumExtension(Browsers.Chrome, Fixture.SideloadedExtension, "Search Helper", location: 3, fromWebstore: false, version: "4.2");
        var shared = new AlertHub(Microsoft.Extensions.Options.Options.Create(new AlertDeliveryOptions()));
        using var second = Create(alerts: shared);

        var changes = await Check(second);
        Assert.Empty(await Check(second));

        var change = Assert.Single(changes);
        Assert.Equal(ExtensionAdded, change.Code);
        Assert.Equal(AlertSeverity.Warning, change.Severity);
        Assert.Equal("New browser extension: Search Helper", change.Title);
        Assert.Contains($"\"Search Helper\" ({Fixture.SideloadedExtension}, version 4.2, registered in the Windows registry by another program)", change.Message);
        Assert.Contains("Google Chrome profile \"Alex\" (Default) of alex", change.Message);
        Assert.Contains("Installed by policy: no.", change.Message);
        Assert.Contains("Another program installed it", change.Message);
        Assert.Equal($"Chrome/alex/Default/{Fixture.SideloadedExtension}", change.Resource);

        var alert = Assert.Single(shared.Snapshot().Alerts);
        Assert.Equal((ModuleId, ExtensionAdded), (alert.Module, alert.Code));
        Assert.Equal(10002, AlertEventIds.For(alert.Module, alert.Code, alert.Severity));
    }

    [Fact]
    public async Task PolicyInstalledExtension_SaysSo()
    {
        TypicalMachine();
        using var watchdog = Create();
        await Check(watchdog);

        _fixture.FirefoxAddons("Profiles/abcd.default-release", "alex",
            Fixture.FirefoxAddon("uBlock0@raymondhill.net", "uBlock Origin"),
            Fixture.FirefoxAddon("corp@example.com", "Corp Tool", source: "enterprise-policy"));
        var change = Assert.Single(await Check(watchdog));

        Assert.Equal(ExtensionAdded, change.Code);
        Assert.Contains("Installed by policy: yes.", change.Message);
        Assert.Contains("Mozilla Firefox profile \"default-release\" (abcd.default-release)", change.Message);
    }

    [Fact]
    public async Task RemovedExtension_IsInfo_AndCanBeTurnedOff()
    {
        TypicalMachine();
        using (var watchdog = Create())
        {
            await Check(watchdog);
            _fixture.RemoveChromiumExtension(Browsers.Chrome, Fixture.StoreExtension);

            var change = Assert.Single(await Check(watchdog));

            Assert.Equal(ExtensionRemoved, change.Code);
            Assert.Equal(AlertSeverity.Info, change.Severity);
            Assert.Contains("was removed from the Google Chrome profile", change.Message);
        }

        _fixture.AddChromiumExtension(Browsers.Chrome, Fixture.StoreExtension, "uBlock Origin Lite");
        using var quiet = Create(Options(o => o.ReportRemovals = false));
        Assert.Equal(ExtensionAdded, Assert.Single(await Check(quiet)).Code);
        _fixture.RemoveChromiumExtension(Browsers.Chrome, Fixture.StoreExtension);
        Assert.Empty(await Check(quiet));
    }

    [Fact]
    public async Task ManyChanges_AreSummarized_AndIgnoredIdsStayQuiet()
    {
        TypicalMachine();
        using var watchdog = Create(Options(o =>
        {
            o.MaxIndividualAlerts = 2;
            o.MaxChangesPerAlert = 2;
            o.IgnoredExtensionIds = new[] { "ignored*" };
        }));
        await Check(watchdog);

        for (var i = 0; i < 4; i++)
        {
            _fixture.AddChromiumExtension(Browsers.Edge, new string((char)('d' + i), 32), $"Thing {i}");
        }
        _fixture.AddChromiumExtension(Browsers.Edge, "ignoredignoredignoredignoredigno", "Approved");

        var change = Assert.Single(await Check(watchdog));

        Assert.Equal(ExtensionsAdded, change.Code);
        Assert.Equal(AlertSeverity.Warning, change.Severity);
        Assert.Equal("4 new browser extensions", change.Title);
        Assert.Contains("and 2 more", change.Message);
        Assert.DoesNotContain("Approved", change.Message);
    }

    [Fact]
    public async Task NewAndDeletedProfiles_AreInfo_AndTheirExtensionsAreNotReportedOneByOne()
    {
        TypicalMachine();
        using var watchdog = Create();
        await Check(watchdog);

        _fixture.ChromiumProfile(Browsers.Chrome, "Profile 2", "Guest-ish");
        _fixture.AddChromiumExtension(Browsers.Chrome, Fixture.SideloadedExtension, "Helper", folder: "Profile 2");
        var added = Assert.Single(await Check(watchdog));
        Assert.Equal(ProfileAdded, added.Code);
        Assert.Equal(AlertSeverity.Info, added.Severity);
        Assert.Contains("with 1 extension: \"Helper\"", added.Message);

        Directory.Delete(_fixture.ProfilePath(Browsers.Chrome, "Profile 2"), recursive: true);
        var removed = Assert.Single(await Check(watchdog));
        Assert.Equal(ProfileRemoved, removed.Code);
        Assert.Contains("is gone, with the 1 extension it had", removed.Message);
    }

    [Fact]
    public async Task UnreadableProfile_KeepsItsInventory_RaisesAWarning_AndClears()
    {
        TypicalMachine();
        using var watchdog = Create();
        var raised = new List<BrowserExtensionFinding>();
        var cleared = new List<BrowserExtensionFinding>();
        watchdog.AlertRaised += raised.Add;
        watchdog.AlertCleared += cleared.Add;
        await Check(watchdog);

        var prefs = Path.Join(_fixture.ProfilePath(Browsers.Chrome), "Secure Preferences");
        var good = await File.ReadAllTextAsync(prefs);
        await File.WriteAllTextAsync(prefs, "{ truncated");
        Assert.Empty(await Check(watchdog));
        Assert.Equal(ProfileUnreadable, Assert.Single(raised).Code);

        await File.WriteAllTextAsync(prefs, good);
        Assert.Empty(await Check(watchdog));
        Assert.Equal(ProfileUnreadable, Assert.Single(cleared).Code);
    }

    [Fact]
    public async Task UserWhoIsNotRead_IsNotAChange()
    {
        TypicalMachine();
        _fixture.ChromiumProfile(Browsers.Chrome, "Default", user: "sam");
        _fixture.AddChromiumExtension(Browsers.Chrome, Fixture.StoreExtension, "uBlock Origin Lite", user: "sam");
        var both = Options(o => o.UserProfileFolders = new[] { _fixture.Home("alex"), _fixture.Home("sam") });
        using (var first = Create(both))
        {
            await Check(first);
        }

        // sam's folder is out of reach (for example a roaming profile that isn't there).
        Directory.Move(_fixture.Home("sam"), _fixture.Home("sam") + ".away");
        using (var second = Create(both))
        {
            Assert.Empty(await Check(second));
        }

        Directory.Move(_fixture.Home("sam") + ".away", _fixture.Home("sam"));
        using var third = Create(both);
        Assert.Empty(await Check(third));
    }

    [Fact]
    public async Task PolicyEntries_AreReported_AndUnreadScopesAreKept()
    {
        TypicalMachine();
        _policies.Scopes.Add("User:S-1-5-21-1");
        _policies.Entries.Add(FakePolicyReader.ForceInstall(Browsers.Chrome, Fixture.PolicyExtension, "User:S-1-5-21-1"));
        using var watchdog = Create();
        await Check(watchdog);

        _policies.Entries.Add(FakePolicyReader.ForceInstall(Browsers.Edge, Fixture.SideloadedExtension));
        var added = Assert.Single(await Check(watchdog));
        Assert.Equal(PolicyAdded, added.Code);
        Assert.Equal(AlertSeverity.Warning, added.Severity);
        Assert.Contains($"Microsoft Edge force-install (ExtensionInstallForcelist) policy for this computer (all users): {Fixture.SideloadedExtension}", added.Message);
        Assert.Contains("users can't remove it", added.Message);
        Assert.Equal($"Edge/Machine/{Fixture.SideloadedExtension}", added.Resource);

        // The user signed out: their hive isn't read, so their entry isn't gone.
        _policies.Scopes.Remove("User:S-1-5-21-1");
        _policies.Entries.RemoveAll(e => e.Scope != "Machine");
        Assert.Empty(await Check(watchdog));

        _policies.Entries.Clear();
        var removed = Assert.Single(await Check(watchdog));
        Assert.Equal(PolicyRemoved, removed.Code);
        Assert.Equal(AlertSeverity.Info, removed.Severity);
    }

    [Fact]
    public async Task UnreadablePolicies_AreAStandingWarning()
    {
        TypicalMachine();
        _policies.Failure = new UnauthorizedAccessException("denied");
        using var watchdog = Create();

        var findings = await watchdog.CheckOnceAsync(default);

        Assert.Equal(PolicyUnavailable, Assert.Single(findings).Code);
        _policies.Failure = null;
        var changes = await Check(watchdog);
        Assert.Empty(await watchdog.CheckOnceAsync(default));
        // Policies are baselined when they are first read, not reported as added.
        Assert.Equal(BaselineCreated, Assert.Single(changes).Code);
        Assert.Contains("no extension install policies", changes[0].Message);
    }

    [Fact]
    public async Task TurningABrowserOff_ForgetsIt_SoTurningItBackOnStartsFresh()
    {
        TypicalMachine();
        using (var watchdog = Create())
        {
            await Check(watchdog);
        }
        using (var noChrome = Create(Options(o => o.WatchChrome = false)))
        {
            Assert.Empty(await Check(noChrome));
        }

        _fixture.AddChromiumExtension(Browsers.Chrome, Fixture.SideloadedExtension, "Added while off");
        using var again = Create();
        var change = Assert.Single(await Check(again));
        Assert.Equal(ProfileAdded, change.Code);
    }

    [Fact]
    public async Task CorruptState_StartsOver_AndSaysSo()
    {
        TypicalMachine();
        var options = Options();
        Directory.CreateDirectory(Path.GetDirectoryName(options.StatePath)!);
        await File.WriteAllTextAsync(options.StatePath!, "{\"version\":99}");
        using var watchdog = Create(options);

        var changes = await Check(watchdog);

        Assert.Equal(new[] { StateUnreadable, BaselineCreated }, changes.Select(c => c.Code));
    }

    [Fact]
    public async Task UnwritableState_IsAStandingWarning()
    {
        TypicalMachine();
        var blocker = Path.Join(_fixture.Root, "not-a-folder");
        await File.WriteAllTextAsync(blocker, "");
        using var watchdog = Create(Options(o => o.StatePath = Path.Join(blocker, "state.json")));

        var findings = await watchdog.CheckOnceAsync(default);

        Assert.Equal(StateSaveFailed, Assert.Single(findings).Code);
    }

    [Fact]
    public async Task RunAsync_ChecksAndWaitsOnTheTimeProvider_UntilCancelled()
    {
        TypicalMachine();
        var time = new ManualTime();
        using var watchdog = Create(time: time);
        var checks = 0;
        var secondCheck = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        watchdog.CheckCompleted += _ =>
        {
            if (Interlocked.Increment(ref checks) == 2)
            {
                secondCheck.TrySetResult();
            }
        };
        using var cancellation = new CancellationTokenSource();

        var run = watchdog.RunAsync(cancellation.Token);
        await time.TimerCreated.Task.WaitAsync(TimeSpan.FromSeconds(30));
        Assert.Equal(TimeSpan.FromSeconds(300), time.LastDue);
        time.FireAll();
        await secondCheck.Task.WaitAsync(TimeSpan.FromSeconds(30));
        cancellation.Cancel();
        await run.WaitAsync(TimeSpan.FromSeconds(30));

        Assert.True(checks >= 2);
    }

    public void Dispose() => _fixture.Dispose();

    /// <summary>Time that only moves when the test says so; records the timers Task.Delay creates.</summary>
    private sealed class ManualTime : TimeProvider
    {
        private readonly List<(TimerCallback Callback, object? State)> _timers = new();

        public TaskCompletionSource TimerCreated { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TimeSpan LastDue { get; private set; }

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            lock (_timers)
            {
                _timers.Add((callback, state));
                LastDue = dueTime;
            }
            TimerCreated.TrySetResult();
            return new NoopTimer();
        }

        public void FireAll()
        {
            List<(TimerCallback Callback, object? State)> due;
            lock (_timers)
            {
                due = _timers.ToList();
                _timers.Clear();
            }
            foreach (var (callback, state) in due)
            {
                callback(state);
            }
        }

        private sealed class NoopTimer : ITimer
        {
            public bool Change(TimeSpan dueTime, TimeSpan period) => true;
            public void Dispose() { }
            public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        }
    }
}

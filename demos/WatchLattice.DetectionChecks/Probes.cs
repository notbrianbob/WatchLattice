using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using WatchLattice.BrowserExtensionWatchdog;
using WatchLattice.Canary;
using WatchLattice.Common.Alerts;
using WatchLattice.DefenderWatchdog;
using WatchLattice.FirewallWatchdog;
using WatchLattice.HostsProxyWatchdog;
using WatchLattice.Persistence;
using WatchLattice.ScriptHostAudit;

namespace WatchLattice.DetectionChecks;

/// <summary>Collects what a module publishes, the same alerts the hub would show and write to the Event Log.</summary>
public sealed class CapturingPublisher : IAlertPublisher
{
    private readonly List<ProtectionAlert> _alerts = new();

    public void Publish(string module, string code, AlertSeverity severity, string title, string message, string? resource = null)
    {
        lock (_alerts) _alerts.Add(new(Guid.NewGuid(), DateTimeOffset.UtcNow, module, code, severity, title, message, resource));
    }

    /// <summary>Everything published since the last call.</summary>
    public IReadOnlyList<ProtectionAlert> Take()
    {
        lock (_alerts)
        {
            var taken = _alerts.ToList();
            _alerts.Clear();
            return taken;
        }
    }
}

/// <summary>
/// One module's real code, configured as the hub configures it except that
/// its state files live in a throwaway folder (so the PC's real baselines are
/// untouched) and off-by-default watches the checks need are on.
/// </summary>
public abstract class Probe : IDisposable
{
    protected Probe(CapturingPublisher alerts) => Alerts = alerts;

    protected CapturingPublisher Alerts { get; }

    protected abstract Task RunCheckAsync(CancellationToken cancellationToken);

    /// <summary>Runs one check and returns what it published.</summary>
    public async Task<IReadOnlyList<ProtectionAlert>> CheckAsync(CancellationToken cancellationToken)
    {
        await RunCheckAsync(cancellationToken);
        return Alerts.Take();
    }

    public virtual void Dispose() { }

    public static Probe Create(ProbeKind kind, string workDir)
    {
        var folder = Path.Combine(workDir, kind.ToString());
        Directory.CreateDirectory(folder);
        var alerts = new CapturingPublisher();
        return kind switch
        {
            ProbeKind.Persistence => new PersistenceProbe(alerts, folder),
            ProbeKind.Canary => new CanaryProbe(alerts, folder),
            _ => new HostedProbe(kind, alerts, folder),
        };
    }
}

public sealed class PersistenceProbe : Probe
{
    private readonly PersistenceAuditor _auditor;

    public PersistenceProbe(CapturingPublisher alerts, string folder) : base(alerts)
    {
        var options = Options.Create(new PersistenceOptions
        {
            BaselinePath = Path.Combine(folder, "persistence-baseline.json"),
            WatchRegistry = true,
            WatchStartupFolders = true,
            WatchScheduledTasks = true,
            WatchServices = true,
            WatchWmiSubscriptions = true,
        });
        // No evidence sink: signature verification is its own feature with its own tests.
        _auditor = new PersistenceAuditor(new WindowsPersistenceProvider(options), options, NullLogger<PersistenceAuditor>.Instance, alerts);
    }

    protected override Task RunCheckAsync(CancellationToken cancellationToken) => _auditor.CheckOnceAsync(cancellationToken);
}

/// <summary>The modules that register through their own ServiceCollectionExtensions, built the way the hub builds them.</summary>
public sealed class HostedProbe : Probe
{
    private readonly ServiceProvider _services;
    private readonly ProbeKind _kind;

    public HostedProbe(ProbeKind kind, CapturingPublisher alerts, string folder) : base(alerts)
    {
        _kind = kind;
        string P(string name) => Path.Combine(folder, name);
        var settings = kind switch
        {
            ProbeKind.HostsProxy => new Dictionary<string, string?>
            {
                [$"{HostsProxyWatchdogOptions.SectionName}:StatePath"] = P("state.json"),
                [$"{HostsProxyWatchdogOptions.SectionName}:AlertLogPath"] = P("alerts.log"),
                [$"{HostsProxyWatchdogOptions.SectionName}:ProtectedDomains:0"] = Scenarios.ProtectedTestDomain,
            },
            ProbeKind.Firewall => new Dictionary<string, string?>
            {
                [$"{FirewallWatchdogOptions.SectionName}:StatePath"] = P("state.json"),
                [$"{FirewallWatchdogOptions.SectionName}:AlertLogPath"] = P("alerts.log"),
                // Off by default in the hub; the check turns it on to exercise it.
                [$"{FirewallWatchdogOptions.SectionName}:MonitorInboundAllowRules"] = "true",
            },
            ProbeKind.Defender => new Dictionary<string, string?>
            {
                [$"{DefenderWatchdogOptions.SectionName}:StatePath"] = P("state.json"),
                [$"{DefenderWatchdogOptions.SectionName}:AlertLogPath"] = P("alerts.log"),
            },
            ProbeKind.BrowserExtensions => new Dictionary<string, string?>
            {
                [$"{BrowserExtensionWatchdogOptions.SectionName}:StatePath"] = P("state.json"),
                [$"{BrowserExtensionWatchdogOptions.SectionName}:AlertLogPath"] = P("alerts.log"),
            },
            ProbeKind.ScriptHosts => new Dictionary<string, string?>
            {
                [$"{ScriptHostAuditOptions.SectionName}:StatePath"] = P("state.json"),
                [$"{ScriptHostAuditOptions.SectionName}:AlertLogPath"] = P("alerts.log"),
            },
            _ => throw new ArgumentOutOfRangeException(nameof(kind)),
        };
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
        var services = new ServiceCollection()
            .AddLogging(b => b.SetMinimumLevel(LogLevel.Warning))
            .AddSingleton<IAlertPublisher>(alerts);
        _ = kind switch
        {
            ProbeKind.HostsProxy => services.AddWatchLatticeHostsProxyWatchdog(configuration),
            ProbeKind.Firewall => services.AddWatchLatticeFirewallWatchdog(configuration),
            ProbeKind.Defender => services.AddWatchLatticeDefenderWatchdog(configuration),
            ProbeKind.BrowserExtensions => services.AddWatchLatticeBrowserExtensionWatchdog(configuration),
            _ => services.AddWatchLatticeScriptHostAudit(configuration),
        };
        _services = services.BuildServiceProvider();
    }

    protected override async Task RunCheckAsync(CancellationToken cancellationToken)
    {
        switch (_kind)
        {
            case ProbeKind.HostsProxy: await _services.GetRequiredService<HostsProxyWatchdog.HostsProxyWatchdog>().CheckOnceAsync(cancellationToken); break;
            case ProbeKind.Firewall: await _services.GetRequiredService<FirewallWatchdog.FirewallWatchdog>().CheckOnceAsync(cancellationToken); break;
            case ProbeKind.Defender: await _services.GetRequiredService<DefenderWatchdog.DefenderWatchdog>().CheckOnceAsync(cancellationToken); break;
            case ProbeKind.BrowserExtensions: await _services.GetRequiredService<BrowserExtensionWatchdog.BrowserExtensionWatchdog>().CheckOnceAsync(cancellationToken); break;
            default: _services.GetRequiredService<ScriptHostAuditor>().CheckOnce(cancellationToken); break;
        }
    }

    public override void Dispose() => _services.Dispose();
}

/// <summary>The canary watcher runs continuously (it reacts to file system events), so a check just collects what it raised.</summary>
public sealed class CanaryProbe : Probe
{
    private static string? _documents;
    private readonly CanaryWatcher _watcher;
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _run;

    public CanaryProbe(CapturingPublisher alerts, string folder) : base(alerts)
    {
        _documents = Path.Combine(folder, "Documents");
        Directory.CreateDirectory(_documents);
        var options = new CanaryOptions
        {
            Folders = new List<string> { _documents },
            AlertLogPath = Path.Combine(folder, "canary-alerts.log"),
            ManifestPath = Path.Combine(folder, "canary-manifest.json"),
        };
        _watcher = new CanaryWatcher(Options.Create(options), NullLogger<CanaryWatcher>.Instance, alerts);
        _run = Task.Run(() => _watcher.RunAsync(_stop.Token));
    }

    protected override async Task RunCheckAsync(CancellationToken cancellationToken)
    {
        var armed = DateTime.UtcNow;
        while (_watcher.ActiveCanaries.Count == 0 && DateTime.UtcNow - armed < TimeSpan.FromSeconds(10))
            await Task.Delay(50, cancellationToken);
        await Task.Delay(250, cancellationToken);
    }

    /// <summary>Overwrites the start of one planted canary, as in-place encryption would.</summary>
    public static void OverwriteOne()
    {
        var canary = Directory.EnumerateFiles(_documents ?? throw new InvalidOperationException("The canary watcher is not running."))
            .OrderBy(p => p, StringComparer.Ordinal).First();
        using var stream = new FileStream(canary, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
        var junk = new byte[4096];
        Random.Shared.NextBytes(junk);
        stream.Write(junk);
    }

    public override void Dispose()
    {
        _stop.Cancel();
        try { _run.Wait(TimeSpan.FromSeconds(10)); } catch (AggregateException) { }
        _watcher.Dispose();
        _stop.Dispose();
    }
}

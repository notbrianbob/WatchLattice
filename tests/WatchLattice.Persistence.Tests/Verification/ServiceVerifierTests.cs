using WatchLattice.Persistence.Verification;
using Xunit;
using static WatchLattice.Persistence.Tests.Verification.TaskScenarios;

namespace WatchLattice.Persistence.Tests.Verification;

internal sealed class FakeServiceSource : IServiceSource
{
    public Dictionary<string, ServiceReadResult> Services { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<string> Reads { get; } = new();

    public ServiceReadResult Read(string serviceName)
    {
        Reads.Add(serviceName);
        return Services.TryGetValue(serviceName, out var result) ? result : new(ServiceReadStatus.NotFound);
    }
}

public sealed class ServiceVerifierTests
{
    private const string Defender = @"C:\ProgramData\Microsoft\Windows Defender\Platform";
    private static readonly ServiceDefinition EventLog = new(0x20, 2, @"%SystemRoot%\System32\svchost.exe -k LocalServiceNetworkRestricted -p",
        @"%SystemRoot%\System32\wevtsvc.dll", @"NT AUTHORITY\LocalService", null);

    private readonly FakeServiceSource _services = new();
    private readonly FakeFiles _files = new();
    private readonly List<string> _familiar = new();

    public ServiceVerifierTests()
    {
        _files.Add(@"C:\Windows\System32\wevtsvc.dll", MicrosoftCatalog);
        _files.Add(@"C:\Windows\System32\svchost.exe", MicrosoftCatalog);
    }

    private Task<VerificationRun> VerifyAsync(PersistenceObservation observation) =>
        new PersistenceVerificationEngine(new IEntryVerifier[] { new ServiceVerifier(_services, _files, Paths, _familiar) }, new FakeAccounts())
            .VerifyAsync(observation, VerificationTrigger.Manual, CancellationToken.None);

    private static PersistenceObservation Added(string name, ServiceDefinition service) =>
        new(ServiceVerifier.SourceId, name, PersistenceChangeKind.Added, null, service.ToProjection(), DateTimeOffset.UtcNow);

    private static PersistenceObservation Changed(string name, ServiceDefinition before, ServiceDefinition after) =>
        new(ServiceVerifier.SourceId, name, PersistenceChangeKind.Changed, before.ToProjection(), after.ToProjection(), DateTimeOffset.UtcNow);

    private void Current(string name, ServiceDefinition service) => _services.Services[name] = new(ServiceReadStatus.Found, service);

    [Fact]
    public async Task NewSharedService_ResolvesItsServiceDll_AndPassesForASignedWindowsFile()
    {
        Current("EventLog", EventLog);

        var run = await VerifyAsync(Added("EventLog", EventLog));

        Assert.True(run.Outcome == VerificationOutcome.ChecksPassed, run.Describe());
        Assert.Equal("Service", run.Mechanism);
        Assert.Equal(new[] { "EventLog" }, _services.Reads);
        var action = Assert.Single(run.Actions);
        Assert.Equal(@"C:\Windows\System32\wevtsvc.dll", action.ResolvedPath, ignoreCase: true);
        Assert.Equal(CheckStatus.Pass, run.Check("service.location").Status);
        Assert.Equal(CheckStatus.Pass, run.Check("service.signature").Status);
        Assert.Equal(CheckStatus.Pass, run.Check("service.publisher").Status);
        Assert.Contains("LocalService", run.Check("service").Detail);
    }

    [Fact]
    public async Task ServiceInAUserProfile_IsSuspicious_EvenWhenSigned()
    {
        var evil = new ServiceDefinition(0x10, 2, @"""C:\Users\Bob\AppData\Local\Temp\updater.exe"" --service", null, null, null);
        Current("Updater", evil);
        _files.Add(@"C:\Users\Bob\AppData\Local\Temp\updater.exe", MicrosoftCatalog);

        var run = await VerifyAsync(Added("Updater", evil));

        Assert.Equal(VerificationOutcome.Suspicious, run.Outcome);
        Assert.Equal(CheckStatus.Fail, run.Check("service.location").Status);
        Assert.Contains("user", run.Check("service.location").Detail);
    }

    [Theory]
    [InlineData(@"C:\ProgramData\Vendor\svc.exe")]
    [InlineData(@"C:\Windows\Temp\svc.exe")]
    [InlineData(@"C:\Users\Public\svc.exe")]
    [InlineData(@"C:\Windows\System32\Tasks\svc.exe")]
    public void UserWritableFolders_AreRecognised(string path) =>
        Assert.Equal(ServiceLocation.UserWritable, ServiceAnalysis.Classify(WindowsPath.Resolve(path, Paths, null, _ => true), Paths));

    [Theory]
    [InlineData(@"C:\Windows\System32\svchost.exe", ServiceLocation.Protected)]
    [InlineData(@"C:\Program Files (x86)\Vendor\svc.exe", ServiceLocation.Protected)]
    [InlineData(Defender + @"\4.18.25090.3009-0\MsMpEng.exe", ServiceLocation.Protected)]
    [InlineData(@"D:\Tools\svc.exe", ServiceLocation.Other)]
    public void OtherFolders_AreClassified(string path, ServiceLocation expected) =>
        Assert.Equal(expected, ServiceAnalysis.Classify(WindowsPath.Resolve(path, Paths, null, _ => true), Paths));

    [Fact]
    public void ImagePaths_SplitLikeWindowsParsesThem()
    {
        Assert.Equal((@"C:\Program Files\Vendor App\svc.exe", "-run"), ServiceAnalysis.SplitCommand(@"""C:\Program Files\Vendor App\svc.exe"" -run"));
        Assert.Equal((@"C:\Program Files\Vendor App\svc.exe", "-run"), ServiceAnalysis.SplitCommand(@"C:\Program Files\Vendor App\svc.exe -run"));
        Assert.Equal((@"%SystemRoot%\System32\drivers\x.sys", ""), ServiceAnalysis.SplitCommand(@"\SystemRoot\System32\drivers\x.sys"));
        Assert.Equal((@"%SystemRoot%\System32\svchost.exe", "-k netsvcs -p"), ServiceAnalysis.SplitCommand(@"%SystemRoot%\System32\svchost.exe -k netsvcs -p"));
    }

    [Fact]
    public async Task DefenderPlatformUpdate_IsARoutineUpdate_AndPasses()
    {
        var before = new ServiceDefinition(0x10, 2, $@"""{Defender}\4.18.25080.5-0\MsMpEng.exe""", null, null, null);
        var after = before with { ImagePath = $@"""{Defender}\4.18.25090.3009-0\MsMpEng.exe""" };
        Current("WinDefend", after);
        _files.Add($@"{Defender}\4.18.25090.3009-0\MsMpEng.exe", MicrosoftCatalog);

        Assert.True(ServiceAnalysis.IsRoutineUpdate(before, after, Paths));
        Assert.False(ServiceAnalysis.ChangesTarget(before, after, Paths));
        var run = await VerifyAsync(Changed("WinDefend", before, after));

        Assert.True(run.Outcome == VerificationOutcome.ChecksPassed, run.Describe());
        Assert.Contains("new version", run.Check("logged-change").Detail);
    }

    [Fact]
    public async Task ProgramReplaced_IsSuspicious()
    {
        var after = EventLog with { ServiceDll = @"C:\Windows\System32\evil.dll" };
        Current("EventLog", after);
        _files.Add(@"C:\Windows\System32\evil.dll", MicrosoftCatalog);

        var run = await VerifyAsync(Changed("EventLog", EventLog, after));

        Assert.Equal(VerificationOutcome.Suspicious, run.Outcome);
        Assert.Equal(CheckStatus.Fail, run.Check("logged-change").Status);
        Assert.Contains("ServiceDll", run.Check("logged-change").Detail);
    }

    [Fact]
    public void RenamedFileInANewFolder_IsNotRoutine()
    {
        var before = new ServiceDefinition(0x10, 2, @"C:\Program Files\Vendor\1.0\svc.exe", null, null, null);
        Assert.False(ServiceAnalysis.IsRoutineUpdate(before, before with { ImagePath = @"C:\Program Files\Vendor\2.0\other.exe" }, Paths));
        Assert.False(ServiceAnalysis.IsRoutineUpdate(before, before with { ImagePath = @"C:\ProgramData\Vendor\2.0\svc.exe" }, Paths));
        Assert.False(ServiceAnalysis.IsRoutineUpdate(before, before with { ImagePath = @"C:\Program Files\Vendor\2.0\svc.exe -extra" }, Paths));
        Assert.False(ServiceAnalysis.IsRoutineUpdate(before, before with { ImagePath = @"C:\Program Files\Vendor\2.0\svc.exe", ObjectName = "LocalSystem2" }, Paths));
    }

    [Fact]
    public async Task SwitchToLocalSystem_IsAPrivilegeGain()
    {
        var after = EventLog with { ObjectName = "LocalSystem" };
        Current("EventLog", after);

        var run = await VerifyAsync(Changed("EventLog", EventLog, after));

        Assert.Equal(VerificationOutcome.Suspicious, run.Outcome);
        Assert.Contains("LocalSystem", run.Check("logged-change").Detail);
        Assert.Equal(ChangeArea.Principal, Assert.Single(run.LoggedChanges).Area);
    }

    [Fact]
    public async Task HostProgramAndFailureCommand_NeedReview()
    {
        var service = new ServiceDefinition(0x10, 2, @"C:\Windows\System32\cmd.exe /c C:\Windows\x.bat", null, null, @"C:\Windows\System32\cmd.exe /c recover");
        Current("Odd", service);
        _files.Add(@"C:\Windows\System32\cmd.exe", MicrosoftCatalog);

        var run = await VerifyAsync(Added("Odd", service));

        Assert.Equal(VerificationOutcome.NeedsReview, run.Outcome);
        Assert.Equal(CheckStatus.Warning, run.Check("service.host").Status);
        Assert.Equal(CheckStatus.Warning, run.Check("service.failure-command").Status);
    }

    [Fact]
    public async Task ChangedAgainSinceTheAlert_IsReported()
    {
        var replaced = EventLog with { ServiceDll = @"C:\Windows\System32\evil.dll" };
        Current("EventLog", replaced);
        _files.Add(@"C:\Windows\System32\evil.dll", MicrosoftCatalog);

        var run = await VerifyAsync(Added("EventLog", EventLog));

        Assert.Equal(CheckStatus.Fail, run.Check("since-alert").Status);
        Assert.Single(run.ChangesSinceAlert);
    }

    [Fact]
    public async Task MissingOrUnreadableService_IsNeverAPass()
    {
        var gone = await VerifyAsync(Added("EventLog", EventLog));
        Assert.Equal(VerificationOutcome.NeedsReview, gone.Outcome);
        Assert.Contains("no longer exists", gone.Check("service").Detail);

        var unreadable = await VerifyAsync(new(ServiceVerifier.SourceId, "Locked", PersistenceChangeKind.Added, null, "Unreadable: access denied.", DateTimeOffset.UtcNow));
        Assert.Equal(CheckStatus.Unknown, unreadable.Check("logged-change").Status);
        Assert.NotEqual(VerificationOutcome.ChecksPassed, unreadable.Outcome);

        var invalid = await VerifyAsync(Added(@"..\Other", EventLog));
        Assert.Equal(CheckStatus.Unknown, invalid.Check("service").Status);
        Assert.DoesNotContain(@"..\Other", _services.Reads);
    }

    [Fact]
    public void Projection_RoundTrips_AndOnlyAutoStartWin32ServicesAreInventoried()
    {
        Assert.Equal(EventLog, ServiceDefinition.TryParse(EventLog.ToProjection()));
        Assert.Null(ServiceDefinition.TryParse("Unreadable: access denied."));
        Assert.True(EventLog.IsAutoStartWin32Service);
        Assert.False((EventLog with { Start = 3 }).IsAutoStartWin32Service);
        Assert.False((EventLog with { Type = 0x1 }).IsAutoStartWin32Service);          // kernel driver
        Assert.True((EventLog with { Type = 0x60 }).IsAutoStartWin32Service);          // per-user service template
        Assert.False((EventLog with { Type = 0xE0 }).IsAutoStartWin32Service);         // per-user instance (random suffix per sign-in)
    }

    [Fact]
    public void OnlyServiceAlerts_UseThisVerifier()
    {
        var verifier = new ServiceVerifier(_services, _files, Paths);
        Assert.True(verifier.AppliesTo(Added("EventLog", EventLog)));
        Assert.False(verifier.AppliesTo(Added("EventLog", EventLog) with { Kind = PersistenceChangeKind.Removed }));
        Assert.False(verifier.AppliesTo(Added("EventLog", EventLog) with { SourceId = "ScheduledTasks/S-1-5-18" }));
    }
}

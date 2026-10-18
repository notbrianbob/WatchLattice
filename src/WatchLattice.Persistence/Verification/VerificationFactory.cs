using WatchLattice.Persistence.Verification.Windows;

namespace WatchLattice.Persistence.Verification;

/// <summary>
/// Builds the verification engine with every available verifier, for the hub
/// (automatic checks) and the tray (manual checks as the signed-in user).
/// To verify another persistence mechanism, add its <see cref="IEntryVerifier"/> here.
/// </summary>
public static class VerificationFactory
{
    public static PersistenceVerificationEngine CreateEngine(IEnumerable<string>? familiarPublishers = null)
    {
        var paths = SystemPaths.FromEnvironment();
        if (!OperatingSystem.IsWindows())
        {
            var unavailable = new Unavailable();
            return new PersistenceVerificationEngine(new IEntryVerifier[]
            {
                new ScheduledTaskVerifier(unavailable, unavailable, unavailable, new FileInspector(new UnavailableAuthenticodeInspector()), paths, familiarPublishers),
                new ServiceVerifier(unavailable, new FileInspector(new UnavailableAuthenticodeInspector()), paths, familiarPublishers),
            }, unavailable);
        }
        var accounts = new WindowsAccountResolver(paths);
        var files = new FileInspector(new WindowsAuthenticodeInspector());
        return new PersistenceVerificationEngine(new IEntryVerifier[]
        {
            new ScheduledTaskVerifier(new WindowsScheduledTaskSource(), new WindowsComRegistry(), accounts, files, paths, familiarPublishers),
            new ServiceVerifier(new WindowsServiceRegistry(), files, paths, familiarPublishers),
        }, accounts);
    }

    /// <summary>Off Windows nothing can be looked up; every probe says so, and results are inconclusive.</summary>
    private sealed class Unavailable : IScheduledTaskSource, IServiceSource, IComRegistry, IAccountResolver
    {
        private const string Reason = "Only available on Windows.";
        public TaskReadResult Read(string taskPath) => new(TaskReadStatus.Error, Error: Reason);
        ServiceReadResult IServiceSource.Read(string serviceName) => new(ServiceReadStatus.Error, Error: Reason);
        public ComRegistration Read(ComScope scope, string clsid, string? userSid = null) => new(clsid, false, Error: Reason);
        public IReadOnlyList<string> LoadedUserSids() => Array.Empty<string>();
        public string? ToSid(string account) => null;
        public string? ProfilePath(string sid) => null;
        public string CurrentAccount => Environment.UserName;
    }
}

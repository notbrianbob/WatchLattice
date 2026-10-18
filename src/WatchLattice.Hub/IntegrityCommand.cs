using Microsoft.Extensions.Configuration;
using WatchLattice.Updater;

namespace WatchLattice.Hub;

/// <summary>
/// <c>--verify-install</c> runs the install integrity check once and prints
/// what it found. Read-only, and needs no administrator rights. Exit codes:
/// 0 every file matches, 1 files were changed or are missing, 2 the check
/// could not run (no readable manifest, or files from another release),
/// 11 development build.
/// </summary>
internal static class IntegrityCommand
{
    public static int Run(IConfiguration configuration)
    {
        var options = new InstallIntegrityOptions();
        configuration.GetSection(InstallIntegrityOptions.SectionName).Bind(options);
        var current = ReleaseVersion.FromAssembly(typeof(IntegrityCommand).Assembly);
        if (current.IsDevelopmentBuild)
        {
            Console.WriteLine($"This is a development build ({current}); only release builds ship a file list to check against.");
            return 11;
        }

        var report = InstallIntegrityChecker.Check(AppContext.BaseDirectory, current, options);
        switch (report.State)
        {
            case IntegrityState.Verified:
                Console.WriteLine($"All {report.FilesChecked} checked file(s) in {report.InstallRoot} match WatchLattice {current}.");
                break;
            case IntegrityState.Modified:
                Console.WriteLine($"Installed files in {report.InstallRoot} differ from WatchLattice {current}:");
                foreach (var finding in report.Findings) Console.WriteLine("  " + finding);
                break;
            default:
                Console.WriteLine(report.Problem);
                break;
        }
        foreach (var file in report.Unreadable) Console.WriteLine($"  {file} (could not be read)");
        return report.State switch
        {
            IntegrityState.Verified => 0,
            IntegrityState.Modified => 1,
            _ => 2,
        };
    }
}

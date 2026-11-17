using WatchLattice.Common.Alerts;
using Xunit;

namespace WatchLattice.Common.Tests;

public sealed class AlertGuidanceTests
{
    private static ProtectionAlert Alert(string module, string code, string? resource = null) =>
        new(Guid.NewGuid(), DateTimeOffset.UtcNow, module, code, AlertSeverity.Warning, "title", "message", resource);

    [Fact]
    public void EveryClassifiedAlert_HasItsOwnGuidance()
    {
        var missing = AlertEventIds.Classified
            .Where(c => !c.Code.EndsWith(AlertEventIds.ClearedSuffix, StringComparison.Ordinal))
            .Select(c => (Module: c.Module == "(any)" ? "SomeModule" : c.Module, Code: c.Code.EndsWith('*') ? c.Code.TrimEnd('*') + "Path:C:\\" : c.Code))
            .Where(c => !AlertGuidanceCatalog.HasEntry(c.Module, c.Code))
            .Select(c => $"{c.Module} {c.Code}")
            .ToList();
        Assert.True(missing.Count == 0, "No guidance for: " + string.Join(", ", missing));
    }

    [Fact]
    public void EveryEntry_SaysWhatItMeansAndWhatToDo()
    {
        foreach (var (module, code, _) in AlertEventIds.Classified)
        {
            var guidance = AlertGuidanceCatalog.For(Alert(module == "(any)" ? "Canary" : module, code.TrimEnd('*') + (code.EndsWith('*') ? "Path:C:\\" : "")));
            Assert.False(string.IsNullOrWhiteSpace(guidance.Meaning), $"{module} {code}");
            Assert.False(string.IsNullOrWhiteSpace(guidance.WhatToDo), $"{module} {code}");
            Assert.All(guidance.Actions, a => Assert.False(string.IsNullOrWhiteSpace(a.Label)));
        }
    }

    [Fact]
    public void ModuleFailures_GetGuidanceWhicheverModuleRaisedThem()
    {
        var guidance = AlertGuidanceCatalog.For(Alert("FirewallWatchdog", "MODULE_FAILED"));
        Assert.Contains("restarts it", guidance.Meaning);
    }

    [Fact]
    public void ClearedAlerts_NeedNothing()
    {
        var guidance = AlertGuidanceCatalog.For(Alert("DefenderWatchdog", "REALTIME_OFF_CLEARED"));
        Assert.Equal("Nothing to do.", guidance.WhatToDo);
        Assert.Empty(guidance.Actions);
    }

    [Fact]
    public void UnknownAlerts_GetGeneralGuidance()
    {
        var guidance = AlertGuidanceCatalog.For(Alert("SomethingNew", "NEW_CODE"));
        Assert.Contains("no explanation", guidance.Meaning);
    }

    [Fact]
    public void Canary_OffersItsFileLocation_OnlyForALocalPath()
    {
        var local = AlertGuidanceCatalog.For(Alert("Canary", "CANARY_MODIFIED", @"C:\Users\me\Documents\~budget.xlsx"));
        Assert.Contains(local.Actions, a => a.Kind == SafeActionKind.OpenFileLocation && a.Path == @"C:\Users\me\Documents\~budget.xlsx");

        var share = AlertGuidanceCatalog.For(Alert("Canary", "CANARY_MODIFIED", @"\\server\share\x.docx"));
        Assert.DoesNotContain(share.Actions, a => a.Kind == SafeActionKind.OpenFileLocation);
        Assert.Contains(share.Actions, a => a.Kind == SafeActionKind.DefenderQuickScan);
    }

    [Fact]
    public void Persistence_PointsAtTheScreenForItsSource()
    {
        Assert.Contains(AlertGuidanceCatalog.For(Alert("Persistence", "ENTRY_ADDED", "ScheduledTasks/\\Updater")).Actions, a => a.Kind == SafeActionKind.OpenTaskScheduler);
        Assert.Contains(AlertGuidanceCatalog.For(Alert("Persistence", "ENTRY_ADDED", "Services/Evil")).Actions, a => a.Kind == SafeActionKind.OpenServices);
        Assert.Contains(AlertGuidanceCatalog.For(Alert("Persistence", "ENTRY_ADDED", "Registry/HKCU/Run/x")).Actions, a => a.Kind == SafeActionKind.OpenStartupApps);
    }

    [Theory]
    [InlineData(@"C:\Users\me\file.txt", true)]
    [InlineData(@"D:\", true)]
    [InlineData(@"C:\Program Files\App\app.exe", true)]
    [InlineData(@"\\server\share\file.txt", false)]
    [InlineData(@"\\?\C:\file.txt", false)]
    [InlineData(@"\\.\PhysicalDrive0", false)]
    [InlineData(@"file.txt", false)]
    [InlineData(@"C:file.txt", false)]
    [InlineData(@"C:\a\..\Windows\system32", false)]
    [InlineData(@"C:\a"" & calc & """, false)]
    [InlineData(@"C:\a/b", false)]
    [InlineData("C:\\a\nb", false)]
    [InlineData(@"C:\*.txt", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IsLocalPath_AcceptsOnlyPlainLocalPaths(string? path, bool expected) =>
        Assert.Equal(expected, SafeActionLauncher.IsLocalPath(path));

    [Fact]
    public void Launcher_UsesFixedProgramsAndArguments()
    {
        foreach (var kind in Enum.GetValues<SafeActionKind>().Where(k => k != SafeActionKind.OpenFileLocation))
        {
            // A path on a non-file action must be ignored, whatever it says.
            var info = SafeActionLauncher.StartInfo(new SafeAction(kind, "x", "C:\\evil\" & calc"), _ => true);
            Assert.NotNull(info);
            Assert.DoesNotContain("evil", info!.FileName + info.Arguments + string.Join(' ', info.ArgumentList));
        }
        var scan = SafeActionLauncher.StartInfo(new SafeAction(SafeActionKind.DefenderQuickScan, "x"))!;
        Assert.EndsWith("cmd.exe", scan.FileName);
        Assert.Equal($"/k \"\"{SafeActionLauncher.DefenderCommandLine}\" -Scan -ScanType 1\"", scan.Arguments);
        Assert.EndsWith("MpCmdRun.exe", SafeActionLauncher.DefenderCommandLine);
        Assert.Equal("windowsdefender://threatsettings", SafeActionLauncher.StartInfo(new SafeAction(SafeActionKind.OpenVirusProtectionSettings, "x"))!.FileName);
        Assert.True(SafeActionLauncher.NeedsConfirmation(SafeActionKind.DefenderQuickScan));
        Assert.False(SafeActionLauncher.NeedsConfirmation(SafeActionKind.OpenServices));
    }

    [Fact]
    public void FileLocation_SelectsTheFile_OrOpensItsFolderWhenTheFileIsGone()
    {
        const string file = @"C:\Users\me\Documents\~budget.xlsx";
        var selected = SafeActionLauncher.StartInfo(new SafeAction(SafeActionKind.OpenFileLocation, "x", file), _ => true)!;
        Assert.EndsWith("explorer.exe", selected.FileName);
        Assert.Equal($"/select,\"{file}\"", selected.Arguments);

        var folder = SafeActionLauncher.StartInfo(new SafeAction(SafeActionKind.OpenFileLocation, "x", file), p => p == @"C:\Users\me\Documents")!;
        Assert.Equal("\"C:\\Users\\me\\Documents\"", folder.Arguments);

        Assert.Null(SafeActionLauncher.StartInfo(new SafeAction(SafeActionKind.OpenFileLocation, "x", file), _ => false));
        Assert.Null(SafeActionLauncher.StartInfo(new SafeAction(SafeActionKind.OpenFileLocation, "x", @"\\server\share\x"), _ => true));
        Assert.Null(SafeActionLauncher.StartInfo(new SafeAction(SafeActionKind.OpenFileLocation, "x"), _ => true));
    }
}

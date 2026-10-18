using Xunit;

namespace WatchLattice.ScriptHostAudit.Tests;

public sealed class ProcessCreationEventTests
{
    [Fact]
    public void FromXml_ReadsEveryField_OfAVersion2Event()
    {
        var launch = ProcessCreationEvent.FromXml(Events.Xml(4242, Events.PowerShell, "powershell.exe -NoProfile -File \"C:\\a b\\x.ps1\" & <tag>", Events.Word));

        Assert.NotNull(launch);
        Assert.Equal(4242, launch.RecordId);
        Assert.Equal(new DateTimeOffset(2026, 10, 18, 6, 0, 0, TimeSpan.Zero).AddTicks(1234567), launch.TimeCreated);
        Assert.Equal(Events.PowerShell, launch.NewProcessName);
        Assert.Equal("powershell.exe", launch.HostName);
        Assert.Equal("powershell.exe -NoProfile -File \"C:\\a b\\x.ps1\" & <tag>", launch.CommandLine);
        Assert.Equal(Events.Word, launch.ParentProcessName);
        Assert.Equal("WINWORD.EXE", launch.ParentName);
        Assert.Equal(@"DESKTOP-TEST\alex", launch.User);
        Assert.Equal("0x1a2c", launch.NewProcessId);
        Assert.Equal("0x2b4", launch.ParentProcessId);
        Assert.Equal("not elevated", launch.Elevation);
        Assert.Equal("medium", launch.Integrity);
    }

    [Fact]
    public void FromXml_UsesTheTargetAccount_WhenTheProcessRunsAsAnotherUser()
    {
        var launch = ProcessCreationEvent.FromXml(Events.Xml(1, Events.PowerShell, "x", targetUser: "admin", targetSid: "S-1-5-21-1-2-3-500"));
        Assert.Equal(@"DESKTOP-TEST\admin", launch!.User);
    }

    [Fact]
    public void FromXml_ReadsOlderEvents_WithoutParentOrCommandLine()
    {
        var launch = ProcessCreationEvent.FromXml(Events.Xml(7, Events.PowerShell, commandLine: null, version: 1));

        Assert.NotNull(launch);
        Assert.Null(launch.ParentProcessName);
        Assert.Null(launch.ParentName);
        Assert.Null(launch.CommandLine);
        Assert.Null(launch.Integrity);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not xml")]
    [InlineData("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>4688</EventID></System></Event>")]
    [InlineData("<!DOCTYPE x [<!ENTITY e 'x'>]><Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'/>")]
    public void FromXml_ReturnsNull_ForAnythingElse(string xml) => Assert.Null(ProcessCreationEvent.FromXml(xml));

    [Fact]
    public void FromXml_ReturnsNull_ForOtherEventIds_AndOtherNamespaces()
    {
        Assert.Null(ProcessCreationEvent.FromXml(Events.Xml(1, Events.PowerShell, eventId: 4689)));
        Assert.Null(ProcessCreationEvent.FromXml(Events.Xml(1, Events.PowerShell).Replace("http://schemas.microsoft.com/win/2004/08/events/event", "urn:other")));
    }

    [Fact]
    public void FromXml_ReadsAdjacentAndEmptyDataElements()
    {
        // ToXml() writes <Data Name='X'/> for some empty fields; the field after it must still be read.
        var xml = Events.Xml(9, Events.PowerShell, "x").Replace("<Data Name='TokenElevationType'>%%1938</Data>", "<Data Name='TokenElevationType'/>");
        var launch = ProcessCreationEvent.FromXml(xml);
        Assert.NotNull(launch);
        Assert.Null(launch.TokenElevationType);
        Assert.Equal("0x2b4", launch.ParentProcessId);
        Assert.Equal("x", launch.CommandLine);
    }

    [Theory]
    [InlineData(@"C:\Windows\System32\mshta.exe", "mshta.exe")]
    [InlineData(@"""C:\Program Files\App\run.exe""", "run.exe")]
    [InlineData("pwsh.exe", "pwsh.exe")]
    public void FileName_WorksOnWindowsPaths_OnAnyOs(string path, string name) => Assert.Equal(name, ProcessCreationEvent.FileName(path));
}

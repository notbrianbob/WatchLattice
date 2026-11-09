using Xunit;

namespace WatchLattice.Persistence.Tests;

public sealed class UserProfilesTests
{
    private const string Brian = "S-1-5-21-1111111111-2222222222-3333333333-1001";
    private const string Guest = "S-1-5-21-1111111111-2222222222-3333333333-1002";
    private const string EntraUser = "S-1-12-1-1234567890-1234567890-1234567890-1234567890";

    [Fact]
    public void Select_UnderLocalSystem_ReadsSystemThroughHkcu_AndEverySignedInUserThroughHku()
    {
        var hives = new[]
        {
            ".DEFAULT", "S-1-5-18", "S-1-5-19", "S-1-5-20",
            Guest, Guest + "_Classes", Brian, Brian + "_Classes", EntraUser, EntraUser + "_Classes",
        };

        var accounts = UserProfiles.Select(hives, "S-1-5-18");

        Assert.Equal(new[]
        {
            new UserAccount("S-1-5-18", IsSelf: true),
            new UserAccount(EntraUser, IsSelf: false),
            new UserAccount(Brian, IsSelf: false),
            new UserAccount(Guest, IsSelf: false),
        }, accounts);
    }

    [Fact]
    public void Select_UnderTheUsersOwnAccount_ReadsThatUserOnce_ThroughHkcu()
    {
        var accounts = UserProfiles.Select(new[] { Brian, Brian.ToLowerInvariant(), Guest }, Brian);

        Assert.Equal(new[] { new UserAccount(Brian, true), new UserAccount(Guest, false) }, accounts);
    }

    [Fact]
    public void Select_WithoutReadableHives_StillReadsTheHubsOwnAccount()
    {
        Assert.Equal(new[] { new UserAccount("someone", true) }, UserProfiles.Select(Array.Empty<string>(), "someone"));
    }

    [Theory]
    [InlineData("S-1-5-21-1-2-3-1001", true)]
    [InlineData("S-1-12-1-1-2-3-4", true)]
    [InlineData("S-1-5-21-1-2-3-1001_Classes", false)]
    [InlineData("S-1-5-18", false)]
    [InlineData("S-1-5-19", false)]
    [InlineData(".DEFAULT", false)]
    [InlineData(@"S-1-5-21-1-2-3-1001\Software", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IsSignedInUserHive_AcceptsOnlyRealUserSids(string? name, bool expected) =>
        Assert.Equal(expected, UserProfiles.IsSignedInUserHive(name));

    [Fact]
    public void RunSourceId_KeepsTheFormatEarlierBaselinesAndApprovalsUse()
    {
        // Baselines from 0.8.0 and earlier stored the hub's own HKCU keys under this exact name.
        Assert.Equal("Registry/HKCU-S-1-5-18/Default/Run", UserProfiles.RunSourceId("S-1-5-18", "Run"));
        Assert.Equal($"Registry/HKCU-{Brian}/Default/RunOnce", UserProfiles.RunSourceId(Brian, "RunOnce"));
    }

    [Theory]
    [InlineData(@"%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup", null,
        @"C:\Users\brian\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")]
    [InlineData(@"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup", @"%USERPROFILE%\AppData\Roaming",
        @"C:\Users\brian\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")]
    [InlineData(@"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup", @"D:\Roaming\brian",
        @"D:\Roaming\brian\Microsoft\Windows\Start Menu\Programs\Startup")]
    [InlineData(@"\\fileserver\home$\brian\Startup\", null, @"\\fileserver\home$\brian\Startup")]
    [InlineData(@"E:\MyStartup", null, @"E:\MyStartup")]
    // Variables the hub can't expand for that user, relative paths and missing values use the default folder.
    [InlineData(@"%OneDrive%\Startup", null, @"C:\Users\brian\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")]
    [InlineData(@"Startup", null, @"C:\Users\brian\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")]
    [InlineData(null, null, @"C:\Users\brian\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")]
    [InlineData(@"\\?\C:\Startup", null, @"C:\Users\brian\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")]
    public void StartupFolder_ExpandsOnlyThatUsersProfileVariables(string? startup, string? appData, string expected) =>
        Assert.Equal(expected, UserProfiles.StartupFolder(startup, appData, @"C:\Users\brian\"));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(@"%SystemDrive%\Users\brian")]
    [InlineData(@"Users\brian")]
    public void StartupFolder_WithoutAUsableProfilePath_IsSkipped(string? profile) =>
        Assert.Null(UserProfiles.StartupFolder(@"E:\MyStartup", null, profile));
}

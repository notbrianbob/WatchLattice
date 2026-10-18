using System.Text.Json.Nodes;
using WatchLattice.Common.Alerts;
using WatchLattice.Common.Settings;
using Xunit;

namespace WatchLattice.Common.Tests;

public sealed class BaselineApprovalsTests
{
    private const string Resource = @"Registry/HKCU/Run/Updater";
    private const string Command = @"""C:\Program Files\Vendor\updater.exe"" /background";

    private static ProtectionAlert Alert(string message, string code = "ENTRY_ADDED", string? resource = Resource,
        string module = BaselineApprovals.PersistenceModule) =>
        new(Guid.NewGuid(), DateTimeOffset.UtcNow, module, code, AlertSeverity.Warning, "Autostart entry added", message, resource);

    private static string EntryMessage(string command) =>
        $"{Resource}\nPrevious: (absent)\nCurrent: {command}\n{BaselineApprovals.FingerprintLine(command)}";

    [Fact]
    public void ApprovedEntry_RoundTrips_AndMatchesOnlyTheExactValue()
    {
        var entry = ApprovedEntry.For(Resource, Command);
        Assert.Equal(ApprovedEntry.Prefix + ApprovedEntry.Fingerprint(Command) + " " + Resource, entry.ToString());
        Assert.True(ApprovedEntry.TryParse(entry.ToString(), out var parsed));
        Assert.Equal(entry, parsed);
        Assert.True(parsed.Matches(Resource.ToUpperInvariant(), Command));
        Assert.False(parsed.Matches(Resource, Command + " "));
        Assert.False(parsed.Matches(Resource + "2", Command));
    }

    [Theory]
    [InlineData("")]
    [InlineData("sha256:abc Registry/Run/App")]
    [InlineData("md5:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef Registry/Run/App")]
    [InlineData("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg Registry/Run/App")]
    [InlineData("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")]
    [InlineData("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef-Registry/Run/App")]
    [InlineData("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  ")]
    public void ApprovedEntry_RejectsMalformedLines(string line) => Assert.False(ApprovedEntry.TryParse(line, out _));

    [Fact]
    public void ApprovedEntry_AllowsAnyResourceText_BecauseTheHashComesFirst()
    {
        var resource = "Wmi/Binding/Filter one -> Consumer/CommandLineEventConsumer/two sha256:x";
        Assert.True(ApprovedEntry.TryParse(ApprovedEntry.For(resource, "x").ToString(), out var parsed));
        Assert.Equal(resource, parsed.Resource);
    }

    [Fact]
    public void EntryAlert_ApprovesItsCurrentValue()
    {
        var approval = BaselineApprovals.For(Alert(EntryMessage(Command)));
        Assert.NotNull(approval);
        Assert.Equal(BaselineApprovals.PersistenceSetting, approval.SettingPath);
        Assert.Equal(ApprovedEntry.For(Resource, Command).ToString(), approval.Value);
        Assert.Contains(Resource, approval.Description);
        Assert.NotNull(BaselineApprovals.For(Alert(EntryMessage(Command), code: "ENTRY_CHANGED")));
    }

    [Fact]
    public void Approval_NeedsTheFingerprintAsTheLastLine()
    {
        // A command can contain a line that looks like a fingerprint; only the auditor's own last line counts.
        var forged = $"{Resource}\nCurrent: x\n{BaselineApprovals.FingerprintLine("benign.exe")}\nVerification follows.";
        Assert.Null(BaselineApprovals.For(Alert(forged)));
        Assert.Null(BaselineApprovals.For(Alert($"{Resource}\nCurrent: x")));
        Assert.Null(BaselineApprovals.For(Alert(EntryMessage(Command) + "…")));
    }

    [Fact]
    public void ScriptHostLaunch_ApprovesItsParentHostAndExactCommandLine()
    {
        const string launch = @"C:\Program Files\App\app.exe|C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
        var message = $"powershell.exe started by app.exe\nCommand line: {Command}\n{BaselineApprovals.FingerprintLine(Command)}";
        var approval = BaselineApprovals.For(Alert(message, BaselineApprovals.ScriptHostLaunchedCode, launch, BaselineApprovals.ScriptHostModule));

        Assert.NotNull(approval);
        Assert.Equal(BaselineApprovals.ScriptHostSetting, approval.SettingPath);
        Assert.Equal(ApprovedEntry.For(launch, Command).ToString(), approval.Value);
        Assert.StartsWith("Script host launch", approval.Description);
        Assert.True(BaselineApprovals.IsValid(BaselineApprovals.ScriptHostSetting, approval.Value));
        Assert.Contains(BaselineApprovals.ScriptHostSetting, BaselineApprovals.SettingPaths);
        Assert.True(BaselineApprovals.TryDecode(BaselineApprovals.Encode(approval), out var decoded));
        Assert.Equal(approval, decoded);

        // A summary of several launches, or the same message from another module, approves nothing.
        Assert.Null(BaselineApprovals.For(Alert(message, "SCRIPT_HOST_LAUNCHES", launch, BaselineApprovals.ScriptHostModule)));
        Assert.Null(BaselineApprovals.For(Alert(message, BaselineApprovals.ScriptHostLaunchedCode, launch)));
    }

    [Fact]
    public void OtherAlerts_CannotBeApproved()
    {
        Assert.Null(BaselineApprovals.For(Alert(EntryMessage(Command), code: "ENTRY_REMOVED")));
        Assert.Null(BaselineApprovals.For(Alert(EntryMessage(Command), code: "VERIFY_NEEDS_REVIEW")));
        Assert.Null(BaselineApprovals.For(Alert(EntryMessage(Command), module: "Canary")));
        Assert.Null(BaselineApprovals.For(Alert(EntryMessage(Command), resource: null)));
        // The hub clips resources longer than 512 characters, so the approval could never match.
        Assert.Null(BaselineApprovals.For(Alert(EntryMessage(Command), resource: new string('r', 512) + "…")));
    }

    [Fact]
    public void ExtensionAlert_ApprovesTheExtensionId()
    {
        var alert = Alert("details", code: BaselineApprovals.ExtensionAddedCode, module: BaselineApprovals.ExtensionModule,
            resource: "Edge/alex/Default/abcdefghijklmnopabcdefghijklmnop");
        var approval = BaselineApprovals.For(alert);
        Assert.NotNull(approval);
        Assert.Equal(BaselineApprovals.ExtensionSetting, approval.SettingPath);
        Assert.Equal("abcdefghijklmnopabcdefghijklmnop", approval.Value);

        Assert.NotNull(BaselineApprovals.For(alert with { Resource = "Firefox/alex/abc.default-release/{01234567-89ab-cdef-0123-456789abcdef}" }));
        Assert.NotNull(BaselineApprovals.For(alert with { Resource = "Firefox/alex/abc.default-release/uBlock0@raymondhill.net" }));
        Assert.Null(BaselineApprovals.For(alert with { Resource = "Edge/alex/Default/*" }));
        Assert.Null(BaselineApprovals.For(alert with { Code = "EXTENSIONS_ADDED" }));
    }

    [Fact]
    public void Stage_AppendsOnce_AndKeepsExistingLines()
    {
        var settings = SettingValues.Parse("""{ "Persistence": { "ApprovedEntries": [ "keep me" ], "CheckIntervalSeconds": 60 } }""");
        var approval = BaselineApprovals.For(Alert(EntryMessage(Command)))!;
        Assert.False(BaselineApprovals.IsApproved(settings, approval));
        Assert.True(BaselineApprovals.Stage(settings, approval));
        Assert.False(BaselineApprovals.Stage(settings, approval));
        Assert.True(BaselineApprovals.IsApproved(settings, approval));
        var list = Assert.IsType<JsonArray>(SettingValues.Get(settings, BaselineApprovals.PersistenceSetting));
        Assert.Equal(new[] { "keep me", approval.Value }, list.Select(e => e!.GetValue<string>()));
        Assert.Equal(60, SettingValues.Get(settings, "Persistence:CheckIntervalSeconds")!.GetValue<int>());

        var empty = new JsonObject();
        Assert.True(BaselineApprovals.Stage(empty, new(BaselineApprovals.ExtensionSetting, "abcdefghijklmnopabcdefghijklmnop", "")));
        Assert.Single(Assert.IsType<JsonArray>(SettingValues.Get(empty, BaselineApprovals.ExtensionSetting)));
    }

    [Fact]
    public void Stage_RefusesAnythingButAnApproval()
    {
        Assert.Throws<ArgumentException>(() => BaselineApprovals.Stage(new JsonObject(), new("Updater:Repository", "evil/repo", "")));
        Assert.Throws<ArgumentException>(() => BaselineApprovals.Stage(new JsonObject(), new(BaselineApprovals.ExtensionSetting, "*", "")));
    }

    [Fact]
    public void Encode_RoundTrips_AndDecodeRejectsOtherSettings()
    {
        var resource = "Tasks/\\Vendor\\Update \"quoted\" & ^ %PATH%";
        var approval = new BaselineApproval(BaselineApprovals.PersistenceSetting, ApprovedEntry.For(resource, Command).ToString(), "");
        var token = BaselineApprovals.Encode(approval);
        Assert.All(token, c => Assert.True(char.IsAsciiLetterOrDigit(c) || c is '-' or '_'));
        Assert.True(BaselineApprovals.TryDecode(token, out var decoded));
        Assert.Equal(approval.SettingPath, decoded.SettingPath);
        Assert.Equal(approval.Value, decoded.Value);
        Assert.Contains(resource, decoded.Description);

        Assert.False(BaselineApprovals.TryDecode(BaselineApprovals.Encode(new("Updater:Repository", "evil/repo", "")), out _));
        Assert.False(BaselineApprovals.TryDecode(BaselineApprovals.Encode(new(BaselineApprovals.PersistenceSetting, "not an approval", "")), out _));
        Assert.False(BaselineApprovals.TryDecode("not base64!", out _));
        Assert.False(BaselineApprovals.TryDecode("", out _));
    }

    [Fact]
    public void ApprovalSettings_StayValidSettings()
    {
        var settings = new JsonObject();
        BaselineApprovals.Stage(settings, BaselineApprovals.For(Alert(EntryMessage(Command)))!);
        var field = new SettingField(BaselineApprovals.PersistenceSetting, "Approved entries", SettingKind.TextList, false);
        Assert.Null(SettingsValidator.CheckValue(field, SettingValues.Get(settings, field.Path)));
    }
}

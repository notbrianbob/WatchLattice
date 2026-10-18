using System.Reflection;
using WatchLattice.Common.Alerts;
using Xunit;

namespace WatchLattice.ScriptHostAudit.Tests;

public sealed class EventLogIdTests
{
    public static TheoryData<string> Codes()
    {
        var data = new TheoryData<string>();
        foreach (var field in typeof(ScriptHostAuditor).GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(f => f.IsLiteral && f.FieldType == typeof(string) && f.Name != nameof(ScriptHostAuditor.ModuleId)))
        {
            data.Add((string)field.GetRawConstantValue()!);
        }
        return data;
    }

    [Theory]
    [MemberData(nameof(Codes))]
    public void EveryAlertCode_HasItsOwnEventLogId(string code)
    {
        Assert.True(AlertEventIds.IsClassified(ScriptHostAuditor.ModuleId, code), code);
        Assert.True(AlertEventIds.IsClassified(ScriptHostAuditor.ModuleId, code + AlertEventIds.ClearedSuffix), code);
        Assert.InRange(AlertEventIds.For(ScriptHostAuditor.ModuleId, code, AlertSeverity.Info), 11001, 11499);
    }

    [Fact]
    public void TheApprovalCode_IsTheLaunchCode()
    {
        Assert.Equal(ScriptHostAuditor.ModuleId, BaselineApprovals.ScriptHostModule);
        Assert.Equal(ScriptHostAuditor.ScriptHostLaunched, BaselineApprovals.ScriptHostLaunchedCode);
        Assert.Equal($"{ScriptHostAuditOptions.SectionName}:{nameof(ScriptHostAuditOptions.ApprovedLaunches)}", BaselineApprovals.ScriptHostSetting);
    }
}

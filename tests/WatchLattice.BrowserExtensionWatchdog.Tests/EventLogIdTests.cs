using System.Reflection;
using WatchLattice.Common.Alerts;
using Xunit;

namespace WatchLattice.BrowserExtensionWatchdog.Tests;

public sealed class EventLogIdTests
{
    public static TheoryData<string> Codes()
    {
        var data = new TheoryData<string>();
        foreach (var field in typeof(BrowserExtensionWatchdog).GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(f => f.IsLiteral && f.FieldType == typeof(string) && f.Name != nameof(BrowserExtensionWatchdog.ModuleId)))
        {
            data.Add((string)field.GetRawConstantValue()!);
        }
        return data;
    }

    [Theory]
    [MemberData(nameof(Codes))]
    public void EveryAlertCode_HasItsOwnEventLogId(string code)
    {
        Assert.True(AlertEventIds.IsClassified(BrowserExtensionWatchdog.ModuleId, code), code);
        Assert.True(AlertEventIds.IsClassified(BrowserExtensionWatchdog.ModuleId, code + AlertEventIds.ClearedSuffix), code);
        Assert.InRange(AlertEventIds.For(BrowserExtensionWatchdog.ModuleId, code, AlertSeverity.Info), 10001, 10499);
    }
}

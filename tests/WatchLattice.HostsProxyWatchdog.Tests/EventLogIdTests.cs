using System.Reflection;
using WatchLattice.Common.Alerts;
using Xunit;

namespace WatchLattice.HostsProxyWatchdog.Tests;

public sealed class EventLogIdTests
{
    public static TheoryData<string> Codes()
    {
        var data = new TheoryData<string>();
        foreach (var field in typeof(HostsProxyEvaluator).GetFields(BindingFlags.Public | BindingFlags.Static)
            .Concat(typeof(HostsProxyWatchdog).GetFields(BindingFlags.Public | BindingFlags.Static))
            .Where(f => f.IsLiteral && f.FieldType == typeof(string) && f.Name != nameof(HostsProxyWatchdog.ModuleId)))
        {
            data.Add((string)field.GetRawConstantValue()!);
        }
        return data;
    }

    [Theory]
    [MemberData(nameof(Codes))]
    public void EveryAlertCode_HasItsOwnEventLogId(string code)
    {
        Assert.True(AlertEventIds.IsClassified(HostsProxyWatchdog.ModuleId, code), code);
        Assert.True(AlertEventIds.IsClassified(HostsProxyWatchdog.ModuleId, code + AlertEventIds.ClearedSuffix), code);
    }
}

using WatchLattice.Common.Alerts;
using WatchLattice.Common.Checkup;
using Xunit;

namespace WatchLattice.Common.Tests;

public sealed class SecurityCheckupTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 17, 12, 0, 0, TimeSpan.Zero);

    private sealed class FakeRegistry : IMachineRegistry
    {
        public Dictionary<(string Key, string Name), object> Values { get; } = new();
        public HashSet<string> Keys { get; } = new(StringComparer.OrdinalIgnoreCase);
        public bool Throw { get; init; }

        public object? Read(string key, string name)
        {
            if (Throw) throw new UnauthorizedAccessException("denied");
            return Values.GetValueOrDefault((key, name));
        }

        public bool KeyExists(string key) => Throw ? throw new UnauthorizedAccessException("denied") : Keys.Contains(key);

        public FakeRegistry Set(string key, string name, object value)
        {
            Values[(key, name)] = value;
            Keys.Add(key);
            return this;
        }
    }

    /// <summary>A Windows 11 PC with everything on, as Windows sets it up.</summary>
    private static FakeRegistry Hardened() => new FakeRegistry()
        .Set(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile", "EnableFirewall", 1)
        .Set(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile", "EnableFirewall", 1)
        .Set(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile", "EnableFirewall", 1)
        .Set(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", 1)
        .Set(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin", 5)
        .Set(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "PromptOnSecureDesktop", 1)
        .Set(@"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections", 1)
        .Set(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled", 1)
        .Set(@"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled", 1)
        .Set(@"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", 2);

    private static DefenderFacts Defender(bool realTime = true, bool tamper = true, double daysOld = 0.2) =>
        new(true, realTime, tamper, Now.AddDays(-daysOld));

    private static AlertSnapshot Hub() =>
        new(AlertSnapshot.CurrentVersion, Guid.NewGuid(), Now.AddSeconds(-2), true,
            new[] { new ModuleStatus("Canary", ModuleRunState.Running, Now) }, Array.Empty<ProtectionAlert>());

    private static CheckupItem Item(IReadOnlyList<CheckupItem> items, string id) => items.Single(i => i.Id == id);

    [Fact]
    public void AHardenedPc_IsGoodThroughout_AndEveryItemExplainsItself()
    {
        var items = SecurityCheckup.Run(Hardened(), Defender(), Hub(), Now);
        Assert.All(items, i => Assert.Equal(CheckupStatus.Good, i.Status));
        Assert.All(items, i =>
        {
            Assert.False(string.IsNullOrWhiteSpace(i.WhyItMatters), i.Id);
            Assert.False(string.IsNullOrWhiteSpace(i.HowToChange), i.Id);
        });
        Assert.Equal(items.Count, items.Select(i => i.Id).Distinct().Count());
        Assert.Equal($"{items.Count} good", SecurityCheckup.Summary(items));
    }

    [Fact]
    public void EveryAction_IsOneTheLauncherCanOpen()
    {
        foreach (var item in SecurityCheckup.Run(Hardened(), Defender(), Hub(), Now).Where(i => i.Action is not null))
            Assert.NotNull(SafeActionLauncher.StartInfo(item.Action!, _ => true));
    }

    [Fact]
    public void DefenderOff_IsARisk_AndUnreadableDefender_IsUnknown()
    {
        var off = SecurityCheckup.Run(Hardened(), Defender(realTime: false, tamper: false), Hub(), Now);
        Assert.Equal(CheckupStatus.Risk, Item(off, "defender-realtime").Status);
        Assert.Equal(CheckupStatus.Risk, Item(off, "defender-tamper").Status);

        var unreadable = SecurityCheckup.Run(Hardened(), new DefenderFacts(false, null, null, null, "timed out"), Hub(), Now);
        Assert.Equal(CheckupStatus.Unknown, Item(unreadable, "defender-realtime").Status);
        Assert.Contains("timed out", Item(unreadable, "defender-signatures").Finding);
    }

    [Theory]
    [InlineData(1, CheckupStatus.Good)]
    [InlineData(5, CheckupStatus.Advice)]
    [InlineData(12, CheckupStatus.Risk)]
    public void OldSecurityIntelligence_IsFlaggedByAge(double days, CheckupStatus expected) =>
        Assert.Equal(expected, Item(SecurityCheckup.Run(Hardened(), Defender(daysOld: days), Hub(), Now), "defender-signatures").Status);

    [Fact]
    public void FirewallOffOnPublicNetworks_IsARisk_AndPolicyWinsOverTheLocalSetting()
    {
        var registry = Hardened().Set(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile", "EnableFirewall", 0);
        var item = Item(SecurityCheckup.Run(registry, Defender(), Hub(), Now), "firewall");
        Assert.Equal(CheckupStatus.Risk, item.Status);
        Assert.Equal("Off for public networks.", item.Finding);

        registry.Set(@"SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile", "EnableFirewall", 1);
        Assert.Equal(CheckupStatus.Good, Item(SecurityCheckup.Run(registry, Defender(), Hub(), Now), "firewall").Status);

        registry.Set(@"SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile", "EnableFirewall", 0);
        Assert.Equal(CheckupStatus.Advice, Item(SecurityCheckup.Run(registry, Defender(), Hub(), Now), "firewall").Status);
    }

    [Fact]
    public void UacOff_OrSilentElevation_IsARisk()
    {
        var off = Hardened().Set(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", 0);
        Assert.Equal(CheckupStatus.Risk, Item(SecurityCheckup.Run(off, Defender(), Hub(), Now), "uac").Status);
        var silent = Hardened().Set(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin", 0);
        Assert.Equal(CheckupStatus.Risk, Item(SecurityCheckup.Run(silent, Defender(), Hub(), Now), "uac").Status);
    }

    [Fact]
    public void RemoteDesktop_WithoutNla_IsARisk_WithNla_IsAdvice()
    {
        var on = Hardened().Set(@"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections", 0);
        Assert.Equal(CheckupStatus.Advice, Item(SecurityCheckup.Run(on, Defender(), Hub(), Now), "remote-desktop").Status);
        on.Set(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication", 0);
        Assert.Equal(CheckupStatus.Risk, Item(SecurityCheckup.Run(on, Defender(), Hub(), Now), "remote-desktop").Status);
    }

    [Fact]
    public void AnEnabledSmb1Client_IsARisk_ADisabledOne_IsFine()
    {
        var installed = Hardened().Set(@"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start", 2);
        Assert.Equal(CheckupStatus.Risk, Item(SecurityCheckup.Run(installed, Defender(), Hub(), Now), "smb1").Status);
        installed.Set(@"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start", 4);
        Assert.Equal(CheckupStatus.Good, Item(SecurityCheckup.Run(installed, Defender(), Hub(), Now), "smb1").Status);
    }

    [Fact]
    public void SmartScreenOff_IsARisk()
    {
        var off = Hardened().Set(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled", "Off");
        Assert.Equal(CheckupStatus.Risk, Item(SecurityCheckup.Run(off, Defender(), Hub(), Now), "smartscreen").Status);
    }

    [Fact]
    public void HardwareProtectionsOff_AreAdvice_NotRisks()
    {
        var registry = Hardened()
            .Set(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled", 0)
            .Set(@"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled", 0)
            .Set(@"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", 0);
        var items = SecurityCheckup.Run(registry, Defender(), Hub(), Now);
        Assert.Equal(CheckupStatus.Advice, Item(items, "secure-boot").Status);
        Assert.Equal(CheckupStatus.Advice, Item(items, "memory-integrity").Status);
        Assert.Equal(CheckupStatus.Advice, Item(items, "lsa-protection").Status);
        Assert.Equal($"{items.Count - 3} good • 3 to consider", SecurityCheckup.Summary(items));
    }

    [Fact]
    public void AStoppedHub_IsARisk()
    {
        var stale = Hub() with { HeartbeatAt = Now.AddMinutes(-30), Online = false };
        Assert.Equal(CheckupStatus.Risk, Item(SecurityCheckup.Run(Hardened(), Defender(), stale, Now), "watchlattice").Status);
        Assert.Equal(CheckupStatus.Unknown, Item(SecurityCheckup.Run(Hardened(), Defender(), null, Now), "watchlattice").Status);
    }

    [Fact]
    public void AnUnreadableRegistry_GivesUnknowns_NotACrash()
    {
        var items = SecurityCheckup.Run(new FakeRegistry { Throw = true }, Defender(), Hub(), Now);
        Assert.Equal(CheckupStatus.Unknown, Item(items, "firewall").Status);
        Assert.Equal(CheckupStatus.Good, Item(items, "defender-realtime").Status);
    }
}

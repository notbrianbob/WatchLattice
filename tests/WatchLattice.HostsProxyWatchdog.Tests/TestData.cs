namespace WatchLattice.HostsProxyWatchdog.Tests;

internal static class TestData
{
    public const string DefaultHosts = "127.0.0.1 localhost\n::1 localhost\n";

    public static IReadOnlyDictionary<string, IReadOnlyList<string>> Entries(string hosts) => HostsFileParser.Parse(hosts);

    public static Dictionary<string, string[]> Baseline(string hosts) =>
        Entries(hosts).ToDictionary(e => e.Key, e => e.Value.ToArray());

    public static HostsProxySnapshot Snapshot(string hosts, params ProxyScope[] scopes) => new()
    {
        Hosts = new HostsFileSnapshot { Path = @"C:\Windows\System32\drivers\etc\hosts", Entries = Entries(hosts) },
        Proxy = scopes.Length == 0 ? null : scopes,
    };

    public static ProxyScope Scope(params (string Name, string Value)[] values) => Scope("User:S-1-5-21-1", values);

    public static ProxyScope Scope(string id, params (string Name, string Value)[] values) =>
        new(id, id == "User:S-1-5-21-1" ? @"user PC\alex" : id, values.ToDictionary(v => v.Name, v => v.Value));
}

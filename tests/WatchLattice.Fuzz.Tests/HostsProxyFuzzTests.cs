using System.Net;
using System.Text;
using WatchLattice.Fuzz.Tests.Harness;
using WatchLattice.HostsProxyWatchdog;
using Xunit;

namespace WatchLattice.Fuzz.Tests;

/// <summary>
/// The hosts file is writable by any administrator-level program and the
/// proxy settings by any program the user runs. Both are read by the hub as
/// LocalSystem, so no content may stop the module or be misread.
/// </summary>
public class HostsProxyFuzzTests
{
    private static readonly string[] Words =
    {
        "127.0.0.1", "0.0.0.0", "::1", "::", "10.0.0.5", "fe80::1%3", "::ffff:1.2.3.4", "1", "0x7f.1", "256.1.1.1", "localhost",
        "windowsupdate.com", "update.microsoft.com.", "bücher.example", "xn--bcher-kva.example", "xn--", "#", " # ", " ", "\t",
        "\r\n", "\n", "a.b", ".", "..", "*.example", "github.com",
    };

    private const string SampleHosts =
        "# Copyright (c) 1993-2009 Microsoft Corp.\r\n#\r\n#      102.54.94.97     rhino.acme.com          # source server\r\n" +
        "127.0.0.1       localhost\r\n::1             localhost\r\n10.0.0.5  NAS.Home.  printer.home   # two names\r\n" +
        "0.0.0.0 ads.example.com\r\n0.0.0.0 download.windowsupdate.com\r\n";

    private static readonly (string Written, string Normal)[] Addresses =
    {
        ("127.0.0.1", "127.0.0.1"), ("0.0.0.0", "0.0.0.0"), ("10.0.0.5", "10.0.0.5"), ("203.0.113.9", "203.0.113.9"),
        ("::1", "::1"), ("0:0:0:0:0:0:0:1", "::1"), ("::", "::"), ("2001:DB8::5", "2001:db8::5"),
    };

    private static readonly string[] BlobKeys =
    {
        "Unrecognized", "ProxyEnabled", "ProxyServer", "ProxyBypass", "AutoConfigEnabled", "AutoConfigURL", "AutoDetect",
    };

    [Fact]
    public void HostsFile_AnyText_ParsesToNormalizedEntries()
    {
        Fuzzer.RunText(3000, r => r.Chance(0.5) ? r.Text(Words, 10, 80) : r.Mutate(SampleHosts, Words), text =>
        {
            foreach (var (host, addresses) in HostsFileParser.Parse(text))
            {
                // A host is stored in the form every comparison uses, so normalizing it again changes nothing.
                Assert.Equal(host, HostsFileParser.NormalizeHost(host));
                Assert.NotEmpty(addresses);
                Assert.Equal(addresses.Distinct().OrderBy(a => a, StringComparer.Ordinal), addresses);
                foreach (var address in addresses)
                {
                    Assert.True(IPAddress.TryParse(address, out var parsed), address);
                    Assert.Equal(parsed.ToString(), address);
                    HostsFileParser.IsBlockingAddress(address);
                }
            }
        });
    }

    [Fact]
    public void HostsFile_WrittenAnyUsualWay_ReadsBackExactly()
    {
        Fuzzer.Run(1500, r =>
        {
            var expected = new Dictionary<string, SortedSet<string>>(StringComparer.Ordinal);
            var file = new StringBuilder();
            var lines = r.Count(8, 60);
            for (var i = 0; i < lines; i++)
            {
                switch (r.Next(6))
                {
                    case 0: file.Append("# ").Append(r.Ascii().Replace("\r", "").Replace("\n", "")); break;
                    case 1: file.Append(r.Pick("", "   ", "\t")); break;
                    // Not an address, so Windows ignores the line. (A bare number such as "1" is an address: 0.0.0.1.)
                    case 2: file.Append("name-").Append(r.Identifier()).Append(' ').Append(r.Identifier()).Append(".ignored.test"); break;
                    default:
                    {
                        var (written, normal) = r.Pick(Addresses);
                        file.Append(r.Pick("", " ", "\t")).Append(written);
                        var names = r.Next(1, 4);
                        for (var n = 0; n < names; n++)
                        {
                            var host = r.Identifier(1, 10).ToLowerInvariant() + ".test";
                            // Windows ignores case and one trailing dot.
                            file.Append(r.Pick(" ", "\t", "   ")).Append(r.Chance(0.3) ? host.ToUpperInvariant() : host).Append(r.Chance(0.2) ? "." : "");
                            if (!expected.TryGetValue(host, out var set)) expected[host] = set = new SortedSet<string>(StringComparer.Ordinal);
                            set.Add(normal);
                        }
                        if (r.Chance(0.3)) file.Append(r.Pick(" #", "#", "\t# ")).Append(r.Identifier());
                        break;
                    }
                }
                file.Append(r.Pick("\n", "\r\n"));
            }
            return (Text: file.ToString(), Expected: expected);
        }, input =>
        {
            var parsed = HostsFileParser.Parse(input.Text);
            Assert.Equal(input.Expected.Keys.OrderBy(k => k, StringComparer.Ordinal), parsed.Keys.OrderBy(k => k, StringComparer.Ordinal));
            foreach (var (host, addresses) in input.Expected) Assert.Equal(addresses, parsed[host]);
        }, input => Fuzzer.Literal(input.Text));
    }

    [Fact]
    public void IsWithin_OnlyMatchesADomainAndItsSubdomains()
    {
        Fuzzer.Run(2000, r => (Domain: r.Identifier().ToLowerInvariant() + "." + r.Pick("com", "test", "co.uk"), Label: r.Identifier().ToLowerInvariant()), input =>
        {
            Assert.True(HostsFileParser.IsWithin(input.Domain, input.Domain));
            Assert.True(HostsFileParser.IsWithin(input.Label + "." + input.Domain, input.Domain));
            // Look-alikes that only share an ending or a beginning are different sites.
            Assert.False(HostsFileParser.IsWithin(input.Label + input.Domain, input.Domain));
            Assert.False(HostsFileParser.IsWithin(input.Domain + "." + input.Label, input.Domain));
            Assert.False(HostsFileParser.IsWithin(input.Domain, input.Label + "." + input.Domain));
        });
    }

    [Fact]
    public void Evaluator_AnyHostsFile_NeverThrows_AndAFileEqualsItself()
    {
        Fuzzer.Run(1500, r =>
        {
            var options = new HostsProxyWatchdogOptions
            {
                IgnoredHosts = Enumerable.Range(0, r.Next(3)).Select(_ => r.Token(Words)).ToArray(),
                ProtectedDomains = Enumerable.Range(0, r.Next(3)).Select(_ => r.Token(Words)).ToArray(),
                MaxChangesPerAlert = r.Pick(-1, 0, 1, 2, 20, int.MaxValue),
                IncludeBuiltInProtectedDomains = r.Chance(0.8),
            };
            return (Before: r.Mutate(SampleHosts, Words), After: r.Chance(0.5) ? r.Text(Words, 10, 80) : r.Mutate(SampleHosts, Words), Options: options);
        }, input =>
        {
            var before = HostsFileParser.Parse(input.Before);
            var after = HostsFileParser.Parse(input.After);
            var baseline = before.ToDictionary(e => e.Key, e => e.Value.ToArray(), StringComparer.Ordinal);

            Assert.Null(HostsProxyEvaluator.CompareHosts(baseline, before, "hosts", input.Options));
            var change = HostsProxyEvaluator.CompareHosts(baseline, after, "hosts", input.Options);
            // Line breaks would let a host name forge a second alert line in the logs.
            if (change is not null) Assert.DoesNotContain('\n', change.Message);

            var snapshot = new HostsProxySnapshot { Hosts = new HostsFileSnapshot { Path = "hosts", Entries = after } };
            foreach (var finding in HostsProxyEvaluator.Evaluate(snapshot, input.Options)) Assert.DoesNotContain('\n', finding.Message);
        }, input => $"before {Fuzzer.Literal(input.Before)}, after {Fuzzer.Literal(input.After)}, ignored [{string.Join(", ", input.Options.IgnoredHosts.Select(Fuzzer.Literal))}], protected [{string.Join(", ", input.Options.ProtectedDomains.Select(Fuzzer.Literal))}]");
    }

    [Fact]
    public void ProxyScope_AnyValues_CompareWithoutThrowing_AndEqualSettingsAreNotAChange()
    {
        var names = new[] { "ProxyServer", "ProxyEnable", "AutoConfigURL", "ProxyOverride", "Connection.ProxyServer", "Policy.ProxySettingsPerUser", "WinHttp.ProxyBypass" };
        Fuzzer.Run(1500, r =>
        {
            Dictionary<string, string> Values() => Enumerable.Range(0, r.Next(6))
                .Select(_ => (Name: r.Chance(0.8) ? r.Pick(names) : r.Token(names), Value: r.Token(Words)))
                .GroupBy(v => v.Name).ToDictionary(g => g.Key, g => g.First().Value);
            return (Before: Values(), After: Values(), Name: r.Token());
        }, input =>
        {
            var options = new HostsProxyWatchdogOptions();
            Assert.Null(HostsProxyEvaluator.CompareProxy(input.Before, new ProxyScope("id", input.Name, input.Before), options));
            var change = HostsProxyEvaluator.CompareProxy(input.Before, new ProxyScope("id", input.Name, input.After), options);
            Assert.Equal(change is null, input.Before.Count == input.After.Count && input.Before.All(b => input.After.TryGetValue(b.Key, out var a) && a == b.Value));
            HostsProxyEvaluator.DescribeProxyScopes(new[] { new ProxyScope("id", input.Name, input.After) }, options);
        }, input => $"before {{{string.Join(", ", input.Before.Select(p => Fuzzer.Literal(p.Key) + ": " + Fuzzer.Literal(p.Value)))}}}, after {{{string.Join(", ", input.After.Select(p => Fuzzer.Literal(p.Key) + ": " + Fuzzer.Literal(p.Value)))}}}");
    }

    [Fact]
    public void ConnectionSettingsBlob_AnyBytes_NeverThrows_AndOnlyReportsKnownSettings()
    {
        var sample = Blob(0x0b, "proxy.example:8080", "<local>;*.test", "http://pac.example/proxy.pac");
        Fuzzer.RunBytes(4000, r => r.Chance(0.3) ? r.Bytes() : r.Mutate(sample), bytes =>
        {
            foreach (var winInet in new[] { true, false })
            {
                var values = new Dictionary<string, string>();
                ConnectionSettingsBlob.AddTo(values, "P.", bytes, winInet);
                Assert.NotEmpty(values);
                Assert.All(values.Keys, key => Assert.Contains(key, BlobKeys.Select(k => "P." + k)));
                // Unreadable settings are reported as a digest, never as half-read values.
                if (values.ContainsKey("P.Unrecognized")) Assert.Single(values);
            }
        });
    }

    [Fact]
    public void ConnectionSettingsBlob_WrittenAsWindowsWritesIt_ReadsBackExactly()
    {
        Fuzzer.Run(2000, r => (Flags: r.Next(16), Server: r.Chance(0.3) ? "" : r.Identifier() + ":" + r.Next(1, 65536),
            Bypass: r.Chance(0.5) ? "" : "<local>;" + r.Identifier(), Pac: r.Chance(0.5) ? "" : "http://" + r.Identifier() + "/p.pac",
            Counter: r.Next(int.MaxValue), Trailing: r.Bytes(8, 64)), input =>
        {
            var blob = Blob(input.Flags, input.Server, input.Bypass, input.Pac, input.Counter).Concat(input.Trailing).ToArray();
            var values = new Dictionary<string, string>();
            ConnectionSettingsBlob.AddTo(values, "", blob, winInet: true);

            Assert.Equal((input.Flags & 2) != 0 ? "1" : "0", values["ProxyEnabled"]);
            Assert.Equal((input.Flags & 4) != 0 ? "1" : "0", values["AutoConfigEnabled"]);
            Assert.Equal((input.Flags & 8) != 0 ? "1" : "0", values["AutoDetect"]);
            Assert.Equal(input.Server, values.GetValueOrDefault("ProxyServer", ""));
            Assert.Equal(input.Bypass, values.GetValueOrDefault("ProxyBypass", ""));
            Assert.Equal(input.Pac, values.GetValueOrDefault("AutoConfigURL", ""));

            // Windows bumps the counter on every save; that alone must not read as a change.
            var again = new Dictionary<string, string>();
            ConnectionSettingsBlob.AddTo(again, "", Blob(input.Flags, input.Server, input.Bypass, input.Pac, input.Counter + 1).Concat(input.Trailing).ToArray(), winInet: true);
            Assert.Equal(values, again);
        });
    }

    private static byte[] Blob(int flags, string server, string bypass, string pac, int counter = 7)
    {
        var bytes = new List<byte>();
        void Number(int value) => bytes.AddRange(BitConverter.GetBytes(value));
        void Text(string value)
        {
            Number(value.Length);
            bytes.AddRange(Encoding.Latin1.GetBytes(value));
        }
        Number(0x46);
        Number(counter);
        Number(flags);
        Text(server);
        Text(bypass);
        Text(pac);
        return bytes.ToArray();
    }
}

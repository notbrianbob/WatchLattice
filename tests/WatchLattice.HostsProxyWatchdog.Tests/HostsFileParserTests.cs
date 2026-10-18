using Xunit;

namespace WatchLattice.HostsProxyWatchdog.Tests;

public class HostsFileParserTests
{
    [Fact]
    public void Parse_ReadsEntries_IgnoringCommentsAndJunk()
    {
        var entries = HostsFileParser.Parse("""
            # Copyright (c) 1993-2009 Microsoft Corp.
            #      102.54.94.97     rhino.acme.com          # source server
            127.0.0.1       localhost
            ::1             localhost
            10.0.0.5  NAS.Home.  printer.home   # two names
            not-an-ip example.com
            0.0.0.0 ads.example.com
            10.0.0.6 nas.home
            """.Replace("\n", "\r\n"));

        Assert.Equal(new[] { "127.0.0.1", "::1" }, entries["localhost"]);
        Assert.Equal(new[] { "10.0.0.5", "10.0.0.6" }, entries["nas.home"]);
        Assert.Equal(new[] { "10.0.0.5" }, entries["printer.home"]);
        Assert.Equal(new[] { "0.0.0.0" }, entries["ads.example.com"]);
        Assert.False(entries.ContainsKey("example.com"));
        Assert.False(entries.ContainsKey("rhino.acme.com"));
        Assert.Equal(4, entries.Count);
    }

    [Fact]
    public void Parse_NormalizesAddresses_AndInternationalNames()
    {
        var entries = HostsFileParser.Parse("::ffff:0:0:0:1 x.test\n0000:0000::0001 bücher.example\n");

        Assert.Equal(new[] { "::1" }, entries["xn--bcher-kva.example"]);
        Assert.Single(entries["x.test"]);
    }

    [Theory]
    [InlineData("windowsupdate.com", "windowsupdate.com", true)]
    [InlineData("download.windowsupdate.com", "windowsupdate.com", true)]
    [InlineData("evilwindowsupdate.com", "windowsupdate.com", false)]
    [InlineData("windowsupdate.com.evil.test", "windowsupdate.com", false)]
    public void IsWithin_MatchesTheDomainAndItsSubdomainsOnly(string host, string domain, bool expected) =>
        Assert.Equal(expected, HostsFileParser.IsWithin(host, domain));

    [Theory]
    [InlineData("0.0.0.0", true)]
    [InlineData("127.0.0.1", true)]
    [InlineData("127.1.2.3", true)]
    [InlineData("::", true)]
    [InlineData("::1", true)]
    [InlineData("203.0.113.9", false)]
    public void IsBlockingAddress_RecognizesSinkholes(string address, bool expected) =>
        Assert.Equal(expected, HostsFileParser.IsBlockingAddress(address));
}

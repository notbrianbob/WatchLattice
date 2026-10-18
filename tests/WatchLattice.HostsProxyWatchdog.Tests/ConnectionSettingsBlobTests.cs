using System.Text;
using Xunit;

namespace WatchLattice.HostsProxyWatchdog.Tests;

public class ConnectionSettingsBlobTests
{
    internal static byte[] Blob(int counter, int flags, string server, string bypass, string? autoConfig = null)
    {
        var bytes = new List<byte>();
        void Dword(int value) => bytes.AddRange(BitConverter.GetBytes(value));
        void Text(string value)
        {
            Dword(value.Length);
            bytes.AddRange(Encoding.Latin1.GetBytes(value));
        }

        Dword(0x46);
        Dword(counter);
        Dword(flags);
        Text(server);
        Text(bypass);
        if (autoConfig is not null)
        {
            Text(autoConfig);
            bytes.AddRange(new byte[32]); // WinINET pads the rest of the structure.
        }
        return bytes.ToArray();
    }

    [Fact]
    public void WinInet_ReadsProxyPacAndAutoDetect()
    {
        var values = new Dictionary<string, string>();
        ConnectionSettingsBlob.AddTo(values, "Connection.",
            Blob(7, 0x01 | 0x02 | 0x04 | 0x08, "127.0.0.1:8888", "<local>", "http://wpad.test/proxy.pac"), winInet: true);

        Assert.Equal("1", values["Connection.ProxyEnabled"]);
        Assert.Equal("127.0.0.1:8888", values["Connection.ProxyServer"]);
        Assert.Equal("<local>", values["Connection.ProxyBypass"]);
        Assert.Equal("1", values["Connection.AutoConfigEnabled"]);
        Assert.Equal("http://wpad.test/proxy.pac", values["Connection.AutoConfigURL"]);
        Assert.Equal("1", values["Connection.AutoDetect"]);
    }

    [Fact]
    public void TheChangeCounter_IsNotPartOfTheSettings()
    {
        var first = new Dictionary<string, string>();
        var second = new Dictionary<string, string>();
        ConnectionSettingsBlob.AddTo(first, "C.", Blob(1, 0x09, "", "", ""), winInet: true);
        ConnectionSettingsBlob.AddTo(second, "C.", Blob(99, 0x09, "", "", ""), winInet: true);

        Assert.Equal(first, second);
        Assert.Equal("0", first["C.ProxyEnabled"]);
        Assert.False(first.ContainsKey("C.ProxyServer"));
    }

    [Fact]
    public void WinHttp_DirectAndProxy()
    {
        var direct = new Dictionary<string, string>();
        ConnectionSettingsBlob.AddTo(direct, "WinHTTP.", Blob(0, 0x01, "", ""), winInet: false);
        Assert.Equal(new Dictionary<string, string> { ["WinHTTP.ProxyEnabled"] = "0" }, direct);

        var proxied = new Dictionary<string, string>();
        ConnectionSettingsBlob.AddTo(proxied, "WinHTTP.", Blob(0, 0x03, "proxy.corp:8080", "*.corp"), winInet: false);
        Assert.Equal("1", proxied["WinHTTP.ProxyEnabled"]);
        Assert.Equal("proxy.corp:8080", proxied["WinHTTP.ProxyServer"]);
        Assert.Equal("*.corp", proxied["WinHTTP.ProxyBypass"]);
    }

    [Fact]
    public void Malformed_IsStillComparable_WithoutThrowing()
    {
        var blob = Blob(0, 0x03, "proxy:1", "");
        blob[12] = 0xFF; // proxy length far past the end

        var values = new Dictionary<string, string>();
        ConnectionSettingsBlob.AddTo(values, "C.", blob, winInet: true);
        var tiny = new Dictionary<string, string>();
        ConnectionSettingsBlob.AddTo(tiny, "C.", new byte[] { 1, 2 }, winInet: true);

        Assert.StartsWith("sha256:", Assert.Single(values).Value);
        Assert.StartsWith("sha256:", Assert.Single(tiny).Value);
    }
}

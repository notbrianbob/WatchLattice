using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace WatchLattice.HostsProxyWatchdog;

/// <summary>
/// Reads the binary proxy settings WinINET keeps in
/// <c>Connections\DefaultConnectionSettings</c> and WinHTTP keeps in
/// <c>Connections\WinHttpSettings</c>. Both start with the same layout: a
/// version, a change counter, flags (2 = use a proxy, 4 = use an
/// auto-config URL, 8 = auto-detect), then length-prefixed proxy server and
/// bypass strings; WinINET adds a length-prefixed auto-config URL. The
/// counter is skipped so that rewriting the same settings is not a change.
/// No I/O.
/// </summary>
public static class ConnectionSettingsBlob
{
    private const int ProxyFlag = 0x02;
    private const int AutoConfigFlag = 0x04;
    private const int AutoDetectFlag = 0x08;
    private const int MaxStringBytes = 32 * 1024;

    /// <summary>Adds the settings in <paramref name="blob"/> to <paramref name="values"/>, each name prefixed with <paramref name="prefix"/>.</summary>
    public static void AddTo(IDictionary<string, string> values, string prefix, byte[] blob, bool winInet)
    {
        ReadOnlySpan<byte> span = blob;
        if (span.Length < 12)
        {
            values[prefix + "Unrecognized"] = Digest(span);
            return;
        }

        var flags = BinaryPrimitives.ReadInt32LittleEndian(span[8..]);
        var rest = span[12..];
        if (!TryReadString(ref rest, out var server) || !TryReadString(ref rest, out var bypass))
        {
            values[prefix + "Unrecognized"] = Digest(span[8..]);
            return;
        }
        var autoConfigUrl = "";
        if (winInet && rest.Length > 0 && !TryReadString(ref rest, out autoConfigUrl))
        {
            values[prefix + "Unrecognized"] = Digest(span[8..]);
            return;
        }

        values[prefix + "ProxyEnabled"] = (flags & ProxyFlag) != 0 ? "1" : "0";
        if (server.Length > 0) values[prefix + "ProxyServer"] = server;
        if (bypass.Length > 0) values[prefix + "ProxyBypass"] = bypass;
        if (winInet)
        {
            values[prefix + "AutoConfigEnabled"] = (flags & AutoConfigFlag) != 0 ? "1" : "0";
            if (autoConfigUrl.Length > 0) values[prefix + "AutoConfigURL"] = autoConfigUrl;
            values[prefix + "AutoDetect"] = (flags & AutoDetectFlag) != 0 ? "1" : "0";
        }
    }

    private static bool TryReadString(ref ReadOnlySpan<byte> span, out string value)
    {
        value = "";
        if (span.Length < 4)
        {
            return false;
        }
        var length = BinaryPrimitives.ReadInt32LittleEndian(span);
        if (length < 0 || length > MaxStringBytes || length > span.Length - 4)
        {
            return false;
        }
        value = Encoding.Latin1.GetString(span.Slice(4, length)).TrimEnd('\0');
        span = span[(4 + length)..];
        return true;
    }

    private static string Digest(ReadOnlySpan<byte> bytes) => "sha256:" + Convert.ToHexString(SHA256.HashData(bytes));
}

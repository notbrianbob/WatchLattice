using System.Globalization;
using System.Net;

namespace WatchLattice.HostsProxyWatchdog;

/// <summary>Parses hosts file text the way the Windows resolver reads it. No I/O.</summary>
public static class HostsFileParser
{
    private static readonly IdnMapping Idn = new();

    /// <summary>
    /// Returns host → sorted distinct addresses. Each line is an IP address
    /// followed by one or more host names; <c>#</c> starts a comment. Lines whose
    /// first word is not an IP address are ignored, as Windows ignores them.
    /// </summary>
    public static IReadOnlyDictionary<string, IReadOnlyList<string>> Parse(string text)
    {
        var map = new Dictionary<string, SortedSet<string>>(StringComparer.Ordinal);
        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine;
            var hash = line.IndexOf('#');
            if (hash >= 0)
            {
                line = line[..hash];
            }

            var words = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (words.Length < 2 || !IPAddress.TryParse(words[0], out var address))
            {
                continue;
            }

            var normalizedAddress = address.ToString();
            foreach (var word in words.Skip(1))
            {
                if (NormalizeHost(word) is not { } host)
                {
                    continue;
                }
                if (!map.TryGetValue(host, out var addresses))
                {
                    map[host] = addresses = new SortedSet<string>(StringComparer.Ordinal);
                }
                addresses.Add(normalizedAddress);
            }
        }

        return map.ToDictionary(p => p.Key, p => (IReadOnlyList<string>)p.Value.ToList(), StringComparer.Ordinal);
    }

    /// <summary>Lower case, without a trailing dot, internationalized names in their ASCII form. Null if it isn't a host name.</summary>
    public static string? NormalizeHost(string? value)
    {
        var host = value?.Trim().TrimEnd('.');
        if (string.IsNullOrEmpty(host) || host.Length > 253)
        {
            return null;
        }
        try
        {
            host = Idn.GetAscii(host);
        }
        catch (ArgumentException)
        {
            // Not a valid IDN; keep the text so the entry is still visible.
        }
        return host.ToLowerInvariant();
    }

    /// <summary>True when <paramref name="host"/> is <paramref name="domain"/> or one of its subdomains.</summary>
    public static bool IsWithin(string host, string domain) =>
        host == domain || (host.Length > domain.Length && host.EndsWith(domain, StringComparison.Ordinal)
                                                       && host[host.Length - domain.Length - 1] == '.');

    /// <summary>True for an address that sends traffic nowhere (0.0.0.0, ::, or loopback), which is how hosts files block names.</summary>
    public static bool IsBlockingAddress(string address) =>
        IPAddress.TryParse(address, out var ip)
        && (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) || IPAddress.IsLoopback(ip));
}

using System.Net;
using System.Net.Sockets;

namespace NetDid.Method.WebVh;

/// <summary>
/// Network-destination policy for resolver-controlled HTTP requests.
/// </summary>
internal static class WebVhNetworkPolicy
{
    internal static bool IsPublicAddress(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();

        if (address.AddressFamily == AddressFamily.InterNetwork)
            return IsPublicIpv4(address.GetAddressBytes());

        if (address.AddressFamily != AddressFamily.InterNetworkV6)
            return false;

        if (address.Equals(IPAddress.IPv6Any)
            || address.Equals(IPAddress.IPv6None)
            || IPAddress.IsLoopback(address)
            || address.IsIPv6LinkLocal
            || address.IsIPv6SiteLocal
            || address.IsIPv6UniqueLocal
            || address.IsIPv6Multicast)
        {
            return false;
        }

        var bytes = address.GetAddressBytes();

        // Only globally assigned unicast space is eligible. This excludes IPv4 translation
        // prefixes (including NAT64), discard-only, and other special local-use ranges that are
        // not covered by the IPAddress convenience properties above.
        if ((bytes[0] & 0xe0) != 0x20) // outside 2000::/3
            return false;

        // Reject special/transition ranges inside 2000::/3: 2001::/23 includes Teredo,
        // benchmarking and ORCHID; 2001:db8::/32 and 3fff::/20 are documentation ranges;
        // 2002::/16 is deprecated 6to4 and embeds an unchecked IPv4 destination; 3ffe::/16
        // is the returned 6bone allocation.
        if (bytes[0] == 0x20 && bytes[1] == 0x01
            && ((bytes[2] & 0xfe) == 0x00
                || bytes[2] == 0x0d && bytes[3] == 0xb8))
        {
            return false;
        }

        if (bytes[0] == 0x20 && bytes[1] == 0x02)
            return false;

        if (bytes[0] == 0x3f && bytes[1] == 0xfe)
            return false;

        if (bytes[0] == 0x3f && bytes[1] == 0xff && (bytes[2] & 0xf0) == 0x00)
            return false;

        return true;
    }

    internal static bool IsLocalhost(string host)
    {
        var normalized = host.TrimEnd('.');
        return normalized.Equals("localhost", StringComparison.OrdinalIgnoreCase)
            || normalized.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsPublicIpv4(byte[] bytes)
    {
        var first = bytes[0];
        var second = bytes[1];
        var third = bytes[2];

        // Reject non-routable, private, shared, link-local, documentation,
        // benchmarking, multicast, and reserved address blocks. A resolver of
        // attacker-controlled DIDs should only initiate connections to globally
        // routable destinations.
        return first switch
        {
            0 => false,                                      // 0.0.0.0/8
            10 => false,                                     // 10.0.0.0/8
            100 when second is >= 64 and <= 127 => false,    // 100.64.0.0/10
            127 => false,                                    // 127.0.0.0/8
            169 when second == 254 => false,                 // 169.254.0.0/16
            172 when second is >= 16 and <= 31 => false,     // 172.16.0.0/12
            192 when second == 0 && third == 0 => false,     // 192.0.0.0/24
            192 when second == 0 && third == 2 => false,     // 192.0.2.0/24
            192 when second == 168 => false,                 // 192.168.0.0/16
            198 when second is 18 or 19 => false,            // 198.18.0.0/15
            198 when second == 51 && third == 100 => false,  // 198.51.100.0/24
            203 when second == 0 && third == 113 => false,   // 203.0.113.0/24
            >= 224 => false,                                 // multicast/reserved
            _ => true
        };
    }
}

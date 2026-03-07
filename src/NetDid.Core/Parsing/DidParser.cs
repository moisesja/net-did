using System.Text.RegularExpressions;
using NetDid.Core.Model;

namespace NetDid.Core.Parsing;

/// <summary>
/// W3C DID syntax validation, method extraction, and DID URL parsing.
/// </summary>
public static partial class DidParser
{
    // W3C DID ABNF: did = "did:" method-name ":" method-specific-id
    // method-name = 1*method-char, method-char = %x61-7A / DIGIT (lowercase + digits)
    // method-specific-id = *( *idchar ":" ) 1*idchar, idchar = ALPHA / DIGIT / "." / "-" / "_" / pct-encoded
    [GeneratedRegex(@"^did:[a-z0-9]+:.+$", RegexOptions.Compiled)]
    private static partial Regex DidRegex();

    // DID URL: did-url = did path-abempty [ "?" query ] [ "#" fragment ]
    [GeneratedRegex(@"^(?<did>did:[a-z0-9]+:[^?#/]+)(?<path>/[^?#]*)?(?:\?(?<query>[^#]*))?(?:#(?<fragment>.*))?$", RegexOptions.Compiled)]
    private static partial Regex DidUrlRegex();

    /// <summary>
    /// Validate a DID string conforms to W3C DID syntax: did:&lt;method&gt;:&lt;method-specific-id&gt;
    /// </summary>
    public static bool IsValid(string did)
    {
        if (string.IsNullOrEmpty(did))
            return false;
        return DidRegex().IsMatch(did);
    }

    /// <summary>Extract the method name from a DID string. Returns null if invalid.</summary>
    public static string? ExtractMethod(string did)
    {
        if (!IsValid(did))
            return null;

        var firstColon = did.IndexOf(':');
        var secondColon = did.IndexOf(':', firstColon + 1);
        return did[(firstColon + 1)..secondColon];
    }

    /// <summary>Extract the method-specific identifier.</summary>
    public static string? ExtractMethodSpecificId(string did)
    {
        if (!IsValid(did))
            return null;

        var firstColon = did.IndexOf(':');
        var secondColon = did.IndexOf(':', firstColon + 1);
        return did[(secondColon + 1)..];
    }

    /// <summary>Parse a DID URL (DID + optional path, query, fragment).</summary>
    public static DidUrl? ParseDidUrl(string didUrl)
    {
        if (string.IsNullOrEmpty(didUrl))
            return null;

        var match = DidUrlRegex().Match(didUrl);
        if (!match.Success)
            return null;

        var didStr = match.Groups["did"].Value;
        if (!IsValid(didStr))
            return null;

        var path = match.Groups["path"].Success ? match.Groups["path"].Value : null;
        var query = match.Groups["query"].Success ? match.Groups["query"].Value : null;
        var fragment = match.Groups["fragment"].Success ? match.Groups["fragment"].Value : null;

        return new DidUrl
        {
            Did = new Did(didStr),
            Path = path,
            Query = query,
            Fragment = fragment
        };
    }
}

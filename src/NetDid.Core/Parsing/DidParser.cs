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
    // method-specific-id = *( *idchar ":" ) 1*idchar
    // idchar = ALPHA / DIGIT / "." / "-" / "_" / pct-encoded
    // pct-encoded = "%" HEXDIG HEXDIG
    private const string IdCharPattern = @"[A-Za-z0-9._-]|%[0-9A-Fa-f]{2}";
    private const string MethodSpecificIdPattern = $@"(?:(?:{IdCharPattern})*:)*(?:{IdCharPattern})+";

    // Anchored with \z, not $: in .NET $ also matches before a trailing "\n", so
    // "did:example:123\n" validated (issue #145).
    [GeneratedRegex($@"^did:[a-z0-9]+:{MethodSpecificIdPattern}\z", RegexOptions.Compiled)]
    private static partial Regex DidRegex();

    // DID URL: did-url = did path-abempty [ ";" params ] [ "?" query ] [ "#" fragment ]
    // RFC 3986 allows no raw whitespace or control characters in any URI component, so the
    // component classes exclude them; with \z this rejects a trailing or embedded "\n" (issue #145).
    [GeneratedRegex($@"^(?<did>did:[a-z0-9]+:(?:(?:{IdCharPattern})*:)*(?:{IdCharPattern})+)(?<path>/[^;?#\s\p{{Cc}}]*)?(?:;(?<params>[^?#\s\p{{Cc}}]*))?(?:\?(?<query>[^#\s\p{{Cc}}]*))?(?:#(?<fragment>[^\s\p{{Cc}}]*))?\z", RegexOptions.Compiled)]
    private static partial Regex DidUrlRegex();

    /// <summary>
    /// Validate a bare DID string conforms to W3C DID syntax: did:&lt;method&gt;:&lt;method-specific-id&gt;.
    /// Rejects DID URLs (paths, queries, fragments, parameters).
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

    /// <summary>
    /// Validates a DID reference, which can be either an absolute DID URL
    /// or a relative fragment reference (e.g., "#key-1").
    /// Per W3C DID Core §3.2, relative DID URLs are valid within DID documents.
    /// </summary>
    public static bool IsValidDidReference(string reference)
    {
        if (string.IsNullOrEmpty(reference))
            return false;

        // Relative fragment reference: #fragment
        if (reference.StartsWith('#'))
            return reference.Length > 1;

        // Otherwise, must be a valid absolute DID URL
        return ParseDidUrl(reference) is not null;
    }

    /// <summary>Parse a DID URL (DID + optional path, params, query, fragment).</summary>
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

        var path = match.Groups["path"].Success && match.Groups["path"].Value.Length > 0
            ? match.Groups["path"].Value : null;
        var parameters = match.Groups["params"].Success && match.Groups["params"].Value.Length > 0
            ? match.Groups["params"].Value : null;
        var query = match.Groups["query"].Success && match.Groups["query"].Value.Length > 0
            ? match.Groups["query"].Value : null;
        var fragment = match.Groups["fragment"].Success && match.Groups["fragment"].Value.Length > 0
            ? match.Groups["fragment"].Value : null;

        return new DidUrl
        {
            Did = new Did(didStr),
            Path = path,
            Parameters = parameters,
            Query = query,
            Fragment = fragment
        };
    }
}

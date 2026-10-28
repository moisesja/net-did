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

    // RFC 3986 character sets (DID Core §3.2 defines path-abempty, query and fragment by RFC 3986):
    // pchar = unreserved / pct-encoded / sub-delims / ":" / "@". Raw non-ASCII, invisible format
    // characters, whitespace, controls, and characters such as < > " { } | \ ^ ` are not allowed,
    // and "%" must start a two-hex-digit escape (issue #145).
    private const string Unreserved = @"A-Za-z0-9\-._~";
    private const string SubDelims = @"!$&'()*+,;=";
    private const string PctEncoded = @"%[0-9A-Fa-f]{2}";
    // A path segment character, except ";", which introduces DID URL parameters here.
    private const string PathChar = $@"[{Unreserved}!$&'()*+,=:@/]|{PctEncoded}";
    private const string ParamChar = $@"[{Unreserved}{SubDelims}:@/]|{PctEncoded}";
    private const string QueryOrFragmentChar = $@"[{Unreserved}{SubDelims}:@/?]|{PctEncoded}";

    // DID URL: did-url = did path-abempty [ ";" params ] [ "?" query ] [ "#" fragment ]
    // Anchored with \z, not $ (which also matches before a trailing "\n").
    [GeneratedRegex($@"^(?<did>did:[a-z0-9]+:(?:(?:{IdCharPattern})*:)*(?:{IdCharPattern})+)(?<path>/(?:{PathChar})*)?(?:;(?<params>(?:{ParamChar})*))?(?:\?(?<query>(?:{QueryOrFragmentChar})*))?(?:#(?<fragment>(?:{QueryOrFragmentChar})*))?\z", RegexOptions.Compiled)]
    private static partial Regex DidUrlRegex();

    // A relative DID URL reference "#fragment" (DID Core §3.2), with the same fragment grammar.
    [GeneratedRegex($@"^#(?:{QueryOrFragmentChar})+\z", RegexOptions.Compiled)]
    private static partial Regex RelativeFragmentRegex();

    // RFC 3986 absolute URI: scheme ":" then URI characters, with "[" "]" (IP literals) only
    // before the fragment and at most one "#".
    [GeneratedRegex($@"^[A-Za-z][A-Za-z0-9+.\-]*:(?:[{Unreserved}{SubDelims}:@/?\[\]]|{PctEncoded})*(?:#(?:{QueryOrFragmentChar})*)?\z", RegexOptions.Compiled)]
    private static partial Regex AbsoluteUriRegex();

    /// <summary>
    /// Whether <paramref name="value"/> is an RFC 3986 absolute URI (scheme plus the RFC 3986
    /// character set). Used for service ids and endpoints and alsoKnownAs entries (DID Core
    /// §5.1.3, §5.4).
    /// </summary>
    internal static bool IsAbsoluteUri(string? value)
        => !string.IsNullOrEmpty(value) && AbsoluteUriRegex().IsMatch(value);

    /// <summary>Whether <paramref name="value"/> is a relative "#fragment" reference.</summary>
    internal static bool IsRelativeFragment(string? value)
        => !string.IsNullOrEmpty(value) && RelativeFragmentRegex().IsMatch(value);

    // NetDid's documented shorthand (issue #136): a bare id with no ':' and no '#', such as
    // "files" or "key-1", stands for "#files". It uses the fragment grammar without ':'.
    [GeneratedRegex($@"^(?:[{Unreserved}{SubDelims}@/?]|{PctEncoded})+\z", RegexOptions.Compiled)]
    private static partial Regex BareShorthandRegex();

    /// <summary>Whether <paramref name="value"/> is the bare-id shorthand for "#value".</summary>
    internal static bool IsBareShorthand(string? value)
        => !string.IsNullOrEmpty(value) && BareShorthandRegex().IsMatch(value);

    /// <summary>
    /// Resolves a service or verification-method id against the document's DID: "#x" and the
    /// bare shorthand "x" both become "{did}#x"; anything containing ':' is returned unchanged.
    /// The one equivalence used by dereferencing and by duplicate-id detection (issue #145).
    /// </summary>
    internal static string ResolveRelativeId(string id, string? did)
    {
        if (id.StartsWith('#'))
            return did + id;
        if (!id.Contains(':'))
            return did + "#" + id;
        return id;
    }


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

        // Relative fragment reference: #fragment, with the RFC 3986 fragment grammar (issue #145).
        if (reference.StartsWith('#'))
            return IsRelativeFragment(reference);

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

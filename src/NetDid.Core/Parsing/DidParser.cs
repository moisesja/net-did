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

    // A relative DID URL (DID Core §3.2.2: "MAY contain relative path components, query
    // parameters, and fragment identifiers"): an RFC 3986 relative-ref whose relative-part is
    // path-absolute, path-noscheme or path-empty. The network-path form "//authority…" is not one:
    // it replaces the DID itself, so it never names a resource of this document. A path-noscheme
    // first segment has no ':', so nothing starting "did:" matches here.
    private const string SegmentNzNc = $@"(?:[{Unreserved}{SubDelims}@]|{PctEncoded})+";
    [GeneratedRegex($@"^(?:/(?:(?:{PChar})+(?:/(?:{PChar})*)*)?|{SegmentNzNc}(?:/(?:{PChar})*)*)?(?:\?(?:{QueryOrFragmentChar})*)?(?:#(?:{QueryOrFragmentChar})*)?\z", RegexOptions.Compiled)]
    private static partial Regex RelativeDidUrlRegex();

    // RFC 3986 absolute URI: scheme ":" hier-part [ "?" query ] [ "#" fragment ]. hier-part is
    // "//" authority path-abempty, or a path that does not begin with "//". "[" and "]" appear
    // only around an IP-literal host, which is an IPv6address or an IPvFuture (§3.2.2).
    private const string PChar = $@"[{Unreserved}{SubDelims}:@]|{PctEncoded}";
    private const string H16 = "[0-9A-Fa-f]{1,4}";
    private const string DecOctet = "(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])";
    private const string Ls32 = $@"(?:{H16}:{H16}|{DecOctet}(?:\.{DecOctet}){{3}})";
    private const string Ipv6Address =
        $@"(?:(?:{H16}:){{6}}{Ls32}" +
        $@"|::(?:{H16}:){{5}}{Ls32}" +
        $@"|(?:{H16})?::(?:{H16}:){{4}}{Ls32}" +
        $@"|(?:(?:{H16}:){{0,1}}{H16})?::(?:{H16}:){{3}}{Ls32}" +
        $@"|(?:(?:{H16}:){{0,2}}{H16})?::(?:{H16}:){{2}}{Ls32}" +
        $@"|(?:(?:{H16}:){{0,3}}{H16})?::{H16}:{Ls32}" +
        $@"|(?:(?:{H16}:){{0,4}}{H16})?::{Ls32}" +
        $@"|(?:(?:{H16}:){{0,5}}{H16})?::{H16}" +
        $@"|(?:(?:{H16}:){{0,6}}{H16})?::)";
    private const string IpvFuture = $@"[vV][0-9A-Fa-f]+\.[{Unreserved}{SubDelims}:]+";
    private const string Authority =
        $@"//(?:(?:[{Unreserved}{SubDelims}:]|{PctEncoded})*@)?" +
        $@"(?:\[(?:{Ipv6Address}|{IpvFuture})\]|(?:[{Unreserved}{SubDelims}]|{PctEncoded})*)(?::[0-9]*)?";

    [GeneratedRegex($@"^[A-Za-z][A-Za-z0-9+.\-]*:(?:{Authority}(?:/(?:{PChar})*)*|(?!//)(?:{PChar}|/)*)(?:\?(?:{QueryOrFragmentChar})*)?(?:#(?:{QueryOrFragmentChar})*)?\z", RegexOptions.Compiled)]
    private static partial Regex AbsoluteUriRegex();

    /// <summary>
    /// Whether <paramref name="value"/> is an RFC 3986 absolute URI (scheme plus the RFC 3986
    /// character set). Used for service ids and endpoints and alsoKnownAs entries (DID Core
    /// §5.1.3, §5.4).
    /// </summary>
    internal static bool IsAbsoluteUri(string? value)
        => !string.IsNullOrEmpty(value) && AbsoluteUriRegex().IsMatch(value);

    /// <summary>
    /// Whether <paramref name="value"/> is a relative DID URL (DID Core §3.2.2): a path, query
    /// and/or fragment reference such as "#key-1", "/keys/1", "keys/1#k" or "?versionId=1#k".
    /// A lone "#" is not one.
    /// </summary>
    internal static bool IsRelativeDidUrl(string? value)
        => !string.IsNullOrEmpty(value) && value != "#" && RelativeDidUrlRegex().IsMatch(value);

    // NetDid's documented compatibility shorthand (issue #136): one plain segment such as "files"
    // or "key-1" stands for "#files", where RFC 3986 alone would resolve it to "<did>/files". It
    // has no ':', '/', '?' or '#', and is never a dot-segment, so every other relative reference
    // ("/files", "a/b", "?service=x", "./x") keeps its RFC 3986 meaning.
    [GeneratedRegex($@"^(?:[{Unreserved}{SubDelims}@]|{PctEncoded})+\z", RegexOptions.Compiled)]
    private static partial Regex BareShorthandRegex();

    /// <summary>Whether <paramref name="value"/> is the bare-id shorthand for "#value".</summary>
    internal static bool IsBareShorthand(string? value)
        => !string.IsNullOrEmpty(value) && value is not ("." or "..") && BareShorthandRegex().IsMatch(value);

    /// <summary>
    /// The form in which service and verification-method ids are compared (issue #145): the id
    /// resolved against the document's DID by RFC 3986 §5, which DID Core §3.2.2 requires (scheme
    /// "did", authority "&lt;method&gt;:&lt;method-specific-id&gt;", empty path), written without
    /// the DID itself: "#k", "/keys/1#k", "?versionId=1#k". "keys/1#k", "/keys/1#k" and
    /// "{did}/keys/1#k" are therefore one id. The one exception is the compatibility shorthand:
    /// a plain "x" means "#x" (issue #136). An id of another DID, or any other absolute URI, is
    /// returned unchanged; anything else is no URI reference at all and gets a form that equals
    /// no valid id. The one equivalence used by dereferencing, duplicate-id detection and
    /// verification-relationship checks. It never builds "{did}…", so its cost follows the id,
    /// not the DID: a did:peer DID embeds its whole document and can be megabytes long.
    /// </summary>
    internal static string ComparableId(string id, string? did)
    {
        if (did is not null && id.StartsWith(did, StringComparison.Ordinal)
            && (id.Length == did.Length || id[did.Length] is '/' or '?' or '#'))
            return ResolveAgainstDid(id[did.Length..]);
        if (IsBareShorthand(id))
            return "#" + id;
        if (IsRelativeDidUrl(id))
            return ResolveAgainstDid(id);
        if (IsAbsoluteUri(id))
            return id;
        // Not a URI reference (a network-path "//host#k" would be "did://host#k"; "k 1" is not
        // one at all): it names nothing here, so it must never equal the form of a valid id such
        // as "<did>//host#k", whose form is "//host#k". NUL never occurs in a valid id.
        return "\0" + id;
    }

    // RFC 3986 §5.2.2 for a reference with no scheme or authority, against a base that has an
    // authority and an empty path (the DID): an empty path keeps the base's empty path, any other
    // path becomes absolute ("keys/1" merges to "/keys/1", §5.2.3), and dot segments are removed
    // (§5.2.4). The query and fragment are kept as written.
    private static string ResolveAgainstDid(string reference)
    {
        var end = reference.IndexOfAny(['?', '#']);
        var path = end < 0 ? reference : reference[..end];
        var rest = end < 0 ? "" : reference[end..];
        if (path.Length == 0)
            return rest;
        return RemoveDotSegments(path.StartsWith('/') ? path : "/" + path) + rest;
    }

    // RFC 3986 §5.2.4 for a path that starts with "/".
    private static string RemoveDotSegments(string path)
    {
        if (!path.Contains('.'))
            return path;
        var segments = path.Split('/');
        var output = new List<string>(segments.Length);
        for (var i = 1; i < segments.Length; i++)
        {
            var segment = segments[i];
            if (segment is "." or "..")
            {
                if (segment == ".." && output.Count > 0)
                    output.RemoveAt(output.Count - 1);
                if (i == segments.Length - 1)
                    output.Add("");
                continue;
            }
            output.Add(segment);
        }
        return "/" + string.Join('/', output);
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
    /// Validates a DID reference: an absolute DID URL, or a relative DID URL (W3C DID Core §3.2.2),
    /// which may contain relative path components, query parameters and fragment identifiers
    /// (e.g. "#key-1", "/keys/1", "keys/1#k", "?versionId=1#key-1") and is resolved against the
    /// DID by RFC 3986 §5. Every component follows the RFC 3986 character rules (issue #145).
    /// </summary>
    public static bool IsValidDidReference(string reference)
    {
        if (string.IsNullOrEmpty(reference))
            return false;

        return IsRelativeDidUrl(reference) || ParseDidUrl(reference) is not null;
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

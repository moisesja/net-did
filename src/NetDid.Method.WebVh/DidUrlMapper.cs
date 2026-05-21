using NetDid.Core.Parsing;

namespace NetDid.Method.WebVh;

/// <summary>
/// Maps a did:webvh DID to its HTTPS URL for did.jsonl retrieval.
///
/// did:webvh:SCID:domain           -> https://domain/.well-known/did.jsonl
/// did:webvh:SCID:domain:path      -> https://domain/path/did.jsonl
/// did:webvh:SCID:domain%3A8443    -> https://domain:8443/.well-known/did.jsonl
/// </summary>
public static class DidUrlMapper
{
    /// <summary>Map a did:webvh DID to the HTTPS URL of its did.jsonl file.</summary>
    public static Uri MapToLogUrl(string did) => BuildHttpsUrl(did, "did.jsonl");

    /// <summary>Map a did:webvh DID to the HTTPS URL of its did-witness.json file.</summary>
    public static Uri MapToWitnessUrl(string did) => BuildHttpsUrl(did, "did-witness.json");

    /// <summary>Extract the SCID from a did:webvh DID.</summary>
    public static string ExtractScid(string did)
    {
        var msid = DidParser.ExtractMethodSpecificId(did)
            ?? throw new ArgumentException($"Cannot extract SCID from: {did}");
        // method-specific-id = SCID:domain[:path]
        var firstColon = msid.IndexOf(':');
        if (firstColon < 0)
            throw new ArgumentException($"Invalid did:webvh format — missing domain: {did}");
        return msid[..firstColon];
    }

    /// <summary>Extract the domain from a did:webvh DID.</summary>
    public static string ExtractDomain(string did)
    {
        return ExtractDomainAndPath(did).Domain;
    }

    /// <summary>Extract the optional path from a did:webvh DID.</summary>
    public static string? ExtractPath(string did)
    {
        return ExtractDomainAndPath(did).Path;
    }

    /// <summary>
    /// Validate the domain segment of a did:webvh DID. Returns the decoded host
    /// and optional port. Throws <see cref="ArgumentException"/> on any unsafe input.
    /// Used both by URL mapping (resolve) and by create-time options validation.
    /// </summary>
    internal static (string Host, int? Port) ValidateDomain(string raw, string did)
    {
        if (string.IsNullOrEmpty(raw))
            throw new ArgumentException($"Invalid did:webvh — empty domain: {did}");

        // Decode the spec-mandated percent-encoding (only %3A for the host/port colon
        // is expected by the did:webvh spec). Any other decoded char that is unsafe
        // in a URI authority must be rejected to prevent host pivots and path
        // injection (e.g. %40 -> '@', %2F -> '/', %5C -> '\').
        var decoded = Uri.UnescapeDataString(raw);

        foreach (var c in decoded)
        {
            if (IsUnsafeAuthorityChar(c))
                throw new ArgumentException(
                    $"Invalid did:webvh domain — unsafe character '{c}': {did}");
        }

        string host;
        int? port = null;
        var colonIdx = decoded.IndexOf(':');
        if (colonIdx >= 0)
        {
            // Multiple colons would indicate IPv6 or malformed input; the spec
            // only encodes a single port colon via %3A, so reject anything else.
            if (decoded.IndexOf(':', colonIdx + 1) >= 0)
                throw new ArgumentException(
                    $"Invalid did:webvh domain — multiple colons: {did}");

            host = decoded[..colonIdx];
            var portStr = decoded[(colonIdx + 1)..];
            if (!int.TryParse(portStr, System.Globalization.NumberStyles.None,
                    System.Globalization.CultureInfo.InvariantCulture, out var p)
                || p < 1 || p > 65535)
                throw new ArgumentException(
                    $"Invalid did:webvh domain — invalid port '{portStr}': {did}");
            port = p;
        }
        else
        {
            host = decoded;
        }

        if (string.IsNullOrEmpty(host) || Uri.CheckHostName(host) == UriHostNameType.Unknown)
            throw new ArgumentException(
                $"Invalid did:webvh domain — invalid host '{host}': {did}");

        return (host, port);
    }

    /// <summary>
    /// Validate did:webvh path segments. Each segment must be non-empty, must not
    /// percent-decode to <c>.</c> or <c>..</c>, and must not contain separators or
    /// control characters. Returns the original (still-encoded) segments suitable
    /// for use in a URL path. Throws <see cref="ArgumentException"/> on unsafe input.
    /// </summary>
    internal static IReadOnlyList<string> ValidatePathSegments(string? path, string did)
    {
        if (string.IsNullOrEmpty(path))
            return Array.Empty<string>();

        var segments = path.Split('/');
        var result = new List<string>(segments.Length);

        foreach (var segment in segments)
        {
            if (string.IsNullOrEmpty(segment))
                throw new ArgumentException(
                    $"Invalid did:webvh — empty path segment: {did}");

            var decoded = Uri.UnescapeDataString(segment);
            if (decoded is "." or "..")
                throw new ArgumentException(
                    $"Invalid did:webvh — traversal path segment '{decoded}': {did}");

            foreach (var c in decoded)
            {
                if (IsUnsafePathSegmentChar(c))
                    throw new ArgumentException(
                        $"Invalid did:webvh — unsafe path segment character '{c}': {did}");
            }

            result.Add(segment);
        }

        return result;
    }

    private static Uri BuildHttpsUrl(string did, string filename)
    {
        var (domain, path) = ExtractDomainAndPath(did);
        var (host, port) = ValidateDomain(domain, did);
        var segments = ValidatePathSegments(path, did);

        var builder = new UriBuilder("https", host) { Port = port ?? -1 };
        builder.Path = segments.Count == 0
            ? $"/.well-known/{filename}"
            : "/" + string.Join("/", segments) + "/" + filename;
        return builder.Uri;
    }

    private static bool IsUnsafeAuthorityChar(char c)
    {
        // Forbid anything that could shift parser interpretation of authority.
        // ':' is allowed here (port separator) and handled separately by the caller.
        if (char.IsControl(c) || c == ' ') return true;
        return c is '@' or '/' or '\\' or '?' or '#' or '[' or ']' or '<' or '>'
            or '"' or '\'' or '%' or '{' or '}' or '|' or '^' or '`';
    }

    private static bool IsUnsafePathSegmentChar(char c)
    {
        if (char.IsControl(c) || c == ' ') return true;
        return c is '/' or '\\' or '?' or '#' or '<' or '>' or '"' or '\'' or '%';
    }

    private static (string Domain, string? Path) ExtractDomainAndPath(string did)
    {
        var msid = DidParser.ExtractMethodSpecificId(did)
            ?? throw new ArgumentException($"Cannot parse did:webvh DID: {did}");

        // method-specific-id = SCID:domain[:path-segments...]
        var parts = msid.Split(':');
        if (parts.Length < 2)
            throw new ArgumentException($"Invalid did:webvh format — missing domain: {did}");

        // parts[0] = SCID, parts[1] = domain, parts[2..] = path segments
        var domain = parts[1];
        string? path = null;

        if (parts.Length > 2)
            path = string.Join("/", parts[2..]);

        return (domain, path);
    }
}

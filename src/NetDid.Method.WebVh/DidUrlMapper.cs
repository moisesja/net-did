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
    public static Uri MapToLogUrl(string did)
    {
        var (domain, path) = ExtractDomainAndPath(did);
        var host = Uri.UnescapeDataString(domain);

        if (path is not null)
            return new Uri($"https://{host}/{path}/did.jsonl");
        else
            return new Uri($"https://{host}/.well-known/did.jsonl");
    }

    /// <summary>Map a did:webvh DID to the HTTPS URL of its did-witness.json file.</summary>
    public static Uri MapToWitnessUrl(string did)
    {
        var (domain, path) = ExtractDomainAndPath(did);
        var host = Uri.UnescapeDataString(domain);

        if (path is not null)
            return new Uri($"https://{host}/{path}/did-witness.json");
        else
            return new Uri($"https://{host}/.well-known/did-witness.json");
    }

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

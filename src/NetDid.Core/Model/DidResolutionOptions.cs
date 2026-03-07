namespace NetDid.Core.Model;

public record DidResolutionOptions
{
    /// <summary>
    /// The preferred Media Type for the DID Document representation.
    /// Supported values: "application/did+ld+json" (default), "application/did+json".
    /// </summary>
    public string Accept { get; init; } = DidContentTypes.JsonLd;

    /// <summary>W3C DID Core §7.2 query parameters — passed through by the dereferencer.</summary>
    public string? VersionId { get; init; }
    public string? VersionTime { get; init; }

    /// <summary>
    /// Returns a deterministic string for cache key discrimination.
    /// </summary>
    public string GetCacheDiscriminator()
        => $"{Accept}|{VersionId}|{VersionTime}";
}

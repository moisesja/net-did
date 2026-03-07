namespace NetDid.Core.Model;

public sealed record DereferencingMetadata
{
    /// <summary>The Media Type of the returned content (e.g., "application/did+ld+json").</summary>
    public string? ContentType { get; init; }

    /// <summary>Error code if dereferencing failed: "invalidDidUrl", "notFound", "contentTypeNotSupported".</summary>
    public string? Error { get; init; }
}

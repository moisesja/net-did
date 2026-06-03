namespace NetDid.Core.Model;

public sealed record DidResolutionResult
{
    public required DidDocument? DidDocument { get; init; }
    public required DidResolutionMetadata ResolutionMetadata { get; init; }
    public DidDocumentMetadata? DocumentMetadata { get; init; }

    /// <summary>
    /// Method-specific artifacts produced during resolution (e.g. the parsed did:webvh log).
    /// Populated only when explicitly requested via <see cref="DidResolutionOptions.IncludeLog"/>
    /// or analogous opt-ins. Methods without artifacts leave this null.
    /// </summary>
    public IReadOnlyDictionary<string, object>? Artifacts { get; init; }

    public static DidResolutionResult InvalidDid(string did) => new()
    {
        DidDocument = null,
        ResolutionMetadata = new DidResolutionMetadata { Error = "invalidDid" }
    };

    public static DidResolutionResult MethodNotSupported(string did) => new()
    {
        DidDocument = null,
        ResolutionMetadata = new DidResolutionMetadata { Error = "methodNotSupported" }
    };

    public static DidResolutionResult NotFound(string did) => new()
    {
        DidDocument = null,
        ResolutionMetadata = new DidResolutionMetadata { Error = "notFound" }
    };
}

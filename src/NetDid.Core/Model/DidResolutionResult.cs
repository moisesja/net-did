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

    public static DidResolutionResult InvalidOptions(string did) => new()
    {
        DidDocument = null,
        ResolutionMetadata = new DidResolutionMetadata { Error = "invalidOptions" }
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

    /// <summary>
    /// Resolver-infrastructure failure (DID Resolution semantics: an unexpected error
    /// during the resolution algorithm), as opposed to <see cref="NotFound"/>, which
    /// asserts the DID does not exist. <paramref name="reason"/>, when supplied, is
    /// carried as a "message" beside "error" in the resolution metadata so callers can
    /// tell e.g. a pruned RPC node from a generic failure. Callers must treat the
    /// reason as informational text and escape it before rendering.
    /// </summary>
    /// <remarks>
    /// Like every factory on this type, the code uses the legacy DID Spec Registries
    /// string vocabulary ("internalError"), matching the rest of the library and the
    /// reference-resolver ecosystem. The current W3C DID Resolution draft instead
    /// models errors as RFC 9457 problem-details objects (type
    /// <c>https://www.w3.org/ns/did#INTERNAL_ERROR</c>) with empty document metadata
    /// on failure; that library-wide migration is tracked in issue #123.
    /// </remarks>
    public static DidResolutionResult InternalError(string did, string? reason = null) => new()
    {
        DidDocument = null,
        ResolutionMetadata = new DidResolutionMetadata
        {
            Error = "internalError",
            AdditionalProperties = reason is null
                ? null
                : new Dictionary<string, object> { ["message"] = reason },
        }
    };
}

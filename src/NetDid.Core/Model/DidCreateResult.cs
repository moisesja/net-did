namespace NetDid.Core.Model;

public sealed record DidCreateResult
{
    public required DidDocument DidDocument { get; init; }
    public required Did Did { get; init; }
    public DidDocumentMetadata? Metadata { get; init; }

    /// <summary>Method-specific artifacts (e.g., did.jsonl content for webvh, tx hash for ethr).</summary>
    public IReadOnlyDictionary<string, object>? Artifacts { get; init; }
}

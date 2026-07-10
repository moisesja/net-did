namespace NetDid.Core.Model;

public sealed record DidUpdateResult
{
    public required DidDocument DidDocument { get; init; }
    public IReadOnlyDictionary<string, object>? Artifacts { get; init; }

    /// <summary>
    /// True if this update changed the method's authorization material — for did:webvh:
    /// <c>updateKeys</c>, <c>nextKeyHashes</c>, <c>prerotation</c>, or <c>witness</c> config —
    /// i.e. it was not a document-only edit. did:webvh keeps its update authority in the log
    /// parameters rather than in the DID Document, so a method-agnostic caller reading back
    /// <see cref="DidDocument"/> cannot otherwise tell a document edit apart from a key rotation.
    /// This flag lets such a caller detect and reject an unintended authority change.
    /// </summary>
    public bool AuthorizationChanged { get; init; }
}

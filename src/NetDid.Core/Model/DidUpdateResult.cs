namespace NetDid.Core.Model;

public sealed record DidUpdateResult
{
    public required DidDocument DidDocument { get; init; }
    public IReadOnlyDictionary<string, object>? Artifacts { get; init; }

    /// <summary>
    /// Whether this update changed the method's authorization material — for did:webvh:
    /// <c>updateKeys</c>, <c>nextKeyHashes</c>, <c>prerotation</c>, or <c>witness</c> config.
    /// did:webvh keeps its update authority in the log parameters rather than in the DID Document,
    /// so a method-agnostic caller reading back <see cref="DidDocument"/> cannot otherwise tell a
    /// document edit apart from a key rotation. The default is
    /// <see cref="AuthorizationChangeStatus.Unknown"/> so that a method which does not report change
    /// evidence fails closed: a caller enforcing a document-only postcondition must require
    /// <see cref="AuthorizationChangeStatus.Unchanged"/> and reject both <c>Unknown</c> and
    /// <c>Changed</c>.
    /// </summary>
    public AuthorizationChangeStatus AuthorizationChange { get; init; }
}

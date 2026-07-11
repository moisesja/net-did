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
    /// <c>Changed</c>. This is deliberately coarse — a <c>Changed</c> here may be a policy-only
    /// change (witness / pre-rotation commitments) that leaves the active update keys intact; use
    /// <see cref="UpdateKeyChange"/> and <see cref="EffectiveUpdateKeys"/> to reason about key
    /// rotation specifically.
    /// </summary>
    public AuthorizationChangeStatus AuthorizationChange { get; init; }

    /// <summary>
    /// Whether this update changed the effective set of authorized update keys (for did:webvh:
    /// the effective <c>updateKeys</c>), compared as an order-insensitive set before vs. after the
    /// update. Unlike <see cref="AuthorizationChange"/>, a policy-only change (witness config,
    /// pre-rotation commitments) does not trip this. The default is
    /// <see cref="AuthorizationChangeStatus.Unknown"/> so that a method which does not report the
    /// evidence fails closed; a method also withholds it (reports <c>Unknown</c>) in states where
    /// the parameter-level key set does not determine signing authority — did:webvh does so
    /// whenever key pre-rotation is in play (see <see cref="EffectiveUpdateKeys"/>).
    /// Note that <see cref="AuthorizationChangeStatus.Changed"/> does not by itself imply the
    /// previous key lost authority — an update can add keys, including keys the caller did not
    /// expect. A caller enforcing an exclusive key-rotation postcondition must require
    /// <c>Changed</c> here and require <see cref="EffectiveUpdateKeys"/> to set-equal its intended
    /// post-rotation key set; membership checks alone (new key present, retired key absent) accept
    /// an effective set that also contains unexpected additional keys.
    /// </summary>
    public AuthorizationChangeStatus UpdateKeyChange { get; init; }

    /// <summary>
    /// The public keys (for did:webvh: multibase-encoded, per the effective <c>updateKeys</c> of
    /// the new latest log entry) authorized to sign the NEXT log entry — update or deactivation —
    /// after this one. These are not necessarily the keys that authorized the update being
    /// reported; that was the previous effective set. Lets a method-agnostic caller (a) confirm the
    /// active update-key set actually changed and (b) bind its own new key to the new authority —
    /// for an exclusive rotation, compare this complete set against the intended post-rotation set
    /// rather than checking membership only. Entries use the reporting method's own canonical key
    /// representation (did:webvh: multibase); a consumer's comparison must use the same form the
    /// method reports.
    /// <c>null</c> when the method does not report it (treat as no evidence and fail closed).
    /// did:webvh reports <c>null</c> whenever key pre-rotation is in play: under pre-rotation the
    /// next entry is authorized by its own pre-committed <c>updateKeys</c> (the
    /// <c>nextKeyHashes</c> preimages), so the driver cannot derive the next signer list from the
    /// parameter-level evidence available here — <c>nextKeyHashes</c> are hashes, not keys (the
    /// controller holding the pre-committed keypairs may of course know them). An empty list
    /// means no keys are authorized, i.e. the DID can no longer be updated (a state did:webvh
    /// v1.0 explicitly permits for freezing a DID).
    /// </summary>
    public IReadOnlyList<string>? EffectiveUpdateKeys { get; init; }
}

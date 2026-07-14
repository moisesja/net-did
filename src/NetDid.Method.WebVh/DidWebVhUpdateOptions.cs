using NetCrypto;
using NetDid.Core;
using NetDid.Core.Model;
using NetDid.Method.WebVh.Model;

namespace NetDid.Method.WebVh;

/// <summary>
/// Options for updating an existing did:webvh DID.
/// </summary>
public sealed record DidWebVhUpdateOptions : DidUpdateOptions
{
    /// <summary>The existing did.jsonl content (bytes).</summary>
    public required byte[] CurrentLogContent { get; init; }

    /// <summary>
    /// The Ed25519 signer for an authorized update key (HSM-safe). In ordinary mode this key must
    /// be in the prior effective updateKeys; when pre-rotation governs the entry it must be in the
    /// current explicit, previously committed UpdateKeys.
    /// </summary>
    public required ISigner SigningKey { get; init; }

    /// <summary>
    /// The updated DID Document. If null, the previous document is preserved verbatim — the new
    /// entry republishes the fetched state bytes, including signed nested members the typed
    /// model does not surface. When supplied, the document is deep-copied exactly once at the
    /// start of the update (one JSON-LD serialization round-trip): hashing, signing, the
    /// published log, and <see cref="NetDid.Core.Model.DidUpdateResult.DidDocument"/> all
    /// reflect that private snapshot, never a later state of this instance.
    /// </summary>
    public DidDocument? NewDocument { get; init; }

    /// <summary>Parameter updates to apply. If null, parameters are unchanged.</summary>
    public DidWebVhParameterUpdates? ParameterUpdates { get; init; }

    /// <summary>Witness proofs to include in the did-witness.json artifact.</summary>
    public IReadOnlyList<WitnessProofEntry>? WitnessProofs { get; init; }

    /// <summary>Existing did-witness.json content to merge with new proofs.</summary>
    public byte[]? CurrentWitnessContent { get; init; }
}

/// <summary>
/// Optional parameter updates for an Update operation.
/// Only non-null fields override the previous entry's parameters.
/// </summary>
public sealed record DidWebVhParameterUpdates
{
    /// <summary>
    /// New update keys to authorize. When the previous effective nextKeyHashes is non-empty,
    /// this property is required, must be non-empty, and every member must match a previous
    /// commitment; one member must also correspond to <see cref="DidWebVhUpdateOptions.SigningKey"/>.
    /// </summary>
    public IReadOnlyList<string>? UpdateKeys { get; init; }

    /// <summary>
    /// New pre-rotation key commitments. A non-empty array activates pre-rotation for the next
    /// entry; an explicit empty array deactivates it after the current entry is authorized. This
    /// property is required (but may be empty) whenever the previous effective nextKeyHashes is
    /// non-empty.
    /// </summary>
    public IReadOnlyList<string>? NextKeyHashes { get; init; }

    /// <summary>Update the watcher URL list; an empty array disables watchers.</summary>
    public IReadOnlyList<string>? Watchers { get; init; }

    /// <summary>Update witness configuration.</summary>
    public WitnessConfig? Witness { get; init; }

    /// <summary>New TTL value.</summary>
    public int? Ttl { get; init; }
}

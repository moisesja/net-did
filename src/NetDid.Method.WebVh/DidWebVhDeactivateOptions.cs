using NetCrypto;
using NetDid.Core;
using NetDid.Core.Model;
using NetDid.Method.WebVh.Model;

namespace NetDid.Method.WebVh;

/// <summary>
/// Options for deactivating a did:webvh DID.
/// </summary>
public sealed record DidWebVhDeactivateOptions : DidDeactivateOptions
{
    /// <summary>The existing did.jsonl content (bytes).</summary>
    public required byte[] CurrentLogContent { get; init; }

    /// <summary>
    /// The Ed25519 signer for an authorized update key (HSM-safe). When pre-rotation is active,
    /// this must be a key committed by the prior nextKeyHashes; the deactivation entry reveals it
    /// and explicitly ends pre-rotation.
    /// </summary>
    public required ISigner SigningKey { get; init; }

    /// <summary>Witness proofs to include in the did-witness.json artifact.</summary>
    public IReadOnlyList<WitnessProofEntry>? WitnessProofs { get; init; }

    /// <summary>
    /// Existing did-witness.json content to merge with new proofs. Consumed whenever supplied —
    /// with or without an accompanying <see cref="WitnessProofs"/> batch — and republished in
    /// the resulting artifact; same-version proofs append (witness collection is incremental).
    /// Must be a parseable did:webvh v1.0 witness file (<c>proof</c> member; issue #135) —
    /// unparseable content fails the deactivation with <see cref="ArgumentException"/> rather
    /// than being silently ignored or publishing an artifact stripped of the existing proofs.
    /// Omit it to publish only the supplied <see cref="WitnessProofs"/>.
    /// </summary>
    public byte[]? CurrentWitnessContent { get; init; }
}

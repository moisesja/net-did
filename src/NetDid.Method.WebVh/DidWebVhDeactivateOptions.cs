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

    /// <summary>The Ed25519 signer for an authorized update key (HSM-safe).</summary>
    public required ISigner SigningKey { get; init; }

    /// <summary>Witness proofs to include in the did-witness.json artifact.</summary>
    public IReadOnlyList<WitnessProofEntry>? WitnessProofs { get; init; }

    /// <summary>Existing did-witness.json content to merge with new proofs.</summary>
    public byte[]? CurrentWitnessContent { get; init; }
}

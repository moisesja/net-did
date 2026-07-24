using NetCrypto;
using NetDid.Core;
using NetDid.Core.Model;
using NetDid.Method.WebVh.Model;

namespace NetDid.Method.WebVh;

/// <summary>
/// Options for creating a new did:webvh DID.
/// </summary>
public sealed record DidWebVhCreateOptions : DidCreateOptions
{
    /// <inheritdoc />
    public override string MethodName => "webvh";

    /// <summary>The domain where the DID log will be hosted (e.g., "example.com").</summary>
    public required string Domain { get; init; }

    /// <summary>Optional sub-path under the domain (e.g., "users/alice").</summary>
    public string? Path { get; init; }

    /// <summary>The Ed25519 signer for the update key. Signs the genesis log entry (HSM-safe).</summary>
    public required ISigner UpdateKey { get; init; }

    /// <summary>Additional verification methods to include in the DID Document.</summary>
    public IReadOnlyList<VerificationMethod>? AdditionalVerificationMethods { get; init; }

    /// <summary>Services to include in the DID Document.</summary>
    public IReadOnlyList<Service>? Services { get; init; }

    /// <summary>
    /// Hashes of next update keys. A non-empty array activates pre-rotation for the next entry.
    /// </summary>
    public IReadOnlyList<string>? PreRotationCommitments { get; init; }

    /// <summary>URLs of services that have agreed to watch this DID.</summary>
    public IReadOnlyList<string>? Watchers { get; init; }

    /// <summary>Witness DIDs (must be did:key DIDs).</summary>
    public IReadOnlyList<string>? WitnessDids { get; init; }

    /// <summary>Minimum number of distinct verified witness approvals required.</summary>
    public int WitnessThreshold { get; init; } = 0;

    /// <summary>Witness proofs to include in the did-witness.json artifact.</summary>
    public IReadOnlyList<WitnessProofEntry>? WitnessProofs { get; init; }
}

using NetDid.Core;
using NetDid.Core.Model;

namespace NetDid.Method.WebVh;

/// <summary>
/// Options for creating a new did:webvh DID.
/// </summary>
public sealed record DidWebVhCreateOptions : DidCreateOptions
{
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

    /// <summary>Enable pre-rotation key commitment.</summary>
    public bool EnablePreRotation { get; init; } = false;

    /// <summary>Hashes of next update keys (required when EnablePreRotation is true).</summary>
    public IReadOnlyList<string>? PreRotationCommitments { get; init; }

    /// <summary>Witness DIDs (must be did:key DIDs).</summary>
    public IReadOnlyList<string>? WitnessDids { get; init; }

    /// <summary>Minimum total weight of witness proofs required.</summary>
    public int WitnessThreshold { get; init; } = 0;
}

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

    /// <summary>The Ed25519 signer for an authorized update key (HSM-safe).</summary>
    public required ISigner SigningKey { get; init; }

    /// <summary>The updated DID Document. If null, the previous document is preserved.</summary>
    public DidDocument? NewDocument { get; init; }

    /// <summary>Parameter updates to apply. If null, parameters are unchanged.</summary>
    public DidWebVhParameterUpdates? ParameterUpdates { get; init; }
}

/// <summary>
/// Optional parameter updates for an Update operation.
/// Only non-null fields override the previous entry's parameters.
/// </summary>
public sealed record DidWebVhParameterUpdates
{
    /// <summary>New update keys to authorize.</summary>
    public IReadOnlyList<string>? UpdateKeys { get; init; }

    /// <summary>Enable or change pre-rotation.</summary>
    public bool? Prerotation { get; init; }

    /// <summary>New pre-rotation key commitments.</summary>
    public IReadOnlyList<string>? NextKeyHashes { get; init; }

    /// <summary>Update witness configuration.</summary>
    public WitnessConfig? Witness { get; init; }

    /// <summary>New TTL value.</summary>
    public int? Ttl { get; init; }
}

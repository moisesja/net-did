namespace NetDid.Method.WebVh.Model;

/// <summary>
/// Witness configuration for a did:webvh DID.
/// Witnesses are did:key DIDs that co-sign updates for additional security.
/// </summary>
public sealed class WitnessConfig
{
    /// <summary>Minimum total weight of valid witness proofs required.</summary>
    public int Threshold { get; init; }

    /// <summary>The list of authorized witnesses.</summary>
    public IReadOnlyList<WitnessEntry>? Witnesses { get; init; }
}

/// <summary>
/// A single witness entry.
/// </summary>
public sealed class WitnessEntry
{
    /// <summary>The witness DID (must be a did:key DID).</summary>
    public required string Id { get; init; }

    /// <summary>The weight of this witness's approval. Defaults to 1.</summary>
    public int Weight { get; init; } = 1;
}

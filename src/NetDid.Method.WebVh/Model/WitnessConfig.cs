namespace NetDid.Method.WebVh.Model;

/// <summary>
/// Witness configuration for a did:webvh DID.
/// Witnesses are did:key DIDs that co-sign updates for additional security.
/// </summary>
public sealed class WitnessConfig
{
    /// <summary>Minimum number of distinct verified witness approvals required.</summary>
    public int Threshold { get; init; }

    /// <summary>The list of authorized witnesses.</summary>
    public IReadOnlyList<WitnessEntry>? Witnesses { get; init; }

    // Populated for wire-parsed policies so {} can be distinguished from malformed partial
    // objects such as {"threshold":0}.
    internal bool? ThresholdPropertyPresent { get; init; }
    internal bool? WitnessesPropertyPresent { get; init; }

    internal bool IsDisabled => ThresholdPropertyPresent.HasValue
        ? ThresholdPropertyPresent == false && WitnessesPropertyPresent == false
        : Threshold == 0 && Witnesses is null;
}

/// <summary>
/// A single witness entry.
/// </summary>
public sealed class WitnessEntry
{
    /// <summary>The witness DID (must be a did:key DID).</summary>
    public required string Id { get; init; }

    /// <summary>
    /// Legacy compatibility value. did:webvh 1.0 ignores weights and counts each distinct
    /// verified witness once. Newly serialized policies omit this field.
    /// </summary>
    public int Weight { get; init; } = 1;

    // Retains a parsed legacy weight for exact historical hash/proof reconstruction.
    internal int? LegacyWireWeight { get; init; }
}

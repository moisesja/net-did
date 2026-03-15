namespace NetDid.Method.WebVh.Model;

/// <summary>
/// A single witness proof entry within did-witness.json.
/// Each entry corresponds to one log version that was witnessed.
/// </summary>
public sealed class WitnessProofEntry
{
    /// <summary>The versionId of the log entry these witness proofs apply to.</summary>
    public required string VersionId { get; init; }

    /// <summary>The witness proofs for this version.</summary>
    public required IReadOnlyList<DataIntegrityProofValue> Proofs { get; init; }
}

/// <summary>
/// The did-witness.json file containing witness proofs across all witnessed log versions.
/// Per spec, this is a JSON array of witness proof entries.
/// </summary>
public sealed class WitnessFile
{
    /// <summary>All witness proof entries, one per witnessed log version.</summary>
    public required IReadOnlyList<WitnessProofEntry> Entries { get; init; }
}

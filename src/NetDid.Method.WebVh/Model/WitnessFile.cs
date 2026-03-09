namespace NetDid.Method.WebVh.Model;

/// <summary>
/// The did-witness.json file containing witness proofs for a specific log entry version.
/// </summary>
public sealed class WitnessFile
{
    /// <summary>The versionId of the log entry these witness proofs apply to.</summary>
    public required string VersionId { get; init; }

    /// <summary>The witness proofs.</summary>
    public required IReadOnlyList<DataIntegrityProofValue> Proofs { get; init; }
}

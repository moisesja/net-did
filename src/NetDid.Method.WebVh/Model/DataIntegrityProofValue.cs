namespace NetDid.Method.WebVh.Model;

/// <summary>
/// Serializable data model for a Data Integrity Proof inside a did:webvh log entry or
/// witness file.
/// </summary>
/// <remarks>
/// For log entries this models a <b>controller proof</b>. A did:webvh entry requires at
/// least one controller proof, and one active update key is sufficient to authorize the
/// entry. If multiple controller proofs are supplied, every supplied proof must be
/// structurally valid, cryptographically valid (<c>type</c> <c>DataIntegrityProof</c>,
/// <c>cryptosuite</c> <c>eddsa-jcs-2022</c>, <c>proofPurpose</c> <c>assertionMethod</c>),
/// and signed by an active update key. Controller proofs do not use threshold semantics.
/// See issue #101.
/// </remarks>
public sealed class DataIntegrityProofValue
{
    /// <summary>Always "DataIntegrityProof".</summary>
    public required string Type { get; init; }

    /// <summary>The cryptosuite identifier (e.g., "eddsa-jcs-2022").</summary>
    public required string Cryptosuite { get; init; }

    /// <summary>The DID URL of the verification method (e.g., "did:key:z6Mkf...#z6Mkf...").</summary>
    public required string VerificationMethod { get; init; }

    /// <summary>
    /// ISO 8601 timestamp when the proof was created, or <c>null</c> when absent. The
    /// official did:webvh v1.0 log-entry schema marks <c>created</c> optional; proofs
    /// produced by NetDid always carry it.
    /// </summary>
    public string? Created { get; init; }

    /// <summary>The purpose of this proof (e.g., "assertionMethod").</summary>
    public required string ProofPurpose { get; init; }

    /// <summary>The multibase-encoded signature value.</summary>
    public required string ProofValue { get; init; }

    /// <summary>
    /// Verbatim wire JSON of the proof object as parsed from a DID log; <c>null</c> for
    /// programmatically constructed proofs. The <c>eddsa-jcs-2022</c> signature covers the
    /// whole proof configuration, so members this model does not surface (schema-permitted
    /// <c>id</c>/<c>expires</c> and extensions) must be preserved byte-for-byte both for
    /// signature verification and for re-serializing a fetched log during update/deactivate.
    /// Consumers can read unmodeled members from this JSON. The setter is internal because this
    /// is parser-populated fidelity data: a caller-supplied value (e.g. one containing an
    /// embedded newline) would corrupt JSON Lines re-serialization.
    /// </summary>
    public string? RawJson { get; internal init; }
}

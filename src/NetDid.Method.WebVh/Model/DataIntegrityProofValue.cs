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
/// A did:webvh controller proof is restricted to the members below; log entries whose proofs
/// carry other Data Integrity features (<c>id</c>, <c>expires</c>, <c>previousProof</c>,
/// <c>domain</c>, <c>challenge</c>, <c>@context</c>, or extensions) are rejected as
/// unsupported, because did:webvh does not define them for controller proofs and the resolver
/// does not evaluate them. See issue #101.
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
}

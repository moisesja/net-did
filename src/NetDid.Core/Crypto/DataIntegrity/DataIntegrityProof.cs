namespace NetDid.Core.Crypto.DataIntegrity;

/// <summary>
/// Represents a Data Integrity Proof per the W3C Data Integrity specification.
/// </summary>
public sealed record DataIntegrityProof
{
    public string Type { get; init; } = "DataIntegrityProof";

    /// <summary>The cryptosuite identifier (e.g., "eddsa-jcs-2022").</summary>
    public required string Cryptosuite { get; init; }

    /// <summary>The DID URL of the verification method used to create this proof (e.g., "did:key:z6Mkf...#z6Mkf...").</summary>
    public required string VerificationMethod { get; init; }

    /// <summary>Timestamp when this proof was created.</summary>
    public required DateTimeOffset Created { get; init; }

    /// <summary>The purpose of this proof (e.g., "assertionMethod", "authentication").</summary>
    public required string ProofPurpose { get; init; }

    /// <summary>The multibase-encoded signature value.</summary>
    public required string ProofValue { get; init; }
}

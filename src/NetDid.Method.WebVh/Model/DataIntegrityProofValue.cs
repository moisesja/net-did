namespace NetDid.Method.WebVh.Model;

/// <summary>
/// Serializable data model for a Data Integrity Proof inside a did:webvh log entry or
/// witness file.
/// </summary>
/// <remarks>
/// For log entries this models a <b>controller proof</b>. A did:webvh entry requires at
/// least one controller proof, and one active update key is sufficient to authorize the
/// entry. If multiple controller proofs are supplied, every supplied proof is processed by
/// DataProofsDotnet and must satisfy NetDid's controller policy: the applicable
/// <c>type</c>/<c>cryptosuite</c>/<c>proofPurpose</c>, a valid signature, a unique
/// <c>System.Uri</c>-compatible absolute-URI <c>id</c> without surrounding whitespace when present,
/// a non-dangling <c>previousProof</c> chain, an unexpired
/// <c>expires</c> relative to the entry's <c>versionTime</c>, and a signer in the active
/// <c>updateKeys</c>. Controller proofs do not use threshold semantics. The did:webvh v1.0
/// log-entry schema requires the
/// members below "at minimum" and leaves additional properties open. Unknown members are
/// preserved and signature-bound, but NetDid does not claim application semantics for every
/// extension. The proof-id policy is conservative and is not full WHATWG valid-URL-string
/// conformance. Array-valued <c>domain</c> is not supported by the pinned DataProofsDotnet model.
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
    /// programmatically constructed proofs. The <c>eddsa-jcs-2022</c> signature covers the whole
    /// proof configuration, including schema-permitted members this type does not surface
    /// (<c>id</c>, <c>expires</c>, and any extensions). This verbatim JSON is the input to Data
    /// Integrity verification, and re-emitting it preserves the proof object byte-for-byte when
    /// Update/Deactivate republish a fetched log. A single-object enclosing <c>proof</c> value is
    /// normalized to a one-element array. The setter is internal because it is
    /// parser-populated fidelity data. When <c>null</c>, serialization falls back to the modeled
    /// members above (the shape NetDid emits when it creates a proof).
    /// </summary>
    public string? RawJson { get; internal init; }
}

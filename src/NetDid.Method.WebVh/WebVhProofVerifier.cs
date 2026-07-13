using System.Text.Json;
using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using NetDid.Method.WebVh.Model;

namespace NetDid.Method.WebVh;

/// <summary>
/// Verifies <c>eddsa-jcs-2022</c> Data Integrity proofs on did:webvh log / witness entries via
/// DataProofsDotnet, and parses a <c>did:key</c> verificationMethod into its authorized
/// multibase key (enforcing the DID==fragment anti-spoof rule). Relocated here from the
/// removed <c>NetDid.Core.Crypto.DataIntegrity.DataIntegrityProofEngine</c>; the DID-method-aware
/// parser has no home in DataProofsDotnet (whose dependency direction forbids DID parsing).
/// </summary>
internal static class WebVhProofVerifier
{
    /// <summary>
    /// Verifies a single proof's signature over the entry JSON (with the <c>proof</c> removed).
    /// Returns the signer's multibase key when the signature is valid AND the verificationMethod
    /// is a well-formed <c>did:key</c> (anti-spoof enforced); otherwise <c>null</c>.
    /// </summary>
    public static string? VerifyAndExtractSigner(
        EddsaJcs2022Cryptosuite suite,
        string entryJsonWithoutProof,
        DataIntegrityProofValue proofValue)
    {
        var multibaseKey = ExtractDidKeyMultibase(proofValue.VerificationMethod);
        if (multibaseKey is null)
            return null;

        PublicKeyMaterial publicKey;
        try
        {
            publicKey = PublicKeyMaterial.FromMultikey(multibaseKey);
        }
        catch
        {
            return null;
        }

        // Reconstruct the proof exactly as written on the wire. When the proof was parsed
        // from a DID log, deserialize its verbatim wire JSON so members outside NetDid's
        // model (schema-permitted id/expires and extensions) are part of the recomputed
        // proof configuration — the eddsa-jcs-2022 signature covers them all (issue #101).
        // Otherwise (programmatically built proofs, witness entries) reconstruct from the
        // modeled fields; Created is passed verbatim (no DateTimeOffset round-trip) so the
        // hashed proof configuration is byte-identical to the one signed at creation time.
        DataIntegrityProof? proof;
        if (proofValue.RawJson is not null)
        {
            try
            {
                proof = JsonSerializer.Deserialize<DataIntegrityProof>(
                    proofValue.RawJson, DataProofsJsonOptions.Default);
            }
            catch
            {
                // Fail closed: a wire proof whose shape the Data Integrity model rejects
                // cannot be verified.
                return null;
            }

            if (proof is null)
                return null;

            // The modeled fields drive the caller's policy checks while the wire JSON
            // drives signature verification; a proof value whose two views disagree
            // (impossible via the parser, constructible programmatically) must never
            // verify under one view and be authorized under the other.
            if (!string.Equals(proof.Type, proofValue.Type, StringComparison.Ordinal)
                || !string.Equals(proof.Cryptosuite, proofValue.Cryptosuite, StringComparison.Ordinal)
                || !string.Equals(proof.VerificationMethod, proofValue.VerificationMethod, StringComparison.Ordinal)
                || !string.Equals(proof.Created, proofValue.Created, StringComparison.Ordinal)
                || !string.Equals(proof.ProofPurpose, proofValue.ProofPurpose, StringComparison.Ordinal)
                || !string.Equals(proof.ProofValue, proofValue.ProofValue, StringComparison.Ordinal))
            {
                return null;
            }
        }
        else
        {
            proof = new DataIntegrityProof
            {
                Type = proofValue.Type,
                Cryptosuite = proofValue.Cryptosuite,
                VerificationMethod = proofValue.VerificationMethod,
                Created = proofValue.Created,
                ProofPurpose = proofValue.ProofPurpose,
                ProofValue = proofValue.ProofValue,
            };
        }

        // Fail closed on anything unexpected (malformed entry JSON, or any error the
        // cryptosuite might surface) — a verification path must never throw for hostile input.
        try
        {
            using var document = JsonDocument.Parse(entryJsonWithoutProof);
            var result = suite.VerifyProof(document.RootElement, proof, publicKey);
            return result.Verified ? multibaseKey : null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>
    /// Extracts the signer's multibase key from a <c>did:key</c> verification method URL.
    /// Accepts <c>did:key:z6Mk...#z6Mk...</c> (DID and fragment MUST match) and
    /// <c>did:key:z6Mk...</c> (no fragment). Returns <c>null</c> on any malformed input or
    /// DID/fragment mismatch. Per the did:key spec, the fragment is the method-specific id;
    /// the exact-ordinal match defends against a <c>did:key:&lt;attacker&gt;#&lt;authorized&gt;</c>
    /// confusion attack.
    /// </summary>
    public static string? ExtractDidKeyMultibase(string verificationMethod)
    {
        if (string.IsNullOrEmpty(verificationMethod))
            return null;

        // Reject anything beyond the optional fragment (path, query, params).
        if (verificationMethod.IndexOfAny(['?', '/']) >= 0)
            return null;

        string didPart;
        string? fragment;
        var hashIndex = verificationMethod.IndexOf('#');
        if (hashIndex >= 0)
        {
            didPart = verificationMethod[..hashIndex];
            fragment = verificationMethod[(hashIndex + 1)..];
        }
        else
        {
            didPart = verificationMethod;
            fragment = null;
        }

        if (!didPart.StartsWith("did:key:"))
            return null;

        var multibaseKey = didPart["did:key:".Length..];
        if (string.IsNullOrEmpty(multibaseKey))
            return null;

        // If a fragment is present, it must equal the DID method-specific id.
        if (fragment is not null && !string.Equals(fragment, multibaseKey, StringComparison.Ordinal))
            return null;

        return multibaseKey;
    }
}

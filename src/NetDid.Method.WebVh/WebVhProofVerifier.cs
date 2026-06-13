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

        // Reconstruct the proof exactly as written on the wire. Created is passed verbatim
        // (no DateTimeOffset round-trip) so the hashed proof configuration is byte-identical
        // to the one signed at creation time.
        var proof = new DataIntegrityProof
        {
            Type = proofValue.Type,
            Cryptosuite = proofValue.Cryptosuite,
            VerificationMethod = proofValue.VerificationMethod,
            Created = proofValue.Created,
            ProofPurpose = proofValue.ProofPurpose,
            ProofValue = proofValue.ProofValue,
        };

        try
        {
            using var document = JsonDocument.Parse(entryJsonWithoutProof);
            var result = suite.VerifyProof(document.RootElement, proof, publicKey);
            return result.Verified ? multibaseKey : null;
        }
        catch (JsonException)
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

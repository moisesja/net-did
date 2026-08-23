namespace NetDid.Method.WebVh;

/// <summary>
/// Parses a <c>did:key</c> verificationMethod into its authorized multibase key (enforcing the
/// DID==fragment anti-spoof rule), shared by the controller-proof authorization path
/// (<see cref="WebVhUpdateKeyResolver"/>) and the witness path
/// (<see cref="WebVhWitnessKeyResolver"/>, <see cref="WitnessValidator"/>). Signature
/// verification itself is delegated to DataProofsDotnet's <c>DataIntegrityProofPipeline</c> for
/// both proof kinds; this type carries only DID-method-aware parsing, which has no home in
/// DataProofsDotnet (whose dependency direction forbids DID parsing).
/// </summary>
internal static class WebVhProofVerifier
{
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

    /// <summary>
    /// The strict form did:webvh v1.0 requires of a <b>witness</b> proof's verificationMethod:
    /// exactly <c>did:key:&lt;multibase&gt;#&lt;multibase&gt;</c> — the fragment is REQUIRED and
    /// must equal the DID's method-specific id. The bare-DID form tolerated by
    /// <see cref="ExtractDidKeyMultibase"/> (kept permissive because configured witness
    /// <c>id</c>s are bare DIDs) must not be counted for witness proofs: conforming resolvers
    /// discard it, so counting it would diverge in threshold arithmetic on the same file
    /// (issue #135 review round 2, finding 6).
    /// </summary>
    public static string? ExtractWitnessDidKeyMultibase(string verificationMethod)
    {
        if (string.IsNullOrEmpty(verificationMethod) || !verificationMethod.Contains('#'))
            return null;

        return ExtractDidKeyMultibase(verificationMethod);
    }
}

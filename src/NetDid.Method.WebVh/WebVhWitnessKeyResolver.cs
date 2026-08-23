using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using NetCrypto;

namespace NetDid.Method.WebVh;

/// <summary>
/// The did:webvh <b>witness</b> authorization adapter for the Data Integrity verification
/// pipeline. did:webvh v1.0 states a witness proof's <c>verificationMethod</c> is
/// "<c>did:key:&lt;multibase&gt;#&lt;multibase&gt;</c>" — the fragment form — so this resolver
/// requires it exactly (see <see cref="WebVhProofVerifier.ExtractWitnessDidKeyMultibase"/>).
/// The looser bare-DID form accepted by <see cref="WebVhProofVerifier.ExtractDidKeyMultibase"/>
/// must not be used here: an authorized witness signing with the bare form would be counted by
/// NetDid while every conforming resolver discards it, diverging on the same file (issue #135
/// review round 2, finding 6). The shared helper stays permissive because configured witness
/// <c>id</c>s are bare DIDs.
/// </summary>
/// <remarks>
/// This resolver deliberately carries no witness-membership policy. Whether a verified signer is
/// one of the configured witnesses depends on the specific entry's governing witness
/// configuration, and the same proof is examined for several governed entries during cumulative
/// coverage; keeping membership out of the resolver makes a proof's cryptographic outcome
/// policy-independent, which is what lets <see cref="WitnessValidator"/> memoize it. Membership
/// is enforced by the caller against the governing configuration before a candidate can count
/// toward threshold. An unconfigured proof is cryptographically processed only when a configured
/// candidate names it as a required <c>previousProof</c> dependency, in which case that work is
/// charged to the same resolution budget.
/// </remarks>
internal sealed class WebVhWitnessKeyResolver : IVerificationMethodResolver
{
    private static readonly IReadOnlySet<string> AssertionMethodOnly =
        new HashSet<string>(StringComparer.Ordinal) { "assertionMethod" };

    public static WebVhWitnessKeyResolver Instance { get; } = new();

    public Task<ResolvedVerificationMethod?> ResolveAsync(
        string verificationMethodUrl,
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Resolve(verificationMethodUrl));
    }

    private static ResolvedVerificationMethod? Resolve(string verificationMethodUrl)
    {
        // Strict witness form: fragment REQUIRED and equal to the DID's method-specific id.
        // "did:key:<attacker>#<authorized>" fails the equality check (anti-spoof).
        var multibaseKey = WebVhProofVerifier.ExtractWitnessDidKeyMultibase(verificationMethodUrl);
        if (multibaseKey is null)
            return null;

        PublicKeyMaterial publicKey;
        try
        {
            publicKey = PublicKeyMaterial.FromMultikey(multibaseKey);
        }
        catch (ArgumentException)
        {
            // FromMultikey's documented contract for every malformed input. Fail closed: the
            // proof is unauthorized rather than counted. Anything else is a bug and propagates.
            return null;
        }

        if (publicKey.KeyType != KeyType.Ed25519)
            return null;

        return new ResolvedVerificationMethod
        {
            Id = verificationMethodUrl,
            Controller = $"did:key:{multibaseKey}",
            PublicKey = publicKey,
            Relationships = AssertionMethodOnly,
            ControllerControlsMethod = true
        };
    }
}

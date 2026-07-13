using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using NetCrypto;

namespace NetDid.Method.WebVh;

/// <summary>
/// The did:webvh authorization adapter for the Data Integrity verification pipeline. A
/// controller proof's <c>verificationMethod</c> is authorized only when it is a well-formed
/// <c>did:key</c> (DID==fragment anti-spoof enforced), its Ed25519 multibase appears verbatim in
/// the entry's active <c>updateKeys</c>, and the proof is used for <c>assertionMethod</c>. The
/// pipeline verifies the signature against the returned key; this resolver supplies only the
/// key and the authorization metadata. See issue #101.
/// </summary>
internal sealed class WebVhUpdateKeyResolver : IVerificationMethodResolver
{
    private static readonly IReadOnlySet<string> AssertionMethodOnly =
        new HashSet<string>(StringComparer.Ordinal) { "assertionMethod" };

    private readonly HashSet<string> _authorizedKeys;

    /// <summary>
    /// Snapshots the active update keys once. An <see cref="IReadOnlyList{T}"/> implementation
    /// could otherwise present different contents across the pipeline's per-proof resolutions.
    /// </summary>
    public WebVhUpdateKeyResolver(IReadOnlyList<string> authorizedKeys)
    {
        _authorizedKeys = new HashSet<string>(authorizedKeys, StringComparer.Ordinal);
    }

    public Task<ResolvedVerificationMethod?> ResolveAsync(
        string verificationMethodUrl,
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Resolve(verificationMethodUrl));
    }

    private ResolvedVerificationMethod? Resolve(string verificationMethodUrl)
    {
        // Extract the signer's multibase from the did:key URL with the DID==fragment anti-spoof
        // check. A "did:key:<attacker>#<authorized>" method returns null here (mismatch).
        var multibaseKey = WebVhProofVerifier.ExtractDidKeyMultibase(verificationMethodUrl);
        if (multibaseKey is null)
            return null;

        // Authorize by exact-ordinal membership in the active updateKeys — no substring match.
        if (!_authorizedKeys.Contains(multibaseKey))
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

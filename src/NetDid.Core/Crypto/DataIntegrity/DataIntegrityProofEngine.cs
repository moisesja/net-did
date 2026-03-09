using NetCid;
using NetDid.Core.Crypto.Jcs;

namespace NetDid.Core.Crypto.DataIntegrity;

/// <summary>
/// Creates and verifies Data Integrity Proofs per the eddsa-jcs-2022 cryptosuite.
///
/// Algorithm:
/// 1. Take the document (JSON string) WITHOUT the proof field
/// 2. JCS-canonicalize it (RFC 8785)
/// 3. Sign the canonical UTF-8 bytes with Ed25519
/// 4. Encode signature as multibase (base58btc)
/// </summary>
public sealed class DataIntegrityProofEngine
{
    private readonly ICryptoProvider _crypto;

    public DataIntegrityProofEngine(ICryptoProvider crypto)
    {
        _crypto = crypto ?? throw new ArgumentNullException(nameof(crypto));
    }

    /// <summary>
    /// Create a Data Integrity Proof for the given JSON document.
    /// </summary>
    /// <param name="jsonWithoutProof">The JSON to sign (proof field must NOT be present).</param>
    /// <param name="signer">The ISigner (Ed25519) to sign with.</param>
    /// <param name="proofPurpose">e.g., "assertionMethod" or "authentication".</param>
    /// <param name="created">Timestamp for the proof.</param>
    /// <param name="ct">Cancellation token.</param>
    public async Task<DataIntegrityProof> CreateProofAsync(
        string jsonWithoutProof,
        ISigner signer,
        string proofPurpose,
        DateTimeOffset created,
        CancellationToken ct = default)
    {
        if (signer.KeyType != KeyType.Ed25519)
            throw new ArgumentException("eddsa-jcs-2022 requires an Ed25519 signer.", nameof(signer));

        // JCS-canonicalize and sign
        var canonicalBytes = JsonCanonicalization.CanonicalizeToUtf8(jsonWithoutProof);
        var signature = await signer.SignAsync(canonicalBytes, ct);

        // Multibase-encode the signature (base58btc)
        var proofValue = Multibase.Encode(signature, MultibaseEncoding.Base58Btc);

        // Build the verification method DID URL from the signer's public key
        var multibaseKey = signer.MultibasePublicKey;
        var verificationMethod = $"did:key:{multibaseKey}#{multibaseKey}";

        return new DataIntegrityProof
        {
            Cryptosuite = "eddsa-jcs-2022",
            VerificationMethod = verificationMethod,
            Created = created,
            ProofPurpose = proofPurpose,
            ProofValue = proofValue
        };
    }

    /// <summary>
    /// Verify a Data Integrity Proof against the given JSON document.
    /// </summary>
    /// <param name="jsonWithoutProof">The JSON that was signed (proof field removed).</param>
    /// <param name="proof">The proof to verify.</param>
    /// <returns>True if the signature is valid.</returns>
    public bool VerifyProof(string jsonWithoutProof, DataIntegrityProof proof)
    {
        if (proof.Cryptosuite != "eddsa-jcs-2022")
            return false;

        // Extract the public key from the verificationMethod (did:key DID URL)
        var publicKey = ExtractPublicKeyFromDidKey(proof.VerificationMethod);
        if (publicKey is null)
            return false;

        // Decode the signature from multibase
        byte[] signature;
        try
        {
            signature = Multibase.Decode(proof.ProofValue);
        }
        catch
        {
            return false;
        }

        // JCS-canonicalize and verify
        var canonicalBytes = JsonCanonicalization.CanonicalizeToUtf8(jsonWithoutProof);
        return _crypto.Verify(KeyType.Ed25519, publicKey, canonicalBytes, signature);
    }

    /// <summary>
    /// Extract the raw Ed25519 public key bytes from a did:key verification method URL.
    /// Accepts both "did:key:z6Mkf...#z6Mkf..." and "did:key:z6Mkf..." formats.
    /// </summary>
    public static byte[]? ExtractPublicKeyFromDidKey(string verificationMethod)
    {
        try
        {
            // Strip fragment if present: "did:key:z6Mkf...#z6Mkf..." -> "did:key:z6Mkf..."
            var didPart = verificationMethod.Contains('#')
                ? verificationMethod[..verificationMethod.IndexOf('#')]
                : verificationMethod;

            // Extract method-specific-id: "did:key:z6Mkf..." -> "z6Mkf..."
            if (!didPart.StartsWith("did:key:"))
                return null;

            var multibaseKey = didPart["did:key:".Length..];

            // Decode multibase -> multicodec-prefixed bytes -> raw key
            var decoded = Multibase.Decode(multibaseKey);
            var (codec, rawKey) = Multicodec.Decode(decoded);

            // Verify it's an Ed25519 key
            if (codec != Multicodec.Ed25519Pub)
                return null;

            return rawKey;
        }
        catch
        {
            return null;
        }
    }
}

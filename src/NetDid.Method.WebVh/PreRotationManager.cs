using System.Security.Cryptography;
using System.Text;
using NetCid;
using NetDid.Core.Exceptions;

namespace NetDid.Method.WebVh;

/// <summary>
/// Manages pre-rotation key commitments for did:webvh.
///
/// Pre-rotation commits to future update keys via hash:
///   nextKeyHash = multibase(base58btc, multihash(SHA-256, UTF8(multibasePublicKey)))
///
/// On update:
///   - Every current update key must match one of the previous committed nextKeyHashes
///   - nextKeyHashes must be explicit; a non-empty array continues and [] ends pre-rotation
/// </summary>
public static class PreRotationManager
{
    /// <summary>
    /// Compute the commitment hash for an update key (multibase-encoded public key).
    /// </summary>
    public static string ComputeKeyCommitment(string multibasePublicKey)
    {
        var keyBytes = Encoding.UTF8.GetBytes(multibasePublicKey);
        var hash = SHA256.HashData(keyBytes);
        var multihash = Multicodec.Prefix(0x12, hash);
        return Multibase.Encode(multihash, MultibaseEncoding.Base58Btc);
    }

    /// <summary>
    /// Validate that an update key matches one of the committed key hashes.
    /// Throws LogChainValidationException if validation fails.
    /// </summary>
    public static void ValidateKeyRotation(
        string signerMultibasePublicKey,
        IReadOnlyList<string> committedHashes,
        int versionNumber)
    {
        var commitment = ComputeKeyCommitment(signerMultibasePublicKey);

        if (!committedHashes.Contains(commitment))
        {
            throw new LogChainValidationException(
                versionNumber,
                $"Pre-rotation validation failed at version {versionNumber}: " +
                $"signing key commitment does not match any committed nextKeyHash.");
        }
    }
}

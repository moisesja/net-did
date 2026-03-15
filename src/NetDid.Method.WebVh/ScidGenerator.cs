using System.Security.Cryptography;
using NetCid;
using NetDid.Core.Crypto.Jcs;

namespace NetDid.Method.WebVh;

/// <summary>
/// Generates the Self-Certifying Identifier (SCID) from a genesis log entry.
///
/// Two-pass algorithm:
/// 1. Build genesis entry with {SCID} placeholders
/// 2. JCS-canonicalize the entry (with placeholders)
/// 3. SHA-256 hash the canonical bytes
/// 4. SCID = multibase(base58btc, multihash(0x12, hash))
/// 5. Replace all {SCID} placeholders with the computed SCID
/// </summary>
internal static class ScidGenerator
{
    /// <summary>
    /// The spec-level placeholder used in JSON strings for SCID computation.
    /// Contains characters ({}) that are invalid in DID syntax.
    /// </summary>
    public const string Placeholder = "{SCID}";

    /// <summary>
    /// A DID-syntax-safe placeholder used when constructing DidDocument objects.
    /// Must be replaced with <see cref="Placeholder"/> in serialized JSON before SCID computation.
    /// </summary>
    public const string SafePlaceholder = "SCIDplaceholder";

    /// <summary>
    /// Compute the SCID from a genesis entry that contains {SCID} placeholders.
    /// </summary>
    public static string ComputeScid(string genesisEntryJsonWithPlaceholders)
    {
        var canonicalBytes = JsonCanonicalization.CanonicalizeToUtf8(genesisEntryJsonWithPlaceholders);
        var hash = SHA256.HashData(canonicalBytes);
        var multihash = Multicodec.Prefix(0x12, hash); // 0x12 = sha2-256
        return Multibase.Encode(multihash, MultibaseEncoding.Base58Btc);
    }

    /// <summary>
    /// Replace all {SCID} placeholders in the JSON with the actual SCID value.
    /// Uses string replacement to catch all occurrences regardless of nesting depth.
    /// </summary>
    public static string ReplacePlaceholders(string json, string scid)
    {
        return json.Replace(Placeholder, scid);
    }

    /// <summary>
    /// Compute the entry hash for a log entry (without proof).
    /// entryHash = base58btc(multihash(JCS(entry), SHA-256))
    /// </summary>
    public static string ComputeEntryHash(string entryJsonWithoutProof)
    {
        var canonicalBytes = JsonCanonicalization.CanonicalizeToUtf8(entryJsonWithoutProof);
        var hash = SHA256.HashData(canonicalBytes);
        var multihash = Multicodec.Prefix(0x12, hash);
        return Multibase.Encode(multihash, MultibaseEncoding.Base58Btc);
    }
}

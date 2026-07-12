using System.Security.Cryptography;
using NetCid;

namespace NetDid.Method.WebVh;

/// <summary>
/// Encodes did:webvh v1.0 SHA-256 hashes as bare base58btc multihashes.
/// </summary>
internal static class WebVhHashEncoder
{
    /// <summary>
    /// Hash data with SHA-256, wrap the digest as a complete multihash, and encode the
    /// multihash as bare base58btc (without a multibase prefix).
    /// </summary>
    public static string EncodeSha256(ReadOnlySpan<byte> data)
    {
        var digest = SHA256.HashData(data);
        var multihash = Multihash.Encode(MultihashCode.Sha2_256, digest);
        return Multibase.Encode(
            multihash,
            MultibaseEncoding.Base58Btc,
            includePrefix: false);
    }
}

using NetDid.Core.Encoding;

namespace NetDid.Core.Crypto;

/// <summary>
/// Metadata about a stored key. Never contains private key material.
/// </summary>
public sealed record StoredKeyInfo
{
    public required string Alias { get; init; }
    public required KeyType KeyType { get; init; }
    public required byte[] PublicKey { get; init; }

    /// <summary>
    /// The multicodec-prefixed, multibase-encoded public key.
    /// </summary>
    public string MultibasePublicKey => MultibaseEncoder.Encode(MulticodecEncoder.Prefix(KeyType, PublicKey));
}

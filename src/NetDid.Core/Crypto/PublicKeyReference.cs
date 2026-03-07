using NetDid.Core.Encoding;

namespace NetDid.Core.Crypto;

/// <summary>
/// A public-key-only reference (no private key material).
/// Returned by <see cref="IKeyGenerator.FromPublicKey"/>.
/// </summary>
public sealed class PublicKeyReference
{
    public required KeyType KeyType { get; init; }
    public required byte[] PublicKey { get; init; }

    /// <summary>
    /// The multicodec-prefixed, multibase-encoded public key.
    /// </summary>
    public string MultibasePublicKey => MultibaseEncoder.Encode(MulticodecEncoder.Prefix(KeyType, PublicKey));
}

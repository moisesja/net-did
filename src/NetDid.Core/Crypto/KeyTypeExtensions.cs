using NetCid;

namespace NetDid.Core.Crypto;

/// <summary>
/// Maps <see cref="KeyType"/> to/from multicodec code values defined in <see cref="Multicodec"/>.
/// </summary>
public static class KeyTypeExtensions
{
    private static readonly Dictionary<KeyType, ulong> CodeByKeyType = new()
    {
        [KeyType.Ed25519] = Multicodec.Ed25519Pub,
        [KeyType.X25519] = Multicodec.X25519Pub,
        [KeyType.P256] = Multicodec.P256Pub,
        [KeyType.P384] = Multicodec.P384Pub,
        [KeyType.Secp256k1] = Multicodec.Secp256k1Pub,
        [KeyType.Bls12381G1] = Multicodec.Bls12381G1Pub,
        [KeyType.Bls12381G2] = Multicodec.Bls12381G2Pub,
    };

    private static readonly Dictionary<ulong, KeyType> KeyTypeByCode =
        CodeByKeyType.ToDictionary(kv => kv.Value, kv => kv.Key);

    /// <summary>Get the multicodec code for a key type.</summary>
    public static ulong GetMulticodec(this KeyType keyType) =>
        CodeByKeyType.TryGetValue(keyType, out var code)
            ? code
            : throw new ArgumentException($"Unsupported key type: {keyType}", nameof(keyType));

    /// <summary>Resolve a multicodec code to a <see cref="KeyType"/>.</summary>
    public static KeyType ToKeyType(ulong codec) =>
        KeyTypeByCode.TryGetValue(codec, out var keyType)
            ? keyType
            : throw new ArgumentException($"Unknown multicodec: 0x{codec:X}");
}

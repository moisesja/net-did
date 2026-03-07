using NetDid.Core.Crypto;

namespace NetDid.Core.Encoding;

/// <summary>
/// Multicodec varint prefix encoding/decoding for DID key types.
/// </summary>
public static class MulticodecEncoder
{
    // Multicodec codes (unsigned integers) for each key type.
    // These are encoded as unsigned varints when prefixed to key bytes.
    private static readonly Dictionary<KeyType, int> CodeByKeyType = new()
    {
        [KeyType.Ed25519] = 0xed,
        [KeyType.X25519] = 0xec,
        [KeyType.P256] = 0x1200,
        [KeyType.P384] = 0x1201,
        [KeyType.Secp256k1] = 0xe7,
        [KeyType.Bls12381G1] = 0xea,
        [KeyType.Bls12381G2] = 0xeb,
    };

    private static readonly Dictionary<int, KeyType> KeyTypeByCode =
        CodeByKeyType.ToDictionary(kv => kv.Value, kv => kv.Key);

    /// <summary>
    /// Prefix raw public key bytes with the multicodec varint for the given key type.
    /// </summary>
    public static byte[] Prefix(KeyType keyType, ReadOnlySpan<byte> rawKey)
    {
        if (!CodeByKeyType.TryGetValue(keyType, out var code))
            throw new ArgumentException($"Unsupported key type: {keyType}", nameof(keyType));

        var varint = EncodeVarint(code);
        var result = new byte[varint.Length + rawKey.Length];
        varint.CopyTo(result, 0);
        rawKey.CopyTo(result.AsSpan(varint.Length));
        return result;
    }

    /// <summary>
    /// Decode: strip the multicodec prefix and return (KeyType, rawKeyBytes).
    /// </summary>
    public static (KeyType KeyType, byte[] RawKey) Decode(ReadOnlySpan<byte> prefixedKey)
    {
        var (code, bytesRead) = DecodeVarint(prefixedKey);

        if (!KeyTypeByCode.TryGetValue(code, out var keyType))
            throw new ArgumentException($"Unknown multicodec prefix: 0x{code:X}");

        return (keyType, prefixedKey[bytesRead..].ToArray());
    }

    /// <summary>
    /// Encode an unsigned integer as a varint (protobuf-style unsigned LEB128).
    /// </summary>
    internal static byte[] EncodeVarint(int value)
    {
        if (value < 0)
            throw new ArgumentOutOfRangeException(nameof(value), "Value must be non-negative.");

        var bytes = new List<byte>();
        var v = (uint)value;
        do
        {
            var b = (byte)(v & 0x7F);
            v >>= 7;
            if (v > 0)
                b |= 0x80;
            bytes.Add(b);
        } while (v > 0);

        return bytes.ToArray();
    }

    /// <summary>
    /// Decode an unsigned varint from the start of a byte span.
    /// Returns (value, bytesConsumed).
    /// </summary>
    internal static (int Value, int BytesRead) DecodeVarint(ReadOnlySpan<byte> data)
    {
        int value = 0;
        int shift = 0;
        int bytesRead = 0;

        for (int i = 0; i < data.Length && i < 5; i++)
        {
            var b = data[i];
            value |= (b & 0x7F) << shift;
            shift += 7;
            bytesRead++;

            if ((b & 0x80) == 0)
                return (value, bytesRead);
        }

        throw new ArgumentException("Invalid varint encoding.");
    }
}

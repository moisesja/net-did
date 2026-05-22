using System.Buffers.Binary;
using System.Text;

namespace NetDid.Method.Ethr.Abi;

/// <summary>
/// Decodes Ethereum ABI-encoded return values and event data fields.
///
/// Supported types:
///   address  — 32-byte word, take last 20 bytes
///   uint256  — 32-byte big-endian, returned as ulong (upper bits ignored if > ulong.MaxValue)
///   bytes32  — 32-byte word, trailing null bytes trimmed for string interpretation
///   bytes    — dynamic: follows offset pointer, reads length prefix, then raw bytes
///
/// Event data layouts decoded:
///   DIDOwnerChanged    — owner(32) | previousChange(32)
///   DIDDelegateChanged — delegateType(32) | delegate(32) | validTo(32) | previousChange(32)
///   DIDAttributeChanged — name(32) | valueOffset(32) | validTo(32) | previousChange(32)
///                        | valueLength(32) | valueBytes(padded)
/// </summary>
public static class AbiDecoder
{
    // ── Primitive decoders ───────────────────────────────────────────────────

    /// <summary>Returns the last 20 bytes of a 32-byte ABI address word.</summary>
    public static byte[] DecodeAddress(ReadOnlySpan<byte> word32)
    {
        EnsureLength(word32, 32, nameof(word32));
        return word32[12..].ToArray();
    }

    /// <summary>Decodes a big-endian uint256 word as a ulong (upper 24 bytes must be zero for safety).</summary>
    public static ulong DecodeUint256(ReadOnlySpan<byte> word32)
    {
        EnsureLength(word32, 32, nameof(word32));
        return BinaryPrimitives.ReadUInt64BigEndian(word32[24..]);
    }

    /// <summary>Decodes a bytes32 word as an ASCII string with trailing null bytes trimmed.</summary>
    public static string DecodeBytes32AsString(ReadOnlySpan<byte> word32)
    {
        EnsureLength(word32, 32, nameof(word32));
        var trimmed = word32.TrimEnd((byte)0);
        return Encoding.ASCII.GetString(trimmed);
    }

    /// <summary>
    /// Decodes a dynamic ABI bytes value. The data span must start at offset 0 of the
    /// full event data, and <paramref name="offsetInData"/> gives the byte position of the
    /// ABI offset word that points to the length-prefixed payload.
    /// </summary>
    public static byte[] DecodeDynamicBytes(ReadOnlySpan<byte> data, int offsetInData)
    {
        // The word at offsetInData is the ABI offset pointer (uint256) relative to the
        // start of the data blob.  For event data decoded here the offset is absolute.
        var pointer = (int)BinaryPrimitives.ReadUInt64BigEndian(data[(offsetInData + 24)..][..8]);
        var length  = (int)BinaryPrimitives.ReadUInt64BigEndian(data[(pointer + 24)..][..8]);
        return data[(pointer + 32)..(pointer + 32 + length)].ToArray();
    }

    // ── Event data decoders ──────────────────────────────────────────────────

    /// <summary>
    /// Decodes DIDOwnerChanged event data (2 × 32-byte words).
    /// Returns (owner20bytes, previousChangeBlock).
    /// </summary>
    public static (byte[] Owner, ulong PreviousChange) DecodeOwnerChangedData(ReadOnlySpan<byte> data)
    {
        EnsureMinLength(data, 64, "DIDOwnerChanged data");
        return (DecodeAddress(data[..32]), DecodeUint256(data[32..64]));
    }

    /// <summary>
    /// Decodes DIDDelegateChanged event data (4 × 32-byte words).
    /// Returns (delegateType, delegate20bytes, validTo, previousChange).
    /// </summary>
    public static (string DelegateType, byte[] Delegate, ulong ValidTo, ulong PreviousChange)
        DecodeDelegateChangedData(ReadOnlySpan<byte> data)
    {
        EnsureMinLength(data, 128, "DIDDelegateChanged data");
        return (
            DecodeBytes32AsString(data[..32]),
            DecodeAddress(data[32..64]),
            DecodeUint256(data[64..96]),
            DecodeUint256(data[96..128]));
    }

    /// <summary>
    /// Decodes DIDAttributeChanged event data.
    /// Layout: name(32) | valueOffset(32) | validTo(32) | previousChange(32) | [dynamic bytes payload]
    /// Returns (name, valueBytes, validTo, previousChange).
    /// </summary>
    public static (string Name, byte[] Value, ulong ValidTo, ulong PreviousChange)
        DecodeAttributeChangedData(ReadOnlySpan<byte> data)
    {
        EnsureMinLength(data, 128, "DIDAttributeChanged data");
        var name     = DecodeBytes32AsString(data[..32]);
        // word at offset 32 is the ABI offset pointer for the dynamic `bytes value`
        var value    = DecodeDynamicBytes(data, 32);
        var validTo  = DecodeUint256(data[64..96]);
        var prev     = DecodeUint256(data[96..128]);
        return (name, value, validTo, prev);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static void EnsureLength(ReadOnlySpan<byte> span, int expected, string name)
    {
        if (span.Length < expected)
            throw new ArgumentException($"{name} must be at least {expected} bytes, got {span.Length}.");
    }

    private static void EnsureMinLength(ReadOnlySpan<byte> span, int min, string context)
    {
        if (span.Length < min)
            throw new ArgumentException($"{context} must be at least {min} bytes, got {span.Length}.");
    }
}

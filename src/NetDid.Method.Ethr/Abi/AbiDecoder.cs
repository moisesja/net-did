using System.Buffers.Binary;
using System.Text;

namespace NetDid.Method.Ethr.Abi;

/// <summary>
/// Decodes Ethereum ABI-encoded return values and event data fields.
///
/// Supported types:
///   address  — 32-byte word, take last 20 bytes
///   uint256  — 32-byte big-endian, returned as ulong; throws if upper 24 bytes are non-zero
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
        for (var i = 0; i < 12; i++)
        {
            if (word32[i] != 0)
                throw new ArgumentException(
                    $"ABI address word has non-zero padding at byte {i}.",
                    nameof(word32));
        }
        return word32[12..].ToArray();
    }

    /// <summary>
    /// Decodes a big-endian uint256 word as a <see cref="ulong"/>.
    /// Throws <see cref="ArgumentException"/> if the upper 24 bytes are non-zero,
    /// which would indicate a value larger than <see cref="ulong.MaxValue"/>.
    /// All uint256 fields used by ERC-1056 (block numbers, validTo timestamps,
    /// previousChange pointers) fit comfortably within ulong range in practice;
    /// a non-zero upper word signals a malformed or adversarial RPC response.
    /// </summary>
    public static ulong DecodeUint256(ReadOnlySpan<byte> word32)
    {
        EnsureLength(word32, 32, nameof(word32));
        // Guard: if any of the upper 24 bytes are non-zero the value exceeds ulong.MaxValue.
        // Silently truncating could cause an expired validTo to appear valid (security risk).
        for (int i = 0; i < 24; i++)
        {
            if (word32[i] != 0)
                throw new ArgumentException(
                    $"uint256 value at byte {i} has a non-zero upper byte (0x{word32[i]:X2}). " +
                    "The value exceeds ulong.MaxValue — this indicates a malformed or " +
                    "adversarial RPC response.",
                    nameof(word32));
        }
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
    ///
    /// All bounds and overflow conditions are validated before any slice or allocation;
    /// malformed payloads from untrusted RPC endpoints throw <see cref="ArgumentException"/>.
    /// </summary>
    public static byte[] DecodeDynamicBytes(ReadOnlySpan<byte> data, int offsetInData)
    {
        // 1. Validate offsetInData: we need 32 bytes for the ABI offset word.
        if (offsetInData < 0 || offsetInData + 32 > data.Length)
            throw new ArgumentException(
                $"offset {offsetInData} is out of range: need offset+32={offsetInData + 32} bytes " +
                $"but data is only {data.Length} bytes.",
                nameof(offsetInData));

        // 2. Decode the FULL uint256 pointer before narrowing it. Reading only the low
        // 8 bytes would silently accept malformed words with non-zero high bytes.
        var pointerRaw = DecodeUint256(data.Slice(offsetInData, 32));
        if (pointerRaw > (ulong)int.MaxValue)
            throw new ArgumentException(
                $"ABI pointer value {pointerRaw} overflows int.MaxValue. Payload is malformed.",
                nameof(data));
        var pointer = (int)pointerRaw;

        // 3. Validate pointer: need pointer + 32 bytes for the length word.
        if (pointer > data.Length - 32)
            throw new ArgumentException(
                $"ABI pointer {pointer} is out of range: need pointer+32={pointer + 32} bytes " +
                $"but data is only {data.Length} bytes.",
                nameof(data));

        // 4. Decode the FULL uint256 length before narrowing it.
        var lengthRaw = DecodeUint256(data.Slice(pointer, 32));
        if (lengthRaw > (ulong)int.MaxValue)
            throw new ArgumentException(
                $"ABI length value {lengthRaw} overflows int.MaxValue. Payload is malformed.",
                nameof(data));
        var length = (int)lengthRaw;

        // 5. Validate the payload slice fits within the buffer.
        var payloadStart = pointer + 32;
        if (length > data.Length - payloadStart)
            throw new ArgumentException(
                $"ABI length {length} at pointer {pointer} exceeds data bounds: " +
                $"need {(long)payloadStart + length} bytes but data is only {data.Length} bytes.",
                nameof(data));

        return data[payloadStart..(payloadStart + length)].ToArray();
    }

    // ── Event data decoders ──────────────────────────────────────────────────

    /// <summary>
    /// Decodes DIDOwnerChanged event data (2 × 32-byte words).
    /// Returns (owner20bytes, previousChangeBlock).
    /// </summary>
    public static (byte[] Owner, ulong PreviousChange) DecodeOwnerChangedData(ReadOnlySpan<byte> data)
    {
        EnsureExactLength(data, 64, "DIDOwnerChanged data");
        return (DecodeAddress(data[..32]), DecodeUint256(data[32..64]));
    }

    /// <summary>
    /// Decodes DIDDelegateChanged event data (4 × 32-byte words).
    /// Returns (delegateType, delegate20bytes, validTo, previousChange).
    /// </summary>
    public static (string DelegateType, byte[] Delegate, ulong ValidTo, ulong PreviousChange)
        DecodeDelegateChangedData(ReadOnlySpan<byte> data)
    {
        EnsureExactLength(data, 128, "DIDDelegateChanged data");
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
        // This event has a four-word static head, so the one dynamic value must begin
        // canonically at byte 128. A pointer into the head can reinterpret authority
        // metadata as a payload length and must not be accepted.
        var pointer = DecodeUint256(data[32..64]);
        if (pointer != 128)
            throw new ArgumentException(
                $"DIDAttributeChanged value offset must be 128, got {pointer}.",
                nameof(data));

        EnsureMinLength(data, 160, "DIDAttributeChanged data");
        var length = DecodeUint256(data[128..160]);
        if (length > int.MaxValue)
            throw new ArgumentException(
                $"DIDAttributeChanged value length {length} exceeds int.MaxValue.",
                nameof(data));
        var paddedLength = ((length + 31UL) / 32UL) * 32UL;
        var expectedLength = 160UL + paddedLength;
        if ((ulong)data.Length != expectedLength)
            throw new ArgumentException(
                $"DIDAttributeChanged data must be exactly {expectedLength} bytes for a " +
                $"{length}-byte value, got {data.Length}.",
                nameof(data));

        var paddingStart = 160 + (int)length;
        for (var i = paddingStart; i < data.Length; i++)
        {
            if (data[i] != 0)
                throw new ArgumentException(
                    $"DIDAttributeChanged value has non-zero ABI padding at byte {i}.",
                    nameof(data));
        }

        var value    = data.Slice(160, (int)length).ToArray();
        var validTo  = DecodeUint256(data[64..96]);
        var prev     = DecodeUint256(data[96..128]);
        return (name, value, validTo, prev);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static void EnsureLength(ReadOnlySpan<byte> span, int expected, string name)
    {
        if (span.Length != expected)
            throw new ArgumentException($"{name} must be exactly {expected} bytes, got {span.Length}.");
    }

    private static void EnsureMinLength(ReadOnlySpan<byte> span, int min, string context)
    {
        if (span.Length < min)
            throw new ArgumentException($"{context} must be at least {min} bytes, got {span.Length}.");
    }

    private static void EnsureExactLength(ReadOnlySpan<byte> span, int expected, string context)
    {
        if (span.Length != expected)
            throw new ArgumentException(
                $"{context} must be exactly {expected} bytes, got {span.Length}.");
    }
}

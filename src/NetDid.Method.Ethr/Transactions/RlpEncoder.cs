using System.Numerics;

namespace NetDid.Method.Ethr.Transactions;

/// <summary>
/// Minimal RLP (Recursive Length Prefix) encoder — exactly the subset Ethereum
/// legacy (type-0) transactions need: byte strings, unsigned integers in minimal
/// big-endian form, and one flat list.
///
/// Rules (Ethereum Yellow Paper, appendix B):
///   • single byte &lt; 0x80        → the byte itself
///   • 0–55-byte string           → (0x80 + length) ‖ bytes
///   • &gt;55-byte string          → (0xb7 + lengthOfLength) ‖ length ‖ bytes
///   • 0–55-byte list payload     → (0xc0 + length) ‖ payload
///   • &gt;55-byte list payload   → (0xf7 + lengthOfLength) ‖ length ‖ payload
///   • integers: minimal big-endian, no leading zero bytes; zero → empty string (0x80)
/// </summary>
internal static class RlpEncoder
{
    /// <summary>Encodes a byte string.</summary>
    public static byte[] EncodeBytes(ReadOnlySpan<byte> value)
    {
        if (value.Length == 1 && value[0] < 0x80)
            return [value[0]];

        var prefix = EncodeLength(value.Length, shortOffset: 0x80);
        var result = new byte[prefix.Length + value.Length];
        prefix.CopyTo(result, 0);
        value.CopyTo(result.AsSpan(prefix.Length));
        return result;
    }

    /// <summary>
    /// Encodes an unsigned integer as its minimal big-endian byte string
    /// (no leading zeros; zero encodes as the empty string, 0x80).
    /// </summary>
    public static byte[] EncodeUnsigned(BigInteger value)
    {
        if (value.Sign < 0)
            throw new ArgumentOutOfRangeException(
                nameof(value), value, "RLP integers must be non-negative.");
        return EncodeBytes(ToMinimalBigEndian(value));
    }

    /// <summary>Encodes an unsigned integer (ulong convenience overload).</summary>
    public static byte[] EncodeUnsigned(ulong value)
        => EncodeUnsigned((BigInteger)value);

    /// <summary>Encodes a list of already-RLP-encoded items.</summary>
    public static byte[] EncodeList(IReadOnlyList<byte[]> encodedItems)
    {
        var payloadLength = 0;
        foreach (var item in encodedItems)
            payloadLength += item.Length;

        var prefix = EncodeLength(payloadLength, shortOffset: 0xc0);
        var result = new byte[prefix.Length + payloadLength];
        prefix.CopyTo(result, 0);
        var offset = prefix.Length;
        foreach (var item in encodedItems)
        {
            item.CopyTo(result, offset);
            offset += item.Length;
        }
        return result;
    }

    /// <summary>Minimal big-endian representation of a non-negative integer; zero → empty.</summary>
    public static byte[] ToMinimalBigEndian(BigInteger value)
    {
        if (value.Sign < 0)
            throw new ArgumentOutOfRangeException(
                nameof(value), value, "Expected a non-negative integer.");
        return value.IsZero ? [] : value.ToByteArray(isUnsigned: true, isBigEndian: true);
    }

    private static byte[] EncodeLength(int length, byte shortOffset)
    {
        if (length <= 55)
            return [(byte)(shortOffset + length)];

        // Long form: offset + 55 + number-of-length-bytes, then the length big-endian.
        var lengthBytes = ToMinimalBigEndian(length);
        var prefix = new byte[1 + lengthBytes.Length];
        prefix[0] = (byte)(shortOffset + 55 + lengthBytes.Length);
        lengthBytes.CopyTo(prefix, 1);
        return prefix;
    }
}

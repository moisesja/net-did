namespace NetDid.Method.Ethr.Emulator;

/// <summary>A decoded RLP item: either a byte string or a list of items.</summary>
public sealed record RlpItem
{
    public byte[]? Bytes { get; init; }
    public IReadOnlyList<RlpItem>? Items { get; init; }

    public bool IsList => Items is not null;

    public byte[] AsBytes()
        => Bytes ?? throw new FormatException("Expected an RLP byte string, found a list.");

    public IReadOnlyList<RlpItem> AsList()
        => Items ?? throw new FormatException("Expected an RLP list, found a byte string.");
}

/// <summary>
/// Strict, canonical RLP decoder for the emulator — deliberately implemented
/// independently of the library's encoder so decoding is not writer/reader parity.
///
/// Canonicality is enforced the way real nodes enforce it for transactions:
///   • a single byte &lt; 0x80 must be encoded as itself (0x81xx for xx &lt; 0x80 is rejected)
///   • long-form lengths must not have leading zero bytes and must exceed 55
///   • the input must be exactly one item with no trailing bytes
/// </summary>
public static class RlpDecoder
{
    /// <summary>Decodes exactly one RLP item, rejecting trailing bytes.</summary>
    public static RlpItem Decode(ReadOnlySpan<byte> input)
    {
        var (item, consumed) = DecodeItem(input);
        if (consumed != input.Length)
            throw new FormatException(
                $"RLP input has {input.Length - consumed} trailing byte(s) after the first item.");
        return item;
    }

    private static (RlpItem Item, int Consumed) DecodeItem(ReadOnlySpan<byte> input)
    {
        if (input.Length == 0)
            throw new FormatException("RLP input is empty.");

        var prefix = input[0];

        // Single byte < 0x80: the byte is its own encoding.
        if (prefix < 0x80)
            return (new RlpItem { Bytes = [prefix] }, 1);

        // Short string: 0x80 + length (0..55).
        if (prefix <= 0xb7)
        {
            var length = prefix - 0x80;
            RequireAvailable(input, 1 + length);
            var payload = input.Slice(1, length).ToArray();
            if (length == 1 && payload[0] < 0x80)
                throw new FormatException(
                    "Non-canonical RLP: a single byte below 0x80 must be encoded as itself.");
            return (new RlpItem { Bytes = payload }, 1 + length);
        }

        // Long string: 0xb7 + lengthOfLength, then the big-endian length.
        if (prefix <= 0xbf)
        {
            var (length, headerSize) = ReadLongLength(input, prefix, baseOffset: 0xb7);
            RequireAvailable(input, headerSize + length);
            return (new RlpItem { Bytes = input.Slice(headerSize, length).ToArray() },
                    headerSize + length);
        }

        // Short list: 0xc0 + payload length (0..55).
        if (prefix <= 0xf7)
        {
            var payloadLength = prefix - 0xc0;
            RequireAvailable(input, 1 + payloadLength);
            return (DecodeListPayload(input.Slice(1, payloadLength)), 1 + payloadLength);
        }

        // Long list: 0xf7 + lengthOfLength.
        {
            var (payloadLength, headerSize) = ReadLongLength(input, prefix, baseOffset: 0xf7);
            RequireAvailable(input, headerSize + payloadLength);
            return (DecodeListPayload(input.Slice(headerSize, payloadLength)),
                    headerSize + payloadLength);
        }
    }

    private static RlpItem DecodeListPayload(ReadOnlySpan<byte> payload)
    {
        var items = new List<RlpItem>();
        var offset = 0;
        while (offset < payload.Length)
        {
            var (item, consumed) = DecodeItem(payload[offset..]);
            items.Add(item);
            offset += consumed;
        }
        return new RlpItem { Items = items };
    }

    private static (int Length, int HeaderSize) ReadLongLength(
        ReadOnlySpan<byte> input, byte prefix, byte baseOffset)
    {
        var lengthOfLength = prefix - baseOffset;
        RequireAvailable(input, 1 + lengthOfLength);
        var lengthBytes = input.Slice(1, lengthOfLength);

        if (lengthBytes[0] == 0)
            throw new FormatException("Non-canonical RLP: length has a leading zero byte.");
        if (lengthOfLength > 4)
            throw new FormatException("RLP length exceeds supported input size.");

        var length = 0;
        foreach (var b in lengthBytes)
            length = (length << 8) | b;

        if (length <= 55)
            throw new FormatException(
                "Non-canonical RLP: a payload of 55 bytes or fewer must use the short form.");

        return (length, 1 + lengthOfLength);
    }

    private static void RequireAvailable(ReadOnlySpan<byte> input, int needed)
    {
        if (input.Length < needed)
            throw new FormatException(
                $"Truncated RLP: need {needed} bytes, have {input.Length}.");
    }
}

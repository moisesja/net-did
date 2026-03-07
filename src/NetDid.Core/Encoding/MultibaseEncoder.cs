namespace NetDid.Core.Encoding;

/// <summary>
/// Multibase encoding/decoding per the Multiformats specification.
/// </summary>
public static class MultibaseEncoder
{
    /// <summary>
    /// Encode bytes as a multibase string (default: base58btc, prefix 'z').
    /// </summary>
    public static string Encode(ReadOnlySpan<byte> data, MultibaseEncoding encoding = MultibaseEncoding.Base58Btc)
    {
        return encoding switch
        {
            MultibaseEncoding.Base58Btc => "z" + Base58Btc.Encode(data),
            MultibaseEncoding.Base64Url => "u" + Base64UrlNoPadding.Encode(data),
            MultibaseEncoding.Base32Lower => "b" + Base32Lower.Encode(data),
            _ => throw new ArgumentOutOfRangeException(nameof(encoding), encoding, "Unsupported encoding.")
        };
    }

    /// <summary>
    /// Decode a multibase string back to raw bytes.
    /// </summary>
    public static byte[] Decode(string multibaseString)
    {
        if (string.IsNullOrEmpty(multibaseString))
            throw new ArgumentException("Multibase string cannot be null or empty.", nameof(multibaseString));

        var prefix = multibaseString[0];
        var encoded = multibaseString[1..];

        return prefix switch
        {
            'z' => Base58Btc.Decode(encoded),
            'u' => Base64UrlNoPadding.Decode(encoded),
            'b' => Base32Lower.Decode(encoded),
            _ => throw new ArgumentException($"Unsupported multibase prefix: '{prefix}'", nameof(multibaseString))
        };
    }
}

/// <summary>
/// Base32 lowercase encoding (RFC 4648, no padding).
/// </summary>
internal static class Base32Lower
{
    private const string Alphabet = "abcdefghijklmnopqrstuvwxyz234567";

    public static string Encode(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return string.Empty;

        var result = new char[(data.Length * 8 + 4) / 5];
        int bits = 0;
        int buffer = 0;
        int index = 0;

        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bits += 8;

            while (bits >= 5)
            {
                bits -= 5;
                result[index++] = Alphabet[(buffer >> bits) & 0x1F];
            }
        }

        if (bits > 0)
            result[index++] = Alphabet[(buffer << (5 - bits)) & 0x1F];

        return new string(result, 0, index);
    }

    public static byte[] Decode(string encoded)
    {
        if (string.IsNullOrEmpty(encoded)) return [];

        var result = new byte[encoded.Length * 5 / 8];
        int bits = 0;
        int buffer = 0;
        int index = 0;

        foreach (var c in encoded)
        {
            int value = c switch
            {
                >= 'a' and <= 'z' => c - 'a',
                >= '2' and <= '7' => c - '2' + 26,
                _ => throw new ArgumentException($"Invalid base32 character: '{c}'")
            };

            buffer = (buffer << 5) | value;
            bits += 5;

            if (bits >= 8)
            {
                bits -= 8;
                result[index++] = (byte)((buffer >> bits) & 0xFF);
            }
        }

        return result[..index];
    }
}

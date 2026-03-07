using SimpleBase;

namespace NetDid.Core.Encoding;

/// <summary>
/// Base58 Bitcoin encoding/decoding.
/// </summary>
public static class Base58Btc
{
    public static string Encode(ReadOnlySpan<byte> data)
        => Base58.Bitcoin.Encode(data);

    public static byte[] Decode(string encoded)
        => Base58.Bitcoin.Decode(encoded).ToArray();
}

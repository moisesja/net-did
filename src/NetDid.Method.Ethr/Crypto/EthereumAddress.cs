using System.Text;
using NetCrypto;

namespace NetDid.Method.Ethr.Crypto;

/// <summary>
/// Derives Ethereum addresses from secp256k1 public keys and encodes them
/// using EIP-55 mixed-case checksum encoding.
/// </summary>
public static class EthereumAddress
{
    /// <summary>
    /// Derives a checksummed Ethereum address (EIP-55) from a 33-byte
    /// compressed secp256k1 public key.
    /// </summary>
    public static string FromCompressedPublicKey(byte[] compressed33)
    {
        ArgumentNullException.ThrowIfNull(compressed33);
        if (compressed33.Length != 33)
            throw new ArgumentException("Expected 33-byte compressed public key.", nameof(compressed33));

        // Uncompress via NetCrypto (crypto-dotnet#19): 65-byte [04 | X(32) | Y(32)].
        // Throws ArgumentException if the key is not a valid point on the curve.
        var uncompressed = KeyType.Secp256k1.ToUncompressed(compressed33);

        // Keccak-256 of the 64-byte public key body (skip 0x04 prefix)
        var hash = Keccak256.Hash(uncompressed.AsSpan(1));

        // Take last 20 bytes as address
        var address20 = hash[^20..];
        return ToChecksumAddress(address20);
    }

    /// <summary>
    /// Encodes a 20-byte Ethereum address as an EIP-55 checksummed hex string
    /// with "0x" prefix.
    /// </summary>
    public static string ToChecksumAddress(byte[] address20)
    {
        ArgumentNullException.ThrowIfNull(address20);
        if (address20.Length != 20)
            throw new ArgumentException("Expected 20-byte address.", nameof(address20));

        var lowercaseHex = Convert.ToHexString(address20).ToLowerInvariant();

        // Keccak-256 of the lowercase hex string (ASCII bytes)
        var hash = Keccak256.Hash(Encoding.ASCII.GetBytes(lowercaseHex));

        // For each char at position i: uppercase if the corresponding nibble of hash >= 8
        var result = new char[lowercaseHex.Length];
        for (int i = 0; i < lowercaseHex.Length; i++)
        {
            var c = lowercaseHex[i];
            if (char.IsLetter(c))
            {
                // nibble index within hash bytes: high nibble = i/2*8+4..7, low nibble = i/2*8+0..3
                var nibble = (i % 2 == 0)
                    ? (hash[i / 2] >> 4) & 0xF
                    : hash[i / 2] & 0xF;
                result[i] = nibble >= 8 ? char.ToUpperInvariant(c) : c;
            }
            else
            {
                result[i] = c;
            }
        }

        return "0x" + new string(result);
    }
}

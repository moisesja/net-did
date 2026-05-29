using acryptohashnet;
using System.Text;

namespace NetDid.Method.Ethr.Abi;

/// <summary>
/// Encodes calldata for the two read-only ERC-1056 eth_call methods:
///   changed(address identity)        → selector 0x4b0bebeb
///   identityOwner(address identity)  → selector 0x8733d4e8
///
/// Selectors are computed once at init via Keccak-256 of the canonical signature.
/// </summary>
public static class AbiEncoder
{
    // Cached function selectors (first 4 bytes of keccak256 of canonical signature)
    public static readonly byte[] ChangedSelector;
    public static readonly byte[] IdentityOwnerSelector;

    static AbiEncoder()
    {
        ChangedSelector       = ComputeSelector("changed(address)");
        IdentityOwnerSelector = ComputeSelector("identityOwner(address)");
    }

    private static byte[] ComputeSelector(string signature)
    {
        var keccak = new Keccak256();
        var hash = keccak.ComputeHash(Encoding.ASCII.GetBytes(signature));
        return hash[..4];
    }

    /// <summary>Zero-pads a 20-byte Ethereum address to a 32-byte ABI word.</summary>
    public static byte[] EncodeAddress(byte[] address20)
    {
        if (address20.Length != 20)
            throw new ArgumentException("Expected 20-byte address.", nameof(address20));
        var word = new byte[32];
        address20.CopyTo(word, 12);
        return word;
    }

    /// <summary>Concatenates a 4-byte selector with a 32-byte ABI-encoded address argument.</summary>
    public static byte[] BuildCalldata(byte[] selector4, byte[] address20)
    {
        var result = new byte[4 + 32];
        selector4.CopyTo(result, 0);
        EncodeAddress(address20).CopyTo(result, 4);
        return result;
    }

    /// <summary>Returns hex calldata string (0x-prefixed) for changed(address).</summary>
    public static string ChangedCalldata(byte[] address20)
        => "0x" + Convert.ToHexString(BuildCalldata(ChangedSelector, address20)).ToLowerInvariant();

    /// <summary>Returns hex calldata string (0x-prefixed) for identityOwner(address).</summary>
    public static string IdentityOwnerCalldata(byte[] address20)
        => "0x" + Convert.ToHexString(BuildCalldata(IdentityOwnerSelector, address20)).ToLowerInvariant();
}

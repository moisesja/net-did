using acryptohashnet;
using System.Text;

namespace NetDid.Method.Ethr.Erc1056;

/// <summary>
/// Keccak-256 topic hashes for the three ERC-1056 events.
/// Computed once at startup and cached.
/// </summary>
public static class Erc1056Topics
{
    public static readonly string DIDOwnerChanged =
        ComputeTopic("DIDOwnerChanged(address,address,uint256)");

    public static readonly string DIDDelegateChanged =
        ComputeTopic("DIDDelegateChanged(address,bytes32,address,uint256,uint256)");

    public static readonly string DIDAttributeChanged =
        ComputeTopic("DIDAttributeChanged(address,bytes32,bytes,uint256,uint256)");

    private static string ComputeTopic(string signature)
    {
        var keccak = new Keccak256();
        var hash = keccak.ComputeHash(Encoding.ASCII.GetBytes(signature));
        return "0x" + Convert.ToHexString(hash).ToLowerInvariant();
    }
}

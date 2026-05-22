using NetDid.Method.Ethr.Abi;

namespace NetDid.Method.Ethr.Erc1056;

/// <summary>
/// Static helpers that produce hex calldata strings for ERC-1056 read-only calls.
/// </summary>
public static class Erc1056Calls
{
    /// <summary>Returns 0x-prefixed calldata for changed(address).</summary>
    public static string Changed(string checksumAddress)
        => AbiEncoder.ChangedCalldata(ParseAddress(checksumAddress));

    /// <summary>Returns 0x-prefixed calldata for identityOwner(address).</summary>
    public static string IdentityOwner(string checksumAddress)
        => AbiEncoder.IdentityOwnerCalldata(ParseAddress(checksumAddress));

    private static byte[] ParseAddress(string address)
    {
        var hex = address.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? address[2..] : address;
        return Convert.FromHexString(hex);
    }
}

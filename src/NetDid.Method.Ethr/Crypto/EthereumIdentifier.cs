namespace NetDid.Method.Ethr.Crypto;

/// <summary>
/// Parsed components of the method-specific identifier portion of a did:ethr DID.
///
/// Format:  [network ":"] (ethereum-address | compressed-public-key)
///   ethereum-address   = "0x" 40*HEXDIG    (20 bytes)
///   public-key-hex     = "0x" 66*HEXDIG    (33 bytes compressed)
///   network            = "mainnet" | "goerli" | "sepolia" | "polygon" | "0x" *HEXDIG
///
/// When no network is specified the resolved network is "mainnet".
/// </summary>
public sealed record EthrIdentifier(
    string Network,
    string IdentityAddress,
    bool IsPublicKey,
    byte[]? PublicKeyBytes)
{
    private static readonly Dictionary<string, string> NamedNetworkChainIds = new(StringComparer.OrdinalIgnoreCase)
    {
        ["mainnet"]  = "1",
        ["goerli"]   = "5",
        ["sepolia"]  = "11155111",
        ["polygon"]  = "137",
    };

    /// <summary>
    /// Returns the numeric chain-ID string (e.g. "1", "11155111") for use in CAIP-10 blockchainAccountId.
    /// Hex chain IDs (0x…) are converted to decimal.
    /// </summary>
    public string ChainId =>
        NamedNetworkChainIds.TryGetValue(Network, out var id)
            ? id
            : Network.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                ? Convert.ToUInt64(Network[2..], 16).ToString()
                : Network;

    /// <summary>
    /// Parses the method-specific identifier from a full did:ethr DID string.
    /// Throws <see cref="ArgumentException"/> if the format is invalid.
    /// </summary>
    public static EthrIdentifier Parse(string did)
    {
        ArgumentNullException.ThrowIfNull(did);

        // Strip "did:ethr:" prefix
        const string prefix = "did:ethr:";
        if (!did.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException($"Not a did:ethr DID: {did}", nameof(did));

        var rest = did[prefix.Length..];
        return ParseMethodSpecificId(rest);
    }

    /// <summary>
    /// Parses the method-specific-id portion (everything after "did:ethr:").
    /// </summary>
    public static EthrIdentifier ParseMethodSpecificId(string methodSpecificId)
    {
        ArgumentNullException.ThrowIfNull(methodSpecificId);

        string network;
        string addressOrKey;

        // Strategy: find the last occurrence of ":0x" — everything before it is the
        // network name (which may itself contain colons, e.g. "artis:sigma1"),
        // everything from the "0x" onward is the address or compressed public key.
        //
        // Cases:
        //   "0x..."                   → no prefix, mainnet
        //   "sepolia:0x..."           → network="sepolia"
        //   "0xaa36a7:0x..."          → network="0xaa36a7"
        //   "artis:sigma1:0x..."      → network="artis:sigma1"
        //   "a:b:c:0x..."             → network="a:b:c"
        var lastColon0x = methodSpecificId.LastIndexOf(":0x", StringComparison.OrdinalIgnoreCase);

        if (lastColon0x < 0)
        {
            // No ":0x" separator — the whole string must itself start with 0x (bare address/key, mainnet)
            network      = "mainnet";
            addressOrKey = methodSpecificId;
        }
        else
        {
            network      = methodSpecificId[..lastColon0x].ToLowerInvariant();
            addressOrKey = methodSpecificId[(lastColon0x + 1)..];
        }

        if (!addressOrKey.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException($"Method-specific id must start with 0x: {methodSpecificId}");

        var hexBody = addressOrKey[2..];

        if (hexBody.Length == 40)
        {
            // Plain Ethereum address
            return new EthrIdentifier(
                Network: network,
                IdentityAddress: "0x" + hexBody.ToLowerInvariant(),
                IsPublicKey: false,
                PublicKeyBytes: null);
        }

        if (hexBody.Length == 66)
        {
            // Compressed secp256k1 public key
            var pubKeyBytes = Convert.FromHexString(hexBody);
            var address = EthereumAddress.FromCompressedPublicKey(pubKeyBytes);
            return new EthrIdentifier(
                Network: network,
                IdentityAddress: address.ToLowerInvariant(),
                IsPublicKey: true,
                PublicKeyBytes: pubKeyBytes);
        }

        throw new ArgumentException(
            $"Invalid method-specific id length (expected 40 or 66 hex chars after 0x): {hexBody.Length}");
    }
}

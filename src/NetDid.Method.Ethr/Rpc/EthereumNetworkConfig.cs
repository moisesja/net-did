namespace NetDid.Method.Ethr.Rpc;

/// <summary>Network configuration for a single Ethereum network / RPC endpoint.</summary>
public sealed record EthereumNetworkConfig
{
    public required string Name { get; init; }       // "mainnet", "sepolia", etc.
    public required string RpcUrl { get; init; }
    /// <summary>Hex chain ID (e.g. "0x1"). Auto-detected via eth_chainId if null.</summary>
    public string? ChainId { get; init; }
    /// <summary>ERC-1056 registry address. Defaults to the canonical universal registry.</summary>
    public string RegistryAddress { get; init; } = "0xdCa7EF03e98e0DC2B855bE647C39ABe984fcF21B";
}

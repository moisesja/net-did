namespace NetDid.Method.Ethr.Rpc;

/// <summary>Network configuration for a single Ethereum network / RPC endpoint.</summary>
public sealed record EthereumNetworkConfig
{
    public required string Name { get; init; }
    /// <summary>JSON-RPC endpoint URL. Supply via <c>with { RpcUrl = "..." }</c> when starting from a <see cref="KnownNetworks"/> entry.</summary>
    public required string RpcUrl { get; init; }
    /// <summary>Hex chain ID (e.g. "0x1"). Auto-detected via eth_chainId if null.</summary>
    public string? ChainId { get; init; }
    /// <summary>ERC-1056 registry address.</summary>
    public required string RegistryAddress { get; init; }
    /// <summary>
    /// Contracts deployed before ethr-did-registry 0.0.3 track nonces differently for
    /// meta-transactions. Relevant for Phase 2 (Update / Deactivate). Mirrors the JS
    /// resolver's <c>legacyNonce</c> field.
    /// </summary>
    public bool LegacyNonce { get; init; } = false;
}

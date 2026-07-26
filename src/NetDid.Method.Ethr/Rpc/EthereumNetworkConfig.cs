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
    /// meta-transactions. Mirrors the JS resolver's <c>legacyNonce</c> field.
    /// </summary>
    public bool LegacyNonce { get; init; } = false;

    /// <summary>
    /// Sanity ceiling (in wei) on the <c>eth_gasPrice</c> value this library will sign into a
    /// transaction. The RPC endpoint is untrusted and the gas price it reports becomes a fee
    /// the caller's key authorizes, so a hostile or compromised node could otherwise drain a
    /// funded signer to the block producer while every operation still "succeeds". A price
    /// above this ceiling aborts the write before anything is signed.
    ///
    /// <para>The default — 5,000 gwei — is roughly two orders of magnitude above normal
    /// mainnet congestion, so it never rejects an honest price; it exists purely to bound a
    /// malicious one. Chains with unusual native-token denominations, or callers who genuinely
    /// need to outbid extreme congestion, should raise it deliberately.</para>
    /// </summary>
    public ulong MaxGasPriceWei { get; init; } = 5_000UL * 1_000_000_000UL;
}

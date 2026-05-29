namespace NetDid.Method.Ethr.Rpc;

/// <summary>
/// Pre-populated registry of known ERC-1056 contract deployments, mirroring the
/// <c>deployments.ts</c> catalogue in the JS reference resolver
/// (decentralized-identity/ethr-did-resolver).
///
/// Each entry has <see cref="EthereumNetworkConfig.RpcUrl"/> set to an empty string.
/// Supply a real endpoint using the record <c>with</c> expression before passing the
/// config to <see cref="DidEthrMethod"/>:
/// <code>
/// var config = KnownNetworks.Sepolia with { RpcUrl = "https://sepolia.drpc.org" };
/// </code>
///
/// <see cref="All"/> contains every active (non-deprecated) network.
/// Deprecated networks (Ropsten, Rinkeby, Goerli, Kovan) are omitted, matching
/// the commented-out entries in the JS source.
/// </summary>
public static class KnownNetworks
{
    // ── Registry addresses ────────────────────────────────────────────────────
    // Two distinct contract deployments exist in the wild:
    //   Legacy  — 0xdCa7EF03... (ethr-did-registry ≤ 0.0.2, legacyNonce = true)
    //   Current — 0x03d5003b... (ethr-did-registry ≥ 0.0.3, legacyNonce = false)

    private const string LegacyRegistry  = "0xdca7ef03e98e0dc2b855be647c39abe984fcf21b";
    private const string CurrentRegistry = "0x03d5003bf0e79C5F5223588F347ebA39AfbC3818";

    // ── Active mainnet-class networks ─────────────────────────────────────────

    public static readonly EthereumNetworkConfig Mainnet = new()
    {
        Name            = "mainnet",
        RpcUrl          = "",
        ChainId         = "0x1",
        RegistryAddress = LegacyRegistry,
        LegacyNonce     = true,
    };

    public static readonly EthereumNetworkConfig Polygon = new()
    {
        Name            = "polygon",
        RpcUrl          = "",
        ChainId         = "0x89",        // 137
        RegistryAddress = LegacyRegistry,
        LegacyNonce     = true,
    };

    public static readonly EthereumNetworkConfig Gnosis = new()
    {
        Name            = "gno",
        RpcUrl          = "",
        ChainId         = "0x64",        // 100
        RegistryAddress = CurrentRegistry,
        LegacyNonce     = false,
    };

    public static readonly EthereumNetworkConfig Aurora = new()
    {
        Name            = "aurora",
        RpcUrl          = "",
        ChainId         = "0x4e454152", // 1313161554
        RegistryAddress = "0x63eD58B671EeD12Bc1652845ba5b2CDfBff198e0",
        LegacyNonce     = true,
    };

    public static readonly EthereumNetworkConfig EnergyWebChain = new()
    {
        Name            = "ewc",
        RpcUrl          = "",
        ChainId         = "0xf6",        // 246
        RegistryAddress = "0xE29672f34e92b56C9169f9D485fFc8b9A136BCE4",
        LegacyNonce     = false,
    };

    public static readonly EthereumNetworkConfig ArtisS1 = new()
    {
        Name            = "artis:sigma1",
        RpcUrl          = "",
        ChainId         = "0x3C401",     // 246529
        RegistryAddress = LegacyRegistry,
        LegacyNonce     = true,
    };

    // ── Testnets ──────────────────────────────────────────────────────────────

    public static readonly EthereumNetworkConfig Sepolia = new()
    {
        Name            = "sepolia",
        RpcUrl          = "",
        ChainId         = "0xaa36a7",   // 11155111
        RegistryAddress = CurrentRegistry,
        LegacyNonce     = false,
    };

    public static readonly EthereumNetworkConfig Holesky = new()
    {
        Name            = "holesky",
        RpcUrl          = "",
        ChainId         = "0x4268",     // 17000
        RegistryAddress = CurrentRegistry,
        LegacyNonce     = false,
    };

    public static readonly EthereumNetworkConfig PolygonMumbai = new()
    {
        Name            = "polygon:test",
        RpcUrl          = "",
        ChainId         = "0x13881",    // 80001
        RegistryAddress = LegacyRegistry,
        LegacyNonce     = true,
    };

    public static readonly EthereumNetworkConfig Volta = new()
    {
        Name            = "volta",
        RpcUrl          = "",
        ChainId         = "0x12047",    // 73799
        RegistryAddress = "0xC15D5A57A8Eb0e1dCBE5D88B8f9a82017e5Cc4AF",
        LegacyNonce     = false,
    };

    public static readonly EthereumNetworkConfig ArtisT1 = new()
    {
        Name            = "artis:tau1",
        RpcUrl          = "",
        ChainId         = "0x3C401",    // 246785 — note: shares chain ID encoding w/ sigma1 in hex
        RegistryAddress = LegacyRegistry,
        LegacyNonce     = true,
    };

    public static readonly EthereumNetworkConfig LineaGoerli = new()
    {
        Name            = "linea:goerli",
        RpcUrl          = "",
        ChainId         = "0xe704",     // 59140
        RegistryAddress = CurrentRegistry,
        LegacyNonce     = false,
    };

    // ── Catalogue ─────────────────────────────────────────────────────────────

    /// <summary>
    /// All active (non-deprecated) known network configurations, in the same order
    /// as <c>deployments.ts</c>. RpcUrl is empty in every entry — use
    /// <c>with { RpcUrl = "..." }</c> to produce a ready-to-use config.
    /// </summary>
    public static readonly IReadOnlyList<EthereumNetworkConfig> All =
    [
        Mainnet, Sepolia, Gnosis, Holesky, EnergyWebChain, Volta,
        ArtisT1, ArtisS1, Polygon, PolygonMumbai, Aurora, LineaGoerli,
    ];

    /// <summary>
    /// Looks up a known network by name (case-insensitive) or hex chain ID (e.g. "0xaa36a7").
    /// Returns <c>null</c> if no match is found.
    /// </summary>
    public static EthereumNetworkConfig? Find(string nameOrChainId)
        => All.FirstOrDefault(n =>
            string.Equals(n.Name, nameOrChainId, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(n.ChainId, nameOrChainId, StringComparison.OrdinalIgnoreCase));
}

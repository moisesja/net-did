namespace NetDid.Method.Ethr.Rpc;

/// <summary>
/// Ethereum JSON-RPC client interface used by the did:ethr resolver.
///
/// Phase 1 methods (Create + Resolve) are marked below.
/// Phase 2 methods (Update / Deactivate) are declared here so the interface is
/// stable; DefaultEthereumRpcClient throws NotImplementedException for them.
/// </summary>
public interface IEthereumRpcClient
{
    // ── Phase 1 ──────────────────────────────────────────────────────────────

    /// <summary>eth_call — call a read-only contract function.</summary>
    Task<string> CallAsync(string to, string data, CancellationToken ct = default);

    /// <summary>eth_getLogs — fetch matching event logs.</summary>
    Task<IReadOnlyList<EthereumLogEntry>> GetLogsAsync(EthereumLogFilter filter, CancellationToken ct = default);

    /// <summary>eth_blockNumber — latest block number.</summary>
    Task<ulong> GetBlockNumberAsync(CancellationToken ct = default);

    /// <summary>eth_chainId — chain ID as ulong.</summary>
    Task<ulong> GetChainIdAsync(CancellationToken ct = default);

    /// <summary>
    /// eth_getBlockByNumber — returns the Unix timestamp of a specific block.
    /// Required for VersionId / VersionTime resolution.
    /// </summary>
    Task<ulong> GetBlockTimestampAsync(ulong blockNumber, CancellationToken ct = default);

    // ── Phase 2 (declared; throw NotImplementedException in Phase 1) ──────────

    /// <summary>eth_sendRawTransaction — broadcast a signed transaction.</summary>
    Task<string> SendRawTransactionAsync(byte[] signedTransaction, CancellationToken ct = default);

    /// <summary>eth_getTransactionCount — nonce for an address.</summary>
    Task<ulong> GetTransactionCountAsync(string address, CancellationToken ct = default);

    /// <summary>eth_gasPrice — current gas price.</summary>
    Task<ulong> GetGasPriceAsync(CancellationToken ct = default);
}
